#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
mod ssl;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
mod nginx;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
mod keyless {
	use ssl::*;
	use nginx::*;

	use error::Error as ngx_http_keyless_error_t;
	use opcode::Op as ngx_http_keyless_operation_t;

	include!(concat!(env!("OUT_DIR"), "/keyless.rs"));
}

mod get_cert;

use std::ptr;
use std::mem;
use std::slice;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

extern crate libc;

#[macro_use]
extern crate enum_primitive;

extern crate num;
use num::FromPrimitive;

#[macro_use]
extern crate nom;
use nom::IResult;

named!(parse_cipher_suites<Vec<u16>>, many0!(nom::be_u16));

#[allow(dead_code)]
mod error;
use error::Error;

#[allow(dead_code)]
mod opcode;
use opcode::Op;

const SESS_ID_CTX: &'static str = "keyless-HTTP";

const KEY_METHOD: ssl::SSL_PRIVATE_KEY_METHOD = ssl::SSL_PRIVATE_KEY_METHOD {
	type_: Some(key_type),
	max_signature_len: Some(key_max_signature_len),
	sign: Some(key_sign),
	sign_digest: None,
	decrypt: Some(key_decrypt),
	complete: Some(key_complete),
};

#[no_mangle]
#[allow(non_upper_case_globals)]
pub static mut ngx_http_keyless_ctx_conf_index: std::os::raw::c_int = -1;

static mut SSL_CONN_INDEX: std::os::raw::c_int = -1;

#[no_mangle]
#[allow(non_upper_case_globals)]
#[allow(dead_code)]
pub static ngx_http_keyless_module_ctx: nginx::ngx_http_module_t = nginx::ngx_http_module_t {
	preconfiguration: None,
	postconfiguration: None,

	create_main_conf: None,
	init_main_conf: None,

	create_srv_conf: Some(create_srv_conf),
	merge_srv_conf: Some(merge_srv_conf),

	create_loc_conf: None,
	merge_loc_conf: None,
};

unsafe fn get_conn(ssl: *const ssl::SSL) -> *mut keyless::ngx_http_keyless_conn_t {
	ssl::SSL_get_ex_data(ssl, SSL_CONN_INDEX) as *mut keyless::ngx_http_keyless_conn_t
}

pub extern "C" fn create_srv_conf(cf: *mut nginx::ngx_conf_t) -> *mut std::os::raw::c_void {
	if let Some(kcscf) =
		unsafe {
			(nginx::ngx_pcalloc((*cf).pool,
		                   mem::size_of::<keyless::ngx_http_keyless_srv_conf_t>())
			as *mut keyless::ngx_http_keyless_srv_conf_t).as_mut()
		} {
		// set by ngx_pcalloc():
		//
		//     kcscf.address = { 0, NULL };

		kcscf.timeout = nginx::NGX_CONF_UNSET_MSEC as usize;
		kcscf.fallback = nginx::NGX_CONF_UNSET as isize;

		kcscf as *mut keyless::ngx_http_keyless_srv_conf_t as *mut std::os::raw::c_void
	} else {
		ptr::null_mut()
	}
}

pub extern "C" fn merge_srv_conf(cf: *mut nginx::ngx_conf_t,
                                 parent: *mut std::os::raw::c_void,
                                 child: *mut std::os::raw::c_void)
                                 -> *mut i8 {
	let prev = unsafe { (parent as *const keyless::ngx_http_keyless_srv_conf_t).as_ref() }
		.unwrap();
	let conf = unsafe { (child as *mut keyless::ngx_http_keyless_srv_conf_t).as_mut() }
		.unwrap();

	if conf.address.data.is_null() {
		if prev.address.data.is_null() {
			conf.address.data = "\0".as_ptr() as *mut u8;
			conf.address.len = 0;
		} else {
			conf.address = prev.address;
		};
	};

	if conf.timeout == nginx::NGX_CONF_UNSET_MSEC as usize {
		conf.timeout = if prev.timeout == nginx::NGX_CONF_UNSET_MSEC as usize {
			250
		} else {
			prev.timeout
		};
	};

	if conf.fallback == nginx::NGX_CONF_UNSET as isize {
		conf.fallback = if prev.fallback == nginx::NGX_CONF_UNSET as isize {
			1
		} else {
			prev.fallback
		};
	};

	if conf.address.len == 0 ||
	   OsStr::from_bytes(unsafe {
		slice::from_raw_parts(conf.address.data, conf.address.len)
	}) == "off" {
		return nginx::NGX_CONF_OK;
	};

	let ssl = unsafe {
		nginx::ngx_http_conf_get_module_srv_conf(cf, &nginx::ngx_http_ssl_module)
	} as *mut nginx::ngx_http_ssl_srv_conf_t;
	if ssl.is_null() || unsafe { (*ssl).ssl.ctx }.is_null() {
		return nginx::NGX_CONF_ERROR;
	};

	let mut u: nginx::ngx_url_t = nginx::ngx_url_t::default();
	u.url = conf.address;
	u.default_port = 2407;
	unsafe { nginx::ngx_url_set_no_resolve(&mut u) };

	if unsafe { nginx::ngx_parse_url((*cf).pool, &mut u) } != nginx::NGX_OK as isize ||
	   u.addrs.is_null() {
		return nginx::NGX_CONF_ERROR;
	};

	let addr = unsafe { ptr::read(u.addrs) };
	if addr.sockaddr.is_null() {
		return nginx::NGX_CONF_ERROR;
	};

	conf.pc.sockaddr = addr.sockaddr;
	conf.pc.socklen = addr.socklen;
	conf.pc.name = &mut conf.address;

	conf.pc.get = unsafe { mem::transmute(nginx::ngx_event_get_peer as *const ()) };
	conf.pc.log = unsafe { (*cf).log };
	//conf.pc.log_error = nginx::NGX_ERROR_ERR;

	if unsafe { ssl::RAND_bytes(mem::transmute(&mut conf.id), 8) } != 1 {
		return nginx::NGX_CONF_ERROR;
	}

	conf.pool = unsafe { (*(*cf).cycle).pool };

	unsafe {
		nginx::ngx_queue_init(&mut conf.recv_ops);
		nginx::ngx_queue_init(&mut conf.send_ops);
	};

	unsafe {
		ssl::SSL_CTX_set_select_certificate_cb((*ssl).ssl.ctx, Some(select_certificate_cb));
		ssl::SSL_CTX_set_cert_cb((*ssl).ssl.ctx, Some(cert_cb), ptr::null_mut());
	};

	unsafe {
		if ngx_http_keyless_ctx_conf_index == -1 {
			ngx_http_keyless_ctx_conf_index =
				ssl::SSL_CTX_get_ex_new_index(0,
				                              ptr::null_mut(),
				                              ptr::null_mut(),
				                              None,
				                              None);
			if ngx_http_keyless_ctx_conf_index == -1 {
				return nginx::NGX_CONF_ERROR;
			};
		};

		if SSL_CONN_INDEX == -1 {
			SSL_CONN_INDEX = ssl::SSL_get_ex_new_index(0,
			                                           ptr::null_mut(),
			                                           ptr::null_mut(),
			                                           None,
			                                           None);
			if SSL_CONN_INDEX == -1 {
				return nginx::NGX_CONF_ERROR;
			};
		};
	};

	if unsafe {
		ssl::SSL_CTX_set_ex_data((*ssl).ssl.ctx, ngx_http_keyless_ctx_conf_index, child)
	} != 1 {
		return nginx::NGX_CONF_ERROR;
	};

	nginx::NGX_CONF_OK
}

pub extern "C" fn select_certificate_cb(client_hello: *const ssl::SSL_CLIENT_HELLO)
                                        -> std::os::raw::c_int {
	let c = unsafe { nginx::ngx_ssl_get_connection((*client_hello).ssl) };

	let conn = unsafe {
		(nginx::ngx_pcalloc((*c).pool,
		                    mem::size_of::<keyless::ngx_http_keyless_conn_t>()) as
		 *mut keyless::ngx_http_keyless_conn_t)
			.as_mut()
	};
	if conn.is_none() {
		return -1;
	};

	let conn = conn.unwrap();

	if unsafe {
		ssl::SSL_set_ex_data((*(*c).ssl).connection,
		                     SSL_CONN_INDEX,
		                     conn as *mut keyless::ngx_http_keyless_conn_t as
		                     *mut std::os::raw::c_void)
	} != 1 {
		return -1;
	};

	conn.key.type_ = ssl::NID_undef as i32;

	let cipher_list = unsafe { ssl::SSL_get_ciphers((*client_hello).ssl) };

	for cipher_suite in
		match parse_cipher_suites(unsafe {
			slice::from_raw_parts((*client_hello).cipher_suites,
			                      (*client_hello).cipher_suites_len)
		}) {
			IResult::Done(i, ref v) if i.is_empty() => v,
			_ => return -1,
		} {
		let cipher = unsafe { ssl::SSL_get_cipher_by_value(*cipher_suite) };
		if !cipher.is_null() &&
		   unsafe {
			ssl::SSL_CIPHER_is_ECDSA(cipher) == 1 &&
			ssl::sk_find(cipher_list,
			             ptr::null_mut(),
			             cipher as *mut std::os::raw::c_void) == 1
		} {
			conn.get_cert.ecdsa_cipher = 1;
			break;
		}
	}

	let mut extension_data: *const u8 = ptr::null();
	let mut extension_len: usize = 0;

	if unsafe {
		ssl::SSL_early_callback_ctx_extension_get(client_hello,
		                                          ssl::TLSEXT_TYPE_signature_algorithms as
		                                          u16,
		                                          &mut extension_data,
		                                          &mut extension_len)
	} == 1 {
		let mut extension: ssl::CBS = ssl::CBS::default();
		unsafe { ssl::CBS_init(&mut extension, extension_data, extension_len) };

		let mut sig_algs: ssl::CBS = ssl::CBS::default();

		let cln = unsafe { nginx::ngx_pool_cleanup_add((*c).pool, 0).as_mut() };
		if cln.is_none() ||
		   unsafe {
			ssl::CBS_get_u16_length_prefixed(&mut extension, &mut sig_algs) != 1 ||
			ssl::CBS_len(&sig_algs) == 0 || ssl::CBS_len(&extension) != 0 ||
			ssl::CBS_len(&sig_algs) % 2 != 0 ||
			ssl::CBS_stow(&sig_algs,
			              &mut conn.get_cert.sig_algs,
			              &mut conn.get_cert.sig_algs_len) != 1
		} {
			return -1;
		};

		let cln = cln.unwrap();
		cln.handler = unsafe { mem::transmute(ssl::OPENSSL_free as *const ()) };
		cln.data = conn.get_cert.sig_algs as *mut std::os::raw::c_void;
	}

	1
}

#[allow(unused_variables)]
pub extern "C" fn cert_cb(ssl_conn: *mut ssl::SSL,
                          data: *mut std::os::raw::c_void)
                          -> std::os::raw::c_int {
	let c = unsafe { nginx::ngx_ssl_get_connection(ssl_conn) };
	let ssl = unsafe { (*(*c).ssl).connection };

	let conn = unsafe { get_conn(ssl).as_mut() };
	if conn.is_none() {
		return 1;
	};

	let conn = conn.unwrap();
	let op = unsafe { conn.op.as_mut() };

	if op.is_none() {
		conn.op = unsafe {
			keyless::ngx_http_keyless_start_operation(Op::GetCertificate,
			                                          c,
			                                          conn,
			                                          ptr::null(),
			                                          0)
		};

		conn.get_cert.sig_algs = ptr::null_mut();
		conn.get_cert.ecdsa_cipher = 0;

		return if conn.op.is_null() { 0 } else { -1 };
	};

	let op = op.unwrap();

	let ctx = unsafe { ssl::SSL_get_SSL_CTX(ssl) };

	let conf = unsafe {
		(ssl::SSL_CTX_get_ex_data(ctx, ngx_http_keyless_ctx_conf_index) as
		 *mut keyless::ngx_http_keyless_srv_conf_t)
			.as_ref()
	};
	if conf.is_none() {
		unsafe { keyless::ngx_http_keyless_cleanup_operation(op) };
		return 0;
	};

	let conf = conf.unwrap();

	let mut payload: ssl::CBS = ssl::CBS::default();

	match unsafe { keyless::ngx_http_keyless_operation_complete(op, &mut payload) } {
		ssl::ssl_private_key_failure => {
			let mut rc = 0;

			if op.error == Error::CertNotFound {
				if conf.fallback != 1 {
					unsafe { ssl::SSL_certs_clear(ssl) };
				};

				rc = 1;
			};

			unsafe { keyless::ngx_http_keyless_cleanup_operation(op) };
			return rc;
		}
		ssl::ssl_private_key_retry => return -1,
		ssl::ssl_private_key_success => (),
	}

	if unsafe { ssl::CBS_len(&payload) } == 0 || op.ski.is_null() {
		unsafe { keyless::ngx_http_keyless_cleanup_operation(op) };
		return 0;
	}

	unsafe {
		ptr::copy_nonoverlapping(op.ski,
		                         conn.ski.as_mut_ptr(),
		                         ssl::SHA_DIGEST_LENGTH as usize)
	};

	let mut sha_ctx: ssl::SHA256_CTX = ssl::SHA256_CTX::default();
	let mut sid_ctx: [u8; ssl::SHA256_DIGEST_LENGTH as usize] =
		[0; ssl::SHA256_DIGEST_LENGTH as usize];

	unsafe {
		ssl::SHA256_Init(&mut sha_ctx);
		ssl::SHA256_Update(&mut sha_ctx,
		                   SESS_ID_CTX.as_ptr() as *const std::os::raw::c_void,
		                   SESS_ID_CTX.len());
		ssl::SHA256_Update(&mut sha_ctx,
		                   ssl::CBS_data(&payload) as *const std::os::raw::c_void,
		                   ssl::CBS_len(&payload));
		ssl::SHA256_Final(sid_ctx.as_mut_ptr(), &mut sha_ctx);
	};

	if unsafe { ssl::SSL_set_session_id_context(ssl, sid_ctx.as_ptr(), 16) } != 1 {
		unsafe { keyless::ngx_http_keyless_cleanup_operation(op) };
		return 0;
	}

	if !op.ocsp_response.is_null() &&
	   unsafe {
		ssl::SSL_set_ocsp_response(ssl, op.ocsp_response, op.ocsp_response_length)
	} != 1 {
		unsafe { keyless::ngx_http_keyless_cleanup_operation(op) };
		return 0;
	}

	if !op.sct_list.is_null() &&
	   unsafe {
		ssl::SSL_set_signed_cert_timestamp_list(ssl, op.sct_list, op.sct_list_length)
	} != 1 {
		unsafe { keyless::ngx_http_keyless_cleanup_operation(op) };
		return 0;
	}

	let ret = get_cert::parse(unsafe {
		slice::from_raw_parts(ssl::CBS_data(&payload), ssl::CBS_len(&payload))
	});
	let res = match ret {
		IResult::Done(i, ref v) if i.is_empty() => v,
		_ => {
			unsafe { keyless::ngx_http_keyless_cleanup_operation(op) };
			return 0;
		}
	};

	let public_key = ssl::ssl_cert_parse_pubkey(res.leaf);
	if public_key.is_null() {
		unsafe { keyless::ngx_http_keyless_cleanup_operation(op) };
		return 0;
	}

	match unsafe { ssl::EVP_PKEY_id(public_key) as u32 } {
		ssl::EVP_PKEY_RSA => conn.key.type_ = ssl::NID_rsaEncryption as i32,
		ssl::EVP_PKEY_EC => conn.key.type_ = unsafe { ssl::EC_GROUP_get_curve_name(
			ssl::EC_KEY_get0_group(ssl::EVP_PKEY_get0_EC_KEY(public_key))) },
		_ => (),
	}

	conn.key.sig_len = unsafe { ssl::EVP_PKEY_size(public_key) } as usize;

	unsafe {
		ssl::EVP_PKEY_free(public_key);
	};

	let mut certs = Vec::new();
	certs.push(unsafe {
		ssl::CRYPTO_BUFFER_new(res.leaf.as_ptr(), res.leaf.len(), (*ctx).pool)
	} as *const ssl::CRYPTO_BUFFER);

	for &cert in &res.chain {
		certs.push(unsafe {
			ssl::CRYPTO_BUFFER_new(cert.as_ptr(), cert.len(), (*ctx).pool)
		} as *const ssl::CRYPTO_BUFFER);
	}

	unsafe {
		ssl::SSL_set_chain_and_key(ssl,
		                           certs.as_ptr(),
		                           certs.len(),
		                           ptr::null_mut(),
		                           &KEY_METHOD)
	};

	unsafe { keyless::ngx_http_keyless_cleanup_operation(op) };
	1
}

pub extern "C" fn key_type(ssl_conn: *mut ssl::SSL) -> std::os::raw::c_int {
	let c = unsafe { nginx::ngx_ssl_get_connection(ssl_conn) };

	if let Some(conn) = unsafe { get_conn((*(*c).ssl).connection).as_ref() } {
		conn.key.type_
	} else {
		ssl::NID_undef as i32
	}
}

pub extern "C" fn key_max_signature_len(ssl_conn: *mut ssl::SSL) -> u64 {
	let c = unsafe { nginx::ngx_ssl_get_connection(ssl_conn) };

	if let Some(conn) = unsafe { get_conn((*(*c).ssl).connection).as_ref() } {
		conn.key.sig_len as u64
	} else {
		0
	}
}

fn key_start_operation(op: Op,
                       ssl_conn: *mut ssl::SSL,
                       in_ptr: *const u8,
                       in_len: usize)
                       -> ssl::ssl_private_key_result_t {
	let c = unsafe { nginx::ngx_ssl_get_connection(ssl_conn) };

	if let Some(conn) = unsafe { get_conn((*(*c).ssl).connection).as_mut() } {
		conn.op = unsafe {
			keyless::ngx_http_keyless_start_operation(op, c, conn, in_ptr, in_len)
		};
		if conn.op.is_null() {
			ssl::ssl_private_key_failure
		} else {
			ssl::ssl_private_key_retry
		}
	} else {
		ssl::ssl_private_key_failure
	}
}

#[allow(unused_variables)]
pub extern "C" fn key_sign(ssl_conn: *mut ssl::SSL,
                           out: *mut u8,
                           out_len: *mut usize,
                           max_out: usize,
                           signature_algorithm: u16,
                           in_ptr: *const u8,
                           in_len: usize)
                           -> ssl::ssl_private_key_result_t {
	let opcode = match signature_algorithm as u32 {
		ssl::SSL_SIGN_RSA_PKCS1_MD5_SHA1 => Op::RSASignMD5SHA1,
		ssl::SSL_SIGN_RSA_PKCS1_SHA1 => Op::RSASignSHA1,
		ssl::SSL_SIGN_RSA_PKCS1_SHA256 => Op::RSASignSHA256,
		ssl::SSL_SIGN_RSA_PKCS1_SHA384 => Op::RSASignSHA384,
		ssl::SSL_SIGN_RSA_PKCS1_SHA512 => Op::RSASignSHA512,

		ssl::SSL_SIGN_RSA_PSS_SHA256 => Op::RSAPSSSignSHA256,
		ssl::SSL_SIGN_RSA_PSS_SHA384 => Op::RSAPSSSignSHA384,
		ssl::SSL_SIGN_RSA_PSS_SHA512 => Op::RSAPSSSignSHA512,

		ssl::SSL_SIGN_ECDSA_SHA1 => Op::ECDSASignSHA1,
		ssl::SSL_SIGN_ECDSA_SECP256R1_SHA256 => Op::ECDSASignSHA256,
		ssl::SSL_SIGN_ECDSA_SECP384R1_SHA384 => Op::ECDSASignSHA384,
		ssl::SSL_SIGN_ECDSA_SECP521R1_SHA512 => Op::ECDSASignSHA512,

		_ => return ssl::ssl_private_key_failure,
	};

	let mut hash: [u8; ssl::SHA512_DIGEST_LENGTH as usize] =
		[0; ssl::SHA512_DIGEST_LENGTH as usize];

	let hash_len = match signature_algorithm as u32 {
		ssl::SSL_SIGN_RSA_PKCS1_MD5_SHA1 => {
			unsafe {
				ssl::MD5(in_ptr, in_len, hash.as_mut_ptr());
				ssl::SHA1(in_ptr,
				          in_len,
				          hash[ssl::MD5_DIGEST_LENGTH as usize..].as_mut_ptr());
			};
			ssl::MD5_DIGEST_LENGTH + ssl::SHA_DIGEST_LENGTH
		}
		ssl::SSL_SIGN_RSA_PKCS1_SHA1 |
		ssl::SSL_SIGN_ECDSA_SHA1 => {
			unsafe { ssl::SHA1(in_ptr, in_len, hash.as_mut_ptr()) };
			ssl::SHA_DIGEST_LENGTH
		}
		ssl::SSL_SIGN_RSA_PKCS1_SHA256 |
		ssl::SSL_SIGN_ECDSA_SECP256R1_SHA256 |
		ssl::SSL_SIGN_RSA_PSS_SHA256 => {
			unsafe { ssl::SHA256(in_ptr, in_len, hash.as_mut_ptr()) };
			ssl::SHA256_DIGEST_LENGTH
		}
		ssl::SSL_SIGN_RSA_PKCS1_SHA384 |
		ssl::SSL_SIGN_ECDSA_SECP384R1_SHA384 |
		ssl::SSL_SIGN_RSA_PSS_SHA384 => {
			unsafe { ssl::SHA384(in_ptr, in_len, hash.as_mut_ptr()) };
			ssl::SHA384_DIGEST_LENGTH
		}
		ssl::SSL_SIGN_RSA_PKCS1_SHA512 |
		ssl::SSL_SIGN_ECDSA_SECP521R1_SHA512 |
		ssl::SSL_SIGN_RSA_PSS_SHA512 => {
			unsafe { ssl::SHA512(in_ptr, in_len, hash.as_mut_ptr()) };
			ssl::SHA512_DIGEST_LENGTH
		}
		_ => return ssl::ssl_private_key_failure,
	} as usize;

	key_start_operation(opcode, ssl_conn, hash.as_ptr(), hash_len)
}

#[allow(unused_variables)]
pub extern "C" fn key_decrypt(ssl_conn: *mut ssl::SSL,
                              out: *mut u8,
                              out_len: *mut usize,
                              max_out: usize,
                              in_ptr: *const u8,
                              in_len: usize)
                              -> ssl::ssl_private_key_result_t {
	key_start_operation(Op::RSADecryptRaw, ssl_conn, in_ptr, in_len)
}

pub extern "C" fn key_complete(ssl_conn: *mut ssl::SSL,
                               out: *mut u8,
                               out_len: *mut usize,
                               max_out: usize)
                               -> ssl::ssl_private_key_result_t {
	let c = unsafe { nginx::ngx_ssl_get_connection(ssl_conn) };

	let conn = unsafe { get_conn((*(*c).ssl).connection).as_mut() };
	if conn.is_none() {
		return ssl::ssl_private_key_failure;
	};

	let conn = conn.unwrap();

	let mut payload: ssl::CBS = ssl::CBS::default();

	let mut rc = unsafe { keyless::ngx_http_keyless_operation_complete(conn.op, &mut payload) };
	match rc {
		ssl::ssl_private_key_retry => return rc,
		ssl::ssl_private_key_success => {
			unsafe { *out_len = ssl::CBS_len(&payload) };

			if unsafe {
				ssl::CBS_len(&payload) > max_out ||
				ssl::CBS_copy_bytes(&mut payload, out, ssl::CBS_len(&payload)) != 1
			} {
				rc = ssl::ssl_private_key_failure;
			};
		}
		ssl::ssl_private_key_failure => (),
	}

	unsafe { keyless::ngx_http_keyless_cleanup_operation(conn.op) };
	rc
}

#[no_mangle]
pub extern "C" fn ngx_http_keyless_error_string(code: u16) -> *const u8 {
	let msg: &'static str = match Error::from_u16(code) {
		Some(Error::None) => "no error\0",
		Some(Error::CryptoFailed) => "cryptography error\0",
		Some(Error::KeyNotFound) => "key not found\0",
		Some(Error::DiskRead) => "disk read failure\0",
		Some(Error::VersionMismatch) => "version mismatch\0",
		Some(Error::BadOpcode) => "bad opcode\0",
		Some(Error::UnexpectedOpcode) => "unexpected opcode\0",
		Some(Error::Format) => "malformed message\0",
		Some(Error::Internal) => "internal error\0",
		Some(Error::CertNotFound) => "certificate not found\0",
		Some(Error::Expired) => "sealing key expired\0",
		Some(Error::NotAuthorised) => "client not authorised\0",
		_ => "unknown error\0",
	};
	msg.as_ptr()
}

#[no_mangle]
pub extern "C" fn ngx_http_keyless_socket_write_handler(wev: *mut nginx::ngx_event_t) {
	let c = unsafe { ((*wev).data as *mut nginx::ngx_connection_t).as_mut() }.unwrap();
	let conf = unsafe { (c.data as *mut keyless::ngx_http_keyless_srv_conf_t).as_mut() }
		.unwrap();
	let send = c.send.unwrap();

	while let Some(op) = unsafe {
		keyless::ngx_http_keyless_helper_send_queue_head(&mut conf.send_ops).as_mut()
	} {
		while op.send.pos < op.send.last {
			let size = unsafe {
				send(c,
				     op.send.pos,
				     op.send.last.offset(-(op.send.pos as isize)) as usize) as
				isize
			};
			if size > 0 {
				op.send.pos = unsafe { op.send.pos.offset(size) };
			} else if size == 0 || size == nginx::NGX_AGAIN as isize {
				return;
			} else {
				unsafe { nginx::ngx_connection_set_error(c) };
				return;
			}
		}

		unsafe { nginx::ngx_queue_remove(&mut op.send_queue) };

		unsafe {
			ssl::OPENSSL_cleanse(op.send.start as *mut std::os::raw::c_void,
			                     op.send.end.offset(-(op.send.start as isize)) as
			                     usize);
			ssl::OPENSSL_free(op.send.start as *mut libc::c_void);
		};

		op.send.start = ptr::null_mut();
		op.send.pos = ptr::null_mut();
		op.send.last = ptr::null_mut();
		op.send.end = ptr::null_mut();
	}
}
