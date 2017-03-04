#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
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

use std::ptr;
use std::mem;
use std::slice;
use std::io::Cursor;

extern crate libc;

extern crate byteorder;
use byteorder::{BigEndian, ReadBytesExt};

#[macro_use]
extern crate enum_primitive;

extern crate num;
use num::FromPrimitive;

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

static mut SSL_CONN_INDEX: std::os::raw::c_int = -1;

pub fn get_conn(ssl: *const ssl::SSL) -> *mut keyless::ngx_http_keyless_conn_t {
	unsafe {
		ssl::SSL_get_ex_data(ssl, SSL_CONN_INDEX) as *mut keyless::ngx_http_keyless_conn_t
	}
}

#[no_mangle]
pub extern "C" fn ngx_http_keyless_create_srv_conf(cf: *mut nginx::ngx_conf_t)
                                                   -> *mut std::os::raw::c_void {
	let kcscf = unsafe {
		nginx::ngx_pcalloc((*cf).pool,
		                   mem::size_of::<keyless::ngx_http_keyless_srv_conf_t>())
	} as *mut keyless::ngx_http_keyless_srv_conf_t;
	if kcscf.is_null() {
		return ptr::null_mut();
	};

	// set by ngx_pcalloc():
	//
	//     kcscf->address = { 0, NULL };

	unsafe {
		(*kcscf).timeout = nginx::NGX_CONF_UNSET_MSEC as usize;
		(*kcscf).fallback = nginx::NGX_CONF_UNSET as isize;
	};

	kcscf as *mut std::os::raw::c_void
}

#[no_mangle]
pub extern "C" fn ngx_http_keyless_merge_srv_conf(cf: *const nginx::ngx_conf_t,
                                                  parent: *const std::os::raw::c_void,
                                                  child: *mut std::os::raw::c_void)
                                                  -> *const u8 {
	let prev = parent as *const keyless::ngx_http_keyless_srv_conf_t;
	let conf = child as *mut keyless::ngx_http_keyless_srv_conf_t;

	if (unsafe { (*conf).address.data }).is_null() {
		if (unsafe { (*prev).address.data }).is_null() {
			unsafe {
				(*conf).address.data = "\0".as_ptr() as *mut u8;
				(*conf).address.len = 0;
			};
		} else {
			unsafe { (*conf).address = (*prev).address };
		};
	};

	if unsafe { (*conf).timeout } == nginx::NGX_CONF_UNSET_MSEC as usize {
		if unsafe { (*prev).timeout } == nginx::NGX_CONF_UNSET_MSEC as usize {
			unsafe { (*conf).timeout = 250 };
		} else {
			unsafe { (*conf).timeout = (*prev).timeout };
		};
	};

	if unsafe { (*conf).fallback } == nginx::NGX_CONF_UNSET as isize {
		if unsafe { (*prev).fallback } == nginx::NGX_CONF_UNSET as isize {
			unsafe { (*conf).fallback = 1 };
		} else {
			unsafe { (*conf).fallback = (*prev).fallback };
		};
	};

	if unsafe {
		(*conf).address.len == 0 ||
		libc::strcmp((*conf).address.data as *const i8,
		             "off\0".as_ptr() as *const i8) == 0
	} {
		return nginx::NGX_CONF_OK;
	};

	let ssl = unsafe {
		nginx::ngx_http_conf_get_module_srv_conf(cf, &nginx::ngx_http_ssl_module)
	} as *mut nginx::ngx_http_ssl_srv_conf_t;
	if ssl.is_null() || unsafe { (*ssl).ssl.ctx }.is_null() {
		return nginx::NGX_CONF_ERROR;
	};

	let mut u: nginx::ngx_url_t = nginx::ngx_url_t::default();
	u.url = unsafe { (*conf).address };
	u.default_port = 2407;
	unsafe { nginx::ngx_url_set_no_resolve(&mut u) };

	if u.url.len >= 4 &&
	   unsafe {
		libc::strncmp(u.url.data as *const i8, "udp:\0".as_ptr() as *const i8, 4)
	} == 0 {
		u.url.data = unsafe { u.url.data.offset(4) };
		u.url.len -= 4;

		unsafe { (*conf).pc.type_ = libc::SOCK_DGRAM };
	} else if u.url.len >= 4 &&
	          unsafe {
		libc::strncmp(u.url.data as *const i8, "tcp:\0".as_ptr() as *const i8, 4)
	} == 0 {
		u.url.data = unsafe { u.url.data.offset(4) };
		u.url.len -= 4;
	};

	if unsafe { nginx::ngx_parse_url((*cf).pool, &mut u) } != nginx::NGX_OK as isize ||
	   u.addrs.is_null() || unsafe { ptr::read(u.addrs) }.sockaddr.is_null() {
		return nginx::NGX_CONF_ERROR;
	};

	unsafe {
		(*conf).pc.sockaddr = ptr::read(u.addrs).sockaddr;
		(*conf).pc.socklen = ptr::read(u.addrs).socklen;
		(*conf).pc.name = &mut (*conf).address;

		(*conf).pc.get = mem::transmute(nginx::ngx_event_get_peer as *const ());
		(*conf).pc.log = (*cf).log;
		//(*conf).pc.log_error = nginx::NGX_ERROR_ERR;
	};

	if unsafe { ssl::RAND_bytes(mem::transmute(&(*conf).id), 8) } != 1 {
		return nginx::NGX_CONF_ERROR;
	}

	unsafe { (*conf).pool = (*(*cf).cycle).pool };

	unsafe {
		nginx::ngx_queue_init(&mut (*conf).recv_ops);
		nginx::ngx_queue_init(&mut (*conf).send_ops);
	};

	unsafe {
		ssl::SSL_CTX_set_select_certificate_cb((*ssl).ssl.ctx, Some(select_certificate_cb));
		ssl::SSL_CTX_set_cert_cb((*ssl).ssl.ctx, Some(cert_cb), ptr::null_mut());
	};

	unsafe {
		if keyless::ngx_http_keyless_ctx_conf_index == -1 {
			keyless::ngx_http_keyless_ctx_conf_index =
				ssl::SSL_CTX_get_ex_new_index(0,
				                              ptr::null_mut(),
				                              ptr::null_mut(),
				                              None,
				                              None);
			if keyless::ngx_http_keyless_ctx_conf_index == -1 {
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
		ssl::SSL_CTX_set_ex_data((*ssl).ssl.ctx,
		                         keyless::ngx_http_keyless_ctx_conf_index,
		                         conf as *mut std::os::raw::c_void)
	} != 1 {
		return nginx::NGX_CONF_ERROR;
	};

	nginx::NGX_CONF_OK
}

pub extern "C" fn select_certificate_cb(client_hello: *const ssl::SSL_CLIENT_HELLO)
                                        -> std::os::raw::c_int {
	let c = unsafe { nginx::ngx_ssl_get_connection((*client_hello).ssl) };

	let conn = unsafe {
		nginx::ngx_pcalloc((*c).pool,
		                   mem::size_of::<keyless::ngx_http_keyless_conn_t>())
	} as *mut keyless::ngx_http_keyless_conn_t;
	if conn.is_null() ||
	   unsafe {
		ssl::SSL_set_ex_data((*(*c).ssl).connection,
		                     SSL_CONN_INDEX,
		                     conn as *mut std::os::raw::c_void)
	} != 1 {
		return -1;
	}

	unsafe { (*conn).key.type_ = ssl::NID_undef as i32 };

	let cipher_list = unsafe { ssl::SSL_get_ciphers((*client_hello).ssl) };

	let mut cipher_suites = Cursor::new(unsafe {
		slice::from_raw_parts((*client_hello).cipher_suites,
		                      (*client_hello).cipher_suites_len)
	});

	while let Some(cipher_suite) = cipher_suites.read_u16::<BigEndian>().ok() {
		let cipher = unsafe { ssl::SSL_get_cipher_by_value(cipher_suite) };
		if !cipher.is_null() &&
		   unsafe {
			ssl::SSL_CIPHER_is_ECDSA(cipher) == 1 &&
			ssl::sk_find(cipher_list,
			             ptr::null_mut(),
			             cipher as *mut std::os::raw::c_void) == 1
		} {
			unsafe { (*conn).get_cert.ecdsa_cipher = 1 };
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

		let cln = unsafe { nginx::ngx_pool_cleanup_add((*c).pool, 0) };
		if cln.is_null() ||
		   unsafe {
			ssl::CBS_get_u16_length_prefixed(&mut extension, &mut sig_algs) != 1 ||
			ssl::CBS_len(&sig_algs) == 0 || ssl::CBS_len(&extension) != 0 ||
			ssl::CBS_len(&sig_algs) % 2 != 0 ||
			ssl::CBS_stow(&sig_algs,
			              &mut (*conn).get_cert.sig_algs,
			              &mut (*conn).get_cert.sig_algs_len) != 1
		} {
			return -1;
		}

		unsafe {
			(*cln).handler = mem::transmute(ssl::OPENSSL_free as *const ());
			(*cln).data = (*conn).get_cert.sig_algs as *mut std::os::raw::c_void;
		};
	}

	1
}

#[allow(unused_variables)]
pub extern "C" fn cert_cb(ssl_conn: *mut ssl::SSL,
                          data: *mut std::os::raw::c_void)
                          -> std::os::raw::c_int {
	let c = unsafe { nginx::ngx_ssl_get_connection(ssl_conn) };
	let ssl = unsafe { (*(*c).ssl).connection };

	let conn = get_conn(ssl);
	if conn.is_null() {
		return 1;
	};

	if (unsafe { (*conn).op }).is_null() {
		let op = unsafe {
			keyless::ngx_http_keyless_start_operation(Op::GetCertificate,
			                                          c,
			                                          conn,
			                                          ptr::null(),
			                                          0)
		};

		unsafe {
			(*conn).get_cert.sig_algs = ptr::null_mut();
			(*conn).get_cert.ecdsa_cipher = 0;

			(*conn).op = op;
		};

		return if op.is_null() { 0 } else { -1 };
	};

	let conf = unsafe {
		ssl::SSL_CTX_get_ex_data(ssl::SSL_get_SSL_CTX(ssl),
		                         keyless::ngx_http_keyless_ctx_conf_index)
	} as *mut keyless::ngx_http_keyless_srv_conf_t;
	if conf.is_null() {
		unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
		return 0;
	};

	let mut payload: ssl::CBS = ssl::CBS::default();

	match unsafe { keyless::ngx_http_keyless_operation_complete((*conn).op, &mut payload) } {
		ssl::ssl_private_key_failure => {
			let mut rc = 0;

			if unsafe { (*(*conn).op).error } == Error::CertNotFound {
				if unsafe { (*conf).fallback } != 1 {
					unsafe { ssl::SSL_certs_clear(ssl) };
				}

				rc = 1;
			};

			unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
			return rc;
		}
		ssl::ssl_private_key_retry => return -1,
		ssl::ssl_private_key_success => (),
	}

	if unsafe { ssl::CBS_len(&payload) } == 0 || unsafe { (*(*conn).op).ski }.is_null() {
		unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
		return 0;
	}

	unsafe {
		ptr::copy_nonoverlapping((*(*conn).op).ski,
		                         (*conn).ski.as_mut_ptr(),
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
		unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
		return 0;
	}

	if !unsafe { (*(*conn).op).ocsp_response }.is_null() &&
	   unsafe {
		ssl::SSL_set_ocsp_response(ssl,
		                           (*(*conn).op).ocsp_response,
		                           (*(*conn).op).ocsp_response_length)
	} != 1 {
		unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
		return 0;
	}

	if !unsafe { (*(*conn).op).sct_list }.is_null() &&
	   unsafe {
		ssl::SSL_set_signed_cert_timestamp_list(ssl,
		                                        (*(*conn).op).sct_list,
		                                        (*(*conn).op).sct_list_length)
	} != 1 {
		unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
		return 0;
	}

	unsafe {
		ssl::SSL_certs_clear(ssl);
		ssl::SSL_set_private_key_method(ssl, &KEY_METHOD);
	};

	let mut child: ssl::CBS = ssl::CBS::default();

	if unsafe { ssl::CBS_get_u16_length_prefixed(&mut payload, &mut child) } != 1 {
		unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
		return 0;
	}

	let public_key = ssl::ssl_cert_parse_pubkey(&child);
	if public_key.is_null() {
		unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
		return 0;
	}

	match unsafe { ssl::EVP_PKEY_id(public_key) as u32 } {
		ssl::EVP_PKEY_RSA => unsafe { (*conn).key.type_ = ssl::NID_rsaEncryption as i32 },
		ssl::EVP_PKEY_EC => unsafe { (*conn).key.type_ = ssl::EC_GROUP_get_curve_name(
			ssl::EC_KEY_get0_group(ssl::EVP_PKEY_get0_EC_KEY(public_key))) },
		_ => (),
	}

	unsafe {
		(*conn).key.sig_len = ssl::EVP_PKEY_size(public_key) as usize;
		ssl::EVP_PKEY_free(public_key);
	};

	if unsafe {
		ssl::SSL_use_certificate_ASN1(ssl, ssl::CBS_data(&child), ssl::CBS_len(&child))
	} != 1 {
		unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
		return 0;
	}

	while unsafe { ssl::CBS_len(&payload) } != 0 {
		if unsafe { ssl::CBS_get_u16_length_prefixed(&mut payload, &mut child) } != 1 {
			unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
			return 0;
		}

		if unsafe {
			ssl::SSL_add_chain_cert_ASN1(ssl,
			                             ssl::CBS_data(&child),
			                             ssl::CBS_len(&child))
		} != 1 {
			unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
			return 0;
		}
	}

	unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
	1
}

pub extern "C" fn key_type(ssl_conn: *mut ssl::SSL) -> std::os::raw::c_int {
	let c = unsafe { nginx::ngx_ssl_get_connection(ssl_conn) };

	let conn = get_conn(unsafe { (*(*c).ssl).connection });
	if conn.is_null() {
		ssl::NID_undef as i32
	} else {
		unsafe { (*conn).key.type_ }
	}
}

pub extern "C" fn key_max_signature_len(ssl_conn: *mut ssl::SSL) -> u64 {
	let c = unsafe { nginx::ngx_ssl_get_connection(ssl_conn) };

	let conn = get_conn(unsafe { (*(*c).ssl).connection });
	if conn.is_null() {
		0
	} else {
		unsafe { (*conn).key.sig_len as u64 }
	}
}

fn key_start_operation(op: Op,
                       ssl_conn: *mut ssl::SSL,
                       in_ptr: *const u8,
                       in_len: usize)
                       -> ssl::ssl_private_key_result_t {
	let c = unsafe { nginx::ngx_ssl_get_connection(ssl_conn) };

	let conn = get_conn(unsafe { (*(*c).ssl).connection });
	if conn.is_null() {
		return ssl::ssl_private_key_failure;
	};

	let op = unsafe { keyless::ngx_http_keyless_start_operation(op, c, conn, in_ptr, in_len) };
	if op.is_null() {
		ssl::ssl_private_key_failure
	} else {
		unsafe { (*conn).op = op };

		ssl::ssl_private_key_retry
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

	let conn = get_conn(unsafe { (*(*c).ssl).connection });
	if conn.is_null() {
		return ssl::ssl_private_key_failure;
	};

	let mut payload: ssl::CBS = ssl::CBS::default();

	let mut rc =
		unsafe { keyless::ngx_http_keyless_operation_complete((*conn).op, &mut payload) };
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

	unsafe { keyless::ngx_http_keyless_cleanup_operation((*conn).op) };
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
