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

	pub use self::ngx_http_keyless_operation_t::*;

	pub fn get_conn(ssl: *const SSL) -> *mut ngx_http_keyless_conn_t {
		unsafe {
			SSL_get_ex_data(ssl, ngx_http_keyless_ssl_conn_index) as
			*mut ngx_http_keyless_conn_t
		}
	}
}

use std::ptr;

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

#[no_mangle]
pub extern "C" fn ngx_http_keyless_key_type(ssl_conn: *mut ssl::SSL) -> ::std::os::raw::c_int {
	let c = nginx::ngx_ssl_get_connection(ssl_conn);

	let conn = keyless::get_conn(unsafe { (*(*c).ssl).connection });
	if conn.is_null() {
		ssl::NID_undef as i32
	} else {
		unsafe { (*conn).key.type_ }
	}
}

#[no_mangle]
pub extern "C" fn ngx_http_keyless_key_max_signature_len(ssl_conn: *mut ssl::SSL) -> usize {
	let c = nginx::ngx_ssl_get_connection(ssl_conn);

	let conn = keyless::get_conn(unsafe { (*(*c).ssl).connection });
	if conn.is_null() {
		0
	} else {
		unsafe { (*conn).key.sig_len }
	}
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn ngx_http_keyless_key_sign(ssl_conn: *mut ssl::SSL,
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
			unsafe { ssl::MD5(in_ptr, in_len, hash.as_mut_ptr()) };
			unsafe {
				ssl::SHA1(in_ptr,
				          in_len,
				          hash[ssl::MD5_DIGEST_LENGTH as usize..].as_mut_ptr())
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

	let c = nginx::ngx_ssl_get_connection(ssl_conn);

	let conn = keyless::get_conn(unsafe { (*(*c).ssl).connection });
	if conn.is_null() {
		return ssl::ssl_private_key_failure;
	};

	let op = unsafe {
		keyless::ngx_http_keyless_start_operation(opcode,
		                                          c,
		                                          conn,
		                                          hash.as_ptr(),
		                                          hash_len)
	};
	if op.is_null() {
		ssl::ssl_private_key_failure
	} else {
		unsafe { (*conn).op = op };

		ssl::ssl_private_key_retry
	}
}

#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn ngx_http_keyless_key_decrypt(ssl_conn: *mut ssl::SSL,
                                               out: *mut u8,
                                               out_len: *mut usize,
                                               max_out: usize,
                                               in_ptr: *const u8,
                                               in_len: usize)
                                               -> ssl::ssl_private_key_result_t {
	let c = nginx::ngx_ssl_get_connection(ssl_conn);

	let conn = keyless::get_conn(unsafe { (*(*c).ssl).connection });
	if conn.is_null() {
		return ssl::ssl_private_key_failure;
	};

	let op = unsafe {
		keyless::ngx_http_keyless_start_operation(Op::RSADecryptRaw,
		                                          c,
		                                          conn,
		                                          in_ptr,
		                                          in_len)
	};
	if op.is_null() {
		ssl::ssl_private_key_failure
	} else {
		unsafe { (*conn).op = op };

		ssl::ssl_private_key_retry
	}
}

#[no_mangle]
pub extern "C" fn ngx_http_keyless_key_complete(ssl_conn: *mut ssl::SSL,
                                                out: *mut u8,
                                                out_len: *mut usize,
                                                max_out: usize)
                                                -> ssl::ssl_private_key_result_t {
	let c = nginx::ngx_ssl_get_connection(ssl_conn);

	let conn = keyless::get_conn(unsafe { (*(*c).ssl).connection });
	if conn.is_null() {
		return ssl::ssl_private_key_failure;
	};

	let mut payload: ssl::CBS = [0; 2];

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

// this is ssl_cert_parse_pubkey & ssl_cert_skip_to_spki from boringssl-f71036e/ssl/ssl_cert.c
#[no_mangle]
pub extern "C" fn ngx_http_keyless_ssl_cert_parse_pubkey(in_cbs: *const ssl::CBS)
                                                         -> *mut ssl::EVP_PKEY {
	let mut buf = unsafe { *in_cbs };
	let mut toplevel: ssl::CBS = [0; 2];
	let mut tbs_cert: ssl::CBS = [0; 2];

	if unsafe {
		ssl::CBS_get_asn1(&mut buf, &mut toplevel, ssl::CBS_ASN1_SEQUENCE) == 1 &&
		ssl::CBS_len(&buf) == 0 &&
		ssl::CBS_get_asn1(&mut toplevel, &mut tbs_cert, ssl::CBS_ASN1_SEQUENCE) == 1 &&
		/* version */
		ssl::CBS_get_optional_asn1(&mut tbs_cert, ptr::null_mut(), ptr::null_mut(),
			ssl::CBS_ASN1_CONSTRUCTED | ssl::CBS_ASN1_CONTEXT_SPECIFIC) == 1 &&
		/* serialNumber */
		ssl::CBS_get_asn1(&mut tbs_cert, ptr::null_mut(), ssl::CBS_ASN1_INTEGER) == 1 &&
		/* signature algorithm */
		ssl::CBS_get_asn1(&mut tbs_cert, ptr::null_mut(), ssl::CBS_ASN1_SEQUENCE) == 1 &&
		/* issuer */
		ssl::CBS_get_asn1(&mut tbs_cert, ptr::null_mut(), ssl::CBS_ASN1_SEQUENCE) == 1 &&
		/* validity */
		ssl::CBS_get_asn1(&mut tbs_cert, ptr::null_mut(), ssl::CBS_ASN1_SEQUENCE) == 1 &&
		/* subject */
		ssl::CBS_get_asn1(&mut tbs_cert, ptr::null_mut(), ssl::CBS_ASN1_SEQUENCE) == 1
	} {
		unsafe { ssl::EVP_parse_public_key(&mut tbs_cert) }
	} else {
		ptr::null_mut()
	}
}
