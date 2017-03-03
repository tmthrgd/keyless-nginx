#[allow(dead_code)]
#[allow(non_camel_case_types)]
mod ssl;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
mod nginx;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
mod keyless {
	use ssl::*;
	use nginx::*;

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

mod error;
use error::Error;

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
	if conn == ptr::null_mut() {
		return ssl::ssl_private_key_failure;
	};

	let op = unsafe {
		keyless::ngx_http_keyless_start_operation(keyless::NGX_HTTP_KEYLESS_OP_RSA_DECRYPT_RAW,
		                                          c,
		                                          conn,
		                                          in_ptr,
		                                          in_len)
	};
	if op == ptr::null_mut() {
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
	if conn == ptr::null_mut() {
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
