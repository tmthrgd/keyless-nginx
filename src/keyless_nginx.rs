#[allow(dead_code)]
#[allow(non_camel_case_types)]
mod ssl;

use std::ptr;

#[macro_use]
extern crate enum_primitive;

extern crate num;
use num::FromPrimitive;

mod error;
use error::Error;

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
