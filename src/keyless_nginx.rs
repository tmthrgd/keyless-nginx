#[allow(dead_code)]
#[allow(non_camel_case_types)]

mod ssl {
	include!(concat!(env!("OUT_DIR"), "/openssl.rs"));

	pub const CBS_ASN1_SEQUENCE: ::std::os::raw::c_uint = 0x10 | CBS_ASN1_CONSTRUCTED;
}

extern crate libc;

use std::ptr;

#[macro_use]
extern crate enum_primitive;

extern crate num;
use num::FromPrimitive;

enum_from_primitive! {
enum Error {
	// The range [0x0000, 0x0100) is for errors taken from Cloudflare's upstream.
	None             = 0x0000, // No error
	CryptoFailed     = 0x0001, // Cryptographic error
	KeyNotFound      = 0x0002, // Private key not found
	DiskRead         = 0x0003, // [Deprecated]: Disk read failure
	VersionMismatch  = 0x0004, // Client-Server version mismatch
	BadOpcode        = 0x0005, // Invalid/unsupported opcode
	UnexpectedOpcode = 0x0006, // Opcode sent at wrong time/direction
	Format           = 0x0007, // Malformed message
	Internal         = 0x0008, // Other internal error
	CertNotFound     = 0x0009, // Certificate not found
	Expired          = 0x0010, // The sealing key has expired

	// The range [0x0100, 0xc000) is for errors from our protocol version.
	NotAuthorised = 0x0101, // The client was not authorised to perform that request.

	// The range [0xc000, 0xffff) is reserved for private errors.
}
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

	unsafe {
		if ssl::CBS_get_asn1(&mut buf, &mut toplevel, ssl::CBS_ASN1_SEQUENCE) == 1 &&
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
		ssl::CBS_get_asn1(&mut tbs_cert, ptr::null_mut(), ssl::CBS_ASN1_SEQUENCE) == 1 {
			ssl::EVP_parse_public_key(&mut tbs_cert)
		} else {
			ptr::null_mut()
		}
	}
}
