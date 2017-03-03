include!(concat!(env!("OUT_DIR"), "/openssl.rs"));

pub const CBS_ASN1_SEQUENCE: ::std::os::raw::c_uint = 0x10 | CBS_ASN1_CONSTRUCTED;

pub use libc::free as OPENSSL_free;

pub use self::stack_st as stack_st_SSL_CIPHER;

pub use self::ssl_private_key_result_t::*;

// this is ssl_cert_parse_pubkey & ssl_cert_skip_to_spki from boringssl-f71036e/ssl/ssl_cert.c
pub fn ssl_cert_parse_pubkey(in_cbs: &CBS) -> *mut EVP_PKEY {
	let mut buf = *in_cbs;
	let mut toplevel: CBS = [0; 2];
	let mut tbs_cert: CBS = [0; 2];

	if unsafe {
		CBS_get_asn1(&mut buf, &mut toplevel, CBS_ASN1_SEQUENCE) == 1 &&
		CBS_len(&buf) == 0 &&
		CBS_get_asn1(&mut toplevel, &mut tbs_cert, CBS_ASN1_SEQUENCE) == 1 &&
		/* version */
		CBS_get_optional_asn1(&mut tbs_cert, ::ptr::null_mut(), ::ptr::null_mut(),
			CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC) == 1 &&
		/* serialNumber */
		CBS_get_asn1(&mut tbs_cert, ::ptr::null_mut(), CBS_ASN1_INTEGER) == 1 &&
		/* signature algorithm */
		CBS_get_asn1(&mut tbs_cert, ::ptr::null_mut(), CBS_ASN1_SEQUENCE) == 1 &&
		/* issuer */
		CBS_get_asn1(&mut tbs_cert, ::ptr::null_mut(), CBS_ASN1_SEQUENCE) == 1 &&
		/* validity */
		CBS_get_asn1(&mut tbs_cert, ::ptr::null_mut(), CBS_ASN1_SEQUENCE) == 1 &&
		/* subject */
		CBS_get_asn1(&mut tbs_cert, ::ptr::null_mut(), CBS_ASN1_SEQUENCE) == 1
	} {
		unsafe { EVP_parse_public_key(&mut tbs_cert) }
	} else {
		::ptr::null_mut()
	}
}
