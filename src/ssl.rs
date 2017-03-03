include!(concat!(env!("OUT_DIR"), "/openssl.rs"));

pub const CBS_ASN1_SEQUENCE: ::std::os::raw::c_uint = 0x10 | CBS_ASN1_CONSTRUCTED;