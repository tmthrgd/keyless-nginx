extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
	let openssl_path = env::var("OPENSSL_INCLUDE").unwrap();
	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

	let mut b = bindgen::builder();

	if !openssl_path.is_empty() {
		b = b.clang_arg("-I".to_string() + &openssl_path);
	};

	let _ = b.no_unstable_rust()
		.hide_type("^(__)?pthread")
		.opaque_type("CBS")
		.whitelisted_function("^CBS_.*")
		.whitelisted_var("^CBS_.*")
		.opaque_type("EVP_PKEY")
		.whitelisted_function("EVP_parse_public_key")
		.header("rust_openssl.h")
		.generate()
		.expect("build failed")
		.write_to_file(out_path.join("openssl.rs"));
}