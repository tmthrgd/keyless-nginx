extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn new_builder(openssl_path: &String, nginx_path: &String) -> bindgen::Builder {
	let mut b = bindgen::builder()
		.no_unstable_rust()
		.clang_arg("-DBORINGSSL_SHARED_LIBRARY");

	if !openssl_path.is_empty() {
		b = b.clang_arg("-I".to_string() + &openssl_path);
	};

	if !nginx_path.is_empty() {
		let nginx_path = PathBuf::from(nginx_path);
		b = b.clang_arg("-I".to_string() +
			           nginx_path.join("src/core").to_str().unwrap())
			.clang_arg("-I".to_string() +
			           nginx_path.join("src/event").to_str().unwrap())
			.clang_arg("-I".to_string() +
			           nginx_path.join("src/event/modules").to_str().unwrap())
			.clang_arg("-I".to_string() +
			           nginx_path.join("src/os/unix").to_str().unwrap())
			.clang_arg("-I".to_string() + nginx_path.join("objs").to_str().unwrap())
			.clang_arg("-I".to_string() +
			           nginx_path.join("src/http").to_str().unwrap())
			.clang_arg("-I".to_string() +
			           nginx_path.join("src/http/modules").to_str().unwrap())
			.clang_arg("-I".to_string() +
			           nginx_path.join("src/http/v2").to_str().unwrap());
	};

	b
}

fn main() {
	let openssl_path = env::var("OPENSSL_INCLUDE").unwrap_or(String::new());
	let nginx_path = env::var("NGINX_DIR").unwrap_or(String::new());
	let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

	println!("{} {}", openssl_path, nginx_path);

	let _ = new_builder(&openssl_path, &nginx_path)
		// CBS_*
		.opaque_type("CBS")
		.whitelisted_function("^CBS.*")
		.whitelisted_var("^CBS.*")
		// EVP_parse_public_key
		.opaque_type("EVP_PKEY")
		.whitelisted_function("EVP_parse_public_key")
		// ssl_private_key_result_t
		.whitelisted_type("ssl_private_key_result_t")
		// rust_nginx.h
		//  SSL
		.whitelisted_type("SSL")
		//  SSL_CTX
		.opaque_type("SSL_CTX")
		.whitelisted_type("SSL_CTX")
		// keyless_nginx.rs
		.whitelisted_function("SSL_[gs]et_ex_data")
		.whitelisted_type("SSL_CLIENT_HELLO")
		.opaque_type("SSL_CIPHER")
		.hide_type("stack_st_SSL_CIPHER")
		.whitelisted_function("SSL_get_ciphers")
		.whitelisted_function("SSL_get_cipher_by_value")
		.whitelisted_function("SSL_CIPHER_is_ECDSA")
		.whitelisted_function("sk_find")
		.whitelisted_function("SSL_early_callback_ctx_extension_get")
		.whitelisted_var("TLSEXT_TYPE_signature_algorithms")
		.whitelisted_var("NID_undef")
		.whitelisted_var("^SSL_SIGN_.*")
		.whitelisted_function("MD5")
		.whitelisted_function("^SHA(1|256|384|512)$")
		.whitelisted_var(".*_DIGEST_LENGTH$")
		// rust_openssl.h
		.header("rust_openssl.h")
		.generate()
		.expect("build failed")
		.write_to_file(out_path.join("openssl.rs"));

	let _ = new_builder(&openssl_path, &nginx_path)
		// ngx_ssl_connection_index
		.whitelisted_var("ngx_ssl_connection_index")
		// ngx_connection_t
		.hide_type("^SSL.*")
		.opaque_type("ngx_listening_t")
		.opaque_type("ngx_log_t")
		.opaque_type("ngx_pool_t")
		.opaque_type("ngx_buf_t")
		.whitelisted_type("ngx_connection_t")
		// ngx_keyless_module.h
		.opaque_type("ngx_event_t")
		.whitelisted_type("ngx_event_t")
		.opaque_type("ngx_queue_t")
		.whitelisted_type("ngx_queue_t")
		.opaque_type("ngx_peer_connection_t")
		.whitelisted_type("ngx_peer_connection_t")
		.whitelisted_type("ngx_flag_t")
		// keyless_nginx.rs
		.whitelisted_type("ngx_pool_cleanup_t")
		.whitelisted_function("ngx_pool_cleanup_add")
		.whitelisted_function("ngx_pcalloc")
		// rust_nginx.h
		.header("rust_nginx.h")
		.generate()
		.expect("build failed")
		.write_to_file(out_path.join("nginx.rs"));

	let _ = new_builder(&openssl_path, &nginx_path)
		.whitelist_recursively(false)
		.whitelisted_function("^ngx_http_keyless_.*")
		.whitelisted_type("^ngx_http_keyless_.*")
		.whitelisted_var("^ngx_http_keyless_.*")
		.hide_type("ngx_http_keyless_error_t")
		.hide_type("ngx_http_keyless_operation_t")
		.header("ngx_keyless_module.h")
		.generate()
		.expect("build failed")
		.write_to_file(out_path.join("keyless.rs"));
}
