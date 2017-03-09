extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn new_builder(openssl_path: &String, nginx_path: &String) -> bindgen::Builder {
	let mut b = bindgen::builder()
		.no_unstable_rust()
		.derive_default(true)
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
		.opaque_type("CRYPTO_MUTEX")
		.opaque_type("ssl_cipher_preference_list_st")
		.opaque_type("^X509_STORE(_CTX)?$")
		.opaque_type("ssl_session_st")
		.opaque_type("X509")
		.opaque_type("X509_VERIFY_PARAM")
		.opaque_type("EVP_CIPHER_CTX")
		.opaque_type("HMAC_CTX")
		.opaque_type("timeval")
		.opaque_type("CRYPTO_EX_DATA")
		.whitelisted_type("SSL_CTX")
		// keyless_nginx.rs
		.whitelisted_function("SSL_[gs]et_ex_data")
		.whitelisted_function("SSL_CTX_get_ex_data")
		.whitelisted_function("SSL_get_SSL_CTX")
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
		.whitelisted_var("^(MD5|SHA(256|384|512)?)_DIGEST_LENGTH$")
		.whitelisted_function("SSL_certs_clear")
		.whitelisted_function("^SHA256_.*")
		.opaque_type("SHA256_CTX")
		.whitelisted_type("SHA256_CTX")
		.whitelisted_function("CRYPTO_BUFFER_new")
		.whitelisted_function("^SSL_set_(ocsp_response|signed_cert_timestamp_list|chain_and_key|session_id_context)$")
		.whitelisted_function("^SSL_CTX_set_(select_certificate|cert)_cb$")
		.whitelisted_function("^EVP_PKEY_(id|free|size)$")
		.whitelisted_var("^EVP_PKEY_(RSA|EC)$")
		.whitelisted_var("NID_rsaEncryption")
		.whitelisted_function("EC_GROUP_get_curve_name")
		.whitelisted_function("EC_KEY_get0_group")
		.whitelisted_function("EVP_PKEY_get0_EC_KEY")
		.whitelisted_function("RAND_bytes")
		.whitelisted_function("^SSL(_CTX)?_get_ex_new_index$")
		.whitelisted_function("SSL_CTX_set_ex_data")
		.whitelisted_function("OPENSSL_cleanse")
		// rust_openssl.h
		.header("rust_openssl.h")
		.generate()
		.expect("build failed")
		.write_to_file(out_path.join("openssl.rs"));

	let _ = new_builder(&openssl_path, &nginx_path)
		// ngx_connection_t
		.hide_type("^SSL.*")
		.opaque_type("ngx_listening_t")
		.opaque_type("ngx_thread_task_t")
		.opaque_type("ngx_file_t")
		.whitelisted_type("ngx_connection_t")
		// ngx_keyless_module.h
		.opaque_type("ngx_queue_t")
		.whitelisted_type("ngx_queue_t")
		.whitelisted_type("ngx_peer_connection_t")
		.whitelisted_type("ngx_flag_t")
		.whitelisted_type("ngx_atomic_uint_t")
		// keyless_nginx.rs
		.whitelisted_type("ngx_pool_cleanup_t")
		.whitelisted_function("ngx_pool_cleanup_add")
		.whitelisted_function("ngx_pcalloc")
		.opaque_type("ngx_pool_t")
		.opaque_type("ngx_log_t")
		.whitelisted_type("ngx_conf_t")
		.whitelisted_var("NGX_CONF_UNSET")
		.whitelisted_type("ngx_http_ssl_srv_conf_t")
		.whitelisted_type("ngx_url_t")
		.whitelisted_var("ngx_http_ssl_module")
		.whitelisted_var("NGX_OK")
		.whitelisted_type("ngx_connection_log_error_e")
		.whitelisted_function("ngx_parse_url")
		.whitelisted_function("ngx_event_get_peer")
		.opaque_type("ngx_module_t")
		.opaque_type("ngx_rbtree_t")
		.opaque_type("ngx_rbtree_node_t")
		.whitelisted_type("ngx_http_module_t")
		.whitelisted_type("ngx_event_t")
		.whitelisted_var("NGX_AGAIN")
		// rust_nginx.h
		.whitelisted_function("^ngx_http_keyless_macro_.*")
		.whitelisted_function("^ngx_http_keyless_bitfield_.*")
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
