use ssl::*;

include!(concat!(env!("OUT_DIR"), "/nginx.rs"));

pub fn ngx_ssl_get_connection(ssl_conn: *const SSL) -> *mut ngx_connection_t {
	unsafe { SSL_get_ex_data(ssl_conn, ngx_ssl_connection_index) as *mut ngx_connection_t }
}
