use ssl::*;

include!(concat!(env!("OUT_DIR"), "/nginx.rs"));

pub const NGX_CONF_UNSET_MSEC: ::std::os::raw::c_int = -1;

pub fn ngx_ssl_get_connection(ssl_conn: *const SSL) -> *mut ngx_connection_t {
	unsafe { SSL_get_ex_data(ssl_conn, ngx_ssl_connection_index) as *mut ngx_connection_t }
}
