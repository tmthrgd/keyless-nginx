use ssl::*;

include!(concat!(env!("OUT_DIR"), "/nginx.rs"));

pub const NGX_CONF_UNSET_MSEC: ::std::os::raw::c_int = -1;

pub const NGX_CONF_OK: *mut i8 = 0 as *mut i8;
pub const NGX_CONF_ERROR: *mut i8 = !0 as *mut i8;

pub use self::ngx_connection_log_error_e::*;

pub use self::ngx_http_keyless_macro_ngx_ssl_get_connection as ngx_ssl_get_connection;
pub use self::ngx_http_keyless_macro_ngx_http_conf_get_module_srv_conf
	as ngx_http_conf_get_module_srv_conf;
pub use self::ngx_http_keyless_macro_ngx_queue_init as ngx_queue_init;
pub use self::ngx_http_keyless_macro_ngx_queue_remove as ngx_queue_remove;
pub use self::ngx_http_keyless_macro_ngx_del_timer as ngx_del_timer;
pub use self::ngx_http_keyless_bitfield_ngx_url_t_no_resolve as ngx_url_set_no_resolve;
pub use self::ngx_http_keyless_bitfield_ngx_connection_t_error as ngx_connection_set_error;

pub fn ngx_queue_empty(q: &ngx_queue_t) -> bool {
	q as *const ngx_queue_t == q.prev as *const ngx_queue_t
}

pub fn ngx_queue_head(q: &mut ngx_queue_t) -> Option<&mut ngx_queue_t> {
	unsafe { q.next.as_mut() }
}
