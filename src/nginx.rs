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
pub use self::ngx_http_keyless_bitfield_ngx_url_t_no_resolve as ngx_url_set_no_resolve;
