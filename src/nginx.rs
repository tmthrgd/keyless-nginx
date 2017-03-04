use ssl::*;

include!(concat!(env!("OUT_DIR"), "/nginx.rs"));

pub const NGX_CONF_UNSET_MSEC: ::std::os::raw::c_int = -1;

pub use self::ngx_http_keyless_macro_ngx_ssl_get_connection as ngx_ssl_get_connection;
