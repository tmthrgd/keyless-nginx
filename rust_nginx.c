#include "rust_nginx.h"

extern ngx_connection_t *ngx_http_keyless_macro_ngx_ssl_get_connection(ngx_ssl_conn_t *ssl_conn) {
	return ngx_ssl_get_connection(ssl_conn);
}