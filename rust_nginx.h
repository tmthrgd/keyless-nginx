#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>

extern ngx_connection_t *ngx_http_keyless_macro_ngx_ssl_get_connection(ngx_ssl_conn_t *ssl_conn);

// -*- mode: c;-*-