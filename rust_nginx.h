#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>

extern ngx_connection_t *ngx_http_keyless_macro_ngx_ssl_get_connection(ngx_ssl_conn_t *ssl_conn);
extern void *ngx_http_keyless_macro_ngx_http_conf_get_module_srv_conf(const ngx_conf_t *cf, const ngx_module_t *module);
extern void ngx_http_keyless_macro_ngx_queue_init(ngx_queue_t *q);
extern void ngx_http_keyless_macro_ngx_queue_remove(ngx_queue_t *q);
extern void ngx_http_keyless_macro_ngx_del_timer(ngx_event_t *ev);
extern void ngx_http_keyless_macro_ngx_post_event(ngx_event_t *ev, ngx_queue_t *q);
extern void ngx_http_keyless_bitfield_ngx_url_t_no_resolve(ngx_url_t *u);
extern void ngx_http_keyless_bitfield_ngx_connection_t_error(ngx_connection_t *c);

// -*- mode: c;-*-