#include "rust_nginx.h"

extern ngx_connection_t *ngx_http_keyless_macro_ngx_ssl_get_connection(ngx_ssl_conn_t *ssl_conn) {
	return ngx_ssl_get_connection(ssl_conn);
}

extern void *ngx_http_keyless_macro_ngx_http_conf_get_module_srv_conf(const ngx_conf_t *cf, const ngx_module_t *module) {
	return ngx_http_conf_get_module_srv_conf(cf, (*module));
}

extern void ngx_http_keyless_macro_ngx_queue_init(ngx_queue_t *q) {
	ngx_queue_init(q);
}

extern void ngx_http_keyless_macro_ngx_queue_remove(ngx_queue_t *q) {
	ngx_queue_remove(q);
}

extern void ngx_http_keyless_macro_ngx_del_timer(ngx_event_t *ev) {
	ngx_del_timer(ev);
}

extern void ngx_http_keyless_macro_ngx_post_event(ngx_event_t *ev, ngx_queue_t *q) {
	ngx_post_event(ev, q);
}

extern void ngx_http_keyless_bitfield_ngx_url_t_no_resolve(ngx_url_t *u) {
	u->no_resolve = 1;
}

extern void ngx_http_keyless_bitfield_ngx_connection_t_error(ngx_connection_t *c) {
	c->error = 1;
}