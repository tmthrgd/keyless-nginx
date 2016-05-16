#ifndef _NGX_HTTP_KEYLESS_H_INCLUDED_
#define _NGX_HTTP_KEYLESS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#define NGX_KEYLESS_DEFAULT_PORT 2407

typedef struct ngx_keyless_ctx_st NGX_KEYLESS_CTX;

NGX_KEYLESS_CTX *ngx_keyless_create(ngx_pool_t *pool, ngx_log_t *log, X509 *cert,
		const struct sockaddr *address, size_t address_len);
NGX_KEYLESS_CTX *ngx_keyless_parse_and_create(ngx_pool_t *pool, ngx_log_t *log, X509 *cert,
		const char *addr, size_t addr_len);

NGX_KEYLESS_CTX *ngx_keyless_ssl_get_ctx(SSL *ssl);
NGX_KEYLESS_CTX *ngx_keyless_ssl_ctx_get_ctx(SSL_CTX *ssl_ctx);

int ngx_keyless_attach_ssl(SSL *ssl, NGX_KEYLESS_CTX *ctx);
int ngx_keyless_attach_ssl_ctx(SSL_CTX *ssl_ctx, NGX_KEYLESS_CTX *ctx);

void ngx_keyless_free(NGX_KEYLESS_CTX *ctx);

#endif /* _NGX_HTTP_KEYLESS_H_INCLUDED_ */
