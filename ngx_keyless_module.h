#ifndef _NGX_HTTP_VIPER_RADON_H_INCLUDED_
#define _NGX_HTTP_VIPER_RADON_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#if NGX_HTTP_SSL

#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#define KEYLESS_DEFAULT_PORT 1163

typedef struct keyless_ctx_st KEYLESS_CTX;

KEYLESS_CTX *keyless_create(ngx_pool_t *pool, X509 *cert, struct sockaddr *address, size_t address_len);
KEYLESS_CTX *keyless_parse_and_create(ngx_pool_t *pool, X509 *cert, const char *addr, size_t addr_len);

KEYLESS_CTX *ssl_get_keyless_ctx(SSL *ssl);
KEYLESS_CTX *ssl_ctx_get_keyless_ctx(SSL_CTX *ssl_ctx);

int keyless_attach_ssl(SSL *ssl, KEYLESS_CTX *ctx);
int keyless_attach_ssl_ctx(SSL_CTX *ssl_ctx, KEYLESS_CTX *ctx);

void keyless_free(ngx_pool_t *pool, KEYLESS_CTX *ctx);

#endif /* NGX_HTTP_SSL */

#endif /* _NGX_HTTP_VIPER_RADON_H_INCLUDED_ */
