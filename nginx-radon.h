#ifndef _NGX_HTTP_VIPER_RADON_H_INCLUDED_
#define _NGX_HTTP_VIPER_RADON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#if NGX_HTTP_SSL

#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#define RADON_DEFAULT_PORT 1163

typedef struct radon_ctx_st RADON_CTX;

RADON_CTX *radon_create(ngx_pool_t *pool, X509 *cert, struct sockaddr *address, size_t address_len);
RADON_CTX *radon_parse_and_create(ngx_pool_t *pool, X509 *cert, const char *addr, size_t addr_len);

int radon_attach_ssl(SSL *ssl, RADON_CTX *ctx);
int radon_attach_ssl_ctx(SSL_CTX *ssl_ctx, RADON_CTX *ctx);

void radon_free(ngx_pool_t *pool, RADON_CTX *ctx);

#endif /* NGX_HTTP_SSL */

#endif /* _NGX_HTTP_VIPER_RADON_H_INCLUDED_ */
