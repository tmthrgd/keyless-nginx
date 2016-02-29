#ifndef _NGX_HTTP_VIPER_RADON_H_INCLUDED_
#define _NGX_HTTP_VIPER_RADON_H_INCLUDED_

/*#ifndef RADON_FOR_NGINX
#	define RADON_FOR_NGINX 0
#endif*/

#define RADON_FOR_NGINX 1

#if RADON_FOR_NGINX
#	include <ngx_config.h>
#	include <ngx_core.h>
#endif

#if !RADON_FOR_NGINX || NGX_HTTP_SSL

#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#define RADON_DEFAULT_PORT 1163

typedef struct radon_ctx_st RADON_CTX;

RADON_CTX *radon_create(X509 *cert, struct sockaddr *address, size_t address_len);
#if RADON_FOR_NGINX
RADON_CTX *radon_create_from_string(ngx_pool_t *pool, X509 *cert, const char *addr, size_t addr_len);
#endif

int radon_attach(SSL *ssl, RADON_CTX *ctx);
int radon_attach_to_ssl_ctx(SSL_CTX *ssl_ctx, RADON_CTX *ctx);
int radon_attach_from_ssl_ctx(SSL *ssl);

void radon_free(RADON_CTX *ctx);

#endif /* !RADON_FOR_NGINX || NGX_HTTP_SSL */

#endif /* _NGX_HTTP_VIPER_RADON_H_INCLUDED_ */
