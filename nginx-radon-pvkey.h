#ifndef _NGX_HTTP_VIPER_RADON_H_INCLUDED_
#define _NGX_HTTP_VIPER_RADON_H_INCLUDED_

#include <ngx_config.h>

#if NGX_HTTP_SSL
#	include <openssl/evp.h>
#	include <openssl/x509.h>

EVP_PKEY *radon_private_key_shell(X509 *cert, const char *sock, size_t sock_len);

#endif /* NGX_HTTP_SSL */

#endif /* _NGX_HTTP_VIPER_RADON_H_INCLUDED_ */
