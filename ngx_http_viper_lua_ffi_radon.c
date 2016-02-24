#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "nginx-radon-pvkey.h"

#if NGX_HTTP_SSL

int ngx_http_viper_lua_ffi_radon_set_private_key(ngx_http_request_t *r, const char *sock, size_t sock_len, char **err)
{
	ngx_ssl_conn_t *ssl_conn;
	X509 *x509;
	EVP_PKEY *pkey;

	if (r->connection == NULL || r->connection->ssl == NULL) {
		*err = "bad request";
		return NGX_ERROR;
	}

	ssl_conn = r->connection->ssl->connection;

	if (ssl_conn == NULL) {
		*err = "bad ssl conn";
		return NGX_ERROR;
	}

	x509 = SSL_get_certificate(ssl_conn);

	if (x509 == NULL) {
		*err = "SSL_get_certificate failed";
		return NGX_ERROR;
	}

	pkey = radon_private_key_shell(x509, sock, sock_len);

	if (pkey == NULL) {
		*err = "radon_private_key_shell failed";
		return NGX_ERROR;
	}

	if (SSL_use_PrivateKey(ssl_conn, pkey) == 0) {
		EVP_PKEY_free(pkey);

		*err = "SSL_use_PrivateKey failed";
		return NGX_ERROR;
	}

	EVP_PKEY_free(pkey);

	return NGX_OK;
}

#endif /* NGX_HTTP_SSL */
