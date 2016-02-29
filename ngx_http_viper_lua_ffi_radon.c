#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx-radon.h>

#if NGX_HTTP_SSL

int ngx_http_viper_lua_ffi_radon_set_private_key(ngx_http_request_t *r, const char *addr, size_t addr_len, char **err)
{
	ngx_ssl_conn_t *ssl_conn;
	X509 *x509;
	RADON_CTX *ctx;

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

	ctx = radon_create_from_string(r->pool, x509, addr, addr_len);
	if (ctx == NULL) {
		*err = "radon_create failed";
		return NGX_ERROR;
	}

	if (!radon_attach(ssl_conn, ctx)) {
		radon_free(ctx);

		*err = "radon_attach failed";
		return NGX_ERROR;
	}

	return NGX_OK;
}

#endif /* NGX_HTTP_SSL */
