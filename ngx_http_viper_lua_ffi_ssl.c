#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if NGX_HTTP_SSL

int ngx_http_viper_lua_ffi_ssl_client_has_ecdsa(ngx_http_request_t *r, char **err)
{
	ngx_ssl_conn_t *ssl_conn;
#ifdef OPENSSL_IS_BORINGSSL
	size_t i;
#else
	int i;
#endif

	if (!r->connection || !r->connection->ssl) {
		*err = "bad request";
		return NGX_ERROR;
	}

	ssl_conn = r->connection->ssl->connection;

#ifdef OPENSSL_IS_BORINGSSL
	if (!ssl_conn) {
		*err = "bad ssl conn";
		return NGX_ERROR;
	}

	if (!ssl_conn->cipher_list_by_id) {
		*err = "bad cipher list";
		return NGX_ERROR;
	}

	for (i = 0; i < sk_SSL_CIPHER_num(ssl_conn->cipher_list_by_id); i++) {
		if (SSL_CIPHER_is_ECDSA(sk_SSL_CIPHER_value(ssl_conn->cipher_list_by_id, i))) {
			return NGX_OK;
		}
	}
#else
#	define SSL_aECDSA 0x00000040L // taken from openssl-1.0.2f/ssl/ssl_locl.h

	if (!ssl_conn || !ssl_conn->session) {
		*err = "bad ssl conn";
		return NGX_ERROR;
	}

	if (!ssl_conn->session->ciphers) {
		*err = "bad cipher list";
		return NGX_ERROR;
	}

	for (i = 0; i < sk_SSL_CIPHER_num(ssl_conn->session->ciphers); i++) {
		if ((sk_SSL_CIPHER_value(ssl_conn->session->ciphers, i)->algorithm_auth & SSL_aECDSA) != 0) {
			return NGX_OK;
		}
	}

#	undef SSL_aECDSA
#endif

	return NGX_DECLINED;
}

#endif /* NGX_HTTP_SSL */
