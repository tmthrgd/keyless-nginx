#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if NGX_HTTP_SSL

enum {
	NGX_HTTP_VIPER_ADDR_TYPE_UNIX  = 0,
	NGX_HTTP_VIPER_ADDR_TYPE_INET  = 1,
	NGX_HTTP_VIPER_ADDR_TYPE_INET6 = 2
};

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

int ngx_http_viper_lua_ffi_ssl_server_addr(ngx_http_request_t *r, char **addr, size_t *addrlen, int *addrtype, char **err)
{
	ngx_ssl_conn_t       *ssl_conn;
	ngx_connection_t     *c;
	struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
	struct sockaddr_in6  *sin6;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
	struct sockaddr_un   *saun;
#endif

	if (!r->connection || !r->connection->ssl) {
		*err = "bad request";
		return NGX_ERROR;
	}

	ssl_conn = r->connection->ssl->connection;
	if (!ssl_conn) {
		*err = "bad ssl conn";
		return NGX_ERROR;
	}

	c = ngx_ssl_get_connection(ssl_conn);

	if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
		return 0;
	}

	switch (c->local_sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)c->local_sockaddr;
			*addr = ngx_palloc(r->pool, NGX_INET6_ADDRSTRLEN);
			*addrlen = ngx_inet_ntop(AF_INET6, &sin6->sin6_addr.s6_addr, (u_char *)*addr, NGX_INET6_ADDRSTRLEN);

			if (*addrlen == 0) {
				ngx_pfree(r->pool, *addr); *addr = NULL;

				*err = "ngx_inet_ntop failed";
				return NGX_ERROR;
			}

			*addrtype = NGX_HTTP_VIPER_ADDR_TYPE_INET6;
			break;
#endif
#if (NGX_HAVE_UNIX_DOMAIN)
		case AF_UNIX:
			saun = (struct sockaddr_un *)c->local_sockaddr;

			/* on Linux sockaddr might not include sun_path at all */
			if (c->local_socklen <= (socklen_t)offsetof(struct sockaddr_un, sun_path)) {
				*addr = "";
				*addrlen = 0;
			} else {
				*addr = saun->sun_path;
				*addrlen = ngx_strlen(saun->sun_path);
			}

			*addrtype = NGX_HTTP_VIPER_ADDR_TYPE_UNIX;
			break;
#endif
		default: /* AF_INET */
			sin = (struct sockaddr_in *)c->local_sockaddr;
			*addr = ngx_palloc(r->pool, NGX_INET_ADDRSTRLEN);
			*addrlen = ngx_inet_ntop(AF_INET, &sin->sin_addr.s_addr, (u_char *)*addr, NGX_INET_ADDRSTRLEN);

			if (*addrlen == 0) {
				ngx_pfree(r->pool, *addr); *addr = NULL;

				*err = "ngx_inet_ntop failed";
				return NGX_ERROR;
			}

			*addrtype = NGX_HTTP_VIPER_ADDR_TYPE_INET;
			break;
	}

	return NGX_OK;
}

#endif /* NGX_HTTP_SSL */
