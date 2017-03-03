#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>

#include <openssl/crypto.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include "ngx_keyless_module.h"

#define NGX_HTTP_KEYLESS_OP_UDP_BUFFER_SIZE (2*1024)

#define NGX_HTTP_KEYLESS_VERSION (0x80 | 1)

#define NGX_HTTP_KEYLESS_HEADER_LENGTH 8

#define NGX_HTTP_KEYLESS_PAD_TO 1024

static void *ngx_http_keyless_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_keyless_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static int ngx_http_keyless_select_certificate_cb(const SSL_CLIENT_HELLO *client_hello);
static int ngx_http_keyless_cert_cb(ngx_ssl_conn_t *ssl_conn, void *data);

static void ngx_http_keyless_socket_read_handler(ngx_event_t *rev);
static void ngx_http_keyless_socket_read_udp_handler(ngx_event_t *rev);
static void ngx_http_keyless_socket_write_handler(ngx_event_t *wev);

static void ngx_http_keyless_operation_timeout_handler(ngx_event_t *ev);
static void ngx_http_keyless_cleanup_timer_handler(void *data);

extern int ngx_http_keyless_key_type(ngx_ssl_conn_t *ssl_conn);
extern size_t ngx_http_keyless_key_max_signature_len(ngx_ssl_conn_t *ssl_conn);
extern enum ssl_private_key_result_t ngx_http_keyless_key_sign(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out, uint16_t signature_algorithm,
		const uint8_t *in, size_t in_len);
extern enum ssl_private_key_result_t ngx_http_keyless_key_decrypt(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len);
extern enum ssl_private_key_result_t ngx_http_keyless_key_complete(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out);

extern const char *ngx_http_keyless_error_string(ngx_http_keyless_error_t code);

extern EVP_PKEY *ngx_http_keyless_ssl_cert_parse_pubkey(const CBS *in);

static ngx_str_t ngx_http_keyless_sess_id_ctx = ngx_string("keyless-HTTP");

const SSL_PRIVATE_KEY_METHOD ngx_http_keyless_key_method = {
	ngx_http_keyless_key_type,
	ngx_http_keyless_key_max_signature_len,
	ngx_http_keyless_key_sign,
	NULL,
	ngx_http_keyless_key_decrypt,
	ngx_http_keyless_key_complete,
};

static int g_ssl_ctx_exdata_conf_index = -1;
int ngx_http_keyless_ssl_conn_index = -1;

static ngx_command_t ngx_http_keyless_module_commands[] = {
	{ ngx_string("keyless_ssl"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_keyless_srv_conf_t, address),
	  NULL },

	{ ngx_string("keyless_ssl_timeout"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_msec_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_keyless_srv_conf_t, timeout),
	  NULL },

	{ ngx_string("keyless_ssl_fallback"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_flag_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_keyless_srv_conf_t, fallback),
	  NULL },

	ngx_null_command
};

ngx_http_module_t ngx_http_keyless_module_ctx = {
	NULL,                             /* preconfiguration */
	NULL,                             /* postconfiguration */

	NULL,                             /* create main configuration */
	NULL,                             /* init main configuration */

	ngx_http_keyless_create_srv_conf, /* create server configuration */
	ngx_http_keyless_merge_srv_conf,  /* merge server configuration */

	NULL,                             /* create location configuration */
	NULL                              /* merge location configuration */
};

ngx_module_t ngx_http_keyless_module = {
	NGX_MODULE_V1,
	&ngx_http_keyless_module_ctx,     /* module context */
	ngx_http_keyless_module_commands, /* module directives */
	NGX_HTTP_MODULE,                  /* module type */
	NULL,                             /* init master */
	NULL,                             /* init module */
	NULL,                             /* init process */
	NULL,                             /* init thread */
	NULL,                             /* exit thread */
	NULL,                             /* exit process */
	NULL,                             /* exit master */
	NGX_MODULE_V1_PADDING
};

static void *ngx_http_keyless_create_srv_conf(ngx_conf_t *cf)
{
	ngx_http_keyless_srv_conf_t *kcscf;

	kcscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_keyless_srv_conf_t));
	if (!kcscf) {
		return NULL;
	}

	/*
	 * set by ngx_pcalloc():
	 *
	 *     kcscf->address = { 0, NULL };
	 */

	kcscf->timeout = NGX_CONF_UNSET_MSEC;
	kcscf->fallback = NGX_CONF_UNSET;

	return kcscf;
}

static char *ngx_http_keyless_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	const ngx_http_keyless_srv_conf_t *prev = parent;
	ngx_http_keyless_srv_conf_t *conf = child;

	ngx_http_ssl_srv_conf_t *ssl;
	ngx_url_t u;

	ngx_conf_merge_str_value(conf->address, prev->address, "");
	ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 250);
	ngx_conf_merge_value(conf->fallback, prev->fallback, 1);

	if (!conf->address.len || ngx_strcmp(conf->address.data, "off") == 0) {
		return NGX_CONF_OK;
	}

	ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
	if (!ssl || !ssl->ssl.ctx) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "no SSL configured for the server");
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&u, sizeof(ngx_url_t));
	u.url = conf->address;
	u.default_port = 2407;
	u.no_resolve = 1;

	if (u.url.len >= 4 && ngx_strncasecmp(u.url.data, (u_char *)"udp:", 4) == 0) {
		u.url.data += 4;
		u.url.len -= 4;

		conf->pc.type = SOCK_DGRAM;
	} else if (u.url.len >= 4 && ngx_strncasecmp(u.url.data, (u_char *)"tcp:", 4) == 0) {
		u.url.data += 4;
		u.url.len -= 4;
	}

	if (ngx_parse_url(cf->pool, &u) != NGX_OK || !u.addrs || !u.addrs[0].sockaddr) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "invalid URL given in ether directive");
		return NGX_CONF_ERROR;
	}

	conf->pc.sockaddr = u.addrs[0].sockaddr;
	conf->pc.socklen = u.addrs[0].socklen;
	conf->pc.name = &conf->address;

	conf->pc.get = ngx_event_get_peer;
	conf->pc.log = cf->log;
	conf->pc.log_error = NGX_ERROR_ERR;

	if (RAND_bytes((uint8_t *)&conf->id, sizeof(conf->id)) != 1) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "RAND_bytes(...) failed");
		return NGX_CONF_ERROR;
	}

	conf->pool = cf->cycle->pool;

	ngx_queue_init(&conf->recv_ops);
	ngx_queue_init(&conf->send_ops);

	SSL_CTX_set_select_certificate_cb(ssl->ssl.ctx, ngx_http_keyless_select_certificate_cb);
	SSL_CTX_set_cert_cb(ssl->ssl.ctx, ngx_http_keyless_cert_cb, NULL);

	if (g_ssl_ctx_exdata_conf_index == -1) {
		g_ssl_ctx_exdata_conf_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_ctx_exdata_conf_index == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
				"SSL_CTX_get_ex_new_index(...) failed");
			return NGX_CONF_ERROR;
		}
	}

	if (ngx_http_keyless_ssl_conn_index == -1) {
		ngx_http_keyless_ssl_conn_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (ngx_http_keyless_ssl_conn_index == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
				"SSL_get_ex_new_index(...) failed");
			return NGX_CONF_ERROR;
		}
	}

	if (!SSL_CTX_set_ex_data(ssl->ssl.ctx, g_ssl_ctx_exdata_conf_index, conf)) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_set_ex_data(...) failed");
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static int ngx_http_keyless_select_certificate_cb(const SSL_CLIENT_HELLO *client_hello)
{
	const uint8_t *extension_data;
	size_t extension_len;
	CBS extension, cipher_suites, sig_algs;
	STACK_OF(SSL_CIPHER) *cipher_list;
	uint16_t cipher_suite;
	const SSL_CIPHER *cipher;
	ngx_connection_t *c;
	ngx_http_keyless_conn_t *conn;
	ngx_pool_cleanup_t *cln;

	c = ngx_ssl_get_connection(client_hello->ssl);

	conn = ngx_pcalloc(c->pool, sizeof(ngx_http_keyless_conn_t));
	if (!conn || !SSL_set_ex_data(c->ssl->connection, ngx_http_keyless_ssl_conn_index, conn)) {
		return -1;
	}

	conn->key.type = NID_undef;

	cipher_list = SSL_get_ciphers(client_hello->ssl);

	CBS_init(&cipher_suites, client_hello->cipher_suites, client_hello->cipher_suites_len);

	while (CBS_len(&cipher_suites) != 0) {
		if (!CBS_get_u16(&cipher_suites, &cipher_suite)) {
			return -1;
		}

		cipher = SSL_get_cipher_by_value(cipher_suite);
		if (cipher && SSL_CIPHER_is_ECDSA(cipher)
			&& sk_SSL_CIPHER_find(cipher_list, NULL, cipher)) {
			conn->get_cert.ecdsa_cipher = 1;
			break;
		}
	}

	if (SSL_early_callback_ctx_extension_get(client_hello, TLSEXT_TYPE_signature_algorithms,
			&extension_data, &extension_len)) {
		CBS_init(&extension, extension_data, extension_len);

		cln = ngx_pool_cleanup_add(c->pool, 0);
		if (!cln || !CBS_get_u16_length_prefixed(&extension, &sig_algs)
			|| CBS_len(&sig_algs) == 0
			|| CBS_len(&extension) != 0
			|| CBS_len(&sig_algs) % 2 != 0
			|| !CBS_stow(&sig_algs, &conn->get_cert.sig_algs,
				&conn->get_cert.sig_algs_len)) {
			return -1;
		}

		cln->handler = OPENSSL_free;
		cln->data = conn->get_cert.sig_algs;
	}

	return 1;
}

static int ngx_http_keyless_cert_cb(ngx_ssl_conn_t *ssl_conn, void *data)
{
	int ret = 0;
	ngx_connection_t *c;
	ngx_http_keyless_srv_conf_t *conf;
	ngx_http_keyless_conn_t *conn;
	SSL *ssl;
	CBS payload, child;
	EVP_PKEY *public_key = NULL;
	SHA256_CTX sha_ctx;
	uint8_t sid_ctx[SHA256_DIGEST_LENGTH];

	c = ngx_ssl_get_connection(ssl_conn);
	ssl = c->ssl->connection;

	conn = SSL_get_ex_data(ssl, ngx_http_keyless_ssl_conn_index);
	if (!conn) {
		return 1;
	}

	if (!conn->op) {
		conn->op = ngx_http_keyless_start_operation(NGX_HTTP_KEYLESS_OP_GET_CERTIFICATE,
			c, conn, NULL, 0);

		conn->get_cert.sig_algs = NULL;
		conn->get_cert.ecdsa_cipher = 0;

		if (!conn->op) {
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
				"ngx_http_keyless_start_operation("
				"NGX_HTTP_KEYLESS_OP_GET_CERTIFICATE) failed");
			return 0;
		}

		return -1;
	}

	conf = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), g_ssl_ctx_exdata_conf_index);
	if (!conf) {
		goto error;
	}

	switch (ngx_http_keyless_operation_complete(conn->op, &payload)) {
		case ssl_private_key_failure:
			if (conn->op->error == NGX_HTTP_KEYLESS_ERROR_CERT_NOT_FOUND) {
				if (!conf->fallback) {
					SSL_certs_clear(ssl);
				}

				ret = 1;
			}

			goto error;
		case ssl_private_key_retry:
			return -1;
		case ssl_private_key_success:
			break;
	}

	if (CBS_len(&payload) == 0 || !conn->op->ski) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "get certificate format error");
		goto error;
	}

	ngx_memcpy(conn->ski, conn->op->ski, SHA_DIGEST_LENGTH);

	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, ngx_http_keyless_sess_id_ctx.data,
		ngx_http_keyless_sess_id_ctx.len);
	SHA256_Update(&sha_ctx, CBS_data(&payload), CBS_len(&payload));
	SHA256_Final(sid_ctx, &sha_ctx);

	if (!SSL_set_session_id_context(ssl, sid_ctx, 16)) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "SSL_set_session_id_context(...) failed");
		goto error;
	}

	if (conn->op->ocsp_response && !SSL_set_ocsp_response(ssl,
			conn->op->ocsp_response, conn->op->ocsp_response_length)) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"SSL_set_ocsp_response(...) failed");
		goto error;
	}

	if (conn->op->sct_list && !SSL_set_signed_cert_timestamp_list(ssl, conn->op->sct_list,
				conn->op->sct_list_length)) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"SSL_set_signed_cert_timestamp_list(...) failed");
		goto error;
	}

	SSL_certs_clear(ssl);
	SSL_set_private_key_method(ssl, &ngx_http_keyless_key_method);

	if (!CBS_get_u16_length_prefixed(&payload, &child)) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "get certificate format error");
		goto error;
	}

	public_key = ngx_http_keyless_ssl_cert_parse_pubkey(&child);
	if (!public_key) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0,
			"ngx_http_keyless_ssl_cert_parse_pubkey(...) failed");
		goto error;
	}

	switch (EVP_PKEY_id(public_key)) {
		case EVP_PKEY_RSA:
			conn->key.type = NID_rsaEncryption;
			break;
		case EVP_PKEY_EC:
			conn->key.type = EC_GROUP_get_curve_name(EC_KEY_get0_group(
				EVP_PKEY_get0_EC_KEY(public_key)));
			break;
	}

	conn->key.sig_len = EVP_PKEY_size(public_key);
	EVP_PKEY_free(public_key);

	if (!SSL_use_certificate_ASN1(ssl, CBS_data(&child), CBS_len(&child))) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "SSL_use_certificate_ASN1(...) failed");
		goto error;
	}

	while (CBS_len(&payload) != 0) {
		if (!CBS_get_u16_length_prefixed(&payload, &child)) {
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "get certificate format error");
			goto error;
		}

		if (!SSL_add_chain_cert_ASN1(ssl, CBS_data(&child), CBS_len(&child))) {
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
				"SSL_add_chain_cert_ASN1(...) failed");
			goto error;
		}
	}

	ret = 1;

error:
	if (ret == 0) {
		ERR_clear_error();
	}

	ngx_http_keyless_cleanup_operation(conn->op);
	return ret;
}

extern ngx_http_keyless_op_t *ngx_http_keyless_start_operation(ngx_http_keyless_operation_t opcode,
		ngx_connection_t *c, ngx_http_keyless_conn_t *conn, const uint8_t *in,
		size_t in_len)
{
	SSL *ssl;
	ngx_http_keyless_srv_conf_t *conf;
	ngx_http_keyless_op_t *op = NULL;
	const struct sockaddr_in *sin;
#if NGX_HAVE_INET6
	const struct sockaddr_in6 *sin6;
#endif
	CBB payload, child;
	uint8_t *p;
	const uint8_t *sni, *ip;
	size_t len, len2, ip_len;
	ngx_int_t rc;

	CBB_zero(&payload);

	ssl = c->ssl->connection;

	conf = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), g_ssl_ctx_exdata_conf_index);
	if (!conf) {
		goto error;
	}

	if (!conf->pc.connection) {
		rc = ngx_event_connect_peer(&conf->pc);
		if (rc == NGX_ERROR || rc == NGX_DECLINED) {
			ngx_log_error(NGX_LOG_EMERG, c->log, 0,
				"ngx_event_connect_peer(...) failed");
			goto error;
		}

		conf->pc.connection->data = conf;
		conf->pc.connection->pool = conf->pool;

		if (conf->pc.type == SOCK_DGRAM) {
			conf->pc.connection->read->handler = ngx_http_keyless_socket_read_udp_handler;
		} else {
			conf->pc.connection->read->handler = ngx_http_keyless_socket_read_handler;
		}

		conf->pc.connection->write->handler = ngx_http_keyless_socket_write_handler;
	}

	op = ngx_pcalloc(conf->pool, sizeof(ngx_http_keyless_op_t));
	if (!op) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_pcalloc(...) failed");
		goto error;
	}

	op->conf = conf;
	op->ev = c->write;
	op->log = c->log;

	do {
		op->id = ngx_atomic_fetch_add(&conf->id, 1);
	} while (!op->id);

	if (!CBB_init(&payload, NGX_HTTP_KEYLESS_HEADER_LENGTH + NGX_HTTP_KEYLESS_PAD_TO + 4)
		// header
		|| !CBB_add_u8(&payload, NGX_HTTP_KEYLESS_VERSION)
		|| !CBB_add_u24(&payload, 0) // length placeholder
		|| !CBB_add_u32(&payload, op->id)
		// opcode tag
		|| !CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_OPCODE)
		|| !CBB_add_u16_length_prefixed(&payload, &child)
		|| !CBB_add_u16(&child, opcode)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_*(...) failed");
		goto error;
	}

	if (conn->key.type
		// ski tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_SKI)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_bytes(&child, conn->ski, SHA_DIGEST_LENGTH))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_*(...) failed");
		goto error;
	}

	sni = (const uint8_t *)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (sni // sni tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_SNI)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_bytes(&child, sni, ngx_strlen(sni)))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_*(...) failed");
		goto error;
	}

	switch (c->sockaddr->sa_family) {
#if NGX_HAVE_INET6
		case AF_INET6:
			sin6 = (const struct sockaddr_in6 *)c->sockaddr;

			ip_len = 16;
			ip = (const uint8_t *)&sin6->sin6_addr.s6_addr[0];
			break;
#endif /* NGX_HAVE_INET6 */
		case AF_INET:
			sin = (const struct sockaddr_in *)c->sockaddr;

			ip_len = 4;
			ip = (const uint8_t *)&sin->sin_addr.s_addr;
			break;
		default:
			ip_len = 0;
			break;
	}

	if (ip_len
		// client ip tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_CLIENT_IP)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_bytes(&child, ip, ip_len))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_*(...) failed");
		goto error;
	}

	if (ngx_connection_local_sockaddr(c, NULL, 0) == NGX_OK) {
		switch (c->local_sockaddr->sa_family) {
#if NGX_HAVE_INET6
			case AF_INET6:
				sin6 = (const struct sockaddr_in6 *)c->local_sockaddr;

				ip_len = 16;
				ip = (const uint8_t *)&sin6->sin6_addr.s6_addr[0];
				break;
#endif /* NGX_HAVE_INET6 */
			case AF_INET:
				sin = (const struct sockaddr_in *)c->local_sockaddr;

				ip_len = 4;
				ip = (const uint8_t *)&sin->sin_addr.s_addr;
				break;
			default:
				ip_len = 0;
				break;
		}

		if (ip_len
			// server ip tag
			&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_SERVER_IP)
				|| !CBB_add_u16_length_prefixed(&payload, &child)
				|| !CBB_add_bytes(&child, ip, ip_len))) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_*(...) failed");
			goto error;
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_connection_local_sockaddr(...) failed");
	}

	if (conn->get_cert.sig_algs
		// sig algs tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_SIG_ALGS)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_bytes(&child, conn->get_cert.sig_algs,
				conn->get_cert.sig_algs_len))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_*(...) failed");
		goto error;
	}

	if (conn->get_cert.ecdsa_cipher
		// ecdsa cipher tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_ECDSA_CIPHER)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_u8(&child, conn->get_cert.ecdsa_cipher))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_*(...) failed");
		goto error;
	}

	if (in // payload tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_PAYLOAD)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_bytes(&child, in, in_len))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_*(...) failed");
		goto error;
	}

	if (!CBB_flush(&payload)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_flush(...) failed");
		goto error;
	}

	len = CBB_len(&payload) - NGX_HTTP_KEYLESS_HEADER_LENGTH;
	if (len < NGX_HTTP_KEYLESS_PAD_TO) {
		// padding tag
		if (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_PADDING)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_space(&child, &p, NGX_HTTP_KEYLESS_PAD_TO - len)) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_*(...) failed");
			goto error;
		}

		ngx_memzero(p, NGX_HTTP_KEYLESS_PAD_TO - len);
	}

	if (!CBB_finish(&payload, &p, &len)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_finish(...) failed");
		goto error;
	}

	len2 = len - NGX_HTTP_KEYLESS_HEADER_LENGTH;
	if (len2 > 0xffffff) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "body too large to encode length");
		goto error;
	}

	// set length
	p[1] = len2 >> 16;
	p[2] = len2 >> 8;
	p[3] = len2;

	op->send.start = p;
	op->send.pos = p;
	op->send.last = p + len;
	op->send.end = p + len;

	if (conf->timeout) {
		op->timer.handler = ngx_http_keyless_operation_timeout_handler;
		op->timer.data = c->write;
		op->timer.log = c->log;

		op->cln = ngx_pool_cleanup_add(c->pool, 0);
		if (!op->cln) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_pool_cleanup_add(...) failed");
			goto error;
		}

		op->cln->handler = ngx_http_keyless_cleanup_timer_handler;
		op->cln->data = &op->timer;

		ngx_add_timer(&op->timer, conf->timeout);
	}

	ngx_queue_insert_tail(&conf->recv_ops, &op->recv_queue);
	ngx_queue_insert_tail(&conf->send_ops, &op->send_queue);

	conf->pc.connection->write->handler(conf->pc.connection->write);

	CBB_cleanup(&payload);

	return op;

error:
	CBB_cleanup(&payload);

	if (op) {
		if (op->send.start) {
			OPENSSL_cleanse(op->send.start, op->send.end - op->send.start);
			OPENSSL_free(op->send.start);
		}

		ngx_pfree(conf->pool, op);
	}

	return NULL;
}

extern enum ssl_private_key_result_t ngx_http_keyless_operation_complete(ngx_http_keyless_op_t *op,
		CBS *out)
{
	ngx_http_keyless_operation_t opcode = 0;
	uint16_t tag;
	CBS msg, child, payload;
	int saw_opcode = 0, saw_payload = 0;

	if (op->recv.last - op->recv.pos < NGX_HTTP_KEYLESS_HEADER_LENGTH) {
		if (op->timer.timedout) {
			ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless operation timed out");
			return ssl_private_key_failure;
		}

		return ssl_private_key_retry;
	}

	CBS_init(&msg, op->recv.pos, op->recv.last - op->recv.pos);

	if (!CBS_skip(&msg, NGX_HTTP_KEYLESS_HEADER_LENGTH)) {
		ngx_log_error(NGX_LOG_ERR, op->log, 0, "CBS_skip(...) failed");
		return ssl_private_key_failure;
	}

	while (CBS_len(&msg) != 0) {
		if (!CBS_get_u16(&msg, &tag)
			|| !CBS_get_u16_length_prefixed(&msg, &child)) {
			ngx_log_error(NGX_LOG_ERR, op->log, 0, "CBS_*(...) failed");
			return ssl_private_key_failure;
		}

		switch (tag) {
			case NGX_HTTP_KEYLESS_TAG_OPCODE:
				if (saw_opcode || CBS_len(&child) != 2) {
					ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
						ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_FORMAT));
					return ssl_private_key_failure;
				}

				if (!CBS_get_u16(&child, (uint16_t *)&opcode)) {
					ngx_log_error(NGX_LOG_ERR, op->log, 0, "CBS_*(...) failed");
					return ssl_private_key_failure;
				}

				saw_opcode = 1;
				break;
			case NGX_HTTP_KEYLESS_TAG_PAYLOAD:
				if (saw_payload) {
					ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
						ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_FORMAT));
					return ssl_private_key_failure;
				}

				payload = child;
				saw_payload = 1;
				break;
			case NGX_HTTP_KEYLESS_TAG_SKI:
				if (op->ski || CBS_len(&child) != SHA_DIGEST_LENGTH) {
					ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
						ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_FORMAT));
					return ssl_private_key_failure;
				}

				op->ski = CBS_data(&child);
				break;
			case NGX_HTTP_KEYLESS_TAG_OCSP_RESPONSE:
				if (op->ocsp_response) {
					ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
						ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_FORMAT));
					return ssl_private_key_failure;
				}

				op->ocsp_response = CBS_data(&child);
				op->ocsp_response_length = CBS_len(&child);
				break;
			case NGX_HTTP_KEYLESS_TAG_SIGNED_CERT_TIMESTAMPS:
				if (op->sct_list) {
					ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
						ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_FORMAT));
					return ssl_private_key_failure;
				}

				op->sct_list = CBS_data(&child);
				op->sct_list_length = CBS_len(&child);
				break;
		}
	}

	if (!saw_opcode || !saw_payload) {
		ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
			ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_FORMAT));
		return ssl_private_key_failure;
	}

	switch (opcode) {
		case NGX_HTTP_KEYLESS_OP_RESPONSE:
			*out = payload;
			return ssl_private_key_success;
		case NGX_HTTP_KEYLESS_OP_ERROR:
			if (CBS_len(&payload) != 2) {
				ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
					ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_FORMAT));
				return ssl_private_key_failure;
			}

			if (!CBS_get_u16(&payload, (uint16_t *)&op->error)) {
				ngx_log_error(NGX_LOG_ERR, op->log, 0, "CBS_*(...) failed");
			} else {
				ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless error: %s",
					ngx_http_keyless_error_string(op->error));
			}

			return ssl_private_key_failure;
		case NGX_HTTP_KEYLESS_OP_RSA_DECRYPT:
		case NGX_HTTP_KEYLESS_OP_RSA_DECRYPT_RAW:
		case NGX_HTTP_KEYLESS_OP_RSA_SIGN_MD5SHA1:
		case NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA1:
		case NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA224:
		case NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA256:
		case NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA384:
		case NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA512:
		case NGX_HTTP_KEYLESS_OP_RSA_PSS_SIGN_SHA256:
		case NGX_HTTP_KEYLESS_OP_RSA_PSS_SIGN_SHA384:
		case NGX_HTTP_KEYLESS_OP_RSA_PSS_SIGN_SHA512:
		case NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_MD5SHA1:
		case NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA1:
		case NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA224:
		case NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA256:
		case NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA384:
		case NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA512:
		case NGX_HTTP_KEYLESS_OP_GET_CERTIFICATE:
		case NGX_HTTP_KEYLESS_OP_PING:
		case NGX_HTTP_KEYLESS_OP_PONG:
		case NGX_HTTP_KEYLESS_OP_ACTIVATE:
		case NGX_HTTP_KEYLESS_OP_ED25519_SIGN:
			ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
				ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_UNEXPECTED_OPCODE));
			return ssl_private_key_failure;
		default:
			ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
				ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_BAD_OPCODE));
			return ssl_private_key_failure;
	}
}

extern void ngx_http_keyless_cleanup_operation(ngx_http_keyless_op_t *op)
{
	if (op->cln) {
		op->cln->handler = NULL;
	}

	if (op->timer.handler) {
		ngx_del_timer(&op->timer);
	}

	if (op->send.start) {
		OPENSSL_cleanse(op->send.start, op->send.end - op->send.start);
		OPENSSL_free(op->send.start);

		op->send.start = NULL;
		op->send.pos = NULL;
		op->send.last = NULL;
		op->send.end = NULL;
	}

	if (op->recv.start) {
		OPENSSL_cleanse(op->recv.start, op->recv.end - op->recv.start);
		ngx_pfree(op->conf->pool, op->recv.start);

		op->recv.start = NULL;
		op->recv.pos = NULL;
		op->recv.last = NULL;
		op->recv.end = NULL;
	}

	if (ngx_queue_prev(&op->recv_queue)
		&& ngx_queue_next(ngx_queue_prev(&op->recv_queue)) == &op->recv_queue) {
		ngx_queue_remove(&op->recv_queue);
	}

	if (ngx_queue_prev(&op->send_queue)
		&& ngx_queue_next(ngx_queue_prev(&op->send_queue)) == &op->send_queue) {
		ngx_queue_remove(&op->send_queue);
	}

	ngx_pfree(op->conf->pool, op);
}

static void ngx_http_keyless_socket_read_handler(ngx_event_t *rev)
{
	ngx_connection_t *c;
	ngx_http_keyless_srv_conf_t *conf;
	ngx_http_keyless_op_t *op;
	ngx_queue_t *q;
	ngx_buf_t recv;
	ssize_t size, n;
	uint8_t *new_buf;
	CBS payload;
	uint8_t vers;
	uint32_t length, id;

	c = rev->data;
	conf = c->data;

	if (conf->tmp_recv.start) {
		recv = conf->tmp_recv;

		conf->tmp_recv.start = NULL;
		conf->tmp_recv.pos = NULL;
		conf->tmp_recv.last = NULL;
		conf->tmp_recv.end = NULL;
	} else {
		size = NGX_HTTP_KEYLESS_HEADER_LENGTH + NGX_HTTP_KEYLESS_PAD_TO + 4;
		recv.start = ngx_palloc(c->pool, size);
		if (!recv.start) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"ngx_palloc failed to allocated recv buffer");
			return;
		}

		recv.pos = recv.start;
		recv.last = recv.start;
		recv.end = recv.start + size;
	}

	while (1) {
		n = recv.end - recv.last;

		/* buffer not big enough? enlarge it by twice */
		if (n == 0) {
			size = recv.end - recv.start;

			new_buf = ngx_palloc(c->pool, size * 2);
			if (!new_buf) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"ngx_palloc failed to allocated new recv buffer");
				return;
			}

			ngx_memcpy(new_buf, recv.start, size);

			OPENSSL_cleanse(recv.start, size);
			ngx_pfree(c->pool, recv.start);

			recv.start = new_buf;
			recv.pos = new_buf;
			recv.last = new_buf + size;
			recv.end = new_buf + size * 2;

			n = recv.end - recv.last;
		}

		size = c->recv(c, recv.last, n);
		if (size > 0) {
			recv.last += size;
		} else if (size == 0 || size == NGX_AGAIN) {
			break;
		} else {
			c->error = 1;
			return;
		}
	}

done_read:
	CBS_init(&payload, recv.pos, recv.last - recv.pos);

	if (CBS_len(&payload) < NGX_HTTP_KEYLESS_HEADER_LENGTH) {
		goto store_temp;
	}

	if (!CBS_get_u8(&payload, &vers)
		|| vers != NGX_HTTP_KEYLESS_VERSION
		|| !CBS_get_u24(&payload, &length)
		|| !CBS_get_u32(&payload, &id)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBS_*(...) failed or format error");
		goto cleanup;
	}

	if (length > CBS_len(&payload)) {
		goto store_temp;
	}

	for (q = ngx_queue_head(&conf->recv_ops);
		q != ngx_queue_sentinel(&conf->recv_ops);
		q = ngx_queue_next(q)) {
		op = ngx_queue_data(q, ngx_http_keyless_op_t, recv_queue);

		if (op->id != id) {
			continue;
		}

		ngx_queue_remove(&op->recv_queue);

		if (CBS_len(&payload) > length) {
			op->recv.start = ngx_palloc(c->pool,
				NGX_HTTP_KEYLESS_HEADER_LENGTH + length);
			if (!op->recv.start) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"ngx_palloc failed to allocated recv buffer");
				return;
			}

			op->recv.pos = op->recv.start;
			op->recv.last = ngx_cpymem(op->recv.pos, recv.pos,
				NGX_HTTP_KEYLESS_HEADER_LENGTH + length);
			op->recv.end = op->recv.last;
		} else {
			op->recv = recv;
		}

		ngx_post_event(op->ev, &ngx_posted_events);

		if (CBS_len(&payload) > length) {
			goto process_next;
		} else {
			return;
		}
	}

	ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid header id: %ud", id);

process_next:
	if (CBS_len(&payload) > length) {
		recv.pos += length;
		goto done_read;
	}

cleanup:
	OPENSSL_cleanse(recv.start, recv.last - recv.start);
	ngx_pfree(c->pool, recv.start);
	return;

store_temp:
	if (recv.pos != recv.start
		&& recv.end - recv.start > (ssize_t)(ngx_pagesize * 4)
		&& (recv.end - recv.start) - (recv.last - recv.pos) > (ssize_t)ngx_pagesize) {
		conf->tmp_recv.start = ngx_palloc(c->pool, recv.last - recv.pos);
		if (!conf->tmp_recv.start) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				"ngx_palloc failed to allocated recv buffer");

			conf->tmp_recv = recv;
			return;
		}

		conf->tmp_recv.pos = conf->tmp_recv.start;
		conf->tmp_recv.last = ngx_cpymem(conf->tmp_recv.pos, recv.pos, recv.last - recv.pos);
		conf->tmp_recv.end = conf->tmp_recv.last;
		goto cleanup;
	} else {
		conf->tmp_recv = recv;
	}
}

static void ngx_http_keyless_socket_read_udp_handler(ngx_event_t *rev)
{
	ngx_connection_t *c;
	ngx_http_keyless_srv_conf_t *conf;
	ngx_http_keyless_op_t *op;
	ngx_queue_t *q;
	ngx_buf_t recv;
	ssize_t size;
	CBS payload;
	uint8_t vers;
	uint32_t length, id;

	c = rev->data;
	conf = c->data;

	recv.start = ngx_palloc(c->pool, NGX_HTTP_KEYLESS_OP_UDP_BUFFER_SIZE);
	if (!recv.start) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"ngx_palloc failed to allocated recv buffer");
		return;
	}

	recv.pos = recv.start;
	recv.last = recv.start;
	recv.end = recv.start + NGX_HTTP_KEYLESS_OP_UDP_BUFFER_SIZE;

	size = c->recv(c, recv.last, recv.end - recv.last);
	if (size > 0) {
		recv.last += size;
	} else if (size == 0 || size == NGX_AGAIN) {
		goto cleanup;
	} else {
		c->error = 1;
		goto cleanup;
	}

	CBS_init(&payload, recv.pos, recv.last - recv.pos);

	if (CBS_len(&payload) < NGX_HTTP_KEYLESS_HEADER_LENGTH
		|| !CBS_get_u8(&payload, &vers)
		|| vers != NGX_HTTP_KEYLESS_VERSION
		|| !CBS_get_u24(&payload, &length)
		|| !CBS_get_u32(&payload, &id)
		|| length != CBS_len(&payload)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBS_*(...) failed or format error");
		goto cleanup;
	}

	for (q = ngx_queue_head(&conf->recv_ops);
		q != ngx_queue_sentinel(&conf->recv_ops);
		q = ngx_queue_next(q)) {
		op = ngx_queue_data(q, ngx_http_keyless_op_t, recv_queue);

		if (op->id != id) {
			continue;
		}

		ngx_queue_remove(&op->recv_queue);

		op->recv = recv;

		ngx_post_event(op->ev, &ngx_posted_events);
		return;
	}

	ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid header id: %ud", id);

cleanup:
	OPENSSL_cleanse(recv.start, recv.last - recv.start);
	ngx_pfree(c->pool, recv.start);
}

static void ngx_http_keyless_socket_write_handler(ngx_event_t *wev)
{
	ngx_connection_t *c;
	ngx_http_keyless_srv_conf_t *conf;
	ngx_http_keyless_op_t *op;
	ngx_queue_t *q;
	ssize_t size;

	c = wev->data;
	conf = c->data;

	while (!ngx_queue_empty(&conf->send_ops)) {
		q = ngx_queue_head(&conf->send_ops);
		op = ngx_queue_data(q, ngx_http_keyless_op_t, send_queue);

		while (op->send.pos < op->send.last) {
			size = c->send(c, op->send.pos, op->send.last - op->send.pos);
			if (size > 0) {
				op->send.pos += size;

				if (conf->pc.type == SOCK_DGRAM) {
					break;
				}
			} else if (size == 0 || size == NGX_AGAIN) {
				return;
			} else {
				c->error = 1;
				return;
			}
		}

		ngx_queue_remove(&op->send_queue);

		if (op->send.pos != op->send.last) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "keyless send truncated");
		} else {
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "keyless send done");
		}

		OPENSSL_cleanse(op->send.start, op->send.end - op->send.start);
		OPENSSL_free(op->send.start);

		op->send.start = NULL;
		op->send.pos = NULL;
		op->send.last = NULL;
		op->send.end = NULL;
	}
}

static void ngx_http_keyless_operation_timeout_handler(ngx_event_t *ev)
{
	ngx_event_t *wev = ev->data;

	ngx_post_event(wev, &ngx_posted_events);
}

static void ngx_http_keyless_cleanup_timer_handler(void *data)
{
	ngx_event_t *ev = data;

	if (ev->timer_set) {
		ngx_del_timer(ev);
	}
}