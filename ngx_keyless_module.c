#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_event.h>

#include <kssl.h>
#include <kssl_helpers.h>

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define NGX_HTTP_KEYLESS_OP_BUFFER_SIZE 2*1024

/* taken from boringssl-1e4ae00/ssl/internal.h */
#define SSL_CURVE_SECP256R1 23
#define SSL_CURVE_SECP384R1 24
#define SSL_CURVE_SECP521R1 25

#define NGX_KEYLESS_SSL_HASH_CIPHER    224
#define NGX_KEYLESS_SSL_HASH_EC_CURVES 225

typedef struct {
	ngx_str_t address;

	ngx_peer_connection_t pc;

	ngx_atomic_uint_t id;

	ngx_pool_t *pool;

	ngx_queue_t recv_ops;
	ngx_queue_t send_ops;
} ngx_http_keyless_srv_conf_t;

typedef struct {
	ngx_http_keyless_srv_conf_t *conf;

	ngx_event_t *ev;
	ngx_event_t timer;

	unsigned int id;

	ngx_log_t *log;

	ngx_buf_t send;
	ngx_buf_t recv;

	ngx_queue_t recv_queue;
	ngx_queue_t send_queue;
} ngx_http_keyless_op_t;

typedef struct {
	ngx_http_keyless_op_t *op;

	struct {
		int type;
		size_t sig_len;
	} key;

	unsigned char ski[KSSL_SKI_SIZE];
} ngx_http_keyless_conn_t;

static void *ngx_http_keyless_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_keyless_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static int ngx_http_keyless_select_certificate_cb(const struct ssl_early_callback_ctx *ctx);
static int ngx_http_keyless_cert_cb(ngx_ssl_conn_t *ssl_conn, void *data);

static ngx_http_keyless_op_t *ngx_http_keyless_start_operation(kssl_opcode_et opcode,
		ngx_connection_t *c, ngx_http_keyless_conn_t *conn, const uint8_t *in,
		size_t in_len);
static enum ssl_private_key_result_t ngx_http_keyless_operation_complete(ngx_http_keyless_op_t *op,
		const uint8_t **out, size_t *out_len);
static void ngx_http_keyless_cleanup_operation(ngx_http_keyless_op_t *op);

static void ngx_http_keyless_socket_read_handler(ngx_event_t *rev);
static void ngx_http_keyless_socket_write_handler(ngx_event_t *wev);

static void ngx_http_keyless_operation_timeout_handler(ngx_event_t *ev);
static void ngx_http_keyless_cleanup_timer_handler(void *data);

static int ngx_http_keyless_key_type(ngx_ssl_conn_t *ssl_conn);
static size_t ngx_http_keyless_key_max_signature_len(ngx_ssl_conn_t *ssl_conn);
static enum ssl_private_key_result_t ngx_http_keyless_key_sign(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out, const EVP_MD *md, const uint8_t *in,
		size_t in_len);
static enum ssl_private_key_result_t ngx_http_keyless_key_decrypt(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len);
static enum ssl_private_key_result_t ngx_http_keyless_key_complete(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out);

const SSL_PRIVATE_KEY_METHOD ngx_http_keyless_key_method = {
	ngx_http_keyless_key_type,
	ngx_http_keyless_key_max_signature_len,
	ngx_http_keyless_key_sign,
	ngx_http_keyless_key_complete,
	ngx_http_keyless_key_decrypt,
	ngx_http_keyless_key_complete,
};

static int g_ssl_ctx_exdata_conf_index = -1;
static int g_ssl_exdata_conn_index = -1;

static ngx_command_t ngx_http_keyless_module_commands[] = {
	{ ngx_string("keyless_ssl"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_keyless_srv_conf_t, address),
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

	return kcscf;
}

static char *ngx_http_keyless_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
	const ngx_http_keyless_srv_conf_t *prev = parent;
	ngx_http_keyless_srv_conf_t *conf = child;

	ngx_http_ssl_srv_conf_t *ssl;
	ngx_url_t u;

	ngx_conf_merge_str_value(conf->address, prev->address, "");

	if (!conf->address.len || ngx_strcmp(conf->address.data, "off") == 0) {
		return NGX_CONF_OK;
	}

	ssl = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
	if (!ssl || !ssl->ssl.ctx) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "no ssl configured for the server");
		return NGX_CONF_ERROR;
	}

	ngx_memzero(&u, sizeof(ngx_url_t));
	u.url = conf->address;
	u.default_port = 2407;
	u.no_resolve = 1;

	if (ngx_parse_url(cf->pool, &u) != NGX_OK || !u.addrs || !u.addrs[0].sockaddr) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "invalid url given in ether directive");
		return NGX_CONF_ERROR;
	}

	conf->pc.sockaddr = u.addrs[0].sockaddr;
	conf->pc.socklen = u.addrs[0].socklen;
	conf->pc.name = &conf->address;

	conf->pc.type = SOCK_DGRAM;

	conf->pc.get = ngx_event_get_peer;
	conf->pc.log = cf->log;
	conf->pc.log_error = NGX_ERROR_ERR;

	conf->pool = cf->cycle->pool;

	ngx_queue_init(&conf->recv_ops);
	ngx_queue_init(&conf->send_ops);

	SSL_CTX_set_tlsext_servername_callback(ssl->ssl.ctx, NULL);
	SSL_CTX_set_select_certificate_cb(ssl->ssl.ctx, ngx_http_keyless_select_certificate_cb);
	SSL_CTX_set_cert_cb(ssl->ssl.ctx, ngx_http_keyless_cert_cb, NULL);

	if (g_ssl_ctx_exdata_conf_index == -1) {
		g_ssl_ctx_exdata_conf_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_ctx_exdata_conf_index == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
				"SSL_CTX_get_ex_new_index failed");
			return NGX_CONF_ERROR;
		}
	}

	if (g_ssl_exdata_conn_index == -1) {
		g_ssl_exdata_conn_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_exdata_conn_index == -1) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_get_ex_new_index failed");
			return NGX_CONF_ERROR;
		}
	}

	if (!SSL_CTX_set_ex_data(ssl->ssl.ctx, g_ssl_ctx_exdata_conf_index, conf)) {
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_XTX_set_ex_data failed");
		return NGX_CONF_ERROR;
	}

	return NGX_CONF_OK;
}

static int ngx_http_keyless_select_certificate_cb(const struct ssl_early_callback_ctx *ctx)
{
	const uint8_t *extension_data;
	size_t extension_len, sig_algs_len;
	CBS extension, cipher_suites, server_name_list, host_name, sig_algs, ec_curves;
	int has_server_name;
	uint16_t cipher_suite, ec_curve;
	uint8_t name_type;
	const SSL_CIPHER *cipher;
	char *server_name = NULL;
	unsigned char tmp_sig_algs[256];
	unsigned char *sig_algs_end = &tmp_sig_algs[0];
	int rc = -1;
	ngx_connection_t *c;
	ngx_http_keyless_conn_t *conn;

	has_server_name = SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_server_name,
		&extension_data, &extension_len);
	if (has_server_name) {
		CBS_init(&extension, extension_data, extension_len);

		if (!CBS_get_u16_length_prefixed(&extension, &server_name_list)
			|| !CBS_get_u8(&server_name_list, &name_type)
			/* Although the server_name extension was intended to be extensible to
			 * new name types and multiple names, OpenSSL 1.0.x had a bug which meant
			 * different name types will cause an error. Further, RFC 4366 originally
			 * defined syntax inextensibly. RFC 6066 corrected this mistake, but
			 * adding new name types is no longer feasible.
			 *
			 * Act as if the extensibility does not exist to simplify parsing. */
			|| !CBS_get_u16_length_prefixed(&server_name_list, &host_name)
			|| CBS_len(&server_name_list) != 0
			|| CBS_len(&extension) != 0
			|| name_type != TLSEXT_NAMETYPE_host_name
			|| CBS_len(&host_name) == 0
			|| CBS_len(&host_name) > TLSEXT_MAXLEN_host_name
			|| CBS_contains_zero_byte(&host_name)
			|| !CBS_strdup(&host_name, &server_name)) {
			goto cleanup;
		}

		ctx->ssl->tlsext_hostname = server_name;

		if (ngx_http_ssl_servername(ctx->ssl, NULL, NULL) == SSL_TLSEXT_ERR_NOACK) {
			ctx->ssl->s3->tmp.should_ack_sni = 0;
		}
	}

	if (SSL_early_callback_ctx_extension_get(ctx,
			TLSEXT_TYPE_signature_algorithms, &extension_data, &extension_len)) {
		CBS_init(&extension, extension_data, extension_len);

		if (!CBS_get_u16_length_prefixed(&extension, &sig_algs)
			|| CBS_len(&sig_algs) == 0
			|| CBS_len(&extension) != 0
			|| CBS_len(&sig_algs) % 2 != 0
			|| CBS_len(&sig_algs) > sizeof(tmp_sig_algs) - 4
				- (sig_algs_end - tmp_sig_algs)) {
			goto cleanup;
		}

		sig_algs_len = CBS_len(&sig_algs);

		if (!CBS_copy_bytes(&sig_algs, sig_algs_end, sig_algs_len)) {
			goto cleanup;
		}

		sig_algs_end += sig_algs_len;

		if (SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_elliptic_curves,
				&extension_data, &extension_len)) {
			CBS_init(&extension, extension_data, extension_len);

			if (!CBS_get_u16_length_prefixed(&extension, &ec_curves)
				|| CBS_len(&ec_curves) == 0
				|| CBS_len(&extension) != 0
				|| CBS_len(&ec_curves) % 2 != 0
				|| CBS_len(&ec_curves) > sizeof(tmp_sig_algs) - 2
					- (sig_algs_end - tmp_sig_algs)) {
				goto cleanup;
			}

			while (CBS_len(&ec_curves) != 0) {
				if (!CBS_get_u16(&ec_curves, &ec_curve)) {
					goto cleanup;
				}

				switch (ec_curve) {
					case SSL_CURVE_SECP256R1:
					case SSL_CURVE_SECP384R1:
					case SSL_CURVE_SECP521R1:
						*sig_algs_end++ = NGX_KEYLESS_SSL_HASH_EC_CURVES;
						*sig_algs_end++ = (unsigned char)ec_curve;
						break;
				}
			}
		} else {
			/* Clients are not required to send a supported_curves extension. In this
			 * case, the server is free to pick any curve it likes. See RFC 4492,
			 * section 4, paragraph 3. */
			*sig_algs_end++ = NGX_KEYLESS_SSL_HASH_EC_CURVES;
			*sig_algs_end++ = SSL_CURVE_SECP256R1;
		}

		CBS_init(&cipher_suites, ctx->cipher_suites, ctx->cipher_suites_len);

		while (CBS_len(&cipher_suites) != 0) {
			if (!CBS_get_u16(&cipher_suites, &cipher_suite)) {
				goto cleanup;
			}

			cipher = SSL_get_cipher_by_value(cipher_suite);
			if (cipher && SSL_CIPHER_is_ECDSA(cipher)
				&& sk_SSL_CIPHER_find(ctx->ssl->ctx->cipher_list_by_id,
					NULL, cipher)) {
				*sig_algs_end++ = NGX_KEYLESS_SSL_HASH_CIPHER;
				*sig_algs_end++ = TLSEXT_signature_ecdsa;
				break;
			}
		}
	} else if (has_server_name) {
		*sig_algs_end++ = TLSEXT_hash_sha256;
		*sig_algs_end++ = TLSEXT_signature_rsa;
	} else {
		*sig_algs_end++ = TLSEXT_hash_sha1;
		*sig_algs_end++ = TLSEXT_signature_rsa;
	}

	c = ngx_ssl_get_connection(ctx->ssl);

	conn = ngx_pcalloc(c->pool, sizeof(ngx_http_keyless_conn_t));
	if (!conn) {
		goto cleanup;
	}

	if (!SSL_set_ex_data(c->ssl->connection, g_ssl_exdata_conn_index, conn)) {
		goto cleanup;
	}

	conn->op = ngx_http_keyless_start_operation(KSSL_OP_CERTIFICATE_REQUEST, c, conn,
		tmp_sig_algs, sig_algs_end - tmp_sig_algs);
	if (!conn->op) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"ngx_http_keyless_start_operation(KSSL_OP_CERTIFICATE_REQUEST) failed");
		goto cleanup;
	}

	rc = 1;

cleanup:
	if (server_name) {
		ctx->ssl->tlsext_hostname = NULL;
		OPENSSL_free(server_name);
	}

	return rc;
}

static int ngx_http_keyless_cert_cb(ngx_ssl_conn_t *ssl_conn, void *data)
{
	ngx_connection_t *c;
	ngx_http_keyless_conn_t *conn;
	const unsigned char *payload;
	size_t payload_len;
	BIO *bio = NULL;
	X509 *x509;
	EVP_PKEY *public_key = NULL;
	u_long n;

	c = ngx_ssl_get_connection(ssl_conn);

	conn = SSL_get_ex_data(c->ssl->connection, g_ssl_exdata_conn_index);
	if (!conn) {
		return 1;
	}

	switch (ngx_http_keyless_operation_complete(conn->op, &payload, &payload_len)) {
		case ssl_private_key_failure:
			goto error;
		case ssl_private_key_retry:
			return -1;
		case ssl_private_key_success:
			/* KSSL_ERROR_CERT_NOT_FOUND error */
			if (!payload && !payload_len) {
				return 1;
			}

			break;
	}

	bio = BIO_new_mem_buf((unsigned char *)payload, (int)payload_len);
	if (!bio) {
		goto error;
	}

	x509 = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
	if (!x509) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "PEM_read_bio_X509_AUX(...) failed");
		goto error;
	}

	SSL_certs_clear(c->ssl->connection);
	SSL_set_private_key_method(c->ssl->connection, &ngx_http_keyless_key_method);

	if (!SSL_use_certificate(c->ssl->connection, x509)
		/*|| !SSL_set_session_id_context(c->ssl, sid_ctx, sid_ctx_length)*/) {
		X509_free(x509);
		goto error;
	}

	public_key = X509_get_pubkey(x509);
	if (!public_key) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "X509_get_pubkey failed");
		X509_free(x509);
		goto error;
	}

	conn->key.type = EVP_PKEY_id(public_key);
	conn->key.sig_len = EVP_PKEY_size(public_key);

	if (!x509->cert_info
		|| !x509->cert_info->key
		|| !x509->cert_info->key->public_key
		|| !x509->cert_info->key->public_key->length) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "certificate does not contain valid public key");
		X509_free(x509);
		goto error;
	}

	if (!SHA1(x509->cert_info->key->public_key->data,
			x509->cert_info->key->public_key->length, conn->ski)) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "SHA1 failed");
		X509_free(x509);
		goto error;
	}

	switch (conn->key.type) {
		case EVP_PKEY_RSA:
		case EVP_PKEY_EC:
			break;
		default:
			X509_free(x509);
			goto error;
	}

	X509_free(x509);

	while (1) {
		x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (!x509) {
			n = ERR_peek_last_error();

			if (ERR_GET_LIB(n) == ERR_LIB_PEM && ERR_GET_REASON(n) == PEM_R_NO_START_LINE) {
				/* end of file */
				ERR_clear_error();
				break;
			}

			/* some real error */
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "PEM_read_bio_X509(...) failed");
			goto error;
	        }

		if (!SSL_add0_chain_cert(c->ssl->connection, x509)) {
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
				"SSL_add_extra_chain_cert(...) failed");
			goto error;
		}
	}

	BIO_free(bio);
	ngx_http_keyless_cleanup_operation(conn->op);

	return 1;

error:
	if (public_key) {
		EVP_PKEY_free(public_key);
	}

	if (bio) {
		BIO_free(bio);
	}

	ngx_http_keyless_cleanup_operation(conn->op);

	return 0;
}

static ngx_http_keyless_op_t *ngx_http_keyless_start_operation(kssl_opcode_et opcode,
		ngx_connection_t *c, ngx_http_keyless_conn_t *conn, const uint8_t *in,
		size_t in_len)
{
	ngx_http_keyless_srv_conf_t *conf;
	ngx_http_keyless_op_t *op = NULL;
	const struct sockaddr_in *sin;
#if NGX_HAVE_INET6
	const struct sockaddr_in6 *sin6;
#endif
	kssl_header_st header;
	kssl_operation_st operation;
	size_t length;
	ngx_pool_cleanup_t *cln;
	ngx_int_t rc;

	conf = SSL_CTX_get_ex_data(c->ssl->connection->ctx, g_ssl_ctx_exdata_conf_index);
	if (!conf) {
		goto error;
	}

	if (!conf->pc.connection) {
		rc = ngx_event_connect_peer(&conf->pc);
		if (rc == NGX_ERROR || rc == NGX_DECLINED) {
			ngx_log_error(NGX_LOG_EMERG, c->log, 0, "ngx_event_connect_peer failed");
			goto error;
		}

		conf->pc.connection->data = conf;
		conf->pc.connection->pool = conf->pool;
		conf->pc.connection->read->handler = ngx_http_keyless_socket_read_handler;
		conf->pc.connection->write->handler = ngx_http_keyless_socket_write_handler;
	}

	op = ngx_pcalloc(conf->pool, sizeof(ngx_http_keyless_op_t));
	if (!op) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_pcalloc failed");
		goto error;
	}

	op->conf = conf;
	op->ev = c->write;
	op->log = c->log;

	header.version_maj = KSSL_VERSION_MAJ;
	header.version_min = KSSL_VERSION_MIN;

	do {
		op->id = ngx_atomic_fetch_add(&conf->id, 1);
	} while (!op->id);

	header.id = op->id;

	kssl_zero_operation(&operation);

	operation.is_opcode_set = 1;
	operation.opcode = opcode;

	if (conn->key.type) {
		operation.is_ski_set = 1;
		operation.ski = conn->ski;
	}

	operation.sni = (const unsigned char *)SSL_get_servername(c->ssl->connection,
		TLSEXT_NAMETYPE_host_name);
	if (operation.sni) {
		operation.is_sni_set = 1;
		operation.sni_len = ngx_strlen(operation.sni);
	}

	if (opcode == KSSL_OP_CERTIFICATE_REQUEST) {
		operation.is_sig_algs_set = 1;
		operation.sig_algs_len = in_len;
		operation.sig_algs = in;
	} else {
		operation.is_payload_set = 1;
		operation.payload_len = in_len;
		operation.payload = in;
	}

	switch (c->sockaddr->sa_family) {
#if NGX_HAVE_INET6
		case AF_INET6:
			sin6 = (const struct sockaddr_in6 *)c->sockaddr;

			operation.is_client_ip_set = 1;
			operation.client_ip_len = 16;
			operation.client_ip = (const unsigned char *)&sin6->sin6_addr.s6_addr[0];
			break;
#endif /* NGX_HAVE_INET6 */
		case AF_INET:
			sin = (const struct sockaddr_in *)c->sockaddr;

			operation.is_client_ip_set = 1;
			operation.client_ip_len = 4;
			operation.client_ip = (const unsigned char *)&sin->sin_addr.s_addr;
			break;
	}

	if (ngx_connection_local_sockaddr(c, NULL, 0) == NGX_OK) {
		switch (c->local_sockaddr->sa_family) {
#if NGX_HAVE_INET6
			case AF_INET6:
				sin6 = (const struct sockaddr_in6 *)c->local_sockaddr;

				operation.is_server_ip_set = 1;
				operation.server_ip_len = 16;
				operation.server_ip
					= (const unsigned char *)&sin6->sin6_addr.s6_addr[0];
				break;
#endif /* NGX_HAVE_INET6 */
			case AF_INET:
				sin = (const struct sockaddr_in *)c->local_sockaddr;

				operation.is_server_ip_set = 1;
				operation.server_ip_len = 4;
				operation.server_ip = (const unsigned char *)&sin->sin_addr.s_addr;
				break;
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_connection_local_sockaddr failed");
	}

	length = kssl_flatten_operation(&header, &operation, NULL);
	if (!length) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "kssl_flatten_operation failed");
		goto error;
	}

	op->send.start = ngx_palloc(conf->pool, length);
	if (!op->send.start) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"ngx_palloc failed to allocated recv buffer");
		goto error;
	}

	op->send.pos = op->send.start;
	op->send.last = op->send.start + length;
	op->send.end = op->send.start + length;

	if (!kssl_flatten_operation(&header, &operation, op->send.pos)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "kssl_flatten_operation failed");
		goto error;
	}

	op->timer.handler = ngx_http_keyless_operation_timeout_handler;
	op->timer.data = c->write;
	op->timer.log = c->log;

	cln = ngx_pool_cleanup_add(c->pool, 0);
	if (!cln) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_pool_cleanup_add failed");
		goto error;
	}

	cln->handler = ngx_http_keyless_cleanup_timer_handler;
	cln->data = &op->timer;

	ngx_add_timer(&op->timer, 250);

	ngx_queue_insert_tail(&conf->recv_ops, &op->recv_queue);
	ngx_queue_insert_tail(&conf->send_ops, &op->send_queue);

	conf->pc.connection->write->handler(conf->pc.connection->write);

	return op;

error:
	if (op) {
		if (op->send.start) {
			OPENSSL_cleanse(op->send.start, op->send.end - op->send.start);
			ngx_pfree(conf->pool, op->send.start);
		}

		ngx_pfree(conf->pool, op);
	}

	return NULL;
}

static enum ssl_private_key_result_t ngx_http_keyless_operation_complete(ngx_http_keyless_op_t *op,
		const uint8_t **out, size_t *out_len)
{
	kssl_header_st header;
	kssl_operation_st operation;

	if (op->recv.last - op->recv.pos < (ssize_t)KSSL_HEADER_SIZE) {
		if (op->timer.timedout) {
			ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless operation timed out");
			return ssl_private_key_failure;
		}

		return ssl_private_key_retry;
	}

	assert(kssl_parse_header(op->recv.pos, &header));
	assert(header.version_maj == KSSL_VERSION_MAJ);
	assert(header.id == op->id);

	op->recv.pos += KSSL_HEADER_SIZE;

	if (!kssl_parse_message_payload(op->recv.pos, header.length, &operation)) {
		ngx_log_error(NGX_LOG_ERR, op->log, 0, "kssl_parse_message_payload failed");
		return ssl_private_key_failure;
	}

	op->recv.pos += header.length;

	if (op->recv.last - op->recv.pos != 0) {
		ngx_log_error(NGX_LOG_ERR, op->log, 0, "trailing data recieved");
	}

	switch (operation.opcode) {
		case KSSL_OP_RESPONSE:
			*out = operation.payload;
			*out_len = operation.payload_len;

			return ssl_private_key_success;
		case KSSL_OP_ERROR:
			if (operation.payload_len == 1) {
				ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless error: %s",
					kssl_error_string(operation.payload[0]));

				if (operation.payload[0] == KSSL_ERROR_CERT_NOT_FOUND) {
					*out = NULL;
					*out_len = 0;

					return ssl_private_key_success;
				}
			} else {
				ngx_log_error(NGX_LOG_ERR, op->log, 0, "unkown keyless error");
			}

			return ssl_private_key_failure;
		case KSSL_OP_RSA_DECRYPT:
		case KSSL_OP_RSA_DECRYPT_RAW:
		case KSSL_OP_RSA_SIGN_MD5SHA1:
		case KSSL_OP_RSA_SIGN_SHA1:
		case KSSL_OP_RSA_SIGN_SHA224:
		case KSSL_OP_RSA_SIGN_SHA256:
		case KSSL_OP_RSA_SIGN_SHA384:
		case KSSL_OP_RSA_SIGN_SHA512:
		case KSSL_OP_ECDSA_SIGN_MD5SHA1:
		case KSSL_OP_ECDSA_SIGN_SHA1:
		case KSSL_OP_ECDSA_SIGN_SHA224:
		case KSSL_OP_ECDSA_SIGN_SHA256:
		case KSSL_OP_ECDSA_SIGN_SHA384:
		case KSSL_OP_ECDSA_SIGN_SHA512:
		case KSSL_OP_CERTIFICATE_REQUEST:
		case KSSL_OP_PING:
		case KSSL_OP_PONG:
		case KSSL_OP_ACTIVATE:
			ngx_log_error(NGX_LOG_ERR, op->log, 0,
				kssl_error_string(KSSL_ERROR_UNEXPECTED_OPCODE));
			return ssl_private_key_failure;
		default:
			ngx_log_error(NGX_LOG_ERR, op->log, 0,
				kssl_error_string(KSSL_ERROR_BAD_OPCODE));
			return ssl_private_key_failure;
	}
}

static void ngx_http_keyless_cleanup_operation(ngx_http_keyless_op_t *op)
{
	if (op->recv.start) {
		OPENSSL_cleanse(op->recv.start, op->recv.end - op->recv.start);
		ngx_pfree(op->conf->pool, op->recv.start);

		op->recv.start = NULL;
		op->recv.pos = NULL;
		op->recv.last = NULL;
		op->recv.end = NULL;
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
	kssl_header_st header;
	ssize_t size;

	c = rev->data;
	conf = c->data;

	recv.start = ngx_palloc(c->pool, NGX_HTTP_KEYLESS_OP_BUFFER_SIZE);
	if (!recv.start) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"ngx_palloc failed to allocated recv buffer");
		return;
	}

	recv.pos = recv.start;
	recv.last = recv.start;
	recv.end = recv.start + NGX_HTTP_KEYLESS_OP_BUFFER_SIZE;

	size = c->recv(c, recv.last, recv.end - recv.last);
	if (size > 0) {
		recv.last += size;
	} else if (size == 0 || size == NGX_AGAIN) {
		goto cleanup;
	} else {
		c->error = 1;
		goto cleanup;
	}

	if (recv.last - recv.pos < (ssize_t)KSSL_HEADER_SIZE) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "truncated packet");
		goto cleanup;
	}

	if (!kssl_parse_header(recv.pos, &header)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "kssl_parse_header failed");
		goto cleanup;
	}

	if (header.version_maj != KSSL_VERSION_MAJ) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			kssl_error_string(KSSL_ERROR_VERSION_MISMATCH));
		goto cleanup;
	}

	for (q = ngx_queue_head(&conf->recv_ops);
		q != ngx_queue_sentinel(&conf->recv_ops);
		q = ngx_queue_next(q)) {
		op = ngx_queue_data(q, ngx_http_keyless_op_t, recv_queue);

		if (op->id != header.id) {
			continue;
		}

		ngx_queue_remove(&op->recv_queue);

		op->recv = recv;

		ngx_post_event(op->ev, &ngx_posted_events);
		return;
	}

	ngx_log_error(NGX_LOG_ERR, c->log, 0, "invalid header id: %ud", header.id);

cleanup:
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

	if (ngx_queue_empty(&conf->send_ops)) {
		return;
	}

	q = ngx_queue_head(&conf->send_ops);
	op = ngx_queue_data(q, ngx_http_keyless_op_t, send_queue);

	size = c->send(c, op->send.pos, op->send.last - op->send.pos);
	if (size > 0) {
		op->send.pos += size;
	} else if (size == 0 || size == NGX_AGAIN) {
		return;
	} else {
		c->error = 1;
		return;
	}

	ngx_queue_remove(&op->send_queue);

	if (op->send.pos != op->send.last) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "keyless send truncated");
	} else {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "keyless send done");
	}

	OPENSSL_cleanse(op->send.start, op->send.end - op->send.start);
	ngx_pfree(c->pool, op->send.start);

	op->send.start = NULL;
	op->send.pos = NULL;
	op->send.last = NULL;
	op->send.end = NULL;
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

static int ngx_http_keyless_key_type(ngx_ssl_conn_t *ssl_conn)
{
	const ngx_connection_t *c;
	const ngx_http_keyless_conn_t *conn;

	c = ngx_ssl_get_connection(ssl_conn);

	conn = SSL_get_ex_data(c->ssl->connection, g_ssl_exdata_conn_index);
	if (!conn) {
		return 1;
	}

	return conn->key.type;
}

static size_t ngx_http_keyless_key_max_signature_len(ngx_ssl_conn_t *ssl_conn)
{
	const ngx_connection_t *c;
	const ngx_http_keyless_conn_t *conn;

	c = ngx_ssl_get_connection(ssl_conn);

	conn = SSL_get_ex_data(c->ssl->connection, g_ssl_exdata_conn_index);
	if (!conn) {
		return 1;
	}

	return conn->key.sig_len;
}

static enum ssl_private_key_result_t ngx_http_keyless_key_sign(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out, const EVP_MD *md, const uint8_t *in,
		size_t in_len)
{
	kssl_opcode_et opcode;
	ngx_connection_t *c;
	ngx_http_keyless_conn_t *conn;

	switch (EVP_MD_type(md)) {
		case NID_sha1:
			opcode = KSSL_OP_RSA_SIGN_SHA1;
			break;
		case NID_sha224:
			opcode = KSSL_OP_RSA_SIGN_SHA224;
			break;
		case NID_sha256:
			opcode = KSSL_OP_RSA_SIGN_SHA256;
			break;
		case NID_sha384:
			opcode = KSSL_OP_RSA_SIGN_SHA384;
			break;
		case NID_sha512:
			opcode = KSSL_OP_RSA_SIGN_SHA512;
			break;
		case NID_md5_sha1:
			opcode = KSSL_OP_RSA_SIGN_MD5SHA1;
			break;
		default:
			return ssl_private_key_failure;
	}

	c = ngx_ssl_get_connection(ssl_conn);

	conn = SSL_get_ex_data(c->ssl->connection, g_ssl_exdata_conn_index);
	if (!conn) {
		return ssl_private_key_failure;
	}

	if (conn->key.type == EVP_PKEY_EC) {
		opcode |= KSSL_OP_ECDSA_MASK;
	}

	conn->op = ngx_http_keyless_start_operation(opcode, c, conn, in, in_len);
	if (!conn->op) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"ngx_http_keyless_start_operation(%s) failed", kssl_op_string(opcode));
		return ssl_private_key_failure;
	}

	return ssl_private_key_retry;
}

static enum ssl_private_key_result_t ngx_http_keyless_key_decrypt(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len)
{
	ngx_connection_t *c;
	ngx_http_keyless_conn_t *conn;

	c = ngx_ssl_get_connection(ssl_conn);

	conn = SSL_get_ex_data(c->ssl->connection, g_ssl_exdata_conn_index);
	if (!conn) {
		return ssl_private_key_failure;
	}

	conn->op = ngx_http_keyless_start_operation(KSSL_OP_RSA_DECRYPT_RAW, c, conn, in, in_len);
	if (!conn->op) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"ngx_http_keyless_start_operation(KSSL_OP_RSA_DECRYPT_RAW) failed");
		return ssl_private_key_failure;
	}

	return ssl_private_key_retry;
}

static enum ssl_private_key_result_t ngx_http_keyless_key_complete(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out)
{
	const ngx_connection_t *c;
	const ngx_http_keyless_conn_t *conn;
	const uint8_t *tmp;
	size_t tmp_len;
	enum ssl_private_key_result_t rc;

	c = ngx_ssl_get_connection(ssl_conn);

	conn = SSL_get_ex_data(c->ssl->connection, g_ssl_exdata_conn_index);
	if (!conn) {
		return ssl_private_key_failure;
	}

	rc = ngx_http_keyless_operation_complete(conn->op, &tmp, &tmp_len);
	if (rc == ssl_private_key_retry) {
		return rc;
	}

	if (rc == ssl_private_key_success) {
		if (tmp_len > max_out) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "payload longer than max_out");
		} else {
			ngx_memcpy(out, tmp, tmp_len);
			*out_len = tmp_len;
		}
	}

	ngx_http_keyless_cleanup_operation(conn->op);

	return rc;
}
