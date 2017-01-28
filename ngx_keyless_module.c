#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_event.h>

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#define NGX_HTTP_KEYLESS_OP_BUFFER_SIZE 2*1024

#define NGX_HTTP_KEYLESS_VERSION_MAJOR 2
#define NGX_HTTP_KEYLESS_VERSION_MINOR 0

#define NGX_HTTP_KEYLESS_HEADER_LENGTH 8

#define NGX_HTTP_KEYLESS_PAD_TO 1024

enum {
	// The range [0x0000, 0x0100) is for tags taken from Cloudflare's upstream.
	// [Deprecated]: SHA256 hash of RSA public key
	NGX_HTTP_KEYLESS_TAG_DIGEST    = 0x0001,
	// Server Name Identifier
	NGX_HTTP_KEYLESS_TAG_SNI       = 0x0002,
	// Client IP Address
	NGX_HTTP_KEYLESS_TAG_CLIENT_IP = 0x0003,
	// SHA1 hash of Subject Key Info
	NGX_HTTP_KEYLESS_TAG_SKI       = 0x0004,
	// Server IP Address
	NGX_HTTP_KEYLESS_TAG_SERVER_IP = 0x0005,
	// Signature Algorithms
	NGX_HTTP_KEYLESS_TAG_SIG_ALGS  = 0x0006,
	// Request operation code (see ngx_http_keyless_operation_t)
	NGX_HTTP_KEYLESS_TAG_OPCODE    = 0x0011,
	// Request payload
	NGX_HTTP_KEYLESS_TAG_PAYLOAD   = 0x0012,
	// Padding
	NGX_HTTP_KEYLESS_TAG_PADDING   = 0x0020,

	// The range [0x0100, 0xc000) is for tags from our protocol version.
	// The stapled OCSP response
	NGX_HTTP_KEYLESS_TAG_OCSP_RESPONSE = 0x0101,
	// The request authorisation
	NGX_HTTP_KEYLESS_TAG_AUTHORISATION = 0x0102,

	// The range [0xc000, 0xffff) is reserved for private tags.
	// One iff ECDSA ciphers are supported
	NGX_HTTP_KEYLESS_TAG_ECDSA_CIPHER = 0xc001,
};

typedef enum {
	// The range [0x0000, 0x0100) is for opcodes taken from Cloudflare's upstream.

	// Decrypt data using RSA with or without padding
	NGX_HTTP_KEYLESS_OP_RSA_DECRYPT     = 0x0001,
	NGX_HTTP_KEYLESS_OP_RSA_DECRYPT_RAW = 0x0008,

	// Sign data using RSA
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_MD5SHA1 = 0x0002,
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA1    = 0x0003,
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA224  = 0x0004,
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA256  = 0x0005,
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA384  = 0x0006,
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA512  = 0x0007,

	// Sign data using RSA-PSS
#define NGX_HTTP_KEYLESS_OP_RSA_PSS_MASK          0x0030
	NGX_HTTP_KEYLESS_OP_RSA_PSS_SIGN_SHA256 = 0x0035,
	NGX_HTTP_KEYLESS_OP_RSA_PSS_SIGN_SHA384 = 0x0036,
	NGX_HTTP_KEYLESS_OP_RSA_PSS_SIGN_SHA512 = 0x0037,

	// Sign data using ECDSA
#define NGX_HTTP_KEYLESS_OP_ECDSA_MASK           0x0010
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_MD5SHA1 = 0x0012,
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA1    = 0x0013,
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA224  = 0x0014,
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA256  = 0x0015,
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA384  = 0x0016,
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA512  = 0x0017,

	// Request a certificate and chain
	NGX_HTTP_KEYLESS_OP_GET_CERTIFICATE = 0x0020,

	// [Deprecated]: A test message
	NGX_HTTP_KEYLESS_OP_PING = 0x00F1,
	NGX_HTTP_KEYLESS_OP_PONG = 0x00F2,

	// [Deprecated]: A verification message
	NGX_HTTP_KEYLESS_OP_ACTIVATE = 0x00F3,

	// Response
	NGX_HTTP_KEYLESS_OP_RESPONSE = 0x00F0,
	NGX_HTTP_KEYLESS_OP_ERROR    = 0x00FF,

	// The range [0x0100, 0xc000) is for opcodes from our protocol version.
	NGX_HTTP_KEYLESS_OP_ED25519_SIGN = 0x0101, // Sign data using Ed25519

	// The range [0xc000, 0xffff) is reserved for private opcodes.
} ngx_http_keyless_operation_t;

typedef enum {
	// The range [0x0000, 0x0100) is for errors taken from Cloudflare's upstream.
	// No error
	NGX_HTTP_KEYLESS_ERROR_NONE              = 0x0000,
	// Cryptographic error
	NGX_HTTP_KEYLESS_ERROR_CRYPTO_FAILED     = 0x0001,
	// Private key not found
	NGX_HTTP_KEYLESS_ERROR_KEY_NOT_FOUND     = 0x0002,
	// [Deprecated]: Disk read failure
	NGX_HTTP_KEYLESS_ERROR_DISK_READ         = 0x0003,
	// Client-Server version mismatch
	NGX_HTTP_KEYLESS_ERROR_VERSION_MISMATCH  = 0x0004,
	// Invalid/unsupported opcode
	NGX_HTTP_KEYLESS_ERROR_BAD_OPCODE        = 0x0005,
	// Opcode sent at wrong time/direction
	NGX_HTTP_KEYLESS_ERROR_UNEXPECTED_OPCODE = 0x0006,
	// Malformed message
	NGX_HTTP_KEYLESS_ERROR_FORMAT            = 0x0007,
	// Other internal error
	NGX_HTTP_KEYLESS_ERROR_INTERNAL          = 0x0008,
	// Certificate not found
	NGX_HTTP_KEYLESS_ERROR_CERT_NOT_FOUND    = 0x0009,

	// The range [0x0100, 0xc000) is for errors from our protocol version.
	// The client was not authorised to perform that request.
	NGX_HTTP_KEYLESS_ERROR_NOT_AUTHORISED = 0x0101,

	// The range [0xc000, 0xffff) is reserved for private errors.
} ngx_http_keyless_error_t;

typedef struct {
	ngx_str_t address;
	ngx_msec_t timeout;
	ngx_flag_t fallback;

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
	ngx_pool_cleanup_t *cln;

	unsigned int id;

	ngx_http_keyless_error_t error;
	const uint8_t *ski;

	const uint8_t *ocsp_response;
	size_t ocsp_response_length;

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

	unsigned char ski[SHA_DIGEST_LENGTH];

	struct {
		uint8_t *sig_algs;
		size_t sig_algs_len;

		uint8_t ecdsa_cipher;
	} get_cert;
} ngx_http_keyless_conn_t;

static void *ngx_http_keyless_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_keyless_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static int ngx_http_keyless_select_certificate_cb(const SSL_CLIENT_HELLO *client_hello);
static int ngx_http_keyless_cert_cb(ngx_ssl_conn_t *ssl_conn, void *data);

static ngx_http_keyless_op_t *ngx_http_keyless_start_operation(ngx_http_keyless_operation_t opcode,
		ngx_connection_t *c, ngx_http_keyless_conn_t *conn, const uint8_t *in,
		size_t in_len);
static enum ssl_private_key_result_t ngx_http_keyless_operation_complete(ngx_http_keyless_op_t *op,
		CBS *out);
static void ngx_http_keyless_cleanup_operation(ngx_http_keyless_op_t *op);

static void ngx_http_keyless_socket_read_handler(ngx_event_t *rev);
static void ngx_http_keyless_socket_write_handler(ngx_event_t *wev);

static void ngx_http_keyless_operation_timeout_handler(ngx_event_t *ev);
static void ngx_http_keyless_cleanup_timer_handler(void *data);

static int ngx_http_keyless_key_type(ngx_ssl_conn_t *ssl_conn);
static size_t ngx_http_keyless_key_max_signature_len(ngx_ssl_conn_t *ssl_conn);
static enum ssl_private_key_result_t ngx_http_keyless_key_sign(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out, uint16_t signature_algorithm,
		const uint8_t *in, size_t in_len);
static enum ssl_private_key_result_t ngx_http_keyless_key_decrypt(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len);
static enum ssl_private_key_result_t ngx_http_keyless_key_complete(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out);

static const char *ngx_http_keyless_error_string(ngx_http_keyless_error_t error);

/* this is ssl_cert_parse_pubkey & ssl_cert_skip_to_spki from boringssl-f71036e/ssl/ssl_cert.c */
static EVP_PKEY *ngx_http_keyless_ssl_cert_parse_pubkey(const CBS *in);

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
static int g_ssl_exdata_conn_index = -1;

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
		ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "SSL_CTX_set_ex_data failed");
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
	if (!conn || !SSL_set_ex_data(c->ssl->connection, g_ssl_exdata_conn_index, conn)) {
		return -1;
	}

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
	int ret = 0, had_leaf = 0;
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

	conn = SSL_get_ex_data(ssl, g_ssl_exdata_conn_index);
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
				"ngx_http_keyless_start_operation(NGX_HTTP_KEYLESS_OP_GET_CERTIFICATE)"
				" failed");
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
				goto error;
			}

			goto error;
		case ssl_private_key_retry:
			return -1;
		case ssl_private_key_success:
			break;
	}

	if (CBS_len(&payload) == 0 || !conn->op->ski) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"get certificate format erorr");
		goto error;
	}

	ngx_memcpy(conn->ski, conn->op->ski, SHA_DIGEST_LENGTH);

	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, ngx_http_keyless_sess_id_ctx.data,
		ngx_http_keyless_sess_id_ctx.len);
	SHA256_Update(&sha_ctx, CBS_data(&payload), CBS_len(&payload));
	SHA256_Final(sid_ctx, &sha_ctx);

	if (!SSL_set_session_id_context(ssl, sid_ctx, 16)) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "SSL_set_session_id_context() failed");
		goto error;
	}

	if (conn->op->ocsp_response && !SSL_set_ocsp_response(ssl,
			conn->op->ocsp_response, conn->op->ocsp_response_length)) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"SSL_set_ocsp_response(...) failed");
		goto error;
	}

	SSL_certs_clear(ssl);
	SSL_set_private_key_method(ssl, &ngx_http_keyless_key_method);

	while (CBS_len(&payload) != 0) {
		if (!CBS_get_u16_length_prefixed(&payload, &child)) {
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "get certificate format erorr");
			goto error;
		}

		if (!had_leaf) {
			if (!SSL_use_raw_certificate(ssl, CBS_data(&child), CBS_len(&child))) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"SSL_use_raw_certificate(...) failed");
				goto error;
			}

			public_key = ngx_http_keyless_ssl_cert_parse_pubkey(&child);
			if (!public_key) {
				ngx_log_error(NGX_LOG_EMERG, c->log, 0,
					"ngx_http_keyless_ssl_cert_parse_pubkey failed");
				goto error;
			}

			had_leaf = 1;
			continue;
		}

		if (!SSL_add_raw_chain_cert(ssl, CBS_data(&child), CBS_len(&child))) {
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
				"SSL_add_raw_chain_cert(...) failed");
			goto error;
		}
	}

	switch (EVP_PKEY_id(public_key)) {
		case EVP_PKEY_RSA:
			conn->key.type = NID_rsaEncryption;
			break;
		case EVP_PKEY_EC:
			conn->key.type = EC_GROUP_get_curve_name(EC_KEY_get0_group(
				EVP_PKEY_get0_EC_KEY(public_key)));
			break;
		default:
			ngx_log_error(NGX_LOG_EMERG, c->log, 0,
				"certificate does not contain a supported key type");
			goto error;
	}

	conn->key.sig_len = EVP_PKEY_size(public_key);

	ret = 1;

error:
	if (ret == 0) {
		ERR_clear_error();
	}

	EVP_PKEY_free(public_key);
	ngx_http_keyless_cleanup_operation(conn->op);
	return ret;
}

static ngx_http_keyless_op_t *ngx_http_keyless_start_operation(ngx_http_keyless_operation_t opcode,
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
	size_t len, ip_len;
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

	do {
		op->id = ngx_atomic_fetch_add(&conf->id, 1);
	} while (!op->id);

	if (!CBB_init(&payload, NGX_HTTP_KEYLESS_HEADER_LENGTH + NGX_HTTP_KEYLESS_PAD_TO + 4)
		// header
		|| !CBB_add_u8(&payload, NGX_HTTP_KEYLESS_VERSION_MAJOR)
		|| !CBB_add_u8(&payload, NGX_HTTP_KEYLESS_VERSION_MINOR)
		|| !CBB_add_u16(&payload, 0) // length placeholder
		|| !CBB_add_u32(&payload, op->id)
		// opcode tag
		|| !CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_OPCODE)
		|| !CBB_add_u16_length_prefixed(&payload, &child)
		|| !CBB_add_u16(&child, opcode)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
		goto error;
	}

	if (conn->key.type
		// ski tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_SKI)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_bytes(&child, conn->ski, SHA_DIGEST_LENGTH))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
		goto error;
	}

	sni = (const uint8_t *)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (sni // sni tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_SNI)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_bytes(&child, sni, ngx_strlen(sni)))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
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
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
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
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
			goto error;
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_connection_local_sockaddr failed");
	}

	if (conn->get_cert.sig_algs
		// sig algs tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_SIG_ALGS)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_bytes(&child, conn->get_cert.sig_algs,
				conn->get_cert.sig_algs_len))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
		goto error;
	}

	if (conn->get_cert.ecdsa_cipher
		// ecdsa cipher tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_ECDSA_CIPHER)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_u8(&child, conn->get_cert.ecdsa_cipher))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
		goto error;
	}

	if (in // payload tag
		&& (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_PAYLOAD)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_bytes(&child, in, in_len))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
		goto error;
	}

	if (!CBB_flush(&payload)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_flush failed");
		goto error;
	}

	len = CBB_len(&payload) - NGX_HTTP_KEYLESS_HEADER_LENGTH;
	if (len < NGX_HTTP_KEYLESS_PAD_TO) {
		// padding tag
		if (!CBB_add_u16(&payload, NGX_HTTP_KEYLESS_TAG_PADDING)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_space(&child, &p, NGX_HTTP_KEYLESS_PAD_TO - len)) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
			goto error;
		}

		ngx_memzero(p, NGX_HTTP_KEYLESS_PAD_TO - len);
	}

	if (!CBB_finish(&payload, &p, &len)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_finish failed");
		goto error;
	}

	if (len - NGX_HTTP_KEYLESS_HEADER_LENGTH > UINT16_MAX) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "body too large to encode length");
		goto error;
	}

	*(uint16_t *)(p + 2) = htons(len - NGX_HTTP_KEYLESS_HEADER_LENGTH); // set length

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
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_pool_cleanup_add failed");
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

static enum ssl_private_key_result_t ngx_http_keyless_operation_complete(ngx_http_keyless_op_t *op,
		CBS *out)
{
	ngx_http_keyless_operation_t opcode = 0;
	uint16_t tag;
	CBS msg, child, payload;
	int saw_opcode = 0, saw_payload = 0, saw_padding = 0, saw_authorisation = 0;

	if (op->recv.last - op->recv.pos < NGX_HTTP_KEYLESS_HEADER_LENGTH) {
		if (op->timer.timedout) {
			ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless operation timed out");
			return ssl_private_key_failure;
		}

		return ssl_private_key_retry;
	}

	CBS_init(&msg, op->recv.pos, op->recv.last - op->recv.pos);

	if (!CBS_skip(&msg, NGX_HTTP_KEYLESS_HEADER_LENGTH)) {
		ngx_log_error(NGX_LOG_ERR, op->log, 0, "CBS_skip failed");
		return ssl_private_key_failure;
	}

	while (CBS_len(&msg) != 0) {
		if (!CBS_get_u16(&msg, &tag)
			|| !CBS_get_u16_length_prefixed(&msg, &child)) {
			ngx_log_error(NGX_LOG_ERR, op->log, 0, "CBS_* failed");
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
					ngx_log_error(NGX_LOG_ERR, op->log, 0, "CBS_* failed");
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
			case NGX_HTTP_KEYLESS_TAG_PADDING:
				if (saw_padding) {
					ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
						ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_FORMAT));
					return ssl_private_key_failure;
				}

				saw_padding = 1;
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
			case NGX_HTTP_KEYLESS_TAG_AUTHORISATION:
				if (saw_authorisation) {
					ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
						ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_FORMAT));
					return ssl_private_key_failure;
				}

				saw_authorisation = 1;
				break;
			case NGX_HTTP_KEYLESS_TAG_DIGEST:
			case NGX_HTTP_KEYLESS_TAG_SNI:
			case NGX_HTTP_KEYLESS_TAG_CLIENT_IP:
			case NGX_HTTP_KEYLESS_TAG_SERVER_IP:
			case NGX_HTTP_KEYLESS_TAG_SIG_ALGS:
			case NGX_HTTP_KEYLESS_TAG_ECDSA_CIPHER:
				ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless: unexpected tag");
				return ssl_private_key_failure;
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
				ngx_log_error(NGX_LOG_ERR, op->log, 0, "CBS_* failed");
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

static void ngx_http_keyless_cleanup_operation(ngx_http_keyless_op_t *op)
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
	ssize_t size;
	CBS payload;
	uint8_t vers;
	uint16_t length;
	uint32_t id;

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

	if (recv.last - recv.pos < NGX_HTTP_KEYLESS_HEADER_LENGTH) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "truncated packet");
		goto cleanup;
	}

	CBS_init(&payload, recv.pos, recv.last - recv.pos);

	if (!CBS_get_u8(&payload, &vers)
		|| vers != NGX_HTTP_KEYLESS_VERSION_MAJOR
		|| !CBS_skip(&payload, 1)
		|| !CBS_get_u16(&payload, &length)
		|| !CBS_get_u32(&payload, &id)
		|| length != CBS_len(&payload)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBS_* failed or format error");
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
	OPENSSL_free(op->send.start);

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
		return NID_undef;
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
		return 0;
	}

	return conn->key.sig_len;
}

static enum ssl_private_key_result_t ngx_http_keyless_key_sign(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out, uint16_t signature_algorithm,
		const uint8_t *in, size_t in_len)
{
	ngx_http_keyless_operation_t opcode;
	ngx_connection_t *c;
	ngx_http_keyless_conn_t *conn;
	const EVP_MD *md;
	uint8_t hash[EVP_MAX_MD_SIZE];
	unsigned hash_len;

	switch (signature_algorithm) {
		case SSL_SIGN_RSA_PKCS1_MD5_SHA1:
			opcode = NGX_HTTP_KEYLESS_OP_RSA_SIGN_MD5SHA1;
			md = EVP_md5_sha1();
			break;
		case SSL_SIGN_RSA_PKCS1_SHA1:
		case SSL_SIGN_ECDSA_SHA1:
			opcode = NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA1;
			md = EVP_sha1();
			break;
		case SSL_SIGN_RSA_PKCS1_SHA256:
		case SSL_SIGN_ECDSA_SECP256R1_SHA256:
		case SSL_SIGN_RSA_PSS_SHA256:
			opcode = NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA256;
			md = EVP_sha256();
			break;
		case SSL_SIGN_RSA_PKCS1_SHA384:
		case SSL_SIGN_ECDSA_SECP384R1_SHA384:
		case SSL_SIGN_RSA_PSS_SHA384:
			opcode = NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA384;
			md = EVP_sha384();
			break;
		case SSL_SIGN_RSA_PKCS1_SHA512:
		case SSL_SIGN_ECDSA_SECP521R1_SHA512:
		case SSL_SIGN_RSA_PSS_SHA512:
			opcode = NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA512;
			md = EVP_sha512();
			break;
		default:
			return ssl_private_key_failure;
	}

	switch (signature_algorithm) {
		case SSL_SIGN_ECDSA_SHA1:
		case SSL_SIGN_ECDSA_SECP256R1_SHA256:
		case SSL_SIGN_ECDSA_SECP384R1_SHA384:
		case SSL_SIGN_ECDSA_SECP521R1_SHA512:
			opcode |= NGX_HTTP_KEYLESS_OP_ECDSA_MASK;
			break;
		case SSL_SIGN_RSA_PSS_SHA256:
		case SSL_SIGN_RSA_PSS_SHA384:
		case SSL_SIGN_RSA_PSS_SHA512:
			opcode |= NGX_HTTP_KEYLESS_OP_RSA_PSS_MASK;
			break;
	}

	c = ngx_ssl_get_connection(ssl_conn);

	conn = SSL_get_ex_data(c->ssl->connection, g_ssl_exdata_conn_index);
	if (!conn) {
		return ssl_private_key_failure;
	}

	if (!EVP_Digest(in, in_len, hash, &hash_len, md, NULL)) {
		return ssl_private_key_failure;
	}

	conn->op = ngx_http_keyless_start_operation(opcode, c, conn, hash, hash_len);
	if (!conn->op) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"ngx_http_keyless_start_operation(...) failed");
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

	conn->op = ngx_http_keyless_start_operation(NGX_HTTP_KEYLESS_OP_RSA_DECRYPT_RAW, c, conn,
		in, in_len);
	if (!conn->op) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"ngx_http_keyless_start_operation(...) failed");
		return ssl_private_key_failure;
	}

	return ssl_private_key_retry;
}

static enum ssl_private_key_result_t ngx_http_keyless_key_complete(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out)
{
	const ngx_connection_t *c;
	const ngx_http_keyless_conn_t *conn;
	CBS payload;
	enum ssl_private_key_result_t rc;

	c = ngx_ssl_get_connection(ssl_conn);

	conn = SSL_get_ex_data(c->ssl->connection, g_ssl_exdata_conn_index);
	if (!conn) {
		return ssl_private_key_failure;
	}

	rc = ngx_http_keyless_operation_complete(conn->op, &payload);
	if (rc == ssl_private_key_retry) {
		return ssl_private_key_retry;
	}

	if (rc == ssl_private_key_success) {
		*out_len = CBS_len(&payload);

		if (CBS_len(&payload) > max_out) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "payload longer than max_out");
			rc = ssl_private_key_failure;
		} else if (!CBS_copy_bytes(&payload, out, CBS_len(&payload))) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBS_copy_bytes failed");
			rc = ssl_private_key_failure;
		}
	}

	ngx_http_keyless_cleanup_operation(conn->op);
	return rc;
}

static const char *ngx_http_keyless_error_string(ngx_http_keyless_error_t error)
{
	switch (error) {
		case NGX_HTTP_KEYLESS_ERROR_NONE:
			return "no error";
		case NGX_HTTP_KEYLESS_ERROR_CRYPTO_FAILED:
			return "cryptography error";
		case NGX_HTTP_KEYLESS_ERROR_KEY_NOT_FOUND:
			return "key not found";
		case NGX_HTTP_KEYLESS_ERROR_DISK_READ:
			return "disk read failure";
		case NGX_HTTP_KEYLESS_ERROR_VERSION_MISMATCH:
			return "version mismatch";
		case NGX_HTTP_KEYLESS_ERROR_BAD_OPCODE:
			return "bad opcode";
		case NGX_HTTP_KEYLESS_ERROR_UNEXPECTED_OPCODE:
			return "unexpected opcode";
		case NGX_HTTP_KEYLESS_ERROR_FORMAT:
			return "malformed message";
		case NGX_HTTP_KEYLESS_ERROR_INTERNAL:
			return "internal error";
		case NGX_HTTP_KEYLESS_ERROR_CERT_NOT_FOUND:
			return "certificate not found";
		case NGX_HTTP_KEYLESS_ERROR_NOT_AUTHORISED:
			return "client not authorised";
		default:
			return "unknown error";
	}
}

/* this is ssl_cert_parse_pubkey & ssl_cert_skip_to_spki from boringssl-f71036e/ssl/ssl_cert.c */
static EVP_PKEY *ngx_http_keyless_ssl_cert_parse_pubkey(const CBS *in) {
  CBS buf = *in, toplevel, tbs_cert;
  if (!CBS_get_asn1(&buf, &toplevel, CBS_ASN1_SEQUENCE) ||
      CBS_len(&buf) != 0 ||
      !CBS_get_asn1(&toplevel, &tbs_cert, CBS_ASN1_SEQUENCE) ||
      /* version */
      !CBS_get_optional_asn1(
          &tbs_cert, NULL, NULL,
          CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 0) ||
      /* serialNumber */
      !CBS_get_asn1(&tbs_cert, NULL, CBS_ASN1_INTEGER) ||
      /* signature algorithm */
      !CBS_get_asn1(&tbs_cert, NULL, CBS_ASN1_SEQUENCE) ||
      /* issuer */
      !CBS_get_asn1(&tbs_cert, NULL, CBS_ASN1_SEQUENCE) ||
      /* validity */
      !CBS_get_asn1(&tbs_cert, NULL, CBS_ASN1_SEQUENCE) ||
      /* subject */
      !CBS_get_asn1(&tbs_cert, NULL, CBS_ASN1_SEQUENCE)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CANNOT_PARSE_LEAF_CERT);
    return NULL;
  }

  return EVP_parse_public_key(&tbs_cert);
}
