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
#include <openssl/x509.h>

#define NGX_HTTP_KEYLESS_OP_BUFFER_SIZE 2*1024

#define NGX_HTTP_KEYLESS_VERSION_MAJOR 1
#define NGX_HTTP_KEYLESS_VERSION_MINOR 0

#define NGX_HTTP_KEYLESS_HEADER_LENGTH 8

#define NGX_HTTP_KEYLESS_PAD_TO 1024

/* taken from boringssl-1e4ae00/ssl/internal.h */
#ifndef SSL_CURVE_SECP256R1
#	define SSL_CURVE_SECP256R1 23
#	define SSL_CURVE_SECP384R1 24
#	define SSL_CURVE_SECP521R1 25
#endif /* SSL_CURVE_SECP256R1 */

enum {
	NGX_HTTP_KEYLESS_TAG_SIGNATURE_ALGORITHMS = 0x01,
	NGX_HTTP_KEYLESS_TAG_SUPPORTED_GROUPS     = 0x02,
	NGX_HTTP_KEYLESS_TAG_ECDSA_CIPHER         = 0x03
};

enum {
	// NGX_HTTP_KEYLESS_TAG_CERT_SKI (1) must occur first.
	NGX_HTTP_KEYLESS_TAG_CERT_SKI   = 0x01,
	// NGX_HTTP_KEYLESS_TAG_CERT_LEAF (2) must occur only once.
	NGX_HTTP_KEYLESS_TAG_CERT_LEAF  = 0x02,
	// NGX_HTTP_KEYLESS_TAG_CERT_CHAIN (3) will occur once, in order,
	// for each extra certificate in the chain.
	NGX_HTTP_KEYLESS_TAG_CERT_CHAIN = 3
};

enum {
	// [Deprecated]: SHA256 hash of RSA public key
	NGX_HTTP_KEYLESS_TAG_DIGEST    = 0x01,
	// Server Name Identifier
	NGX_HTTP_KEYLESS_TAG_SNI       = 0x02,
	// Client IP Address
	NGX_HTTP_KEYLESS_TAG_CLIENT_IP = 0x03,
	// SHA1 hash of Subject Key Info
	NGX_HTTP_KEYLESS_TAG_SKI       = 0x04,
	// Server IP Address
	NGX_HTTP_KEYLESS_TAG_SERVER_IP = 0x05,
	// Request operation code (see ngx_http_keyless_operation_t)
	NGX_HTTP_KEYLESS_TAG_OPCODE    = 0x11,
	// Request payload
	NGX_HTTP_KEYLESS_TAG_PAYLOAD   = 0x12,
	// Padding
	NGX_HTTP_KEYLESS_TAG_PADDING   = 0x20,
};

typedef enum {
	// Decrypt data using RSA with or without padding
	NGX_HTTP_KEYLESS_OP_RSA_DECRYPT     = 0x01,
	NGX_HTTP_KEYLESS_OP_RSA_DECRYPT_RAW = 0x08,

	// Sign data using RSA
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_MD5SHA1 = 0x02,
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA1    = 0x03,
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA224  = 0x04,
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA256  = 0x05,
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA384  = 0x06,
	NGX_HTTP_KEYLESS_OP_RSA_SIGN_SHA512  = 0x07,

	// Sign data using RSA-PSS
#define NGX_HTTP_KEYLESS_OP_RSA_PSS_MASK          0x30
	NGX_HTTP_KEYLESS_OP_RSA_PSS_SIGN_SHA256 = 0x35,
	NGX_HTTP_KEYLESS_OP_RSA_PSS_SIGN_SHA384 = 0x36,
	NGX_HTTP_KEYLESS_OP_RSA_PSS_SIGN_SHA512 = 0x37,

	// Sign data using ECDSA
#define NGX_HTTP_KEYLESS_OP_ECDSA_MASK           0x10
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_MD5SHA1 = 0x12,
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA1    = 0x13,
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA224  = 0x14,
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA256  = 0x15,
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA384  = 0x16,
	NGX_HTTP_KEYLESS_OP_ECDSA_SIGN_SHA512  = 0x17,

	// Request a certificate and chain
	NGX_HTTP_KEYLESS_OP_GET_CERTIFICATE = 0x20,

	// [Deprecated]: A test message
	NGX_HTTP_KEYLESS_OP_PING = 0xF1,
	NGX_HTTP_KEYLESS_OP_PONG = 0xF2,

	// [Deprecated]: A verification message
	NGX_HTTP_KEYLESS_OP_ACTIVATE = 0xF3,

	// Response
	NGX_HTTP_KEYLESS_OP_RESPONSE = 0xF0,
	NGX_HTTP_KEYLESS_OP_ERROR    = 0xFF,
} ngx_http_keyless_operation_t;

typedef enum {
	// No error
	NGX_HTTP_KEYLESS_ERROR_NONE              = 0x00,
	// Cryptographic error
	NGX_HTTP_KEYLESS_ERROR_CRYPTO_FAILED     = 0x01,
	// Private key not found
	NGX_HTTP_KEYLESS_ERROR_KEY_NOT_FOUND     = 0x02,
	// [Deprecated]: Disk read failure
	NGX_HTTP_KEYLESS_ERROR_DISK_READ         = 0x03,
	// Client-Server version mismatch
	NGX_HTTP_KEYLESS_ERROR_VERSION_MISMATCH  = 0x04,
	// Invalid/unsupported opcode
	NGX_HTTP_KEYLESS_ERROR_BAD_OPCODE        = 0x05,
	// Opcode sent at wrong time/direction
	NGX_HTTP_KEYLESS_ERROR_UNEXPECTED_OPCODE = 0x06,
	// Malformed message
	NGX_HTTP_KEYLESS_ERROR_FORMAT            = 0x07,
	// Other internal error
	NGX_HTTP_KEYLESS_ERROR_INTERNAL          = 0x08,
	// Certificate not found
	NGX_HTTP_KEYLESS_ERROR_CERT_NOT_FOUND    = 0x09,
} ngx_http_keyless_error_t;

typedef struct {
	ngx_str_t address;
	ngx_str_t shm_name;
	size_t shm_size;
	ngx_msec_t timeout;
	ngx_flag_t fallback;

	ngx_peer_connection_t pc;

	ngx_atomic_uint_t id;

	ngx_shm_zone_t *shm_zone;

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

	ngx_log_t *log;

	ngx_buf_t send;
	ngx_buf_t recv;

	ngx_queue_t recv_queue;
	ngx_queue_t send_queue;
} ngx_http_keyless_op_t;

typedef struct {
	ngx_http_keyless_op_t *op;

	uint8_t *payload;
	size_t payload_len;

	struct {
		int type;
		size_t sig_len;
	} key;

	unsigned char ski[SHA_DIGEST_LENGTH];
} ngx_http_keyless_conn_t;

typedef struct {
	ngx_rbtree_t session_rbtree;
	ngx_rbtree_node_t sentinel;
	ngx_queue_t expire_queue;
} ngx_http_keyless_cache_t;

typedef struct {
	ngx_rbtree_node_t node;
	ngx_queue_t queue;

	time_t last_used;

	STACK_OF(X509) *chain;

	int type;
	size_t sig_len;

	unsigned char ski[SHA_DIGEST_LENGTH];

	unsigned char sid_ctx[EVP_MAX_MD_SIZE];
	size_t sid_ctx_len;
} ngx_http_keyless_cached_certificate_t;

static void *ngx_http_keyless_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_keyless_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_keyless_cache_init(ngx_shm_zone_t *shm_zone, void *data);
static void ngx_http_keyless_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
		ngx_rbtree_node_t *sentinel);

static int ngx_http_keyless_select_certificate_cb(const struct ssl_early_callback_ctx *ctx);
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

/* this is ngx_ssl_session_id_context from nginx-1.9.15/src/event/ngx_event_openssl.c */
static ngx_int_t ngx_http_keyless_ssl_session_id_context(ngx_connection_t *c, ngx_str_t *sess_ctx,
		X509 *cert);

/* this is from nginx-1.9.15/src/http/modules/ngx_http_ssl_module.c */
static ngx_str_t ngx_http_ssl_sess_id_ctx = ngx_string("HTTP");

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

	{ ngx_string("keyless_ssl_cache"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_str_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_keyless_srv_conf_t, shm_name),
	  NULL },

	{ ngx_string("keyless_ssl_cache_size"),
	  NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
	  ngx_conf_set_size_slot,
	  NGX_HTTP_SRV_CONF_OFFSET,
	  offsetof(ngx_http_keyless_srv_conf_t, shm_size),
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
	 *     kcscf->shm_name = { 0, NULL };
	 */

	kcscf->shm_size = NGX_CONF_UNSET_SIZE;
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
	ngx_conf_merge_str_value(conf->shm_name, prev->shm_name, "");
	ngx_conf_merge_size_value(conf->shm_size, prev->shm_size, 8 * ngx_pagesize);
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

	if (conf->shm_name.len && ngx_strcmp(conf->shm_name.data, "off") != 0) {
		if (conf->shm_size < 8 * ngx_pagesize) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
				"certificate cache size %z bytes is too small", conf->shm_size);
			return NGX_CONF_ERROR;
		}

		conf->shm_zone = ngx_shared_memory_add(cf, &conf->shm_name, conf->shm_size,
			&ngx_http_keyless_module);
		if (!conf->shm_zone) {
			ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "ngx_shared_memory_add failed");
			return NGX_CONF_ERROR;
		}

		conf->shm_zone->init = ngx_http_keyless_cache_init;
	}

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

static ngx_int_t ngx_http_keyless_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
	ngx_slab_pool_t *shpool;
	ngx_http_keyless_cache_t *cache;

	if (data) {
		shm_zone->data = data;
		return NGX_OK;
	}

	shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;

	if (shm_zone->shm.exists) {
		shm_zone->data = shpool->data;
		return NGX_OK;
	}

	cache = ngx_slab_alloc(shpool, sizeof(ngx_http_keyless_cache_t));
	if (cache == NULL) {
		return NGX_ERROR;
	}

	shpool->data = cache;
	shm_zone->data = cache;

	ngx_rbtree_init(&cache->session_rbtree, &cache->sentinel,
		ngx_http_keyless_rbtree_insert_value);
	ngx_queue_init(&cache->expire_queue);

	shpool->log_nomem = 0;

	return NGX_OK;
}

static void ngx_http_keyless_rbtree_insert_value(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
		ngx_rbtree_node_t *sentinel)
{
	ngx_rbtree_node_t **p;
	ngx_http_keyless_cached_certificate_t *certificate, *certificate_temp;

	while (1) {
		if (node->key < temp->key) {
			p = &temp->left;
		} else if (node->key > temp->key) {
			p = &temp->right;
		} else { /* node->key == temp->key */
			certificate = (ngx_http_keyless_cached_certificate_t *)node;
			certificate_temp = (ngx_http_keyless_cached_certificate_t *)temp;

			if (ngx_memn2cmp(certificate->ski, certificate_temp->ski,
					SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH) < 0) {
				p = &temp->left;
			} else {
				p = &temp->right;
			}
		}

		if (*p == sentinel) {
			break;
		}

		temp = *p;
	}

	*p = node;
	node->parent = temp;
	node->left = sentinel;
	node->right = sentinel;
	ngx_rbt_red(node);
}

static int ngx_http_keyless_select_certificate_cb(const struct ssl_early_callback_ctx *ctx)
{
	const uint8_t *extension_data;
	size_t extension_len;
	CBS extension, cipher_suites, server_name_list, host_name, sig_algs, supported_groups;
	int has_server_name;
	uint16_t cipher_suite;
	uint8_t name_type;
	const SSL_CIPHER *cipher;
	char *server_name = NULL;
	CBB payload_cbb, child_cbb;
	int rc = -1;
	ngx_connection_t *c;
	ngx_http_keyless_conn_t *conn;

	if (!CBB_init(&payload_cbb, 256)) {
		goto cleanup;
	}

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

	if (SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_signature_algorithms,
			&extension_data, &extension_len)) {
		CBS_init(&extension, extension_data, extension_len);

		if (!CBS_get_u16_length_prefixed(&extension, &sig_algs)
			|| CBS_len(&sig_algs) == 0
			|| CBS_len(&extension) != 0
			|| CBS_len(&sig_algs) % 2 != 0
			|| !CBB_add_u8(&payload_cbb, NGX_HTTP_KEYLESS_TAG_SIGNATURE_ALGORITHMS)
			|| !CBB_add_u16_length_prefixed(&payload_cbb, &child_cbb)
			|| !CBB_add_bytes(&child_cbb, CBS_data(&sig_algs), CBS_len(&sig_algs))) {
			goto cleanup;
		}

		if (SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_supported_groups,
				&extension_data, &extension_len)) {
			CBS_init(&extension, extension_data, extension_len);

			if (!CBS_get_u16_length_prefixed(&extension, &supported_groups)
				|| CBS_len(&supported_groups) == 0
				|| CBS_len(&extension) != 0
				|| CBS_len(&supported_groups) % 2 != 0
				|| !CBB_add_u8(&payload_cbb, NGX_HTTP_KEYLESS_TAG_SUPPORTED_GROUPS)
				|| !CBB_add_u16_length_prefixed(&payload_cbb, &child_cbb)
				|| !CBB_add_bytes(&child_cbb, CBS_data(&supported_groups),
					CBS_len(&supported_groups))) {
				goto cleanup;
			}
		} else {
			/* Clients are not required to send a supported_curves extension. In this
			 * case, the server is free to pick any curve it likes. See RFC 4492,
			 * section 4, paragraph 3. */
			if (!CBB_add_u8(&payload_cbb, NGX_HTTP_KEYLESS_TAG_SUPPORTED_GROUPS)
				|| !CBB_add_u16_length_prefixed(&payload_cbb, &child_cbb)
				|| !CBB_add_u16(&child_cbb, SSL_CURVE_SECP256R1)) {
				goto cleanup;
			}
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
				if (!CBB_add_u8(&payload_cbb, NGX_HTTP_KEYLESS_TAG_ECDSA_CIPHER)
					|| !CBB_add_u16_length_prefixed(&payload_cbb, &child_cbb)
					|| !CBB_add_u8(&child_cbb, 0xff)) {
					goto cleanup;
				}

				break;
			}
		}
	} else {
		if (!CBB_add_u8(&payload_cbb, NGX_HTTP_KEYLESS_TAG_SIGNATURE_ALGORITHMS)
			|| !CBB_add_u16_length_prefixed(&payload_cbb, &child_cbb)
			|| (has_server_name && !CBB_add_u8(&child_cbb, TLSEXT_hash_sha256))
			|| (has_server_name && !CBB_add_u8(&child_cbb, TLSEXT_signature_rsa))
			|| !CBB_add_u8(&child_cbb, TLSEXT_hash_sha1)
			|| !CBB_add_u8(&child_cbb, TLSEXT_signature_rsa)) {
			goto cleanup;
		}
	}

	c = ngx_ssl_get_connection(ctx->ssl);

	conn = ngx_pcalloc(c->pool, sizeof(ngx_http_keyless_conn_t));
	if (!conn) {
		goto cleanup;
	}

	if (!SSL_set_ex_data(c->ssl->connection, g_ssl_exdata_conn_index, conn)) {
		goto cleanup;
	}

	if (!CBB_finish(&payload_cbb, &conn->payload, &conn->payload_len)) {
		goto cleanup;
	}

	rc = 1;

cleanup:
	CBB_cleanup(&payload_cbb);

	if (server_name) {
		ctx->ssl->tlsext_hostname = NULL;
		OPENSSL_free(server_name);
	}

	return rc;
}

static int ngx_http_keyless_cert_cb(ngx_ssl_conn_t *ssl_conn, void *data)
{
	ngx_connection_t *c;
	ngx_http_keyless_srv_conf_t *conf;
	ngx_http_keyless_conn_t *conn;
	SSL *ssl;
	const unsigned char *p;
	CBS payload, child;
	uint8_t tag;
	X509 *leaf = NULL, *x509;
	EVP_PKEY *public_key = NULL;
	ngx_slab_pool_t *shpool = NULL /* 'may be used uninitialized' warning */;
	ngx_http_keyless_cache_t *cache = NULL /* 'may be used uninitialized' warning */;
	ngx_rbtree_node_t *node, *sentinel;
	ngx_http_keyless_cached_certificate_t *certificate, *min_cert;
	uint32_t hash = 0 /* 'may be used uninitialized' warning */;
#if NGX_DEBUG
	u_char buf[SHA_DIGEST_LENGTH*2];
#endif /* NGX_DEBUG */
	STACK_OF(X509) *chain = NULL;
	ngx_int_t rc;
	time_t min_time;
	ngx_queue_t *q;

	c = ngx_ssl_get_connection(ssl_conn);
	ssl = c->ssl->connection;

	conn = SSL_get_ex_data(ssl, g_ssl_exdata_conn_index);
	if (!conn) {
		return 1;
	}

	if (!conn->op) {
		conn->op = ngx_http_keyless_start_operation(NGX_HTTP_KEYLESS_OP_GET_CERTIFICATE, c,
			conn, conn->payload, conn->payload_len);

		OPENSSL_free(conn->payload);

		if (!conn->op) {
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
				"ngx_http_keyless_start_operation(NGX_HTTP_KEYLESS_OP_GET_CERTIFICATE)"
				" failed");
			return 0;
		}

		return -1;
	}

	conf = SSL_CTX_get_ex_data(ssl->ctx, g_ssl_ctx_exdata_conf_index);
	if (!conf) {
		goto error;
	}

	switch (ngx_http_keyless_operation_complete(conn->op, &payload)) {
		case ssl_private_key_failure:
			if (conn->op->error == NGX_HTTP_KEYLESS_ERROR_CERT_NOT_FOUND) {
				if (!conf->fallback) {
					SSL_certs_clear(ssl);
				}

				goto done;
			}

			goto error;
		case ssl_private_key_retry:
			return -1;
		case ssl_private_key_success:
			break;
	}

	if (!CBS_get_u8(&payload, &tag)
		|| tag != NGX_HTTP_KEYLESS_TAG_CERT_SKI
		|| !CBS_get_u16_length_prefixed(&payload, &child)
		|| CBS_len(&child) != SHA_DIGEST_LENGTH
		|| !CBS_copy_bytes(&child, conn->ski, CBS_len(&child))) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"get certificate format erorr");
		goto error;
	}

	SSL_certs_clear(ssl);
	SSL_set_private_key_method(ssl, &ngx_http_keyless_key_method);

	if (conf->shm_zone) {
		hash = ngx_crc32_short(conn->ski, SHA_DIGEST_LENGTH);

		cache = conf->shm_zone->data;
		shpool = (ngx_slab_pool_t *)conf->shm_zone->shm.addr;

		ngx_shmtx_lock(&shpool->mutex);

		node = cache->session_rbtree.root;
		sentinel = cache->session_rbtree.sentinel;

		while (node != sentinel) {
			if (hash < node->key) {
				node = node->left;
				continue;
			} else if (hash > node->key) {
				node = node->right;
				continue;
			}

			certificate = (ngx_http_keyless_cached_certificate_t *)node;

			rc = ngx_memn2cmp(conn->ski, certificate->ski,
				SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);
			if (rc < 0) {
				node = node->left;
				continue;
			} else if (rc > 0) {
				node = node->right;
				continue;
			}

			certificate->last_used = ngx_time();

			conn->key.type = certificate->type;
			conn->key.sig_len = certificate->sig_len;

			ngx_memcpy(conn->ski, certificate->ski, SHA_DIGEST_LENGTH);

			chain = sk_X509_dup(certificate->chain);
			if (!chain) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"sk_X509_dup(...) failed");
				goto error_shpool_unlock;
			}

			leaf = sk_X509_shift(chain);
			if (!leaf) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"sk_X509_shift(...) failed");
				goto error_shpool_unlock;
			}

			if (!SSL_use_certificate(ssl, leaf)) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"SSL_use_certificate(...) failed");
				goto error_shpool_unlock;
			}

			if (!SSL_set1_chain(ssl, chain)) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"SSL_set1_chain(...) failed");
				goto error_shpool_unlock;
			}

			chain = NULL;

			if (!SSL_set_session_id_context(ssl, certificate->sid_ctx,
					certificate->sid_ctx_len)) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"SSL_set_session_id_context(...) failed");
				goto error_shpool_unlock;
			}

			ngx_shmtx_unlock(&shpool->mutex);

			ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
				"found certificate in cache: \"%*s\"",
				ngx_hex_dump(buf, conn->ski, SHA_DIGEST_LENGTH) - buf, buf);

			goto done;
		}

		ngx_shmtx_unlock(&shpool->mutex);

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"did not find certificate in cache: \"%*s\"",
			ngx_hex_dump(buf, conn->ski, SHA_DIGEST_LENGTH) - buf, buf);

		chain = sk_X509_new_null();
		if (!chain) {
			ngx_log_error(NGX_LOG_EMERG, c->log, 0, "sk_X509_new_null() failed");
			goto error;
		}
	}

	while (CBS_len(&payload) != 0) {
		if (!CBS_get_u8(&payload, &tag)
			|| !CBS_get_u16_length_prefixed(&payload, &child)) {
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
				"get certificate format erorr");
			goto error;
		}

		switch (tag) {
			case NGX_HTTP_KEYLESS_TAG_CERT_LEAF:
			case NGX_HTTP_KEYLESS_TAG_CERT_CHAIN:
				if (tag == NGX_HTTP_KEYLESS_TAG_CERT_LEAF && leaf) {
					ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
						"get certificate format erorr");
					goto error;
				}

				p = CBS_data(&child);

				x509 = d2i_X509(NULL, &p, CBS_len(&child));
				if (!x509) {
					ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
						"d2i_X509(...) failed");
					goto error;
				}

				if (tag == NGX_HTTP_KEYLESS_TAG_CERT_LEAF) {
					leaf = x509;

					if (!SSL_use_certificate(ssl, leaf)) {
						X509_free(leaf);

						ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
							"SSL_use_certificate(...) failed");
						goto error;
					}
				} else if (!SSL_add1_chain_cert(ssl, x509)) {
					X509_free(x509);

					ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
						"SSL_add_extra_chain_cert(...) failed");
					goto error;
				}

				if (!chain) {
					X509_free(x509);
				} else if (sk_X509_push(chain, x509) == 0) {
					X509_free(x509);

					ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
						"sk_X509_push(...) failed");
					goto error;
				}

				break;
			default:
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"get certificate format erorr");
				goto error;
		}
	}

	public_key = X509_get_pubkey(leaf);
	if (!public_key) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "X509_get_pubkey failed");
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
		default:
			ngx_log_error(NGX_LOG_EMERG, c->log, 0,
				"certificate does not contain a supported key type");
			goto error;
	}

	conn->key.sig_len = EVP_PKEY_size(public_key);

	if (ngx_http_keyless_ssl_session_id_context(c, &ngx_http_ssl_sess_id_ctx, leaf) != NGX_OK) {
		goto error;
	}

	if (conf->shm_zone) {
		ngx_shmtx_lock(&shpool->mutex);

		certificate = ngx_slab_alloc_locked(shpool,
			sizeof(ngx_http_keyless_cached_certificate_t));
		if (!certificate) {
			min_time = ngx_time();
			min_cert = NULL;

			for (q = ngx_queue_head(&cache->expire_queue);
				q != ngx_queue_sentinel(&cache->expire_queue);
				q = ngx_queue_next(q)) {
				certificate = ngx_queue_data(q,
					ngx_http_keyless_cached_certificate_t, queue);

				if (certificate->last_used < min_time) {
					min_time = certificate->last_used;
					min_cert = certificate;
				}
			}

			assert(min_cert);

			ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
				"remove certificate from cache: \"%*s\"",
				ngx_hex_dump(buf, min_cert->ski, SHA_DIGEST_LENGTH) - buf, buf);

			sk_X509_pop_free(min_cert->chain, X509_free);
			ngx_queue_remove(&min_cert->queue);
			ngx_rbtree_delete(&cache->session_rbtree, &min_cert->node);
			ngx_slab_free_locked(shpool, min_cert);

			certificate = ngx_slab_alloc_locked(shpool,
				sizeof(ngx_http_keyless_cached_certificate_t));
			if (!certificate) {
				ngx_shmtx_unlock(&shpool->mutex);
				goto done;
			}
		}

		certificate->node.key = hash;

		certificate->last_used = ngx_time();

		certificate->chain = chain;

		certificate->type = conn->key.type;
		certificate->sig_len = conn->key.sig_len;

		ngx_memcpy(certificate->ski, conn->ski, SHA_DIGEST_LENGTH);

		ngx_memcpy(certificate->sid_ctx, ssl->sid_ctx, ssl->sid_ctx_length);
		certificate->sid_ctx_len = ssl->sid_ctx_length;

		ngx_queue_insert_head(&cache->expire_queue, &certificate->queue);
		ngx_rbtree_insert(&cache->session_rbtree, &certificate->node);

		ngx_shmtx_unlock(&shpool->mutex);

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"inserted certificate into cache: \"%*s\"",
			ngx_hex_dump(buf, conn->ski, SHA_DIGEST_LENGTH) - buf, buf);
	}

done:
	ngx_http_keyless_cleanup_operation(conn->op);
	return 1;

error_shpool_unlock:
	ngx_shmtx_unlock(&shpool->mutex);

error:
	ERR_clear_error();

	if (chain) {
		sk_X509_pop_free(chain, X509_free);
	} else if (leaf) {
		X509_free(leaf);
	}

	if (public_key) {
		EVP_PKEY_free(public_key);
	}

	ngx_http_keyless_cleanup_operation(conn->op);
	return 0;
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

	conf = SSL_CTX_get_ex_data(ssl->ctx, g_ssl_ctx_exdata_conf_index);
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

	if (!CBB_init(&payload, 1024 + 3)
		// header
		|| !CBB_add_u8(&payload, NGX_HTTP_KEYLESS_VERSION_MAJOR)
		|| !CBB_add_u8(&payload, NGX_HTTP_KEYLESS_VERSION_MINOR)
		|| !CBB_add_u16(&payload, 0) // length placeholder
		|| !CBB_add_u32(&payload, op->id)
		// opcode tag
		|| !CBB_add_u8(&payload, NGX_HTTP_KEYLESS_TAG_OPCODE)
		|| !CBB_add_u16_length_prefixed(&payload, &child)
		|| !CBB_add_u8(&child, opcode)
		// payload tag
		|| !CBB_add_u8(&payload, NGX_HTTP_KEYLESS_TAG_PAYLOAD)
		|| !CBB_add_u16_length_prefixed(&payload, &child)
		|| !CBB_add_bytes(&child, in, in_len)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
		goto error;
	}

	if (conn->key.type
		// ski tag
		&& (!CBB_add_u8(&payload, NGX_HTTP_KEYLESS_TAG_SKI)
			|| !CBB_add_u16_length_prefixed(&payload, &child)
			|| !CBB_add_bytes(&child, conn->ski, SHA_DIGEST_LENGTH))) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
		goto error;
	}

	sni = (const uint8_t *)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (sni // sni tag
		&& (!CBB_add_u8(&payload, NGX_HTTP_KEYLESS_TAG_SNI)
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
		&& (!CBB_add_u8(&payload, NGX_HTTP_KEYLESS_TAG_CLIENT_IP)
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
			&& (!CBB_add_u8(&payload, NGX_HTTP_KEYLESS_TAG_SERVER_IP)
				|| !CBB_add_u16_length_prefixed(&payload, &child)
				|| !CBB_add_bytes(&child, ip, ip_len))) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_* failed");
			goto error;
		}
	} else {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "ngx_connection_local_sockaddr failed");
	}

	if (!CBB_flush(&payload)) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBB_flush failed");
		goto error;
	}

	len = CBB_len(&payload);
	if (len < NGX_HTTP_KEYLESS_PAD_TO) {
		// padding tag
		if (!CBB_add_u8(&payload, NGX_HTTP_KEYLESS_TAG_PADDING)
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
	uint8_t tag;
	CBS msg, child, payload;
	int saw_opcode = 0, saw_payload = 0, saw_padding = 0;

	if (op->recv.last - op->recv.pos < NGX_HTTP_KEYLESS_HEADER_LENGTH) {
		if (op->timer.timedout) {
			ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless operation timed out");
			return ssl_private_key_failure;
		}

		return ssl_private_key_retry;
	}

	CBS_init(&msg, op->recv.pos + NGX_HTTP_KEYLESS_HEADER_LENGTH,
		op->recv.last - op->recv.pos - NGX_HTTP_KEYLESS_HEADER_LENGTH);

	while (CBS_len(&msg) != 0) {
		if (!CBS_get_u8(&msg, &tag)
			|| !CBS_get_u16_length_prefixed(&msg, &child)) {
			ngx_log_error(NGX_LOG_ERR, op->log, 0, "CBS_* failed");
			return ssl_private_key_failure;
		}

		switch (tag) {
			case NGX_HTTP_KEYLESS_TAG_OPCODE:
				if (saw_opcode) {
					ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless receive error: %s",
						ngx_http_keyless_error_string(NGX_HTTP_KEYLESS_ERROR_FORMAT));
					return ssl_private_key_failure;
				}

				if (!CBS_get_u8(&child, (uint8_t *)&opcode)
					|| CBS_len(&child) != 0) {
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

				// ignore; should this be checked to ensure it is zero?
				saw_padding = 1;
				break;
			case NGX_HTTP_KEYLESS_TAG_DIGEST:
			case NGX_HTTP_KEYLESS_TAG_SNI:
			case NGX_HTTP_KEYLESS_TAG_CLIENT_IP:
			case NGX_HTTP_KEYLESS_TAG_SKI:
			case NGX_HTTP_KEYLESS_TAG_SERVER_IP:
				ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless: unexpected tag");
				return ssl_private_key_failure;
			default:
				ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless: unrecognised tag");
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
			if (!CBS_get_u8(&payload, (uint8_t *)&op->error)
				|| CBS_len(&payload) != 0) {
				ngx_log_error(NGX_LOG_ERR, op->log, 0, "CBS_* failed or format error");
				return ssl_private_key_failure;
			}

			ngx_log_error(NGX_LOG_ERR, op->log, 0, "keyless error: %s",
				ngx_http_keyless_error_string(op->error));
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
		return rc;
	}

	if (rc == ssl_private_key_success) {
		*out_len = CBS_len(&payload);

		if (CBS_len(&payload) > max_out) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "payload longer than max_out");
		} else if (!CBS_copy_bytes(&payload, out, CBS_len(&payload))) {
			ngx_log_error(NGX_LOG_ERR, c->log, 0, "CBS_copy_bytes failed");
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
		default:
			return "unkown error";
	}
}

/* this is ngx_ssl_session_id_context from nginx-1.9.15/src/event/ngx_event_openssl.c */
static ngx_int_t ngx_http_keyless_ssl_session_id_context(ngx_connection_t *c, ngx_str_t *sess_ctx,
		X509 *cert)
{
	int n, i;
	X509_NAME *name;
	EVP_MD_CTX *md;
	unsigned int len;
	STACK_OF(X509_NAME) *list;
	u_char buf[EVP_MAX_MD_SIZE];

	/*
	 * Session ID context is set based on the string provided,
	 * the server certificate, and the client CA list.
	 */

	md = EVP_MD_CTX_create();
	if (md == NULL) {
		return NGX_ERROR;
	}

	if (EVP_DigestInit_ex(md, EVP_sha1(), NULL) == 0) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "EVP_DigestInit_ex() failed");
		goto failed;
	}

	if (EVP_DigestUpdate(md, sess_ctx->data, sess_ctx->len) == 0) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "EVP_DigestUpdate() failed");
		goto failed;
	}

	if (X509_digest(cert, EVP_sha1(), buf, &len) == 0) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "X509_digest() failed");
		goto failed;
	}

	if (EVP_DigestUpdate(md, buf, len) == 0) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "EVP_DigestUpdate() failed");
		goto failed;
	}

	list = SSL_get_client_CA_list(c->ssl->connection);

	if (list != NULL) {
		n = sk_X509_NAME_num(list);

		for (i = 0; i < n; i++) {
			name = sk_X509_NAME_value(list, i);

			if (X509_NAME_digest(name, EVP_sha1(), buf, &len) == 0) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"X509_NAME_digest() failed");
				goto failed;
			}

			if (EVP_DigestUpdate(md, buf, len) == 0) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"EVP_DigestUpdate() failed");
				goto failed;
			}
		}
	}

	if (EVP_DigestFinal_ex(md, buf, &len) == 0) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "EVP_DigestUpdate() failed");
		goto failed;
	}

	EVP_MD_CTX_destroy(md);

	if (SSL_set_session_id_context(c->ssl->connection, buf, len) == 0) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "SSL_set_session_id_context() failed");
		return NGX_ERROR;
	}

	return NGX_OK;

failed:
	EVP_MD_CTX_destroy(md);

	return NGX_ERROR;
}
