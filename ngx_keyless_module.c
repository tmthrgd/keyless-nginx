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
#ifndef SSL_CURVE_SECP256R1
#	define SSL_CURVE_SECP256R1 23
#	define SSL_CURVE_SECP384R1 24
#	define SSL_CURVE_SECP521R1 25
#endif /* SSL_CURVE_SECP256R1 */

#define NGX_HTTP_KEYLESS_TAG_SIGNATURE_ALGORITHMS 1
#define NGX_HTTP_KEYLESS_TAG_SUPPORTED_GROUPS     2
#define NGX_HTTP_KEYLESS_TAG_ECDSA_CIPHER         3

#define NGX_HTTP_KEYLESS_WRITE_WORD(b, v) *(unsigned short*)(b) = htons((v)); (b) += sizeof(unsigned short);

typedef struct {
	ngx_str_t address;
	ngx_str_t shm_name;
	size_t shm_size;
	ngx_msec_t timeout;

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

	unsigned int id;

	unsigned char error;

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

typedef struct {
	ngx_rbtree_t session_rbtree;
	ngx_rbtree_node_t sentinel;
	ngx_queue_t expire_queue;
} ngx_http_keyless_cache_t;

typedef struct {
	ngx_rbtree_node_t node;
	ngx_queue_t queue;

	time_t last_used;

	unsigned char key[SHA256_DIGEST_LENGTH];

	STACK_OF(X509) *chain;

	int type;
	size_t sig_len;

	unsigned char ski[KSSL_SKI_SIZE];

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
		uint8_t *out, size_t *out_len, size_t max_out, uint16_t signature_algorithm,
		const uint8_t *in, size_t in_len);
static enum ssl_private_key_result_t ngx_http_keyless_key_decrypt(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len);
static enum ssl_private_key_result_t ngx_http_keyless_key_complete(ngx_ssl_conn_t *ssl_conn,
		uint8_t *out, size_t *out_len, size_t max_out);

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

			if (ngx_memn2cmp(certificate->key, certificate_temp->key,
					SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH) < 0) {
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
	size_t extension_len, sig_algs_len, supported_groups_len;
	CBS extension, cipher_suites, server_name_list, host_name, sig_algs, supported_groups;
	int has_server_name;
	uint16_t cipher_suite;
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

	if (SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_signature_algorithms,
			&extension_data, &extension_len)) {
		CBS_init(&extension, extension_data, extension_len);

		if (!CBS_get_u16_length_prefixed(&extension, &sig_algs)
			|| CBS_len(&sig_algs) == 0
			|| CBS_len(&extension) != 0
			|| CBS_len(&sig_algs) % 2 != 0
			|| CBS_len(&sig_algs) > sizeof(tmp_sig_algs) - 3 - 5 - 4
				- (sig_algs_end - tmp_sig_algs)) {
			goto cleanup;
		}

		sig_algs_len = CBS_len(&sig_algs);

		*sig_algs_end++ = NGX_HTTP_KEYLESS_TAG_SIGNATURE_ALGORITHMS;
		NGX_HTTP_KEYLESS_WRITE_WORD(sig_algs_end, sig_algs_len);

		if (!CBS_copy_bytes(&sig_algs, sig_algs_end, sig_algs_len)) {
			goto cleanup;
		}

		sig_algs_end += sig_algs_len;

		if (SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_supported_groups,
				&extension_data, &extension_len)) {
			CBS_init(&extension, extension_data, extension_len);

			if (!CBS_get_u16_length_prefixed(&extension, &supported_groups)
				|| CBS_len(&supported_groups) == 0
				|| CBS_len(&extension) != 0
				|| CBS_len(&supported_groups) % 2 != 0
				|| CBS_len(&supported_groups) > sizeof(tmp_sig_algs) - 3 - 4
					- (sig_algs_end - tmp_sig_algs)) {
				goto cleanup;
			}

			supported_groups_len = CBS_len(&supported_groups);

			*sig_algs_end++ = NGX_HTTP_KEYLESS_TAG_SUPPORTED_GROUPS;
			NGX_HTTP_KEYLESS_WRITE_WORD(sig_algs_end, supported_groups_len);

			if (!CBS_copy_bytes(&supported_groups, sig_algs_end,
					supported_groups_len)) {
				goto cleanup;
			}

			sig_algs_end += supported_groups_len;
		} else {
			/* Clients are not required to send a supported_curves extension. In this
			 * case, the server is free to pick any curve it likes. See RFC 4492,
			 * section 4, paragraph 3. */
			*sig_algs_end++ = NGX_HTTP_KEYLESS_TAG_SUPPORTED_GROUPS;
			NGX_HTTP_KEYLESS_WRITE_WORD(sig_algs_end, 2);
			NGX_HTTP_KEYLESS_WRITE_WORD(sig_algs_end, SSL_CURVE_SECP256R1);
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
				*sig_algs_end++ = NGX_HTTP_KEYLESS_TAG_ECDSA_CIPHER;
				NGX_HTTP_KEYLESS_WRITE_WORD(sig_algs_end, 1);
				*sig_algs_end++ = 0xff;
				break;
			}
		}
	} else if (has_server_name) {
		*sig_algs_end++ = NGX_HTTP_KEYLESS_TAG_SIGNATURE_ALGORITHMS;
		NGX_HTTP_KEYLESS_WRITE_WORD(sig_algs_end, 4);
		*sig_algs_end++ = TLSEXT_hash_sha256;
		*sig_algs_end++ = TLSEXT_signature_rsa;
		*sig_algs_end++ = TLSEXT_hash_sha1;
		*sig_algs_end++ = TLSEXT_signature_rsa;
	} else {
		*sig_algs_end++ = NGX_HTTP_KEYLESS_TAG_SIGNATURE_ALGORITHMS;
		NGX_HTTP_KEYLESS_WRITE_WORD(sig_algs_end, 2);
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

	conn->op = ngx_http_keyless_start_operation(KSSL_OP_GET_CERTIFICATE, c, conn,
		tmp_sig_algs, sig_algs_end - tmp_sig_algs);
	if (!conn->op) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
			"ngx_http_keyless_start_operation(KSSL_OP_GET_CERTIFICATE) failed");
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
	ngx_http_keyless_srv_conf_t *conf;
	ngx_http_keyless_conn_t *conn;
	SSL *ssl;
	const unsigned char *payload;
	size_t payload_len;
	BIO *bio = NULL;
	X509 *leaf = NULL, *x509;
	EVP_PKEY *public_key = NULL;
	u_long n;
	ngx_slab_pool_t *shpool = NULL /* 'may be used uninitialized' warning */;
	ngx_http_keyless_cache_t *cache = NULL /* 'may be used uninitialized' warning */;
	ngx_rbtree_node_t *node, *sentinel;
	ngx_http_keyless_cached_certificate_t *certificate, *min_cert;
	uint32_t hash = 0 /* 'may be used uninitialized' warning */;
	size_t i;
	unsigned char key[SHA256_DIGEST_LENGTH];
#if NGX_DEBUG
	u_char buf[SHA256_DIGEST_LENGTH*2];
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

	conf = SSL_CTX_get_ex_data(ssl->ctx, g_ssl_ctx_exdata_conf_index);
	if (!conf) {
		goto error;
	}

	switch (ngx_http_keyless_operation_complete(conn->op, &payload, &payload_len)) {
		case ssl_private_key_failure:
			if (conn->op->error == KSSL_ERROR_CERT_NOT_FOUND) {
				goto done;
			}

			goto error;
		case ssl_private_key_retry:
			return -1;
		case ssl_private_key_success:
			break;
	}

	if (conf->shm_zone) {
		if (!SHA256(payload, payload_len, key)) {
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "SHA256(...) failed");
			goto error;
		}

		hash = ngx_crc32_short(key, SHA256_DIGEST_LENGTH);

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

			rc = ngx_memn2cmp(key, certificate->key, SHA256_DIGEST_LENGTH,
				SHA256_DIGEST_LENGTH);
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

			ngx_memcpy(conn->ski, certificate->ski, KSSL_SKI_SIZE);

			SSL_certs_clear(ssl);
			SSL_set_private_key_method(ssl, &ngx_http_keyless_key_method);

			leaf = sk_X509_value(certificate->chain, 0);
			if (!leaf) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"sk_X509_value(...) failed");
				goto error_shpool_unlock;
			}

			if (!SSL_use_certificate(ssl, leaf)) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"SSL_use_certificate(...) failed");
				goto error_shpool_unlock;
			}

			for (i = 1; i < sk_X509_num(certificate->chain); i++) {
				x509 = sk_X509_value(certificate->chain, i);
				if (!x509) {
					ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
						"sk_X509_value(...) failed");
					goto error_shpool_unlock;
				}

				if (!SSL_add1_chain_cert(ssl, x509)) {
					ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
						"SSL_add_extra_chain_cert(...) failed");
					goto error_shpool_unlock;
				}
			}

			if (!SSL_set_session_id_context(ssl, certificate->sid_ctx,
					certificate->sid_ctx_len)) {
				ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
					"SSL_set_session_id_context(...) failed");
				goto error_shpool_unlock;
			}

			ngx_shmtx_unlock(&shpool->mutex);

			ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
				"found certificate in cache: \"%*s\"",
				ngx_hex_dump(buf, key, SHA256_DIGEST_LENGTH) - buf, buf);

			goto done;
		}

		ngx_shmtx_unlock(&shpool->mutex);

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"did not find certificate in cache: \"%*s\"",
			ngx_hex_dump(buf, key, SHA256_DIGEST_LENGTH) - buf, buf);
	}

	bio = BIO_new_mem_buf((unsigned char *)payload, (int)payload_len);
	if (!bio) {
		goto error;
	}

	leaf = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
	if (!leaf) {
		ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "PEM_read_bio_X509_AUX(...) failed");
		goto error;
	}

	SSL_certs_clear(ssl);
	SSL_set_private_key_method(ssl, &ngx_http_keyless_key_method);

	if (!SSL_use_certificate(ssl, leaf)) {
		goto error;
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

	if (!leaf->cert_info
		|| !leaf->cert_info->key
		|| !leaf->cert_info->key->public_key
		|| !leaf->cert_info->key->public_key->length) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0,
			"certificate does not contain valid public key");
		goto error;
	}

	if (!SHA1(leaf->cert_info->key->public_key->data,
			leaf->cert_info->key->public_key->length, conn->ski)) {
		ngx_log_error(NGX_LOG_EMERG, c->log, 0, "SHA1 failed");
		goto error;
	}

	if (ngx_http_keyless_ssl_session_id_context(c, &ngx_http_ssl_sess_id_ctx, leaf) != NGX_OK) {
		goto error;
	}

	if (conf->shm_zone) {
		chain = sk_X509_new_null();
		if (!chain) {
			ngx_log_error(NGX_LOG_EMERG, c->log, 0, "sk_X509_new_null() failed");
			goto error;
		}

		if (sk_X509_push(chain, leaf) == 0) {
			ngx_log_error(NGX_LOG_EMERG, c->log, 0, "sk_X509_push(...) failed");
			X509_free(leaf);
			goto error;
		}
	}

	for (i = 0; ; i++) {
		x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		if (!x509) {
			n = ERR_peek_last_error();

			if (ERR_GET_LIB(n) == ERR_LIB_PEM && ERR_GET_REASON(n)
					== PEM_R_NO_START_LINE) {
				/* end of file */
				ERR_clear_error();
				break;
			}

			/* some real error */
			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0, "PEM_read_bio_X509(...) failed");
			goto error;
	        }

		if (!SSL_add1_chain_cert(ssl, x509)) {
			X509_free(x509);

			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
				"SSL_add_extra_chain_cert(...) failed");
			goto error;
		}

		if (chain && sk_X509_push(chain, x509) == 0) {
			X509_free(x509);

			ngx_ssl_error(NGX_LOG_EMERG, c->log, 0,
				"sk_X509_push(...) failed");
			goto error;
		}
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
				ngx_hex_dump(buf, min_cert->key, SHA256_DIGEST_LENGTH) - buf, buf);

			sk_X509_pop_free(min_cert->chain, X509_free);
			ngx_queue_remove(&min_cert->queue);
			ngx_rbtree_delete(&cache->session_rbtree, &min_cert->node);
			ngx_slab_free_locked(shpool, min_cert);

			certificate = ngx_slab_alloc_locked(shpool,
				sizeof(ngx_http_keyless_cached_certificate_t));
			if (!certificate) {
				ngx_shmtx_unlock(&shpool->mutex);
				goto skip_cache;
			}
		}

		certificate->node.key = hash;

		certificate->last_used = ngx_time();

		ngx_memcpy(certificate->key, key, SHA256_DIGEST_LENGTH);

		certificate->chain = chain;

		certificate->type = conn->key.type;
		certificate->sig_len = conn->key.sig_len;

		ngx_memcpy(certificate->ski, conn->ski, KSSL_SKI_SIZE);

		ngx_memcpy(certificate->sid_ctx, ssl->sid_ctx, ssl->sid_ctx_length);
		certificate->sid_ctx_len = ssl->sid_ctx_length;

		ngx_queue_insert_head(&cache->expire_queue, &certificate->queue);
		ngx_rbtree_insert(&cache->session_rbtree, &certificate->node);

		ngx_shmtx_unlock(&shpool->mutex);

		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
			"inserted certificate into cache: \"%*s\"",
			ngx_hex_dump(buf, key, SHA256_DIGEST_LENGTH) - buf, buf);
	}

skip_cache:
	BIO_free(bio);

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
	SSL *ssl;
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

	operation.sni = (const unsigned char *)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (operation.sni) {
		operation.is_sni_set = 1;
		operation.sni_len = ngx_strlen(operation.sni);
	}

	operation.is_payload_set = 1;
	operation.payload_len = in_len;
	operation.payload = in;

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

	ngx_add_timer(&op->timer, conf->timeout);

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

				op->error = operation.payload[0];
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
		case KSSL_OP_RSA_PSS_SIGN_SHA256:
		case KSSL_OP_RSA_PSS_SIGN_SHA384:
		case KSSL_OP_RSA_PSS_SIGN_SHA512:
		case KSSL_OP_ECDSA_SIGN_MD5SHA1:
		case KSSL_OP_ECDSA_SIGN_SHA1:
		case KSSL_OP_ECDSA_SIGN_SHA224:
		case KSSL_OP_ECDSA_SIGN_SHA256:
		case KSSL_OP_ECDSA_SIGN_SHA384:
		case KSSL_OP_ECDSA_SIGN_SHA512:
		case KSSL_OP_GET_CERTIFICATE:
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
		uint8_t *out, size_t *out_len, size_t max_out, uint16_t signature_algorithm,
		const uint8_t *in, size_t in_len)
{
	kssl_opcode_et opcode;
	ngx_connection_t *c;
	ngx_http_keyless_conn_t *conn;
	const EVP_MD *md;
	uint8_t hash[EVP_MAX_MD_SIZE];
	unsigned hash_len;

	switch (signature_algorithm) {
		case SSL_SIGN_RSA_PKCS1_MD5_SHA1:
			opcode = KSSL_OP_RSA_SIGN_MD5SHA1;
			md = EVP_md5_sha1();
			break;
		case SSL_SIGN_RSA_PKCS1_SHA1:
		case SSL_SIGN_ECDSA_SHA1:
			opcode = KSSL_OP_RSA_SIGN_SHA1;
			md = EVP_sha1();
			break;
		case SSL_SIGN_RSA_PKCS1_SHA256:
		case SSL_SIGN_ECDSA_SECP256R1_SHA256:
		case SSL_SIGN_RSA_PSS_SHA256:
			opcode = KSSL_OP_RSA_SIGN_SHA256;
			md = EVP_sha256();
			break;
		case SSL_SIGN_RSA_PKCS1_SHA384:
		case SSL_SIGN_ECDSA_SECP384R1_SHA384:
		case SSL_SIGN_RSA_PSS_SHA384:
			opcode = KSSL_OP_RSA_SIGN_SHA384;
			md = EVP_sha384();
			break;
		case SSL_SIGN_RSA_PKCS1_SHA512:
		case SSL_SIGN_ECDSA_SECP521R1_SHA512:
		case SSL_SIGN_RSA_PSS_SHA512:
			opcode = KSSL_OP_RSA_SIGN_SHA512;
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
			opcode |= KSSL_OP_ECDSA_MASK;
			break;
		case SSL_SIGN_RSA_PSS_SHA256:
		case SSL_SIGN_RSA_PSS_SHA384:
		case SSL_SIGN_RSA_PSS_SHA512:
			opcode |= KSSL_OP_RSA_PSS_MASK;
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
