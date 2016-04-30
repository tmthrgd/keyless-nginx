#include <ngx_keyless_module.h>

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if NGX_HTTP_SSL

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
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define OP_BUFFER_SIZE 2*1024

static void ngx_keyless_exit_process(ngx_cycle_t *cycle);

static enum ssl_private_key_result_t operation_complete(SSL *ssl, uint8_t *out, size_t *out_len,
		size_t max_out);

static int key_type(SSL *ssl);
static size_t key_max_signature_len(SSL *ssl);
static enum ssl_private_key_result_t key_sign(SSL *ssl, uint8_t *out, size_t *out_len,
		size_t max_out, const EVP_MD *md, const uint8_t *in, size_t in_len);
#define key_sign_complete operation_complete
static enum ssl_private_key_result_t key_decrypt(SSL *ssl, uint8_t *out, size_t *out_len,
		size_t max_out, const uint8_t *in, size_t in_len);
#define key_decrypt_complete operation_complete

static void socket_read_handler(ngx_event_t *rev);
static void socket_write_handler(ngx_event_t *wev);

typedef struct keyless_ctx_st {
	struct {
		int type;
		size_t sig_len;
	} key;

	const struct sockaddr *address;
	size_t address_len;

	unsigned char ski[KSSL_SKI_SIZE];
	unsigned char digest[KSSL_DIGEST_SIZE];

	ngx_connection_t *c;

	ngx_queue_t recv_ops;
	ngx_queue_t send_ops;

	ngx_pool_t *pool;
	ngx_log_t *log;
} KEYLESS_CTX;

typedef struct {
	ngx_event_t *ev;

	unsigned int id;

	ngx_buf_t send;
	ngx_buf_t recv;

	ngx_queue_t recv_queue;
	ngx_queue_t send_queue;
} keyless_op_st;

static int g_ssl_exdata_ctx_index = -1;
static int g_ssl_ctx_exdata_ctx_index = -1;
static int g_ssl_exdata_op_index = -1;

const SSL_PRIVATE_KEY_METHOD key_method = {
	key_type,
	key_max_signature_len,
	key_sign,
	key_sign_complete,
	key_decrypt,
	key_decrypt_complete,
};

static void ngx_keyless_exit_process(ngx_cycle_t *cycle)
{
	ngx_connection_t *c;
	ngx_uint_t i;

	c = cycle->connections;
	for (i = 0; i < cycle->connection_n; i++) {
		if (c[i].read->handler == socket_read_handler) {
			ngx_close_connection(&c[i]);
		}
	}
}

KEYLESS_CTX *keyless_create(ngx_pool_t *pool, ngx_log_t *log, X509 *cert,
		const struct sockaddr *address, size_t address_len)
{
	EVP_PKEY *public_key = NULL;
	KEYLESS_CTX *ctx = NULL;
	char *hex = NULL;
	size_t i = 0;

	if (g_ssl_exdata_ctx_index == -1) {
		g_ssl_exdata_ctx_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_exdata_ctx_index == -1) {
			goto error;
		}
	}

	if (g_ssl_ctx_exdata_ctx_index == -1) {
		g_ssl_ctx_exdata_ctx_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_ctx_exdata_ctx_index == -1) {
			goto error;
		}
	}

	if (g_ssl_exdata_op_index == -1) {
		g_ssl_exdata_op_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_exdata_op_index == -1) {
			goto error;
		}
	}

	public_key = X509_get_pubkey(cert);
	if (!public_key) {
		goto error;
	}

	ctx = ngx_pcalloc(pool, sizeof(KEYLESS_CTX));
	if (!ctx) {
		goto error;
	}

	ctx->pool = pool;
	ctx->log = log;

	ctx->address = address;
	ctx->address_len = address_len;

	ctx->key.type = EVP_PKEY_id(public_key);
	ctx->key.sig_len = EVP_PKEY_size(public_key);

	if (!cert->cert_info
		|| !cert->cert_info->key
		|| !cert->cert_info->key->public_key
		|| !cert->cert_info->key->public_key->length) {
		goto error;
	}

	if (!SHA1(cert->cert_info->key->public_key->data,
			cert->cert_info->key->public_key->length, ctx->ski)) {
		goto error;
	}

	switch (ctx->key.type) {
		case EVP_PKEY_RSA:
			if (!cert->cert_info->key->pkey
				|| !cert->cert_info->key->pkey->pkey.rsa
				|| !cert->cert_info->key->pkey->pkey.rsa->n) {
				goto error;
			}

			hex = BN_bn2hex(cert->cert_info->key->pkey->pkey.rsa->n);
			if (!hex) {
				goto error;
			}

			for (i = 0; hex[i]; i++) {
				hex[i] = ngx_toupper(hex[i]);
	    		}

			if (!SHA256((const uint8_t *)hex, ngx_strlen(hex), ctx->digest)) {
				goto error;
			}

			OPENSSL_free(hex); hex = NULL;
			break;
		case EVP_PKEY_EC:
			break;
		default:
			goto error;
	}

	EVP_PKEY_free(public_key);

	ngx_queue_init(&ctx->recv_ops);
	ngx_queue_init(&ctx->send_ops);

	return ctx;

error:
	if (hex) {
		OPENSSL_free(hex);
	}

	if (public_key) {
		EVP_PKEY_free(public_key);
	}

	if (ctx) {
		ngx_pfree(pool, ctx);
	}

	return NULL;
}

KEYLESS_CTX *keyless_parse_and_create(ngx_pool_t *pool, ngx_log_t *log, X509 *cert,
		const char *addr, size_t addr_len)
{
	ngx_url_t url;

	ngx_memzero(&url, sizeof(ngx_url_t));

	url.url.len = addr_len;
	url.url.data = (unsigned char *)addr;
	url.default_port = (in_port_t)KEYLESS_DEFAULT_PORT;
	url.no_resolve = 1;

	if (ngx_parse_url(pool, &url) != NGX_OK) {
		return NULL;
	}

	if (!url.addrs || !url.addrs[0].sockaddr) {
		return NULL;
	}

	return keyless_create(pool, log, cert, url.addrs[0].sockaddr, url.addrs[0].socklen);
}

KEYLESS_CTX *ssl_get_keyless_ctx(SSL *ssl)
{
	KEYLESS_CTX *ctx;

	ctx = SSL_get_ex_data(ssl, g_ssl_exdata_ctx_index);
	if (ctx) {
		return ctx;
	}

	return SSL_CTX_get_ex_data(ssl->ctx, g_ssl_ctx_exdata_ctx_index);
}

KEYLESS_CTX *ssl_ctx_get_keyless_ctx(SSL_CTX *ssl_ctx)
{
	return SSL_CTX_get_ex_data(ssl_ctx, g_ssl_ctx_exdata_ctx_index);
}

int keyless_attach_ssl(SSL *ssl, KEYLESS_CTX *ctx)
{
	if (!SSL_set_ex_data(ssl, g_ssl_exdata_ctx_index, ctx)) {
		return 0;
	}

	SSL_set_private_key_method(ssl, &key_method);
	return 1;
}

int keyless_attach_ssl_ctx(SSL_CTX *ssl_ctx, KEYLESS_CTX *ctx)
{
	if (!SSL_CTX_set_ex_data(ssl_ctx, g_ssl_ctx_exdata_ctx_index, ctx)) {
		return 0;
	}

	SSL_CTX_set_private_key_method(ssl_ctx, &key_method);
	return 1;
}

void keyless_free(KEYLESS_CTX *ctx)
{
	keyless_op_st *op;
	ngx_queue_t *q;

	if (ctx->c) {
		ngx_close_connection(ctx->c);
	}

	for (q = ngx_queue_head(&ctx->recv_ops);
		q != ngx_queue_sentinel(&ctx->recv_ops);
		q = ngx_queue_next(q)) {
		op = ngx_queue_data(q, keyless_op_st, recv_queue);

		if (op->send.start) {
			OPENSSL_cleanse(op->send.start, op->send.end - op->send.start);
			ngx_pfree(ctx->pool, op->send.start);
		}

		if (op->recv.start) {
			OPENSSL_cleanse(op->recv.start, op->recv.end - op->recv.start);
			ngx_pfree(ctx->pool, op->recv.start);
		}

		ngx_pfree(ctx->pool, op);
	}

	ngx_pfree(ctx->pool, ctx);
}

static void socket_read_handler(ngx_event_t *rev)
{
	ngx_connection_t *c;
	KEYLESS_CTX *ctx;
	keyless_op_st *op;
	ngx_queue_t *q;
	ngx_buf_t recv;
	kssl_header_st header;
	ssize_t size;

	c = rev->data;
	ctx = c->data;

	recv.start = ngx_palloc(c->pool, OP_BUFFER_SIZE);
	if (!recv.start) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"ngx_palloc failed to allocated recv buffer");
		return;
	}

	recv.pos = recv.start;
	recv.last = recv.start;
	recv.end = recv.start + OP_BUFFER_SIZE;

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

	for (q = ngx_queue_head(&ctx->recv_ops);
		q != ngx_queue_sentinel(&ctx->recv_ops);
		q = ngx_queue_next(q)) {
		op = ngx_queue_data(q, keyless_op_st, recv_queue);

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

static void socket_write_handler(ngx_event_t *wev)
{
	ngx_connection_t *c;
	KEYLESS_CTX *ctx;
	keyless_op_st *op;
	ngx_queue_t *q;
	ssize_t size;

	c = wev->data;
	ctx = c->data;

	if (ngx_queue_empty(&ctx->send_ops)) {
		return;
	}

	q = ngx_queue_head(&ctx->send_ops);
	op = ngx_queue_data(q, keyless_op_st, send_queue);

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

static enum ssl_private_key_result_t start_operation(kssl_opcode_et opcode, SSL *ssl,
		uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len)
{
	KEYLESS_CTX *ctx;
	keyless_op_st *op = NULL;
	ngx_int_t event;
	ngx_event_t *rev, *wev;
	ngx_socket_t s;
	ngx_connection_t *ngx_conn, *c = NULL;
	const struct sockaddr_in *sin;
#if NGX_HAVE_INET6
	const struct sockaddr_in6 *sin6;
#endif
	kssl_header_st header;
	kssl_operation_st operation;
	size_t length;

	ctx = ssl_get_keyless_ctx(ssl);
	if (!ctx) {
		goto error;
	}

	if (!ctx->c) {
		s = socket(ctx->address->sa_family, SOCK_DGRAM, 0);
		ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->log, 0, "UDP socket %d", s);
		if (s == (ngx_socket_t)-1) {
			ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_socket_errno,
				ngx_socket_n " failed");
			goto error;
		}

		c = ngx_get_connection(s, ctx->log);
		if (!c) {
			if (ngx_close_socket(s) == -1) {
				ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_socket_errno,
					ngx_close_socket_n "failed");
			}

			goto error;
		}

		if (ngx_nonblocking(s) == -1) {
			ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_socket_errno,
				ngx_nonblocking_n " failed");
			goto error;
		}

		c->data = ctx;

		c->recv = ngx_udp_recv;
		c->send = ngx_send;
		c->recv_chain = ngx_recv_chain;
		c->send_chain = ngx_send_chain;

		rev = c->read;
		wev = c->write;

		c->log = ctx->log;
		rev->log = c->log;
		wev->log = c->log;
		c->pool = ctx->pool;

		c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

		if (connect(s, ctx->address, ctx->address_len) == -1) {
			ngx_log_error(NGX_LOG_CRIT, ctx->log, ngx_socket_errno,
				"connect() failed");
			goto error;
		}

		/* UDP sockets are always ready to write */
		wev->ready = 1;

		event = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ?
				/* kqueue, epoll */                 NGX_CLEAR_EVENT:
				/* select, poll, /dev/poll */       NGX_LEVEL_EVENT;
				/* eventport event type has no meaning: oneshot only */

		if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
			goto error;
		}

		rev->handler = socket_read_handler;
		wev->handler = socket_write_handler;

		ctx->c = c;

		/* don't close the socket on error if we've gotten this far */
		c = NULL;
	}

	ngx_conn = ngx_ssl_get_connection(ssl);

	op = ngx_pcalloc(ctx->pool, sizeof(keyless_op_st));
	if (!op) {
		goto error;
	}

	op->ev = ngx_conn->write;

	header.version_maj = KSSL_VERSION_MAJ;
	header.version_min = KSSL_VERSION_MIN;

	if (RAND_bytes((uint8_t *)&header.id, sizeof(header.id)) != 1) {
		goto error;
	}

	op->id = header.id;

	kssl_zero_operation(&operation);

	operation.is_opcode_set = 1;
	operation.opcode = opcode;

	operation.is_ski_set = 1;
	operation.ski = ctx->ski;

	if (ctx->key.type == EVP_PKEY_RSA) {
		operation.is_digest_set = 1;
		operation.digest = ctx->digest;
	}

	operation.sni = (const unsigned char *)SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (operation.sni) {
		operation.is_sni_set = 1;
		operation.sni_len = ngx_strlen(operation.sni);
	}

	operation.is_payload_set = 1;
	operation.payload_len = in_len;
	operation.payload = in;

	switch (ngx_conn->sockaddr->sa_family) {
#if NGX_HAVE_INET6
		case AF_INET6:
			sin6 = (const struct sockaddr_in6 *)ngx_conn->sockaddr;

			operation.is_client_ip_set = 1;
			operation.client_ip_len = 16;
			operation.client_ip = (const unsigned char *)&sin6->sin6_addr.s6_addr[0];
			break;
#endif /* NGX_HAVE_INET6 */
		case AF_INET:
			sin = (const struct sockaddr_in *)ngx_conn->sockaddr;

			operation.is_client_ip_set = 1;
			operation.client_ip_len = 4;
			operation.client_ip = (const unsigned char *)&sin->sin_addr.s_addr;
			break;
	}

	if (ngx_connection_local_sockaddr(ngx_conn, NULL, 0) != NGX_OK) {
		goto error;
	}

	switch (ngx_conn->local_sockaddr->sa_family) {
#if NGX_HAVE_INET6
		case AF_INET6:
			sin6 = (const struct sockaddr_in6 *)ngx_conn->local_sockaddr;

			operation.is_server_ip_set = 1;
			operation.server_ip_len = 16;
			operation.server_ip = (const unsigned char *)&sin6->sin6_addr.s6_addr[0];
			break;
#endif /* NGX_HAVE_INET6 */
		case AF_INET:
			sin = (const struct sockaddr_in *)ngx_conn->local_sockaddr;

			operation.is_server_ip_set = 1;
			operation.server_ip_len = 4;
			operation.server_ip = (const unsigned char *)&sin->sin_addr.s_addr;
			break;
	}

	length = kssl_flatten_operation(&header, &operation, NULL);
	if (!length) {
		goto error;
	}

	op->send.start = ngx_palloc(ctx->pool, length);
	if (!op->send.start) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			"ngx_palloc failed to allocated recv buffer");
		goto error;
	}

	op->send.pos = op->send.start;
	op->send.last = op->send.start + length;
	op->send.end = op->send.start + length;

	if (!kssl_flatten_operation(&header, &operation, op->send.pos)) {
		goto error;
	}

	if (!SSL_set_ex_data(ssl, g_ssl_exdata_op_index, op)) {
		goto error;
	}

	ngx_queue_insert_tail(&ctx->recv_ops, &op->recv_queue);
	ngx_queue_insert_tail(&ctx->send_ops, &op->send_queue);

	ctx->c->write->handler(ctx->c->write);

	return ssl_private_key_retry;

error:
	if (c) {
		ngx_close_connection(c);
	}

	if (op) {
		if (op->send.start) {
			OPENSSL_cleanse(op->send.start, op->send.end - op->send.start);
			ngx_pfree(ctx->pool, op->send.start);
		}

		ngx_pfree(ctx->pool, op);
	}

	return ssl_private_key_failure;
}

static enum ssl_private_key_result_t operation_complete(SSL *ssl, uint8_t *out, size_t *out_len,
		size_t max_out)
{
	ngx_connection_t *c;
	KEYLESS_CTX *ctx;
	keyless_op_st *op;
	kssl_header_st header;
	kssl_operation_st operation;
	enum ssl_private_key_result_t rc;

	c = ngx_ssl_get_connection(ssl);

	ctx = ssl_get_keyless_ctx(ssl);
	if (!ctx) {
		return ssl_private_key_failure;
	}

	op = SSL_get_ex_data(ssl, g_ssl_exdata_op_index);
	if (!op) {
		return ssl_private_key_failure;
	}

	if (op->recv.last - op->recv.pos < (ssize_t)KSSL_HEADER_SIZE) {
		return ssl_private_key_retry;
	}

	assert(kssl_parse_header(op->recv.pos, &header));
	assert(header.version_maj == KSSL_VERSION_MAJ);
	assert(header.id == op->id);

	op->recv.pos += KSSL_HEADER_SIZE;

	if (!kssl_parse_message_payload(op->recv.pos, header.length, &operation)) {
		rc = ssl_private_key_failure;
		goto cleanup;
	}

	op->recv.pos += header.length;

	if (op->recv.last - op->recv.pos != 0) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0, "trailing data recieved");
	}

	switch (operation.opcode) {
		case KSSL_OP_RESPONSE:
			if (operation.payload_len > max_out) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0,
					"payload longer than max_out");

				rc = ssl_private_key_failure;
				break;
			}

			ngx_memcpy(out, operation.payload, operation.payload_len);
			*out_len = operation.payload_len;

			rc = ssl_private_key_success;
			break;
		case KSSL_OP_ERROR:
			if (operation.payload_len == 1) {
				ngx_log_error(NGX_LOG_ERR, c->log, 0, "keyless error: %s",
					kssl_error_string(operation.payload[0]));
			}

			rc = ssl_private_key_failure;
			break;
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
		case KSSL_OP_PING:
		case KSSL_OP_PONG:
		case KSSL_OP_ACTIVATE:
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				kssl_error_string(KSSL_ERROR_UNEXPECTED_OPCODE));

			rc = ssl_private_key_failure;
			break;
		default:
			ngx_log_error(NGX_LOG_ERR, c->log, 0,
				kssl_error_string(KSSL_ERROR_BAD_OPCODE));

			rc = ssl_private_key_failure;
			break;
	}

cleanup:
	OPENSSL_cleanse(op->recv.start, op->recv.end - op->recv.start);
	ngx_pfree(ctx->pool, op->recv.start);

	op->recv.start = NULL;
	op->recv.pos = NULL;
	op->recv.last = NULL;
	op->recv.end = NULL;

	ngx_pfree(ctx->pool, op);

	return rc;
}

static int key_type(SSL *ssl)
{
	const KEYLESS_CTX *ctx;

	ctx = ssl_get_keyless_ctx(ssl);
	if (!ctx) {
		return 0;
	}

	return ctx->key.type;
}

static size_t key_max_signature_len(SSL *ssl)
{
	const KEYLESS_CTX *ctx;

	ctx = ssl_get_keyless_ctx(ssl);
	if (!ctx) {
		return 0;
	}

	return ctx->key.sig_len;
}

static enum ssl_private_key_result_t key_sign(SSL *ssl, uint8_t *out, size_t *out_len,
		size_t max_out, const EVP_MD *md, const uint8_t *in, size_t in_len)
{
	kssl_opcode_et opcode;
	const KEYLESS_CTX *ctx;

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

	ctx = ssl_get_keyless_ctx(ssl);
	if (!ctx) {
		return ssl_private_key_failure;
	}

	if (ctx->key.type == EVP_PKEY_EC) {
		opcode |= KSSL_OP_ECDSA_MASK;
	}

	return start_operation(opcode, ssl, out, out_len, max_out, in, in_len);
}

static enum ssl_private_key_result_t key_decrypt(SSL *ssl, uint8_t *out, size_t *out_len,
		size_t max_out, const uint8_t *in, size_t in_len)
{
	return start_operation(KSSL_OP_RSA_DECRYPT_RAW, ssl, out, out_len, max_out, in, in_len);
}

int ngx_http_keyless_ffi_set_private_key(ngx_http_request_t *r, const char *addr, size_t addr_len,
		char **err)
{
	ngx_ssl_conn_t *ssl_conn;
	ngx_connection_t *c;
	X509 *x509;
	KEYLESS_CTX *ctx;
	ngx_pool_cleanup_t *cln;

	if (!r->connection || !r->connection->ssl) {
		*err = "bad request";
		return NGX_ERROR;
	}

	ssl_conn = r->connection->ssl->connection;
	if (!ssl_conn) {
		*err = "bad ssl conn";
		return NGX_ERROR;
	}

	x509 = SSL_get_certificate(ssl_conn);
	if (!x509) {
		*err = "SSL_get_certificate failed";
		return NGX_ERROR;
	}

	c = ngx_ssl_get_connection(ssl_conn);

	ctx = keyless_parse_and_create(c->pool, c->log, x509, addr, addr_len);
	if (!ctx) {
		*err = "keyless_parse_and_create failed";
		return NGX_ERROR;
	}

	if (!keyless_attach_ssl(ssl_conn, ctx)) {
		keyless_free(ctx);

		*err = "keyless_attach_ssl failed";
		return NGX_ERROR;
	}

	cln = ngx_pool_cleanup_add(c->pool, 0);
	if (!cln) {
		keyless_free(ctx);

		*err = "ngx_pool_cleanup_add failed";
		return NGX_ERROR;
	}

	cln->handler = (ngx_pool_cleanup_pt)keyless_free;
	cln->data = ctx;

	return NGX_OK;
}

#endif /* NGX_HTTP_SSL */

ngx_http_module_t ngx_keyless_module_ctx = {
	NULL, /* preconfiguration */
	NULL, /* postconfiguration */

	NULL, /* create main configuration */
	NULL, /* init main configuration */

	NULL, /* create server configuration */
	NULL, /* merge server configuration */

	NULL, /* create location configuration */
	NULL  /* merge location configuration */
};

ngx_module_t ngx_keyless_module = {
	NGX_MODULE_V1,
	&ngx_keyless_module_ctx, /* module context */
	NULL,                       /* module directives */
	NGX_CORE_MODULE,            /* module type */
	NULL,                       /* init master */
	NULL,                       /* init module */
	NULL,                       /* init process */
	NULL,                       /* init thread */
	NULL,                       /* exit thread */
#if NGX_HTTP_SSL
	ngx_keyless_exit_process,   /* exit process */
#else /* NGX_HTTP_SSL */
	NULL,                       /* exit process */
#endif /* NGX_HTTP_SSL */
	NULL,                       /* exit master */
	NGX_MODULE_V1_PADDING
};
