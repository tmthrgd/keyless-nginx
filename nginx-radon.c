#include <nginx-radon.h>

#if !RADON_FOR_NGINX || NGX_HTTP_SSL

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#if RADON_FOR_NGINX
#	include <nginx.h>
#	include <ngx_core.h>
#	include <ngx_http.h>
#	ifdef OPENSSL_IS_BORINGSSL
#		include <ngx_event.h>
#	endif /* OPENSSL_IS_BORINGSSL */
#endif /* RADON_FOR_NGINX */

#define STATE_BUFFER_SIZE 2*1024

#ifndef OPENSSL_IS_BORINGSSL
enum ssl_private_key_result_t {
	ssl_private_key_success,
	// ssl_private_key_retry,
	ssl_private_key_failure,
};
#endif /* OPENSSL_IS_BORINGSSL */

static enum ssl_private_key_result_t operation_complete(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out);

#ifdef OPENSSL_IS_BORINGSSL
static int key_type(SSL *ssl);
static size_t key_max_signature_len(SSL *ssl);
static enum ssl_private_key_result_t key_sign(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const EVP_MD *md, const uint8_t *in, size_t in_len);
#define key_sign_complete operation_complete
static enum ssl_private_key_result_t key_decrypt(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len);
#define key_decrypt_complete operation_complete
#endif /* OPENSSL_IS_BORINGSSL */

typedef struct radon_ctx_st {
#ifdef OPENSSL_IS_BORINGSSL
	struct {
		int type;
		size_t sig_len;
	} key;
#endif /* OPENSSL_IS_BORINGSSL */
	struct sockaddr *address;
	size_t address_len;
	unsigned char ski[SHA_DIGEST_LENGTH];
} RADON_CTX;

typedef struct {
	int sock;
#if RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL)
	ngx_connection_t *c;
	ngx_connection_t *ngx_conn;
#endif
	char buffer[STATE_BUFFER_SIZE];
	size_t buffer_pos;
} state_st;

#define OP_ECDSA_MASK 0x10
#define OP_CUSTOM_MASK 0x100

typedef enum {
	OP_RSA_DECRYPT_RAW    = 0x08,

	// Sign data using RSA
	OP_RSA_SIGN_MD5SHA1   = 0x02,
	OP_RSA_SIGN_SHA1      = 0x03,
	OP_RSA_SIGN_SHA224    = 0x04,
	OP_RSA_SIGN_SHA256    = 0x05,
	OP_RSA_SIGN_SHA384    = 0x06,
	OP_RSA_SIGN_SHA512    = 0x07,
	OP_RSA_SIGN_RAW       = OP_CUSTOM_MASK | 0x01,

	// Sign data using ECDSA
	OP_ECDSA_SIGN_MD5SHA1 = 0x12,
	OP_ECDSA_SIGN_SHA1    = 0x13,
	OP_ECDSA_SIGN_SHA224  = 0x14,
	OP_ECDSA_SIGN_SHA256  = 0x15,
	OP_ECDSA_SIGN_SHA384  = 0x16,
	OP_ECDSA_SIGN_SHA512  = 0x17,
} operation_et;

typedef struct __attribute__((__packed__)) {
	unsigned short operation;
	unsigned long long int in_len;
	unsigned char ski[SHA_DIGEST_LENGTH];
} cmd_req_st;

static int g_ssl_exdata_ctx_index = -1;
static int g_ssl_ctx_exdata_ctx_index = -1;
static int g_ssl_exdata_state_index = -1;

#ifdef OPENSSL_IS_BORINGSSL
const SSL_PRIVATE_KEY_METHOD key_method = {
	key_type,
	key_max_signature_len,
	key_sign,
	key_sign_complete,
	key_decrypt,
	key_decrypt_complete,
};
#endif /* OPENSSL_IS_BORINGSSL */

RADON_CTX *radon_create(X509 *cert, struct sockaddr *address, size_t address_len)
{
	EVP_PKEY *public_key = NULL;
	RADON_CTX *ctx = NULL;

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

	if (g_ssl_exdata_state_index == -1) {
		g_ssl_exdata_state_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
		if (g_ssl_exdata_state_index == -1) {
			goto error;
		}
	}

	public_key = X509_get_pubkey(cert);
	if (!public_key) {
		goto error;
	}

#ifdef OPENSSL_IS_BORINGSSL
	ctx = OPENSSL_malloc(sizeof(RADON_CTX));
	if (!ctx) {
		goto error;
	}

	memset(ctx, 0, sizeof(RADON_CTX));
#else /* OPENSSL_IS_BORINGSSL */
	ctx = OPENSSL_zalloc(sizeof(RADON_CTX));
	if (!ctx) {
		goto error;
	}
#endif /* OPENSSL_IS_BORINGSSL */

	ctx->key.type = EVP_PKEY_id(public_key);
	ctx->key.sig_len = EVP_PKEY_size(public_key);

	ctx->address = OPENSSL_malloc(address_len);
	if (!ctx->address) {
		goto error;
	}

	ctx->address_len = address_len;
	memcpy((char *)ctx->address, (char *)address, address_len);

	if (cert->cert_info == NULL
		|| cert->cert_info->key == NULL
		|| cert->cert_info->key->public_key == NULL
		|| cert->cert_info->key->public_key->length == 0
		|| SHA1(cert->cert_info->key->public_key->data, cert->cert_info->key->public_key->length, ctx->ski) == NULL) {
		goto error;
	}

	switch (ctx->key.type) {
		case EVP_PKEY_RSA:
		case EVP_PKEY_EC:
			break;
		default:
			goto error;
	}

	return ctx;

error:
	if (public_key != NULL) {
		EVP_PKEY_free(public_key);
	}

	if (ctx != NULL) {
		if (ctx->address != NULL) {
			OPENSSL_free(ctx->address); ctx->address = NULL;
		}

		OPENSSL_free(ctx);
	}

	return NULL;
}

#if RADON_FOR_NGINX
RADON_CTX *radon_create_from_string(ngx_pool_t *pool, X509 *cert, const char *addr, size_t addr_len)
{
	ngx_url_t url;

	ngx_memzero(&url, sizeof(ngx_url_t));

	url.url.len = addr_len;
	url.url.data = (unsigned char *)addr;
	url.default_port = (in_port_t)RADON_DEFAULT_PORT;
	url.no_resolve = 1;

	if (ngx_parse_url(pool, &url) != NGX_OK || !url.addrs || !url.addrs[0].sockaddr) {
		return NULL;
	}

	return radon_create(cert, url.addrs[0].sockaddr, url.addrs[0].socklen);
}
#endif

int radon_attach_ssl(SSL *ssl, RADON_CTX *ctx)
{
	if (!SSL_set_ex_data(ssl, g_ssl_exdata_ctx_index, ctx)) {
		return 0;
	}

#ifdef OPENSSL_IS_BORINGSSL
	SSL_set_private_key_method(ssl, &key_method);
#else /* OPENSSL_IS_BORINGSSL */
#	error "only supported on BoringSSL"
#endif /* OPENSSL_IS_BORINGSSL */
	return 1;
}

int radon_attach_ssl_ctx(SSL_CTX *ssl_ctx, RADON_CTX *ctx)
{
	if (!SSL_CTX_set_ex_data(ssl_ctx, g_ssl_ctx_exdata_ctx_index, ctx)) {
		return 0;
	}

#ifdef OPENSSL_IS_BORINGSSL
	SSL_CTX_set_private_key_method(ssl_ctx, &key_method);
#else /* OPENSSL_IS_BORINGSSL */
#	error "only supported on BoringSSL"
#endif /* OPENSSL_IS_BORINGSSL */
	return 1;
}

void radon_free(RADON_CTX *ctx)
{
	if (ctx->address != NULL) {
		OPENSSL_free(ctx->address);
	}

	OPENSSL_free(ctx);
}

#if RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL)
static void socket_udp_handler(ngx_event_t *ev)
{
	ngx_connection_t *c, *ngx_conn;
	state_st *state;
	ssize_t n;

	c = ev->data;
	state = c->data;
	ngx_conn = state->ngx_conn;

	if (STATE_BUFFER_SIZE - state->buffer_pos <= 0) {
		return;
	}

	n = ngx_udp_recv(c, (u_char *)state->buffer + state->buffer_pos, STATE_BUFFER_SIZE - state->buffer_pos);

	if (n == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ngx_handle_read_event(c->read, 0);
		}

		return;
	}

	state->buffer_pos += n;

	ngx_post_event(ngx_conn->write, &ngx_posted_events);
}
#endif /* RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL) */

static enum ssl_private_key_result_t start_operation(operation_et operation, SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len)
{
	int sock = -1;
	RADON_CTX *ctx = NULL;
	state_st *state = NULL;
	cmd_req_st *cmd = NULL;
	size_t i = 0;
	int wrote = -1;
#if RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL)
	ngx_int_t event;
	ngx_event_t *rev, *wev;
	ngx_connection_t *ngx_conn, *c = NULL;
#endif /* RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL) */

	if (in_len + sizeof(cmd_req_st) > STATE_BUFFER_SIZE) {
		goto error;
	}

	ctx = SSL_get_ex_data(ssl, g_ssl_exdata_ctx_index);
	if (!ctx) {
		ctx = SSL_CTX_get_ex_data(ssl->ctx, g_ssl_ctx_exdata_ctx_index);
		if (!ctx) {
			goto error;
		}
	}

#ifdef OPENSSL_IS_BORINGSSL
	state = OPENSSL_malloc(sizeof(state_st));
	if (!state) {
		goto error;
	}

	memset(state, 0, sizeof(state_st));
#else /* OPENSSL_IS_BORINGSSL */
	state = OPENSSL_zalloc(sizeof(state_st));
	if (!state) {
		goto error;
	}
#endif /* OPENSSL_IS_BORINGSSL */

	sock = socket(ctx->address->sa_family, SOCK_DGRAM
#ifdef OPENSSL_IS_BORINGSSL
		| SOCK_NONBLOCK
#endif /* OPENSSL_IS_BORINGSSL */
		, 0);
	if (sock == -1) {
		goto error;
	}

#if RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL)
	ngx_conn = ngx_ssl_get_connection(ssl);
	state->ngx_conn = ngx_conn;

	c = ngx_get_connection(sock, ngx_conn->log);
	if (c == NULL) {
		goto error;
	}
	state->c = c;

	c->data = state;

	rev = c->read;
	wev = c->write;

	rev->log = ngx_conn->log;
	wev->log = ngx_conn->log;

	c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);
#endif /* RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL) */

	if (connect(sock, ctx->address, ctx->address_len) == -1) {
		goto error;
	}
	state->sock = sock;

#if RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL)
	/* UDP sockets are always ready to write */
	wev->ready = 1;

	/* begin: should this be *after* write */
	if (ngx_add_event) {
		event = (ngx_event_flags & NGX_USE_CLEAR_EVENT) ?
				/* kqueue, epoll */                 NGX_CLEAR_EVENT:
				/* select, poll, /dev/poll */       NGX_LEVEL_EVENT;
				/* eventport event type has no meaning: oneshot only */

		if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
			goto error;
		}
	} else {
		/* rtsig */

		if (ngx_add_conn(c) == NGX_ERROR) {
			goto error;
		}
	}

	rev->handler = socket_udp_handler;
	/* end: should this be *after* write */
#endif /* RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL) */

	cmd = (cmd_req_st *)state->buffer;
	cmd->operation = operation;
	cmd->in_len = (unsigned long long int)in_len;
	memcpy((char *)cmd->ski, (char *)ctx->ski, SHA_DIGEST_LENGTH);

	memcpy(state->buffer + sizeof(cmd_req_st), (char *)in, in_len);

	if (!SSL_set_ex_data(ssl, g_ssl_exdata_state_index, state)) {
		goto error;
	}

	for (i = 0; i < in_len + sizeof(cmd_req_st); i += wrote) {
		wrote = write(sock, state->buffer + i, in_len + sizeof(cmd_req_st) - i);
		if (wrote == -1) {
			goto error;
		}
	}

	OPENSSL_cleanse(state->buffer, STATE_BUFFER_SIZE);

#ifdef OPENSSL_IS_BORINGSSL
	return ssl_private_key_retry;
#else /* OPENSSL_IS_BORINGSSL */
	return operation_complete(ssl, out, out_len, max_out);
#endif /* OPENSSL_IS_BORINGSSL */

error:
	if (state != NULL) {
#ifdef OPENSSL_IS_BORINGSSL
		OPENSSL_cleanse(state, sizeof(state_st));
		OPENSSL_free(state);
#else /* OPENSSL_IS_BORINGSSL */
		OPENSSL_clear_free(state, sizeof(state_st));
#endif /* OPENSSL_IS_BORINGSSL */
	}

#if RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL)
	if (c != NULL) {
		ngx_free_connection(c);
	}
#endif /* RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL) */

	if (sock != -1) {
		close(sock);
	}

	return ssl_private_key_failure;
}

static enum ssl_private_key_result_t operation_complete(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out)
{
	state_st *state = NULL;
	unsigned long long *len;
	enum ssl_private_key_result_t ret;

	state = SSL_get_ex_data(ssl, g_ssl_exdata_state_index);
	if (!state) {
		ret = ssl_private_key_failure;
		goto cleanup;
	}

#if !RADON_FOR_NGINX || !defined(OPENSSL_IS_BORINGSSL)
	{
	ssize_t n = read(state->sock, state->buffer + state->buffer_pos, STATE_BUFFER_SIZE - state->buffer_pos);

	if (n == -1) {
#ifdef OPENSSL_IS_BORINGSSL
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return ssl_private_key_retry;
		}
#endif /* OPENSSL_IS_BORINGSSL */

		ret = ssl_private_key_failure;
		goto cleanup;
	}

	state->buffer_pos += n;
	}
#endif /* !RADON_FOR_NGINX || !defined(OPENSSL_IS_BORINGSSL) */

	len = (unsigned long long *)state->buffer;

	if (state->buffer_pos < sizeof(unsigned long long)) {
#if RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL)
		return ssl_private_key_retry;
#else /* RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL) */
		ret = ssl_private_key_failure;
		goto cleanup;
#endif /* RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL) */
	}

	if (*len == 0 || *len > max_out) {
		ret = ssl_private_key_failure;
		goto cleanup;
	}

	if (state->buffer_pos - sizeof(unsigned long long) < *len) {
#ifdef OPENSSL_IS_BORINGSSL
		return ssl_private_key_retry;
#else /* OPENSSL_IS_BORINGSSL */
		ret = ssl_private_key_failure;
		goto cleanup;
#endif /* OPENSSL_IS_BORINGSSL */
	}

	memcpy((char *)out, state->buffer + sizeof(unsigned long long), *len);

	*out_len = *len;
	ret = ssl_private_key_success;
cleanup:
	if (state != NULL) {
#if RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL)
		if (state->c != NULL) {
			ngx_free_connection(state->c); state->c = NULL;
		}
#endif /* RADON_FOR_NGINX && defined(OPENSSL_IS_BORINGSSL) */

		if (state->sock != -1) {
			close(state->sock); state->sock = -1;
		}

#ifdef OPENSSL_IS_BORINGSSL
		OPENSSL_cleanse(state, sizeof(state_st));
		OPENSSL_free(state);
#else /* OPENSSL_IS_BORINGSSL */
		OPENSSL_clear_free(state, sizeof(state_st));
#endif /* OPENSSL_IS_BORINGSSL */
	}

	return ret;
}

#ifdef OPENSSL_IS_BORINGSSL
static int key_type(SSL *ssl)
{
	RADON_CTX *ctx = NULL;

	ctx = SSL_get_ex_data(ssl, g_ssl_exdata_ctx_index);
	if (!ctx) {
		ctx = SSL_CTX_get_ex_data(ssl->ctx, g_ssl_ctx_exdata_ctx_index);
		if (!ctx) {
			return 0;
		}
	}

	return ctx->key.type;
}

static size_t key_max_signature_len(SSL *ssl)
{
	RADON_CTX *ctx = NULL;

	ctx = SSL_get_ex_data(ssl, g_ssl_exdata_ctx_index);
	if (!ctx) {
		ctx = SSL_CTX_get_ex_data(ssl->ctx, g_ssl_ctx_exdata_ctx_index);
		if (!ctx) {
			return 0;
		}
	}

	return ctx->key.sig_len;
}

static enum ssl_private_key_result_t key_sign(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const EVP_MD *md, const uint8_t *in, size_t in_len)
{
	operation_et operation;
	RADON_CTX *ctx = NULL;

	switch (EVP_MD_type(md)) {
		case NID_sha1:
			operation = OP_RSA_SIGN_SHA1;
			break;
		// sha224
		case NID_sha256:
			operation = OP_RSA_SIGN_SHA256;
			break;
		case NID_sha384:
			operation = OP_RSA_SIGN_SHA384;
			break;
		case NID_sha512:
			operation = OP_RSA_SIGN_SHA512;
			break;
		case NID_md5_sha1:
			operation = OP_RSA_SIGN_MD5SHA1;
			break;
		default:
			return ssl_private_key_failure;
	}

	ctx = SSL_get_ex_data(ssl, g_ssl_exdata_ctx_index);
	if (!ctx) {
		ctx = SSL_CTX_get_ex_data(ssl->ctx, g_ssl_ctx_exdata_ctx_index);
		if (!ctx) {
			return ssl_private_key_failure;
		}
	}

	if (ctx->key.type == EVP_PKEY_EC) {
		operation |= OP_ECDSA_MASK;
	}

	return start_operation(operation, ssl, out, out_len, max_out, in, in_len);
}

static enum ssl_private_key_result_t key_decrypt(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len)
{
	return start_operation(OP_RSA_DECRYPT_RAW, ssl, out, out_len, max_out, in, in_len);
}
#endif /* OPENSSL_IS_BORINGSSL */

#if RADON_FOR_NGINX
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

	if (!radon_attach_ssl(ssl_conn, ctx)) {
		radon_free(ctx);

		*err = "radon_attach failed";
		return NGX_ERROR;
	}

	return NGX_OK;
}
#endif /* RADON_FOR_NGINX */

#endif /* NGX_HTTP_SSL */
