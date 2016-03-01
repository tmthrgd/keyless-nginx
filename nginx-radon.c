#include <nginx-radon.h>

#if NGX_HTTP_SSL

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define STATE_BUFFER_SIZE 2*1024

#define REMOTE_ADDR_LEN 16

static enum ssl_private_key_result_t operation_complete(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out);

static int key_type(SSL *ssl);
static size_t key_max_signature_len(SSL *ssl);
static enum ssl_private_key_result_t key_sign(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const EVP_MD *md, const uint8_t *in, size_t in_len);
#define key_sign_complete operation_complete
static enum ssl_private_key_result_t key_decrypt(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len);
#define key_decrypt_complete operation_complete

typedef struct radon_ctx_st {
	struct {
		int type;
		size_t sig_len;
	} key;
	struct sockaddr *address;
	size_t address_len;
	unsigned char ski[SHA_DIGEST_LENGTH];
} RADON_CTX;

typedef struct {
	ngx_connection_t *c;
	ngx_connection_t *ngx_conn;
	char buffer[STATE_BUFFER_SIZE];
	size_t buffer_pos;
} state_st;

#define OP_ECDSA_MASK 0x10

typedef enum {
	OP_RSA_DECRYPT_RAW    = 0x08,

	// Sign data using RSA
	OP_RSA_SIGN_MD5SHA1   = 0x02,
	OP_RSA_SIGN_SHA1      = 0x03,
	OP_RSA_SIGN_SHA224    = 0x04,
	OP_RSA_SIGN_SHA256    = 0x05,
	OP_RSA_SIGN_SHA384    = 0x06,
	OP_RSA_SIGN_SHA512    = 0x07,

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
	unsigned char remote_addr[REMOTE_ADDR_LEN];
	unsigned char ski[SHA_DIGEST_LENGTH];
} cmd_req_st;

static int g_ssl_exdata_ctx_index = -1;
static int g_ssl_ctx_exdata_ctx_index = -1;
static int g_ssl_exdata_state_index = -1;

const SSL_PRIVATE_KEY_METHOD key_method = {
	key_type,
	key_max_signature_len,
	key_sign,
	key_sign_complete,
	key_decrypt,
	key_decrypt_complete,
};

RADON_CTX *radon_create(ngx_pool_t *pool, X509 *cert, struct sockaddr *address, size_t address_len)
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

	ctx = ngx_pcalloc(pool, sizeof(RADON_CTX));
	if (!ctx) {
		goto error;
	}

	ctx->key.type = EVP_PKEY_id(public_key);
	ctx->key.sig_len = EVP_PKEY_size(public_key);

	ctx->address = address;
	ctx->address_len = address_len;

	if (!cert->cert_info
		|| !cert->cert_info->key
		|| !cert->cert_info->key->public_key
		|| !cert->cert_info->key->public_key->length
		|| !SHA1(cert->cert_info->key->public_key->data, cert->cert_info->key->public_key->length, ctx->ski)) {
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
	if (public_key) {
		EVP_PKEY_free(public_key);
	}

	if (ctx) {
		ngx_pfree(pool, ctx);
	}

	return NULL;
}

RADON_CTX *radon_parse_and_create(ngx_pool_t *pool, X509 *cert, const char *addr, size_t addr_len)
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

	return radon_create(pool, cert, url.addrs[0].sockaddr, url.addrs[0].socklen);
}

int radon_attach_ssl(SSL *ssl, RADON_CTX *ctx)
{
	if (!SSL_set_ex_data(ssl, g_ssl_exdata_ctx_index, ctx)) {
		return 0;
	}

	SSL_set_private_key_method(ssl, &key_method);
	return 1;
}

int radon_attach_ssl_ctx(SSL_CTX *ssl_ctx, RADON_CTX *ctx)
{
	if (!SSL_CTX_set_ex_data(ssl_ctx, g_ssl_ctx_exdata_ctx_index, ctx)) {
		return 0;
	}

	SSL_CTX_set_private_key_method(ssl_ctx, &key_method);
	return 1;
}

void radon_free(ngx_pool_t *pool, RADON_CTX *ctx)
{
	ngx_pfree(pool, ctx);
}

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

	if (n == NGX_ERROR) {
		return;
	}

	if (n == NGX_AGAIN) {
		ngx_handle_read_event(c->read, 0);
		return;
	}

	state->buffer_pos += n;

	ngx_post_event(ngx_conn->write, &ngx_posted_events);
}

static enum ssl_private_key_result_t start_operation(operation_et operation, SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len)
{
	int sock = -1;
	RADON_CTX *ctx = NULL;
	state_st *state = NULL;
	cmd_req_st *cmd = NULL;
	size_t i = 0;
	int wrote = -1;
	ngx_int_t event;
	ngx_event_t *rev, *wev;
	ngx_connection_t *ngx_conn, *c = NULL;
	struct sockaddr_in *sin;
#if NGX_HAVE_INET6
	struct sockaddr_in6 *sin6;
#endif

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

	ngx_conn = ngx_ssl_get_connection(ssl);

	state = ngx_pcalloc(ngx_conn->pool, sizeof(state_st));
	if (!state) {
		goto error;
	}

	state->ngx_conn = ngx_conn;

	sock = socket(ctx->address->sa_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sock == -1) {
		goto error;
	}

	c = ngx_get_connection(sock, ngx_conn->log);
	if (!c) {
		goto error;
	}
	state->c = c;

	c->data = state;

	rev = c->read;
	wev = c->write;

	rev->log = ngx_conn->log;
	wev->log = ngx_conn->log;

	c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

	if (connect(sock, ctx->address, ctx->address_len) == -1) {
		goto error;
	}

	/* UDP sockets are always ready to write */
	wev->ready = 1;

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

	cmd = (cmd_req_st *)state->buffer;
	cmd->operation = operation;
	cmd->in_len = (unsigned long long int)in_len;

	switch (ngx_conn->sockaddr->sa_family) {
#if NGX_HAVE_INET6
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ngx_conn->sockaddr;
			memcpy((char *)cmd->remote_addr, (char *)&sin6->sin6_addr.s6_addr, 16);
			break;
#endif /* NGX_HAVE_INET6 */
		case AF_INET:
			sin = (struct sockaddr_in *)ngx_conn->sockaddr;

			// v4InV6Prefix: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff

			/*
			 * set by memset:
			 * 	cmd->remote_addr[0..9] = 0
			 */
			cmd->remote_addr[10] = cmd->remote_addr[11] = 0xff;
			memcpy((char *)cmd->remote_addr + 12, (char *)&sin->sin_addr.s_addr, 4);
			break;
	}

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

	return ssl_private_key_retry;

error:
	if (state) {
		OPENSSL_cleanse(state, sizeof(state_st));
		ngx_pfree(ngx_conn->pool, state);
	}

	if (c) {
		ngx_close_connection(c);
	} else if (sock != -1) {
		close(sock);
	}

	return ssl_private_key_failure;
}

static enum ssl_private_key_result_t operation_complete(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out)
{
	ngx_connection_t *c;
	state_st *state = NULL;
	unsigned long long int *len;
	enum ssl_private_key_result_t ret;

	state = SSL_get_ex_data(ssl, g_ssl_exdata_state_index);
	if (!state) {
		ret = ssl_private_key_failure;
		goto cleanup;
	}

	len = (unsigned long long int *)state->buffer;

	if (state->buffer_pos < sizeof(unsigned long long int)
		|| state->buffer_pos < sizeof(unsigned long long int) + *len) {
		return ssl_private_key_retry;
	}

	if (*len == 0 || *len > max_out) {
		ret = ssl_private_key_failure;
		goto cleanup;
	}

	memcpy((char *)out, state->buffer + sizeof(unsigned long long int), *len);

	*out_len = *len;
	ret = ssl_private_key_success;
cleanup:
	if (state) {
		if (state->c) {
			ngx_close_connection(state->c);
		}

		OPENSSL_cleanse(state, sizeof(state_st));

		c = ngx_ssl_get_connection(ssl);
		ngx_pfree(c->pool, state);
	}

	return ret;
}

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
		case NID_sha224:
			operation = OP_RSA_SIGN_SHA224;
			break;
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

int ngx_http_viper_lua_ffi_radon_set_private_key(ngx_http_request_t *r, const char *addr, size_t addr_len, char **err)
{
	ngx_ssl_conn_t *ssl_conn;
	ngx_connection_t *c;
	X509 *x509;
	RADON_CTX *ctx;

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

	ctx = radon_parse_and_create(c->pool, x509, addr, addr_len);
	if (!ctx) {
		*err = "radon_create failed";
		return NGX_ERROR;
	}

	if (!radon_attach_ssl(ssl_conn, ctx)) {
		radon_free(c->pool, ctx);

		*err = "radon_attach failed";
		return NGX_ERROR;
	}

	return NGX_OK;
}

#endif /* NGX_HTTP_SSL */
