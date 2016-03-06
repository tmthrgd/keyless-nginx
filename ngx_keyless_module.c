#include <ngx_keyless_module.h>

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if NGX_HTTP_SSL

#include <ngx_event.h>

#include <kssl.h>
#include <kssl_helpers.h>

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

#define STATE_BUFFER_SIZE 2*1024

static enum ssl_private_key_result_t operation_complete(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out);

static int key_type(SSL *ssl);
static size_t key_max_signature_len(SSL *ssl);
static enum ssl_private_key_result_t key_sign(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const EVP_MD *md, const uint8_t *in, size_t in_len);
#define key_sign_complete operation_complete
static enum ssl_private_key_result_t key_decrypt(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len);
#define key_decrypt_complete operation_complete

typedef struct keyless_ctx_st {
	struct {
		int type;
		size_t sig_len;
	} key;
	struct sockaddr *address;
	size_t address_len;
	unsigned char ski[KSSL_SKI_SIZE];
	unsigned char digest[KSSL_DIGEST_SIZE];
} KEYLESS_CTX;

typedef struct {
	unsigned int req_id;
	ngx_connection_t *c;
	ngx_connection_t *ngx_conn;
	size_t buffer_pos;
	unsigned char buffer[STATE_BUFFER_SIZE];
} state_st;

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

KEYLESS_CTX *keyless_create(ngx_pool_t *pool, X509 *cert, struct sockaddr *address, size_t address_len)
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

	ctx = ngx_pcalloc(pool, sizeof(KEYLESS_CTX));
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
		|| !cert->cert_info->key->public_key->length) {
		goto error;
	}

	if (!SHA1(cert->cert_info->key->public_key->data, cert->cert_info->key->public_key->length, ctx->ski)) {
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

			for (i = 0; *(hex + i); i++) {
				*(hex + i) = ngx_toupper(*(hex + i));
	    		}

			if (!SHA256((const uint8_t *)hex, ngx_strlen(hex), ctx->digest)) {
				goto error;
			}

			break;
		case EVP_PKEY_EC:
			break;
		default:
			goto error;
	}

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

KEYLESS_CTX *keyless_parse_and_create(ngx_pool_t *pool, X509 *cert, const char *addr, size_t addr_len)
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

	return keyless_create(pool, cert, url.addrs[0].sockaddr, url.addrs[0].socklen);
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

void keyless_free(ngx_pool_t *pool, KEYLESS_CTX *ctx)
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

static enum ssl_private_key_result_t start_operation(kssl_opcode_et opcode, SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len)
{
	int sock = -1;
	KEYLESS_CTX *ctx = NULL;
	state_st *state = NULL;
	size_t i = 0;
	int wrote = -1;
	ngx_int_t event;
	ngx_event_t *rev, *wev;
	ngx_connection_t *ngx_conn, *c = NULL;
	struct sockaddr_in *sin;
#if NGX_HAVE_INET6
	struct sockaddr_in6 *sin6;
#endif
	kssl_header_st header;
	kssl_operation_st operation;
	size_t length;

	if (in_len + KSSL_HEADER_SIZE > STATE_BUFFER_SIZE) {
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

	header.version_maj = KSSL_VERSION_MAJ;
	header.version_min = KSSL_VERSION_MIN;

	if (RAND_bytes((uint8_t *)&header.id, sizeof(header.id)) != 1) {
		goto error;
	}

	state->req_id = header.id;

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
			sin6 = (struct sockaddr_in6 *)ngx_conn->sockaddr;

			operation.is_client_ip_set = 1;
			operation.client_ip_len = 16;
			operation.client_ip = (const unsigned char *)&sin6->sin6_addr.s6_addr;
			break;
#endif /* NGX_HAVE_INET6 */
		case AF_INET:
			sin = (struct sockaddr_in *)ngx_conn->sockaddr;

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
			sin6 = (struct sockaddr_in6 *)ngx_conn->local_sockaddr;

			operation.is_server_ip_set = 1;
			operation.server_ip_len = 16;
			operation.server_ip = (const unsigned char *)&sin6->sin6_addr.s6_addr;
			break;
#endif /* NGX_HAVE_INET6 */
		case AF_INET:
			sin = (struct sockaddr_in *)ngx_conn->local_sockaddr;

			operation.is_server_ip_set = 1;
			operation.server_ip_len = 4;
			operation.server_ip = (const unsigned char *)&sin->sin_addr.s_addr;
			break;
	}

	length = STATE_BUFFER_SIZE;
	if (!kssl_flatten_operation(&header, &operation, (unsigned char *)state->buffer, &length)) {
		goto error;
	}

	if (!SSL_set_ex_data(ssl, g_ssl_exdata_state_index, state)) {
		goto error;
	}

	for (i = 0; i < length; i += wrote) {
		wrote = write(sock, state->buffer + i, length - i);
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
	kssl_header_st header;
	kssl_operation_st operation;
	enum ssl_private_key_result_t rc;

	state = SSL_get_ex_data(ssl, g_ssl_exdata_state_index);
	if (!state) {
		rc = ssl_private_key_failure;
		goto cleanup;
	}

	if (state->buffer_pos < KSSL_HEADER_SIZE) {
		return ssl_private_key_retry;
	}

	if (!kssl_parse_header(state->buffer, &header)) {
		rc = ssl_private_key_failure;
		goto cleanup;
	}

	if (header.version_maj != KSSL_VERSION_MAJ || header.id != state->req_id) {
		rc = ssl_private_key_failure;
		goto cleanup;
	}

	if (!kssl_parse_message_payload(state->buffer + KSSL_HEADER_SIZE, header.length, &operation)) {
		rc = ssl_private_key_failure;
		goto cleanup;
	}

	switch (operation.opcode) {
		case KSSL_OP_RESPONSE:
			memcpy(out, operation.payload, operation.payload_len);
			*out_len = operation.payload_len;

			rc = ssl_private_key_success;
			break;
		case KSSL_OP_ERROR:
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
			// unexpected opcode
			rc = ssl_private_key_failure;
			break;
		case KSSL_OP_PONG:
		case KSSL_OP_ACTIVATE:
			rc = ssl_private_key_failure;
			break;
		default: // unkown opcode
			rc = ssl_private_key_failure;
			break;
	}
cleanup:
	if (state) {
		if (state->c) {
			ngx_close_connection(state->c);
		}

		OPENSSL_cleanse(state, sizeof(state_st));

		c = ngx_ssl_get_connection(ssl);
		ngx_pfree(c->pool, state);
	}

	return rc;
}

static int key_type(SSL *ssl)
{
	KEYLESS_CTX *ctx = NULL;

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
	KEYLESS_CTX *ctx = NULL;

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
	kssl_opcode_et opcode;
	KEYLESS_CTX *ctx = NULL;

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

	ctx = SSL_get_ex_data(ssl, g_ssl_exdata_ctx_index);
	if (!ctx) {
		ctx = SSL_CTX_get_ex_data(ssl->ctx, g_ssl_ctx_exdata_ctx_index);
		if (!ctx) {
			return ssl_private_key_failure;
		}
	}

	if (ctx->key.type == EVP_PKEY_EC) {
		opcode |= KSSL_OP_ECDSA_MASK;
	}

	return start_operation(opcode, ssl, out, out_len, max_out, in, in_len);
}

static enum ssl_private_key_result_t key_decrypt(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const uint8_t *in, size_t in_len)
{
	return start_operation(KSSL_OP_RSA_DECRYPT_RAW, ssl, out, out_len, max_out, in, in_len);
}

int ngx_http_keyless_ffi_set_private_key(ngx_http_request_t *r, const char *addr, size_t addr_len, char **err)
{
	ngx_ssl_conn_t *ssl_conn;
	ngx_connection_t *c;
	X509 *x509;
	KEYLESS_CTX *ctx;

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

	ctx = keyless_parse_and_create(c->pool, x509, addr, addr_len);
	if (!ctx) {
		*err = "keyless_parse_and_create failed";
		return NGX_ERROR;
	}

	if (!keyless_attach_ssl(ssl_conn, ctx)) {
		keyless_free(c->pool, ctx);

		*err = "keyless_attach_ssl failed";
		return NGX_ERROR;
	}

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
	NULL,                       /* exit process */
	NULL,                       /* exit master */
	NGX_MODULE_V1_PADDING
};
