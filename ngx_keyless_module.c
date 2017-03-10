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

#define NGX_HTTP_KEYLESS_VERSION (0x80 | 1)

#define NGX_HTTP_KEYLESS_HEADER_LENGTH 8

#define NGX_HTTP_KEYLESS_PAD_TO 1024

extern void *ngx_http_keyless_create_srv_conf(ngx_conf_t *cf);
extern char *ngx_http_keyless_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static void ngx_http_keyless_socket_read_handler(ngx_event_t *rev);
extern void ngx_http_keyless_socket_write_handler(ngx_event_t *wev);

static void ngx_http_keyless_operation_timeout_handler(ngx_event_t *ev);
static void ngx_http_keyless_cleanup_timer_handler(void *data);

extern const char *ngx_http_keyless_error_string(ngx_http_keyless_error_t code);

extern int ngx_http_keyless_ctx_conf_index;

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

extern ngx_http_module_t ngx_http_keyless_module_ctx;

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

	conf = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), ngx_http_keyless_ctx_conf_index);
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

		conf->pc.connection->read->handler = ngx_http_keyless_socket_read_handler;
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

extern void ngx_http_keyless_helper_remove_if_in_queue(ngx_queue_t *q) {
	if (ngx_queue_prev(q) && ngx_queue_next(ngx_queue_prev(q)) == q) {
		ngx_queue_remove(q);
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