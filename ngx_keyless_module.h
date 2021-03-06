#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>

#include <inttypes.h>

#define NGX_HTTP_KEYLESS_VERSION (0x80 | 1)

#define NGX_HTTP_KEYLESS_HEADER_LENGTH 8

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

	// Encrypt a blob of data
	NGX_HTTP_KEYLESS_OP_SEAL   = 0x0021,
	NGX_HTTP_KEYLESS_OP_UNSEAL = 0x0022,

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
	// The sealing key has expired
	NGX_HTTP_KEYLESS_ERROR_EXPIRED           = 0x0010,

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

	ngx_buf_t tmp_recv;

	ngx_queue_t recv_ops;
	ngx_queue_t send_ops;
} ngx_http_keyless_srv_conf_t;

typedef struct {
	ngx_event_t *ev;
	ngx_event_t timer;
	ngx_pool_cleanup_t *cln;

	uint32_t id;

	ngx_http_keyless_error_t error;
	const uint8_t *ski;
	const uint8_t *ocsp_response;
	size_t ocsp_response_length;
	const uint8_t *sct_list;
	size_t sct_list_length;

	ngx_log_t *log;
	ngx_pool_t *pool;

	ngx_buf_t send;
	ngx_buf_t recv;

	ngx_queue_t recv_queue;
	ngx_queue_t send_queue;
} ngx_http_keyless_op_t;

extern ngx_http_keyless_op_t *ngx_http_keyless_start_operation(ngx_http_keyless_operation_t opcode,
		ngx_connection_t *c, ngx_http_keyless_srv_conf_t *conf, const uint8_t *in, size_t in_len,
		const uint8_t *ski, const uint8_t *sni, const uint8_t *ip, size_t ip_len,
		const uint8_t *sig_algs, size_t sig_algs_len, uint8_t ecdsa_cipher);
extern enum ssl_private_key_result_t ngx_http_keyless_operation_complete(ngx_http_keyless_op_t *op, CBS *out);

// -*- mode: c;-*-