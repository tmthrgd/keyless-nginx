#include <ngx_config.h>
#include "nginx-radon-pvkey.h"

#if NGX_HTTP_SSL

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#ifdef OPENSSL_IS_BORINGSSL
#	include <openssl/ec_key.h>
#	include <openssl/engine.h>
#endif /* OPENSSL_IS_BORINGSSL */

typedef enum {
	RADON_RSA_RAW_SIGN = 1,
	RADON_RSA_DECRYPT = 2,
	RADON_ECDSA_SIGN = 3
} radon_operation_et;

typedef struct {
	struct sockaddr_un address;
	unsigned char ski[SHA_DIGEST_LENGTH];
} radon_app_data_st;

typedef struct __attribute__((__packed__)) {
	int command;
	int padding;
	unsigned long long int in_len;
	unsigned char ski[SHA_DIGEST_LENGTH];
} radon_cmd_req_st;

static int g_rsa_exdata_radon_index = -1;

#ifdef OPENSSL_IS_BORINGSSL

static int g_ecdsa_exdata_radon_index = -1;

#else /* OPENSSL_IS_BORINGSSL */

static void *radon_ec_key_dup_func(void *);
static void radon_ec_key_free_func(void *);

#endif /* OPENSSL_IS_BORINGSSL */

static int radon_run_command(radon_app_data_st *data, radon_operation_et command, size_t *out_len, uint8_t *out, const uint8_t *in, size_t in_len, int padding)
{
	radon_cmd_req_st cmd;
	unsigned long long int ullout_len = 0;
	int sock_fd = -1;

	if ((sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		return 0;
	}

	if (connect(sock_fd, (struct sockaddr *)&data->address, SUN_LEN(&data->address)) == -1) {
		close(sock_fd);
		return 0;
	}

	memset(&cmd, 0, sizeof(radon_cmd_req_st));
	cmd.command = (int)command;
	cmd.padding = padding;
	cmd.in_len = (unsigned long long int)in_len;
	memcpy((char *)cmd.ski, (char *)data->ski, SHA_DIGEST_LENGTH);

	if (write(sock_fd, &cmd, sizeof(cmd)) == -1) {
		close(sock_fd);
		return 0;
	}

	if (write(sock_fd, in, in_len) == -1) {
		close(sock_fd);
		return 0;
	}

	if (read(sock_fd, &ullout_len, sizeof(ullout_len)) == -1) {
		close(sock_fd);
		return 0;
	}

	if (ullout_len != 0 && read(sock_fd, out, (size_t)ullout_len) == -1) {
		close(sock_fd);
		return 0;
	}

	close(sock_fd);

	*out_len = ullout_len;
	return (ullout_len == 0) ? 0 : 1;
}

static int radon_rsa_run_command(radon_operation_et command, RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding)
{
	radon_app_data_st *data = NULL;

	if (!(data = RSA_get_ex_data(rsa, g_rsa_exdata_radon_index))) {
		return 0;
	}

	return radon_run_command(data, command, out_len, out, in, in_len, padding);
}

static int radon_ecdsa_run_command(radon_operation_et command, const uint8_t *digest, size_t digest_len, uint8_t *sig, unsigned int *sig_len, EC_KEY *key)
{
	radon_app_data_st *data = NULL;
	int ret = 0;
	size_t out_len = 0;

#ifdef OPENSSL_IS_BORINGSSL
	if (!(data = EC_KEY_get_ex_data(key, g_ecdsa_exdata_radon_index))) {
#else /* OPENSSL_IS_BORINGSSL */
	if (!(data = EC_KEY_get_key_method_data(key, radon_ec_key_dup_func, radon_ec_key_free_func, radon_ec_key_free_func))) {
#endif /* OPENSSL_IS_BORINGSSL */
		return 0;
	}

	ret = radon_run_command(data, command, &out_len, sig, digest, digest_len, 0);
	*sig_len = (unsigned int)out_len;
	return ret;
}

#ifdef OPENSSL_IS_BORINGSSL

static int radon_rsa_sign_raw(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding)
{
	return radon_rsa_run_command(RADON_RSA_RAW_SIGN, rsa, out_len, out, max_out, in, in_len, padding);
}

static int radon_rsa_decrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out, const uint8_t *in, size_t in_len, int padding)
{
	return radon_rsa_run_command(RADON_RSA_DECRYPT, rsa, out_len, out, max_out, in, in_len, padding);
}

static int radon_ecdsa_sign(const uint8_t *digest, size_t digest_len, uint8_t *sig, unsigned int *sig_len, EC_KEY *key)
{
	return radon_ecdsa_run_command(RADON_ECDSA_SIGN, digest, digest_len, sig, sig_len, key);
}

#else /* OPENSSL_IS_BORINGSSL */

static int radon_rsa_private_decrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
{
	size_t out_len = 0;

	if (radon_rsa_run_command(RADON_RSA_DECRYPT, rsa, &out_len, to, -1, from, (size_t)flen, padding) == 1) {
		return (int)out_len;
	}

	return 0;
}

static int radon_rsa_private_encrypt(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding)
{
	size_t out_len = 0;

	if (radon_rsa_run_command(RADON_RSA_RAW_SIGN, rsa, &out_len, to, -1, from, (size_t)flen, padding) == 1) {
		return (int)out_len;
	}

	return 0;
}

static ECDSA_SIG *radon_ecdsa_do_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *inv, const BIGNUM *rp, EC_KEY *eckey)
{
	ECDSA_SIG *sig = NULL;
	char *raw_sig = NULL, *d2i_sig = NULL;
	unsigned int raw_sig_len = ECDSA_size(eckey);

	if ((d2i_sig = raw_sig = OPENSSL_malloc((size_t)raw_sig_len)) == NULL) {
		return NULL;
	}

	if (radon_ecdsa_run_command(RADON_ECDSA_SIGN, (const uint8_t *)dgst, (size_t)dgst_len, (uint8_t *)raw_sig, &raw_sig_len, eckey) == 1) {
		sig = d2i_ECDSA_SIG(NULL, (const unsigned char **)&d2i_sig, raw_sig_len);
	}

	OPENSSL_free(raw_sig);

	return sig;
}

static void *radon_ec_key_dup_func(void *ptr) {
	radon_app_data_st *data = NULL, *prev = ptr;

	if (prev == NULL || (data = OPENSSL_malloc(sizeof(radon_app_data_st))) == NULL) {
		return NULL;
	}

	*data = *prev;
	return data;
}

static void radon_ec_key_free_func(void *ptr) {
	radon_app_data_st *data = ptr;

	if (data != NULL) {
		OPENSSL_free(data);
	}
}

#endif /* OPENSSL_IS_BORINGSSL */

static const RSA_METHOD *radon_get_rsa_method()
{
	static RSA_METHOD ops;

#ifdef OPENSSL_IS_BORINGSSL
	if (!ops.sign_raw) {
		ops.common.is_static = 1;

		ops.sign_raw = radon_rsa_sign_raw;
		ops.decrypt = radon_rsa_decrypt;
	}
#else /* OPENSSL_IS_BORINGSSL */
	if (!ops.rsa_priv_enc) {
		ops = *RSA_get_default_method();

		ops.rsa_priv_dec = radon_rsa_private_decrypt;
		ops.rsa_priv_enc = radon_rsa_private_encrypt;
	}
#endif /* OPENSSL_IS_BORINGSSL */

	return &ops;
}

static const ECDSA_METHOD *radon_get_ecdsa_method()
{
#ifdef OPENSSL_IS_BORINGSSL
	static ECDSA_METHOD ops;

	if (!ops.sign) {
		ops.common.is_static = 1;

		ops.sign = radon_ecdsa_sign;
	}

	return &ops;
#else /* OPENSSL_IS_BORINGSSL */
	static ECDSA_METHOD *ops = NULL;

	if (ops == NULL && (ops = ECDSA_METHOD_new(ECDSA_get_default_method())) != NULL) {
		ECDSA_METHOD_set_sign(ops, radon_ecdsa_do_sign);
	}

	return ops;
#endif /* OPENSSL_IS_BORINGSSL */
}

static void radon_ex_data_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad, int index, long argl, void* argp) {
	radon_app_data_st *data = ptr;

	if (data != NULL) {
		OPENSSL_free(data);
	}
}

EVP_PKEY *radon_private_key_shell(X509 *cert, const char *sock, size_t sock_len)
{
	EVP_PKEY *key = NULL, *public_key = NULL;
	RSA      *rsa = NULL, *public_rsa = NULL;
	EC_KEY   *ecdsa = NULL, *public_ecdsa = NULL;
#ifdef OPENSSL_IS_BORINGSSL
	ENGINE *engine = NULL;
#endif /* OPENSSL_IS_BORINGSSL */
	radon_app_data_st *data = NULL;

	if (g_rsa_exdata_radon_index == -1 && (g_rsa_exdata_radon_index = RSA_get_ex_new_index(0, NULL, NULL, NULL, radon_ex_data_free)) == -1) {
		goto error;
	}

#ifdef OPENSSL_IS_BORINGSSL
	if (g_ecdsa_exdata_radon_index == -1 && (g_ecdsa_exdata_radon_index = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, radon_ex_data_free)) == -1) {
		goto error;
	}
#endif /* OPENSSL_IS_BORINGSSL */

	if (!(public_key = X509_get_pubkey(cert))) {
		goto error;
	}

	if ((data = OPENSSL_malloc(sizeof(radon_app_data_st))) == NULL) {
		goto error;
	}

	memset(data, 0, sizeof(radon_app_data_st));

	data->address.sun_family = AF_UNIX;
	strncpy(data->address.sun_path, sock, sock_len);

	if (cert->cert_info == NULL
		|| cert->cert_info->key == NULL
		|| cert->cert_info->key->public_key == NULL
		|| cert->cert_info->key->public_key->length == 0
		|| SHA1(cert->cert_info->key->public_key->data, cert->cert_info->key->public_key->length, data->ski) == NULL) {
		goto error;
	}

	if (!(key = EVP_PKEY_new())) {
		goto error;
	}

	switch (EVP_PKEY_type(public_key->type)) {
	case EVP_PKEY_RSA:
		if (!(public_rsa = EVP_PKEY_get1_RSA(public_key))) {
			goto error;
		}

		if (!(rsa = RSA_new())) {
			goto error;
		}

#ifdef OPENSSL_IS_BORINGSSL
		rsa->meth = (RSA_METHOD *)radon_get_rsa_method();
#else /* OPENSSL_IS_BORINGSSL */
		RSA_set_method(rsa, radon_get_rsa_method());
#endif /* OPENSSL_IS_BORINGSSL */

		if (!(rsa->n = BN_dup(public_rsa->n))) {
			goto error;
		}

		if (!(rsa->e = BN_dup(public_rsa->e))) {
			goto error;
		}

		RSA_free(public_rsa); public_rsa = NULL;

		if (!RSA_set_ex_data(rsa, g_rsa_exdata_radon_index, data)) {
			goto error;
		}

		if (!EVP_PKEY_set1_RSA(key, rsa)) {
			goto error;
		}

		break;
	case EVP_PKEY_EC:
		if (!(public_ecdsa = EVP_PKEY_get1_EC_KEY(public_key))) {
			goto error;
		}

#ifdef OPENSSL_IS_BORINGSSL
		if (!(engine = ENGINE_new())) {
			goto error;
		}

		if (!ENGINE_set_ECDSA_method(engine, radon_get_ecdsa_method(), sizeof(ECDSA_METHOD))) {
			goto error;
		}

		if (!(ecdsa = EC_KEY_new_method(engine))) {
			goto error;
		}

		ENGINE_free(engine); engine = NULL;

		EC_KEY_set_group(ecdsa, EC_KEY_get0_group(public_ecdsa));
		EC_KEY_set_public_key(ecdsa, EC_KEY_get0_public_key(public_ecdsa));
		EC_KEY_set_enc_flags(ecdsa, EC_KEY_get_enc_flags(public_ecdsa));
		EC_KEY_set_conv_form(ecdsa, EC_KEY_get_conv_form(public_ecdsa));
#else /* OPENSSL_IS_BORINGSSL */
		if (!(ecdsa = EC_KEY_dup(public_ecdsa))) {
			goto error;
		}

		ECDSA_set_method(ecdsa, radon_get_ecdsa_method());
#endif /* OPENSSL_IS_BORINGSSL */

		EC_KEY_free(public_ecdsa); public_ecdsa = NULL;

#ifdef OPENSSL_IS_BORINGSSL
		if (!EC_KEY_set_ex_data(ecdsa, g_ecdsa_exdata_radon_index, data)) {
#else /* OPENSSL_IS_BORINGSSL */
		if (EC_KEY_insert_key_method_data(ecdsa, data, radon_ec_key_dup_func, radon_ec_key_free_func, radon_ec_key_free_func)
			|| !EC_KEY_get_key_method_data(ecdsa, radon_ec_key_dup_func, radon_ec_key_free_func, radon_ec_key_free_func)) {
#endif /* OPENSSL_IS_BORINGSSL */
			goto error;
		}

		if (!EVP_PKEY_set1_EC_KEY(key, ecdsa)) {
			goto error;
		}

		break;
	default:
		goto error;
	}

	EVP_PKEY_free(public_key); public_key = NULL;

	return key;

error:
	if (key != NULL) {
		EVP_PKEY_free(key);
	}

	if (public_key != NULL) {
		EVP_PKEY_free(public_key);
	}

	if (rsa != NULL) {
		RSA_free(rsa);
	}

	if (public_rsa != NULL) {
		RSA_free(public_rsa);
	}

	if (ecdsa != NULL) {
		EC_KEY_free(ecdsa);
	}
#ifndef OPENSSL_IS_BORINGSSL
	else
#endif /* OPENSSL_IS_BORINGSSL */
	if (data != NULL) {
		OPENSSL_free(data);
	}

	if (public_ecdsa != NULL) {
		EC_KEY_free(public_ecdsa);
	}

#ifdef OPENSSL_IS_BORINGSSL
	if (engine != NULL) {
		ENGINE_free(engine);
	}
#endif /* OPENSSL_IS_BORINGSSL */

	return NULL;
}

#endif /* NGX_HTTP_SSL */
