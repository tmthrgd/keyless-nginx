// kssl_helpers.c: protocol helper operations for keyless ssl
//
// Copyright (c) 2013 CloudFlare, Inc.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include <kssl.h>
#include <kssl_helpers.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// Helper macros for stream processing. These macros ensure that the correct
// byte ordering is used.

// b is the buffer to read from/write to
// o is the offset in the buffer, incremented after the read/write
// v is the value to set
#define READ_BYTE(b, o) (b)[(o)]; (o)++;
#define READ_WORD(b, o) ntohs(*(unsigned short*)(&(b)[(o)])); (o) += sizeof(unsigned short);
#define READ_DWORD(b, o) ntohl(*(unsigned int*)(&(b)[(o)])); (o) += sizeof(unsigned int);
#define WRITE_BYTE(b, o, v) (b)[(o)] = (v); (o)++;
#define WRITE_WORD(b, o, v) *(unsigned short*)(&(b)[(o)]) = htons((v)); (o) += sizeof(unsigned short);
#define WRITE_DWORD(b, o, v) *(unsigned int*)(&(b)[(o)]) = htonl((v)); (o) += sizeof(unsigned int);
#define WRITE_BUFFER(b, o, v, l) memcpy(&(b)[(o)], (v), (l)); (o) += l;

// parse_header: populates a kssl_header structure from a byte stream. Returns
// 1 if successful.
int kssl_parse_header(unsigned char *bytes,      // Stream of bytes containing a kssl_header
                      kssl_header_st *header) {  // Returns the populated header (must be allocated by caller)
	int offset = 0;

	if (!bytes || !header) {
		return 0;
	}

	header->version_maj = READ_BYTE(bytes, offset);
	header->version_min = READ_BYTE(bytes, offset);
	header->length = READ_WORD(bytes, offset);
	header->id = READ_DWORD(bytes, offset);

	return 1;
}

// parse_item: Parse a kssl_item out of the body of a KSSL message
// NOTE: The payload for the item is not copied, a reference
// to the original stream is added to the kssl_item struct. The offset
// is updated if provided. Returns 1 if successful.
int kssl_parse_item(unsigned char *bytes, // Byte stream to parse kssl_item from
                    size_t *offset,       // (optional) if present specifies offset into bytes.
                    kssl_item_st *item) { // The kssl_item parsed (must be allocated by caller)
	size_t local_offset = 0;
	unsigned char local_tag;
	unsigned short local_len;
	unsigned char *local_data;

	if (!bytes || !item) {
		return 0;
	}

	if (offset) {
		local_offset = *offset;
	}

	local_tag = READ_BYTE(bytes, local_offset);
	local_len = READ_WORD(bytes, local_offset);
	local_data = &bytes[local_offset];
	local_offset += local_len;

	item->tag = local_tag;
	item->length = local_len;
	item->data = local_data;

	if (offset) {
		*offset = local_offset;
	}

	return 1;
}

// flatten_header: serialize a header into a pre-allocated byte array
// at a given offset. The offset is updated as bytes are written.  If
// offset pointer is NULL this function starts at offset 0.
int kssl_flatten_header(kssl_header_st *header, // Pointer to kssl_header to serialize
                        unsigned char *bytes,   // Byte buffer to write into (must be allocated
                                                // and have sufficient space for a kssl_header)
                        size_t *offset) {       // (optional) offset intobytes to write to
	size_t local_offset = 0;

	if (!bytes || !header) {
		return 0;
	}

	if (offset) {
		local_offset = *offset;
	}

	WRITE_BYTE(bytes, local_offset, header->version_maj);
	WRITE_BYTE(bytes, local_offset, header->version_min);
	WRITE_WORD(bytes, local_offset, header->length);
	WRITE_DWORD(bytes, local_offset, header->id);

	if (offset) {
		*offset = local_offset;
	}

	return 1;
}

// flatten_item_byte: serialize a kssl_item with a given tag and one
// byte payload at an offset. The offset is updated as bytes are written.
// If offset pointer is NULL this function starts at offset 0. Returns
// 1 if successful.
int kssl_flatten_item_byte(unsigned char tag,     // The kssl_item's tag (see kssl.h)
                           unsigned char payload, // A single byte for the payload
                           unsigned char *bytes,  // Buffer into which kssl_item is written (must
                                                  // be pre-allocated and have room)
                           size_t *offset) {      // (optional) offset into bytes to start writing at
	size_t local_offset = 0;

	if (!bytes) {
		return 0;
	}

	if (offset) {
		local_offset = *offset;
	}

	WRITE_BYTE(bytes, local_offset, tag);
	WRITE_WORD(bytes, local_offset, 1);
	WRITE_BYTE(bytes, local_offset, payload);

	if (offset) {
		*offset = local_offset;
	}

	return 1;
}

// flatten_item: Serialize a single kssl_item. The offset is updated
// as bytes are written. If offset pointer is NULL this function
// starts at offset 0. Returns 1 if successful.
int kssl_flatten_item(unsigned char tag,            // The kssl_item's tag (see kssl.h)
                      const unsigned char *payload, // Buffer containing the item's payload
                      unsigned short payload_len,   // Length of data from payload to copy
                      unsigned char *bytes,         // Buffer into which item is serialized
                      size_t *offset) {             // (optional) offset into bytes to write from
	size_t local_offset = 0;

	if (!bytes) {
		return 0;
	}

	if (offset) {
		local_offset = *offset;
	}

	WRITE_BYTE(bytes, local_offset, tag);
	WRITE_WORD(bytes, local_offset, payload_len);

	if (payload_len) {
		WRITE_BUFFER(bytes, local_offset, payload, payload_len);
	}

	if (offset) {
		*offset = local_offset;
	}

	return 1;
}

// add_padding: adds padding bytes to a KSSL message. Assumes that the buffer
// being written to is calloced.
int kssl_add_padding(unsigned short size,  // Length of padding
                     unsigned char *bytes, // Buffer into which item is serialized
                     size_t *offset) {     // (optional) offset into bytes to write from
	size_t local_offset = 0;

	if (!bytes) {
		return 0;
	}

	if (offset) {
		local_offset = *offset;
	}

	// Add the padding. This gets added even is padding_size == 0

	WRITE_BYTE(bytes, local_offset, KSSL_TAG_PADDING);
	WRITE_WORD(bytes, local_offset, size);

	if (offset) {
		*offset = local_offset;
	}

	return 1;
}

// flatten_operation: serialize a kssl_operation
int kssl_flatten_operation(kssl_header_st *header,
                           kssl_operation_st *operation,
                           unsigned char *out_operation,
                           size_t *length) {
	size_t local_req_len;
	unsigned char *local_req = out_operation;
	size_t offset = 0;
	int padding_size = 0;

	if (!header || !operation || !out_operation || !length) {
		return 0;
	}

	// Allocate response (header + opcode + response)
	local_req_len = KSSL_HEADER_SIZE;

	if (operation->is_opcode_set) {
		local_req_len += KSSL_OPCODE_ITEM_SIZE;
	}

	if (operation->is_payload_set) {
		local_req_len += KSSL_ITEM_HEADER_SIZE + operation->payload_len;
	}

	if (operation->is_ski_set) {
		local_req_len += KSSL_ITEM_HEADER_SIZE + KSSL_SKI_SIZE;
	}

	if (operation->is_digest_set) {
		local_req_len += KSSL_ITEM_HEADER_SIZE + KSSL_DIGEST_SIZE;
	}

	if (operation->is_sni_set) {
		local_req_len += KSSL_ITEM_HEADER_SIZE + operation->sni_len;
	}

	if (operation->is_client_ip_set) {
		local_req_len += KSSL_ITEM_HEADER_SIZE + operation->client_ip_len;
	}

	if (operation->is_server_ip_set) {
		local_req_len += KSSL_ITEM_HEADER_SIZE + operation->server_ip_len;
	}

	// The operation will always be padded to KSSL_PAD_TO +
	// KSSL_ITEM_HEADER_SIZE bytes

	if (local_req_len < KSSL_PAD_TO) {
		padding_size = KSSL_PAD_TO - local_req_len;
	}

	local_req_len += KSSL_ITEM_HEADER_SIZE + padding_size;

	if (local_req_len > *length) {
		return 0;
	}

	// The memory is cleared here to ensure that it is all zero. This is
	// important because the padding added below is done by just adding a
	// KSSL_ITEM at the end of the message stating that it has N bytes of
	// padding.

	memset(local_req, 0, local_req_len);

	// Override header length
	header->length = local_req_len - KSSL_HEADER_SIZE;

	if (!kssl_flatten_header(header, local_req, &offset)) {
		return 0;
	}

	if (operation->is_opcode_set) {
		if (!kssl_flatten_item_byte(KSSL_TAG_OPCODE, operation->opcode, local_req, &offset)) {
			return 0;
		}
	}

	if (operation->is_payload_set) {
		if (!kssl_flatten_item(KSSL_TAG_PAYLOAD, operation->payload, operation->payload_len, local_req, &offset)) {
			return 0;
		}
	}

	if (operation->is_ski_set) {
		if (!kssl_flatten_item(KSSL_TAG_SKI, operation->ski, KSSL_SKI_SIZE, local_req, &offset)) {
			return 0;
		}
	}

	if (operation->is_digest_set) {
		if (!kssl_flatten_item(KSSL_TAG_DIGEST, operation->digest, KSSL_DIGEST_SIZE, local_req, &offset)) {
			return 0;
		}
	}

	if (operation->is_sni_set) {
		if (!kssl_flatten_item(KSSL_TAG_SNI, operation->sni, operation->sni_len, local_req, &offset)) {
			return 0;
		}
	}

	if (operation->is_client_ip_set) {
		if (!kssl_flatten_item(KSSL_TAG_CLIENT_IP, operation->client_ip, operation->client_ip_len, local_req, &offset)) {
			return 0;
		}
	}

	if (operation->is_server_ip_set) {
		if (!kssl_flatten_item(KSSL_TAG_SERVER_IP, operation->server_ip, operation->server_ip_len, local_req, &offset)) {
			return 0;
		}
	}

	if (!kssl_add_padding(padding_size, local_req, &offset)) {
		return 0;
	}

	*length = local_req_len;

	return 1;
}

// zero_operation: initialize a kssl_operation struct
void kssl_zero_operation(kssl_operation_st *operation) {
	if (operation) {
		operation->is_opcode_set = 0;
		operation->opcode = 0;

		operation->is_ski_set = 0;
		operation->ski = NULL;

		operation->is_digest_set = 0;
		operation->digest = NULL;

		operation->is_sni_set = 0;
		operation->sni = NULL;
		operation->sni_len = 0;

		operation->is_payload_set = 0;
		operation->payload = NULL;
		operation->payload_len = 0;

		operation->is_client_ip_set = 0;
		operation->client_ip = NULL;
		operation->client_ip_len = 0;

		operation->is_server_ip_set = 0;
		operation->server_ip = NULL;
		operation->server_ip_len = 0;
	}
}

// parse_message_payload: parse a message payload into a
// kssl_operation struct
int kssl_parse_message_payload(unsigned char *payload,
                               size_t len,
                               kssl_operation_st *operation) {
	size_t offset = 0;
	kssl_item_st temp_item;

	if (!payload || !operation) {
		return 0;
	}

	kssl_zero_operation(operation);

	// Count number of items and validate structure
	while (offset < len) {
		if (len - offset < KSSL_ITEM_HEADER_SIZE) {
			return 0;
		}

		if (!kssl_parse_item(payload, &offset, &temp_item) || len < offset) {
			return 0;
		}

		// Iterate through known tags, populating necessary values
		switch (temp_item.tag) {
			case KSSL_TAG_OPCODE:
				// Skip over malformed tags
				if (temp_item.length != 1) {
					continue;
				}

				operation->opcode = temp_item.data[0];
				operation->is_opcode_set = 1;
				break;
			case KSSL_TAG_SKI:
				// Skip over malformed tags
				if (temp_item.length != KSSL_SKI_SIZE) {
					continue;
				}

				operation->ski = temp_item.data;
				operation->is_ski_set = 1;
				break;
			case KSSL_TAG_DIGEST:
				// Skip over malformed tags
				if (temp_item.length != KSSL_DIGEST_SIZE) {
					continue;
				}

				operation->digest = temp_item.data;
				operation->is_digest_set = 1;
				break;
			case KSSL_TAG_SNI:
				operation->sni_len = temp_item.length;
				operation->sni = temp_item.data;
				operation->is_sni_set = 1;
				break;
			case KSSL_TAG_PAYLOAD:
				operation->payload_len = temp_item.length;
				operation->payload = temp_item.data;
				operation->is_payload_set = 1;
				break;
			case KSSL_TAG_CLIENT_IP:
				operation->client_ip_len = temp_item.length;
				operation->client_ip = temp_item.data;
				operation->is_client_ip_set = 1;
				break;
			case KSSL_TAG_SERVER_IP:
				operation->server_ip_len = temp_item.length;
				operation->server_ip = temp_item.data;
				operation->is_server_ip_set = 1;
				break;
			case KSSL_TAG_PADDING:
				break;
			default:
				break;
		}
	}

	// check to see if opcode and payload are set
	if (!operation->is_opcode_set || !operation->is_payload_set) {
		return 0;
	}

	return 1;
}

// opstring: convert a KSSL opcode byte to a string
const char *kssl_opstring(unsigned char op) {
	switch (op) {
		case KSSL_OP_ERROR:
			return "KSSL_OP_ERROR";
		case KSSL_OP_PING:
			return "KSSL_OP_PING";
		case KSSL_OP_PONG:
			return "KSSL_OP_PONG";
		case KSSL_OP_RSA_DECRYPT:
			return "KSSL_OP_RSA_DECRYPT";
		case KSSL_OP_RSA_DECRYPT_RAW:
			return "KSSL_OP_RSA_DECRYPT_RAW";
		case KSSL_OP_RESPONSE:
			return "KSSL_OP_RESPONSE";
		case KSSL_OP_RSA_SIGN_MD5SHA1:
			return "KSSL_OP_RSA_SIGN_MD5SHA1";
		case KSSL_OP_RSA_SIGN_SHA1:
			return "KSSL_OP_RSA_SIGN_SHA1";
		case KSSL_OP_RSA_SIGN_SHA224:
			return "KSSL_OP_RSA_SIGN_SHA224";
		case KSSL_OP_RSA_SIGN_SHA256:
			return "KSSL_OP_RSA_SIGN_SHA256";
		case KSSL_OP_RSA_SIGN_SHA384:
			return "KSSL_OP_RSA_SIGN_SHA384";
		case KSSL_OP_RSA_SIGN_SHA512:
			return "KSSL_OP_RSA_SIGN_SHA512";
		case KSSL_OP_ECDSA_SIGN_MD5SHA1:
			return "KSSL_OP_ECDSA_SIGN_MD5SHA1";
		case KSSL_OP_ECDSA_SIGN_SHA1:
			return "KSSL_OP_ECDSA_SIGN_SHA1";
		case KSSL_OP_ECDSA_SIGN_SHA224:
			return "KSSL_OP_ECDSA_SIGN_SHA224";
		case KSSL_OP_ECDSA_SIGN_SHA256:
			return "KSSL_OP_ECDSA_SIGN_SHA256";
		case KSSL_OP_ECDSA_SIGN_SHA384:
			return "KSSL_OP_ECDSA_SIGN_SHA384";
		case KSSL_OP_ECDSA_SIGN_SHA512:
			return "KSSL_OP_ECDSA_SIGN_SHA512";
	}

	return "UNKNOWN";
}

// errstring: convert a KSSL error to a string
const char *kssl_errstring(unsigned char err) {
	switch (err) {
		case KSSL_ERROR_NONE:
			return "KSSL_ERROR_NONE";
		case KSSL_ERROR_CRYPTO_FAILED:
			return "KSSL_ERROR_CRYPTO_FAILED";
		case KSSL_ERROR_KEY_NOT_FOUND:
			return "KSSL_ERROR_KEY_NOT_FOUND";
		case KSSL_ERROR_READ:
			return "KSSL_ERROR_READ";
		case KSSL_ERROR_VERSION_MISMATCH:
			return "KSSL_ERROR_VERSION_MISMATCH";
		case KSSL_ERROR_BAD_OPCODE:
			return "KSSL_ERROR_BAD_OPCODE";
		case KSSL_ERROR_UNEXPECTED_OPCODE:
			return "KSSL_ERROR_UNEXPECTED_OPCODE";
		case KSSL_ERROR_FORMAT:
			return "KSSL_ERROR_FORMAT";
		case KSSL_ERROR_INTERNAL:
			return "KSSL_ERROR_INTERNAL";
	}

	return "UNKNOWN";
}
