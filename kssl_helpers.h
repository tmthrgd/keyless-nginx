// kssl_helpers.h: protocol helper operations for keyless ssl
//
// Copyright (c) 2013 CloudFlare, Inc.

#ifndef INCLUDED_KSSL_HELPERS
#define INCLUDED_KSSL_HELPERS 1

#include <kssl.h>

// Helper macros for known sizes of V1 items
#define KSSL_OPCODE_ITEM_SIZE (KSSL_ITEM_HEADER_SIZE + 1)
#define KSSL_ERROR_ITEM_SIZE (KSSL_ITEM_HEADER_SIZE + 1)
#define KSSL_SKI_SIZE 20
#define KSSL_DIGEST_SIZE 32

// Structure containing request information parsed from payload
typedef struct {
	int is_opcode_set;
	kssl_opcode_et opcode;

	int is_ski_set;
	const unsigned char *ski;

	int is_digest_set;
	const unsigned char *digest;

	int is_sni_set;
	unsigned short sni_len;
	const unsigned char *sni;

	int is_payload_set;
	unsigned short payload_len;
	const unsigned char *payload;

	int is_client_ip_set;
	unsigned short client_ip_len;
	const unsigned char *client_ip;

	int is_server_ip_set;
	unsigned short server_ip_len;
	const unsigned char *server_ip;
} kssl_operation_st;

// Initialize a kssl_operation
void kssl_zero_operation(kssl_operation_st *request);

// Parse a raw message to extract kssl_operation information
int kssl_parse_message_payload(
	unsigned char     *payload,  // incoming payload to parse
	size_t             len,      // length of payload
	kssl_operation_st *request); // request structure to populate

// Populate a kssl_header structure from a byte stream
int kssl_parse_header(
	unsigned char  *bytes,    // incoming header to parse
	kssl_header_st *header);  // header structure to populate

// Extract the data from a payload item from a given offset.
// the offset is updated as bytes are read.  If offset pointer is
// NULL this function starts at offset 0.
int kssl_parse_item(
	unsigned char *bytes,    // buffer containing payload
	size_t        *offset,   // offset payload begins, updated to end
	kssl_item_st  *item);    // item structure to populate

// Serialize a header into a pre-allocated byte array at a given
// offset. The offset is updated as bytes are written.  If offset
// pointer is NULL this function starts at offset 0.
int kssl_flatten_header(
	kssl_header_st *header,    // header to serialize
	unsigned char  *bytes,     // buffer to serialize into
	size_t         *offset);   // offset to write header, updated to end

// Serialize a KSSL item with a given tag and one byte payload at an
// offset. The offset is updated as bytes are written.  If offset
// pointer is NULL this function starts at offset 0.
int kssl_flatten_item_byte(
	unsigned char  tag,       // tag value
	unsigned char  payload,   // one-byte payload
	unsigned char *bytes,     // buffer to serialize into
	size_t        *offset);   // offset to write item, updated to end

// Serialize a KSSL item with a given tag and a payload at an offset.
// The offset is updated as bytes are written.  If offset pointer is NULL
// this function starts at offset 0.
int kssl_flatten_item(
	unsigned char        tag,         // tag value
	const unsigned char *payload,     // payload buffer
	unsigned short       payload_len, // size of payload
	unsigned char       *bytes,       // buffer to serialize into
	size_t              *offset);     // offset to write item, updated to end

// Serialize a KSSL request
// Returns the length of the payload, set request_out to NULL to get length.
size_t kssl_flatten_operation(
        kssl_header_st     *header,       // header information
	kssl_operation_st  *request,      // request information, including pointer to payload
	unsigned char      *request_out); // request bytes, to be allocated by the caller

// add_padding: adds padding bytes to a KSSL message. Assumes that the buffer
// being written to is calloced.
int kssl_add_padding(
	unsigned short  size,  // Length of padding
	unsigned char  *bytes, // Buffer into which item is
	                       // serialized
	size_t *offset);       // (optional) offset into bytes
                               // to write from

// Map an opcode to the corresponding string
const char *kssl_op_string(unsigned char op);

// Map an error code to a string
const char *kssl_error_string(unsigned char e);

#endif /* INCLUDED_KSSL_HELPERS */
