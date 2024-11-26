#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"

int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign

struct TLV
{
    // Byte Alignment
    uint8_t unused;
    // One Byte for Type
    uint8_t type;
    // Two Bytes for Length
    uint16_t length;
    // Payload
    uint8_t payload[1024];
};

#define MIN(a, b) (a < b) ? a : b
static inline void print_tlv(uint8_t *buffer, size_t len)
{
    uint8_t *buf = buffer;

    while (buf - buffer < len)
    {
        uint8_t type = *buf;
        fprintf(stderr, "Type: 0x%02x\n", type);
        buf += 1;
        if (buf - buffer >= len)
            return;

        uint16_t length = ntohs(*((uint16_t *)buf));
        buf += 2;
        fprintf(stderr, "Length: %hu\n", length);

        if (type == CLIENT_HELLO || type == SERVER_HELLO ||
            type == KEY_EXCHANGE_REQUEST || type == FINISHED ||
            type == CERTIFICATE || type == DATA)
            continue;
        else
        {
            uint16_t min_length = MIN(len - (buf - buffer), length);
            print_hex(buf, min_length);
            buf += min_length;
        }
    }
}

static inline void print_tlv_struct(struct TLV *tlv)
{
    fprintf(stderr, "Type: 0x%02x\n", tlv->type);
    fprintf(stderr, "Length: %hu\n", tlv->length);
    fprintf(stderr, "Size is %d\n", sizeof(*tlv));
    print_hex(tlv, tlv->length);
}

void set_type(struct TLV *tlv, uint8_t type)
{
    tlv->type = type;
}

void set_length(struct TLV *tlv, uint16_t length)
{
    tlv->length = length;
}

void set_payload(struct TLV *tlv, uint8_t *buf, size_t length)
{
    memcpy(tlv->payload, buf, length);
}

void set_tlv_payload(struct TLV *tlv, struct TLV *nested_tlv, size_t length)
{
    memcpy(tlv->payload, nested_tlv, length);
}

void init_sec(int initial_state)
{
    state_sec = initial_state;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND)
    {
        generate_private_key();
        derive_public_key();
        derive_self_signed_certificate();
        load_ca_public_key("ca_public_key.bin");
    }
    else if (state_sec == SERVER_CLIENT_HELLO_AWAIT)
    {
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        derive_public_key();
    }

    generate_nonce(nonce, NONCE_SIZE);
}

ssize_t input_sec(uint8_t *buf, size_t max_length)
{
    // This passes it directly to standard input (working like Project 1)
    // return input_io(buf, max_length);

    switch (state_sec)
    {
    case CLIENT_CLIENT_HELLO_SEND:
    {
        print("SEND CLIENT HELLO");
        struct TLV tlv;
        set_type(&tlv, CLIENT_HELLO);

        // Handle Nested NONCE TLV
        struct TLV nested_tlv;
        set_type(&nested_tlv, NONCE_CLIENT_HELLO);
        set_length(&nested_tlv, NONCE_SIZE);
        set_payload(&nested_tlv, nonce, NONCE_SIZE);

        // Put Nested TLV into outer TLV payload
        set_tlv_payload(&tlv, &nested_tlv, nested_tlv.length);

        // +3 for (1 type byte, 2 length bytes)
        set_length(&tlv, nested_tlv.length + 3);
        print_tlv_struct(&tlv);

        memcpy(buf, &tlv, sizeof(tlv));
        /* Insert Client Hello sending logic here */

        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return 0;
    }
    case SERVER_SERVER_HELLO_SEND:
    {
        print("SEND SERVER HELLO");

        /* Insert Server Hello sending logic here */

        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return 0;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND:
    {
        print("SEND KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request sending logic here */

        state_sec = CLIENT_FINISHED_AWAIT;
        return 0;
    }
    case SERVER_FINISHED_SEND:
    {
        print("SEND FINISHED");

        /* Insert Finished sending logic here */

        state_sec = DATA_STATE;
        return 0;
    }
    case DATA_STATE:
    {
        /* Insert Data sending logic here */

        // PT refers to the amount you read from stdin in bytes
        // CT refers to the resulting ciphertext size
        // fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, cip_size);

        return 0;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t *buf, size_t length)
{
    // This passes it directly to standard output (working like Project 1)
    return output_io(buf, length);

    switch (state_sec)
    {
    case SERVER_CLIENT_HELLO_AWAIT:
    {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");

        /* Insert Client Hello receiving logic here */

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT:
    {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");

        /* Insert Server Hello receiving logic here */

        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT:
    {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request receiving logic here */

        state_sec = SERVER_FINISHED_SEND;
        break;
    }
    case CLIENT_FINISHED_AWAIT:
    {
        if (*buf != FINISHED)
            exit(4);

        print("RECV FINISHED");

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE:
    {
        if (*buf != DATA)
            exit(4);

        /* Insert Data receiving logic here */

        // PT refers to the resulting plaintext size in bytes
        // CT refers to the received ciphertext size
        // fprintf(stderr, "RECV DATA PT %ld CT %hu\n", data_len, cip_len);
        break;
    }
    default:
        break;
    }
}
