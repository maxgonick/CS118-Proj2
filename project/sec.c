#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"

#define PAYLOAD_OFFSET 3

int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign

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

size_t set_type(uint8_t *buf, uint8_t type)
{
    memcpy(buf, &type, 1);
    return 1;
};

size_t set_length(uint8_t *buf, uint16_t length)
{
    uint16_t length_endian = htons(length);
    memcpy(buf, &length_endian, 2);
    return 2;
}

size_t set_payload(uint8_t *buf, uint8_t *data, size_t length)
{
    memcpy(buf, data, length);
    return length;
}

void init_sec(int initial_state)
{
    state_sec = initial_state;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND)
    {
        // Create a
        generate_private_key();
        // Make g^a
        derive_public_key();
        derive_self_signed_certificate();
        load_ca_public_key("ca_public_key.bin");
    }
    else if (state_sec == SERVER_CLIENT_HELLO_AWAIT)
    {
        load_certificate("server_cert.bin");
        // Gets b
        load_private_key("server_key.bin");
        // Gets g^b
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
        /* Insert Client Hello sending logic here */
        size_t size = 0;
        // Set Outer TLV
        size += set_type(buf + size, CLIENT_HELLO);
        size += set_length(buf + size, 35);

        // Set Inner TLV
        size += set_type(buf + size, NONCE_CLIENT_HELLO);
        size += set_length(buf + size, NONCE_SIZE);
        size += set_payload(buf + size, nonce, NONCE_SIZE);

        print_hex(buf, size);
        print_tlv(buf, size);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return size;
    }
    case SERVER_SERVER_HELLO_SEND:
    {
        print("SEND SERVER HELLO");

        /* Insert Server Hello sending logic here */
        uint16_t size = 0;

        // Server Hello TLV

        size += set_type(buf, SERVER_HELLO);

        // Save 2 bytes for length

        uint8_t *lengthPointer = (buf + size);
        size += 2;

        // Nonce TLV
        size += set_type(buf + size, NONCE_SERVER_HELLO);
        size += set_length(buf + size, NONCE_SIZE);
        size += set_payload(buf + size, peer_nonce, NONCE_SIZE);

        // Certificate TLV
        memcpy(buf + size, certificate, cert_size);

        size += cert_size;

        // Nonce Signature TLV

        size += set_type(buf + size, NONCE_SIGNATURE_SERVER_HELLO);
        uint8_t *signature_length_checkpoint = buf + size;
        size += 2;

        size_t signature_length = sign(peer_nonce, NONCE_SIZE, buf + size);

        set_length(signature_length_checkpoint, signature_length);
        size += signature_length;

        set_length(lengthPointer, size);

        print_tlv(buf, size);
        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return size;
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
    // return output_io(buf, length);
    switch (state_sec)
    {
    case SERVER_CLIENT_HELLO_AWAIT:
    {
        if (*buf != CLIENT_HELLO)
            exit(4);
        /* Insert Client Hello receiving logic here */

        print("RECV CLIENT HELLO");
        print_hex(buf, 38);
        print_tlv(buf, 38);
        // Process outer TLV
        uint8_t outerType;
        memcpy(&outerType, buf, sizeof(uint8_t));
        uint16_t outerLength;
        memcpy(&outerLength, buf + 1, sizeof(uint16_t));
        outerLength = ntohs(outerLength);

        // Process inner TLV
        uint8_t innerType;
        memcpy(&innerType, buf + PAYLOAD_OFFSET, sizeof(uint8_t));
        uint16_t innerLength;
        memcpy(&innerLength, buf + PAYLOAD_OFFSET + 1, sizeof(uint16_t));
        memcpy(&peer_nonce, buf + PAYLOAD_OFFSET + 3, NONCE_SIZE);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT:
    {
        if (*buf != SERVER_HELLO)
            exit(4);

        /* Insert Server Hello receiving logic here */

        print("RECV SERVER HELLO");
        size_t size = 0;
        // Process Outermost (SERVER HELLO) TLV
        uint8_t server_hello_type;
        memcpy(&server_hello_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t server_hello_length;
        memcpy(&server_hello_length, buf + size, sizeof(uint16_t));
        server_hello_length = ntohs(server_hello_length);
        size += sizeof(uint16_t);
        // Process Nonce TLV
        uint8_t nonce_type;
        memcpy(&nonce_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t nonce_length;
        memcpy(&nonce_length, buf + size, sizeof(uint16_t));
        nonce_length = ntohs(nonce_length);
        size += sizeof(uint16_t);
        memcpy(peer_nonce, buf + size, nonce_length);
        size += nonce_length;

        // Process Certificate TLV
        uint8_t certificate_type;
        memcpy(&certificate_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t certificate_length;
        memcpy(&certificate_length, buf + size, sizeof(uint16_t));
        certificate_length = ntohs(certificate_length);
        size += sizeof(uint16_t);
        // Process Certificate Public Key
        uint8_t cert_public_key_type;
        memcpy(&cert_public_key_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t cert_public_key_length;
        memcpy(&cert_public_key_length, buf + size, sizeof(uint16_t));
        cert_public_key_length = ntohs(cert_public_key_length);
        size += sizeof(uint16_t);
        uint8_t *cert_public_key = malloc(cert_public_key_length);
        memcpy(cert_public_key, buf + size, cert_public_key_length);
        size += cert_public_key_length;
        // Process Certificate Signature
        uint8_t cert_signature_type;
        memcpy(&cert_signature_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t cert_signature_length;
        memcpy(&cert_signature_length, buf + size, sizeof(uint16_t));
        cert_signature_length = ntohs(cert_signature_length);
        size += sizeof(uint16_t);
        uint8_t *cert_signature = malloc(cert_public_key_length);
        memcpy(cert_signature, buf + size, cert_public_key_length);
        size += cert_signature_length;
        // Process Nonce Signature
        uint8_t nonce_signature_type;
        memcpy(&nonce_signature_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t nonce_signature_length;
        memcpy(&nonce_signature_length, buf + size, sizeof(uint16_t));
        nonce_signature_length = ntohs(nonce_signature_length);
        size += sizeof(uint16_t);
        uint8_t *nonce_signature = malloc(nonce_signature_length);
        memcpy(nonce_signature, buf + size, nonce_signature_length);
        size += nonce_signature_length;
        fprintf(stderr, "SIZE IS: %zu\n", size);
        print_tlv(buf, size);

        // Verify Certificate with CA Public Key
        int cert_result = verify(cert_public_key, cert_public_key_length, cert_signature, cert_signature_length, ec_ca_public_key);
        fprintf(stderr, "CERT RESULT IS: %d\n", cert_result);

        if (cert_result == false)
        {
            exit(1);
        }

        load_peer_public_key(cert_public_key, cert_public_key_length);

        // Verify Client Nonce
        int nonce_result = verify(peer_nonce, nonce_length, nonce_signature, nonce_signature_length, ec_peer_public_key);

        fprintf(stderr, "NONCE RESULT IS: %d\n", nonce_result);

        if (nonce_result == false)
        {
            exit(2);
        }

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
