#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"

#define PAYLOAD_OFFSET 3
#define IV_LENGTH 16

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

        size += set_type(buf + size, SERVER_HELLO);

        // Save 2 bytes for length

        uint8_t *lengthPointer = (buf + size);
        size += 2;

        // Nonce TLV
        size += set_type(buf + size, NONCE_SERVER_HELLO);
        size += set_length(buf + size, NONCE_SIZE);
        size += set_payload(buf + size, nonce, NONCE_SIZE);

        // Certificate TLV

        // find size of certificate
        uint16_t cert_length;
        memcpy(&cert_length, certificate + 1, 2);
        cert_length = ntohs(cert_length);
        // fprintf(stderr, "CERT SIZE IS %u\n", cert_length);
        memcpy(buf + size, certificate, cert_length + 3);

        size += cert_length + 3;

        // Nonce Signature TLV

        size += set_type(buf + size, NONCE_SIGNATURE_SERVER_HELLO);
        uint8_t *signature_length_checkpoint = buf + size;
        size += 2;

        size_t signature_length = sign(peer_nonce, NONCE_SIZE, buf + size);

        set_length(signature_length_checkpoint, signature_length);
        size += signature_length;

        set_length(lengthPointer, size - 3);

        print_tlv(buf, size);
        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return size;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND:
    {
        print("SEND KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request sending logic here */
        derive_secret();
        derive_keys();

        size_t size = 0;
        size += set_type(buf + size, KEY_EXCHANGE_REQUEST);
        uint8_t *key_exchange_length = buf + size;
        size += sizeof(uint16_t);
        // Set Certificate
        size += set_type(buf + size, CERTIFICATE);
        uint8_t *certificate_length = buf + size;
        size += sizeof(uint16_t);
        size += set_type(buf + size, PUBLIC_KEY);
        size += set_length(buf + size, pub_key_size);
        set_payload(buf + size, public_key, pub_key_size);
        size += pub_key_size;
        size += set_type(buf + size, SIGNATURE);
        uint8_t *signature_length_checkpoint = buf + size;
        size += sizeof(uint16_t);
        size_t signature_length = sign(public_key, pub_key_size, buf + size);
        set_length(signature_length_checkpoint, signature_length);
        size += signature_length;

        set_length(certificate_length, size);

        size += set_type(buf + size, NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST);
        uint8_t *nonce_signature_length_checkpoint = buf + size;
        size += sizeof(uint16_t);
        size_t nonce_signature_length = sign(peer_nonce, NONCE_SIZE, buf + size);
        set_length(nonce_signature_length_checkpoint, nonce_signature_length);
        size += nonce_signature_length;

        set_length(key_exchange_length, size - 3);

        print_tlv(buf, size);

        state_sec = CLIENT_FINISHED_AWAIT;
        return size;
    }
    case SERVER_FINISHED_SEND:
    {
        print("SEND FINISHED");
        derive_secret();
        derive_keys();

        /* Insert Finished sending logic here */
        size_t size = 0;
        size += set_type(buf + size, FINISHED);
        set_length(buf + size, 0);

        state_sec = DATA_STATE;
        return size;
    }
    case DATA_STATE:
    {
        uint8_t std_in_text[943];
        uint16_t std_in_size = input_io(std_in_text, 943);
        if (std_in_size <= 0)
        {
            return 0;
        }
        fprintf(stderr, "STDIN Size: %hu\n", std_in_size);
        /* Insert Data sending logic here */
        size_t size = 0;

        // Set Data TLV
        size += set_type(buf + size, DATA);
        uint8_t *dataLengthCheckpoint = buf + size;
        size += sizeof(uint16_t);

        // SET IV TLV
        size += set_type(buf + size, INITIALIZATION_VECTOR);
        size += set_length(buf + size, IV_LENGTH);
        uint8_t *ivCheckpoint = buf + size;
        size += IV_LENGTH;

        // Set Ciphertext TLV
        size += set_type(buf + size, CIPHERTEXT);
        uint8_t *ciphertextLengthCheckpoint = buf + size;
        size += sizeof(uint16_t);
        uint8_t *ciphertextCheckpoint = buf + size;
        size_t cipher_size = encrypt_data(std_in_text, std_in_size, ivCheckpoint, buf + size);
        set_length(ciphertextLengthCheckpoint, cipher_size);
        size += cipher_size;
        print("SANITY 2");
        // Set MAC TLV
        size += set_type(buf + size, MESSAGE_AUTHENTICATION_CODE);
        size += set_length(buf + size, 32);
        uint8_t *iv_and_ciphertext = malloc(IV_LENGTH + cipher_size);
        memcpy(iv_and_ciphertext, ivCheckpoint, IV_LENGTH);
        memcpy(iv_and_ciphertext + IV_LENGTH, ciphertextCheckpoint, cipher_size);
        hmac(iv_and_ciphertext, IV_LENGTH + cipher_size, buf + size);
        size += 32;

        set_length(dataLengthCheckpoint, size - 3);

        // size += set_payload(buf + size, init)
        // PT refers to the amount you read from stdin in bytes
        // CT refers to the resulting ciphertext size
        // fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, cip_size);

        return size;
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
        print_tlv(buf, 38);
        // Process outer TLV
        size_t size = 0;
        uint8_t client_hello_type;
        memcpy(&client_hello_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t client_hello_length;
        memcpy(&client_hello_length, buf + size, sizeof(uint16_t));
        client_hello_length = ntohs(client_hello_length);
        size += sizeof(uint16_t);

        // Process Nonce TLV
        uint8_t nonce_type;
        memcpy(&nonce_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t nonce_length;
        memcpy(&nonce_length, buf + size, sizeof(uint16_t));
        nonce_length = ntohs(nonce_length);
        size += sizeof(uint16_t);
        memcpy(&peer_nonce, buf + size, nonce_length);
        size += nonce_length;

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
        // fprintf(stderr, "NONCE SIG LENGTH: %d\n", nonce_signature_length);
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

 

        // Verify Client Nonce
        // fprintf(stderr, "Peer Nonce is: ");
        // print_hex(peer_nonce, NONCE_SIZE);
        // fprintf(stderr, "Nonce Signature Length is: %d\n", nonce_signature_length);
        // print_hex(nonce_signature, nonce_signature_length);
        // fprintf(stderr, "Public Key is: ");
        // print_hex(ec_peer_public_key, cert_public_key_length);
        int nonce_result = verify(nonce, NONCE_SIZE, nonce_signature, nonce_signature_length, ec_peer_public_key);

        fprintf(stderr, "NONCE RESULT IS: %d\n", nonce_result);

        if (nonce_result != true)
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
        size_t size = 0;
        uint8_t key_exchange_request_type;
        memcpy(&key_exchange_request_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t key_exchange_request_length;
        memcpy(&key_exchange_request_length, buf + size, sizeof(uint16_t));
        key_exchange_request_length = ntohs(key_exchange_request_length);
        size += sizeof(uint16_t);

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
        load_peer_public_key(cert_public_key, cert_public_key_length);

        // Verify Certificate with CA Public Key
        int cert_result = verify(cert_public_key, cert_public_key_length, cert_signature, cert_signature_length, ec_peer_public_key);
        fprintf(stderr, "CERT RESULT IS: %d\n", cert_result);

        if (cert_result == false)
        {
            exit(1);
        }
        print_hex(peer_nonce, NONCE_SIZE);
        // Verify Client Nonce
        int nonce_result = verify(nonce, NONCE_SIZE, nonce_signature, nonce_signature_length, ec_peer_public_key);

        fprintf(stderr, "NONCE RESULT IS: %d\n", nonce_result);

        if (nonce_result == false)
        {
            exit(2);
        }

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
        size_t size = 0;
        uint8_t data_type;
        memcpy(&data_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t data_length;
        memcpy(&data_length, buf + size, sizeof(uint16_t));
        data_length = ntohs(data_length);
        size += sizeof(uint16_t);
        // Process IV
        uint8_t IV_type;
        memcpy(&IV_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t IV_length;
        memcpy(&IV_length, buf + size, sizeof(uint16_t));
        IV_length = ntohs(IV_length);
        size += sizeof(uint16_t);
        uint8_t IV_data[IV_length];
        memcpy(IV_data, buf + size, IV_length);
        size += IV_length;

        // Process Ciphertext
        uint8_t ciphertext_type;
        memcpy(&ciphertext_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t ciphertext_length;
        memcpy(&ciphertext_length, buf + size, sizeof(uint16_t));
        ciphertext_length = ntohs(ciphertext_length);
        size += sizeof(uint16_t);

        uint8_t *ciphertext_data = malloc(ciphertext_length);
        memcpy(ciphertext_data, buf + size, ciphertext_length);
        size += ciphertext_length;

        // Process MAC
        uint8_t mac_type;
        memcpy(&mac_type, buf + size, sizeof(uint8_t));
        size += sizeof(uint8_t);
        uint16_t mac_length;
        memcpy(&mac_length, buf + size, sizeof(uint16_t));
        mac_length = ntohs(mac_length);
        size += sizeof(uint16_t);
        uint8_t mac_data[32];
        memcpy(mac_data, buf + size, 32);
        size += mac_length;

        // Calculate HMAC Digest
        uint8_t *iv_and_ciphertext = malloc(IV_length + ciphertext_length);
        memcpy(iv_and_ciphertext, IV_data, IV_length);
        memcpy(iv_and_ciphertext + IV_length, ciphertext_data, ciphertext_length);
        uint8_t hmac_data[32];
        hmac(iv_and_ciphertext, IV_length + ciphertext_length, hmac_data);
        print_tlv(buf, size);

        fprintf(stderr, "SENT MAC IS:");
        print_hex(mac_data, mac_length);
        fprintf(stderr, "CALCULATED HMAC IS:");
        print_hex(hmac_data, 32);
        int result = memcmp(hmac_data, mac_data, 32);
        if (result != 0)
        {
            print("HMAC DOES NOT MATCH");
            exit(3);
        }

        print("HMAC MATCH");
        uint8_t decrypted_data[943];
        size_t decrypt_size = decrypt_cipher(ciphertext_data, ciphertext_length, IV_data, decrypted_data);
        fprintf(stderr, "RECV DATA PT %ld CT %hu\n", decrypt_size, ciphertext_length);
        return output_io(decrypted_data, decrypt_size);

        /* Insert Data receiving logic here */

        // PT refers to the resulting plaintext size in bytes
        // CT refers to the received ciphertext size
        break;
    }
    default:
        break;
    }
}
