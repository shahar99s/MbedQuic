#include "mbedtls/aes.h"
#include "mbedtls/cipher.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

// Constants
#define QUIC_AEAD_KEY_LENGTH 16
#define QUIC_AEAD_IV_LENGTH 12
#define QUIC_AEAD_TAG_LENGTH 16
#define QUIC_VERSION 0x00000001
#define MAX_PAYLOAD_LENGTH 2048
#define SAMPLE_SIZE 16
#define AAD_BUFFER_SIZE 256

// Type definitions
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

typedef struct {
    u8* buf;
    u32 len;
} vector_t;

typedef struct {
    u8 header_form;
    u8 fixed_bit;
    u8 packet_type;
    u8 reserved_bits;
    u8 packet_number_length;
    u32 version;
    u8 dcid_len;
    const u8* dcid;
    u8 scid_len;
    const u8* scid;
    u8 token_length;
    const u8* token;
    u16 payload_length;
    u16 packet_number;
} parsed_quic_long_header_t;

// Utility function to print hex data
void print_hex(const char* label, const u8* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// --- Add QUIC varint parser ---
size_t quic_parse_varint(const u8* buf, size_t buf_len, uint64_t* value) {
    if (buf_len == 0) return 0;
    u8 first = buf[0];
    size_t len;
    if ((first & 0xC0) == 0x00) len = 1;
    else if ((first & 0xC0) == 0x40) len = 2;
    else if ((first & 0xC0) == 0x80) len = 4;
    else len = 8;
    if (buf_len < len) return 0;
    uint64_t v = first & (0xFF >> (2 * (len - 1)));
    for (size_t i = 1; i < len; i++) {
        v = (v << 8) | buf[i];
    }
    *value = v;
    return len;
}

// --- Fix HKDF-Expand-Label to always use "tls13 " and context as "" ---
int hkdf_expand_label(const mbedtls_md_info_t* md, const u8* secret, size_t secret_len,
                      const char* label, const u8* context, size_t context_len,
                      u8* out, size_t out_len) {
    u8 hkdf_label[512];
    size_t pos = 0;
    const char* prefix = "tls13 ";
    size_t prefix_len = strlen(prefix);
    size_t label_len = strlen(label);
    size_t total_label_len = prefix_len + label_len;
    if (total_label_len > 255) return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;

    hkdf_label[pos++] = (out_len >> 8) & 0xFF;
    hkdf_label[pos++] = out_len & 0xFF;
    hkdf_label[pos++] = (u8)total_label_len;
    memcpy(hkdf_label + pos, prefix, prefix_len);
    pos += prefix_len;
    memcpy(hkdf_label + pos, label, label_len);
    pos += label_len;
    hkdf_label[pos++] = (u8)context_len;
    if (context_len > 0 && context != NULL) {
        memcpy(hkdf_label + pos, context, context_len);
        pos += context_len;
    }
    return mbedtls_hkdf_expand(md, secret, secret_len, hkdf_label, pos, out, out_len);
}

// --- Fix derive_quic_keys to use "" as context ---
bool derive_quic_keys(const u8* initial_salt, size_t salt_len, const u8* dcid, size_t dcid_len,
                      u8* key, size_t key_len, u8* iv, size_t iv_len, u8* hp_key, size_t hp_key_len) {
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return false;

    u8 initial_secret[32];
    if (mbedtls_hkdf_extract(md, initial_salt, salt_len, dcid, dcid_len, initial_secret) != 0)
        return false;

    u8 client_initial_secret[32];
    u8 empty_context[0] = {};
    if (hkdf_expand_label(md, initial_secret, sizeof(initial_secret), "client in", empty_context, 0, client_initial_secret, sizeof(client_initial_secret)) != 0)
        return false;

    if (hkdf_expand_label(md, client_initial_secret, sizeof(client_initial_secret), "quic key", empty_context, 0, key, key_len) != 0)
        return false;
    if (hkdf_expand_label(md, client_initial_secret, sizeof(client_initial_secret), "quic iv", empty_context, 0, iv, iv_len) != 0)
        return false;
    if (hkdf_expand_label(md, client_initial_secret, sizeof(client_initial_secret), "quic hp", empty_context, 0, hp_key, hp_key_len) != 0)
        return false;

    return true;
}

// Function to check if it is a QUIC long header
bool is_quic_long_header(const vector_t* pkt) {
    return (pkt->buf[0] & 0x80) == 0x80;
}

// Function to parse QUIC long header
bool parse_quic_long_header(const vector_t* pkt, parsed_quic_long_header_t* header) {
    const u8* bytes = pkt->buf;
    const u8* end = pkt->buf + pkt->len;

    if (pkt->len < 7) {
        fprintf(stderr, "Packet too short for QUIC long header\n");
        return false;
    }

    header->header_form = (bytes[0] >> 7) & 0x01;
    header->fixed_bit = (bytes[0] >> 6) & 0x01;
    header->packet_type = (bytes[0] >> 4) & 0x03;
    header->reserved_bits = (bytes[0] >> 2) & 0x03;
    header->packet_number_length = (bytes[0] & 0x03) + 1;
    bytes++;

    if (end - bytes < 4) {
        fprintf(stderr, "Packet too short for version\n");
        return false;
    }
    header->version = ntohl(*(u32*)bytes);
    bytes += 4;

    if (end - bytes < 1) {
        fprintf(stderr, "Packet too short for DCID length\n");
        return false;
    }
    header->dcid_len = *bytes++;

    if (end - bytes < header->dcid_len) {
        fprintf(stderr, "Packet too short for DCID\n");
        return false;
    }
    header->dcid = bytes;
    bytes += header->dcid_len;

    if (end - bytes < 1) {
        fprintf(stderr, "Packet too short for SCID length\n");
        return false;
    }
    header->scid_len = *bytes++;

    if (end - bytes < header->scid_len) {
        fprintf(stderr, "Packet too short for SCID\n");
        return false;
    }
    header->scid = bytes;
    bytes += header->scid_len;

    // --- Parse token length as varint ---
    uint64_t token_length = 0;
    size_t token_len_bytes = quic_parse_varint(bytes, end - bytes, &token_length);
    if (token_len_bytes == 0) {
        fprintf(stderr, "Failed to parse token length varint\n");
        return false;
    }
    header->token_length = (u8)token_length;
    bytes += token_len_bytes;

    if (end - bytes < header->token_length) {
        fprintf(stderr, "Packet too short for token\n");
        return false;
    }
    header->token = bytes;
    bytes += header->token_length;

    // --- Parse payload length as varint ---
    uint64_t payload_length = 0;
    size_t payload_len_bytes = quic_parse_varint(bytes, end - bytes, &payload_length);
    if (payload_len_bytes == 0) {
        fprintf(stderr, "Failed to parse payload length varint\n");
        return false;
    }
    header->payload_length = (u16)payload_length;
    bytes += payload_len_bytes;

    if (end - bytes < header->packet_number_length) {
        fprintf(stderr, "Packet too short for packet number\n");
        return false;
    }

    header->packet_number = 0;
    for (int i = 0; i < header->packet_number_length; i++) {
        header->packet_number = (header->packet_number << 8) | bytes[i];
    }
    bytes += header->packet_number_length;

    // Print the parsed header fields
    printf("Header Form: %u\n", header->header_form);
    printf("Fixed Bit: %u\n", header->fixed_bit);
    printf("Long Packet Type: %u\n", header->packet_type);
    printf("Reserved Bits: %u\n", header->reserved_bits);
    printf("Packet Number Length: %u\n", header->packet_number_length);
    printf("Version: 0x%08X\n", header->version);
    printf("DCID Length: %u\n", header->dcid_len);
    print_hex("DCID", header->dcid, header->dcid_len);
    printf("SCID Length: %u\n", header->scid_len);
    print_hex("SCID", header->scid, header->scid_len);
    printf("Token Length: %u\n", header->token_length);
    if (header->token_length > 0) {
        print_hex("Token", header->token, header->token_length);
    }
    printf("Payload Length: %u\n", header->payload_length);
    printf("Packet Number: %u\n", header->packet_number);

    return true;
}

// Function to parse a QUIC short header (simulated for now)
bool parse_quic_short_header(const vector_t* pkt) {
    printf("Parsing QUIC short header...\n");
    return true;
}

// Function to parse a QUIC packet
bool parse_quic(vector_t* l5_packet, parsed_quic_long_header_t* header) {
    if (is_quic_long_header(l5_packet)) {
        return parse_quic_long_header(l5_packet, header);
    }
    return parse_quic_short_header(l5_packet);
}

// Function to decrypt the QUIC payload using AES-GCM
bool decrypt_quic_payload(const u8* raw_quic_packet, size_t raw_quic_packet_len, parsed_quic_long_header_t* header, u8* decrypted_payload) {
    mbedtls_gcm_context gcm_ctx;
    mbedtls_gcm_init(&gcm_ctx);

    u8 key[QUIC_AEAD_KEY_LENGTH];
    u8 iv[QUIC_AEAD_IV_LENGTH];
    u8 hp_key[QUIC_AEAD_KEY_LENGTH];

    u8 initial_salt[] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
    size_t initial_salt_len = sizeof(initial_salt);

    if (!derive_quic_keys(initial_salt, initial_salt_len, header->dcid, header->dcid_len,
                         key, sizeof(key), iv, sizeof(iv), hp_key, sizeof(hp_key))) {
        fprintf(stderr, "Key derivation failed.\n");
        mbedtls_gcm_free(&gcm_ctx);
        return false;
    }

    print_hex("Key", key, sizeof(key));
    print_hex("IV", iv, sizeof(iv));
    print_hex("HP Key", hp_key, sizeof(hp_key));

    // --- Calculate pn_offset using varint logic ---
    const u8* p = raw_quic_packet;
    p++; // flags
    p += 4; // version
    p++; // dcid len
    p += header->dcid_len;
    p++; // scid len
    p += header->scid_len;

    // token length varint
    uint64_t token_length = 0;
    size_t token_len_bytes = quic_parse_varint(p, raw_quic_packet_len - (p - raw_quic_packet), &token_length);
    p += token_len_bytes;
    p += token_length;

    // payload length varint
    uint64_t payload_length = 0;
    size_t payload_len_bytes = quic_parse_varint(p, raw_quic_packet_len - (p - raw_quic_packet), &payload_length);
    p += payload_len_bytes;

    size_t pn_offset = p - raw_quic_packet;

    // Make a mutable copy of the header for unmasking
    u8 header_copy[AAD_BUFFER_SIZE];
    if (raw_quic_packet_len < pn_offset + 4 + SAMPLE_SIZE) {
        fprintf(stderr, "Packet too short for header protection sampling.\n");
        mbedtls_gcm_free(&gcm_ctx);
        return false;
    }
    memcpy(header_copy, raw_quic_packet, pn_offset + 4); // 4 is max packet number length

    // Get sample for header protection
    u8 sample[SAMPLE_SIZE];
    memcpy(sample, raw_quic_packet + pn_offset + 4, SAMPLE_SIZE);

    // Generate mask
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    if (mbedtls_aes_setkey_enc(&aes_ctx, hp_key, sizeof(hp_key) * 8) != 0) {
        fprintf(stderr, "Failed to set AES key for header protection\n");
        mbedtls_aes_free(&aes_ctx);
        mbedtls_gcm_free(&gcm_ctx);
        return false;
    }
    u8 mask[SAMPLE_SIZE];
    if (mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, sample, mask) != 0) {
        fprintf(stderr, "AES encryption failed for header protection\n");
        mbedtls_aes_free(&aes_ctx);
        mbedtls_gcm_free(&gcm_ctx);
        return false;
    }
    mbedtls_aes_free(&aes_ctx);

    // Unmask first byte in header_copy
    header_copy[0] = (header_copy[0] & 0xF0) | ((header_copy[0] ^ mask[0]) & 0x0F);
    u8 pnl = (header_copy[0] & 0x03) + 1;

    // Unmask packet number bytes in header_copy
    for (u8 i = 0; i < pnl; i++) {
        header_copy[pn_offset + i] ^= mask[1 + i];
    }

    // Reconstruct packet number
    u32 packet_number = 0;
    for (u8 i = 0; i < pnl; i++) {
        packet_number = (packet_number << 8) | header_copy[pn_offset + i];
    }
    print_hex("packet number", (u8*)&packet_number, pnl);

    // Reconstruct full packet number (RFC 9001 §5.4.1)
    u64 expected_pn = 0; // You should set this to the expected next packet number for your connection
    u64 full_packet_number = quic_reconstruct_pn(expected_pn, packet_number, pnl);
    printf("Full Packet Number: %llu\n", (unsigned long long)full_packet_number);

    // Prepare IV
    if (mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, sizeof(key) * 8) != 0) {
        fprintf(stderr, "Failed to set AES-GCM key\n");
        mbedtls_gcm_free(&gcm_ctx);
        return false;
    }
    u8 full_iv[QUIC_AEAD_IV_LENGTH];
    memcpy(full_iv, iv, sizeof(iv));
    for (u8 i = 0; i < pnl; i++) {
        full_iv[sizeof(iv) - 1 - i] ^= (packet_number >> (8 * i)) & 0xFF;
    }
    print_hex("full_iv", full_iv, sizeof(full_iv));

    // Use the unmasked header as AAD
    size_t aad_len = pn_offset + pnl;
    u8 aad[AAD_BUFFER_SIZE];
    memcpy(aad, header_copy, aad_len);

    // Decrypt
    size_t protected_payload_len = header->payload_length;
    if (raw_quic_packet_len < pn_offset + pnl + protected_payload_len) {
        fprintf(stderr, "Packet smaller than Payload length.\n");
        mbedtls_gcm_free(&gcm_ctx);
        return false;
    }
    u8* protected_payload = (u8*)raw_quic_packet + pn_offset + pnl;
    u8* auth_tag = protected_payload + protected_payload_len - QUIC_AEAD_TAG_LENGTH;
    size_t ciphertext_len = protected_payload_len - QUIC_AEAD_TAG_LENGTH;

    if (ciphertext_len > MAX_PAYLOAD_LENGTH) {
        fprintf(stderr, "Ciphertext too long.\n");
        mbedtls_gcm_free(&gcm_ctx);
        return false;
    }

    int ret = mbedtls_gcm_auth_decrypt(&gcm_ctx, ciphertext_len, full_iv, sizeof(full_iv), aad, aad_len,
                                        auth_tag, QUIC_AEAD_TAG_LENGTH, protected_payload, decrypted_payload);

    if (ret != 0) {
        fprintf(stderr, "Decryption failed: %d\n", ret);
        mbedtls_gcm_free(&gcm_ctx);
        return false;
    }

    mbedtls_gcm_free(&gcm_ctx);
    return true;
}

int main() {
    u8 sample_data[] = {
        0xcb, // flags
        0x00, 0x00, 0x00, 0x01, // version
        0x0c, // DCID length
        0x43, 0xec, 0x9d, 0x12, 0x17, 0xb8, 0x8a, 0xdc, 0x99, 0x29, 0x2a, 0xa0, // DCID
        0x00, // SCID Length
        0x00, // Token Length
        0x00, 0x44, // Payload Length (including packet number)
        0xb5, 0x22, // Packet Number
        0xcc, 0x69, 0x77, 0x5d, 0x01, 0x8f, 0xd9, 0x25,
        0xbe, 0xdb, 0xd9, 0x42, 0x14, 0x9d, 0x3e, 0x52, 0x58, 0xb7, 0x2e, 0xe5, 0x6f, 0x80, 0x2c, 0x39,
        0xbf, 0xb7, 0x77, 0xeb, 0xb2, 0xa5, 0xfc, 0x8f, 0x2a, 0x78, 0x83, 0xbd, 0x02, 0x5d, 0x31, 0x52,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    vector_t l5_packet = {
        .buf = sample_data,
        .len = sizeof(sample_data)
    };

    parsed_quic_long_header_t header;
    if (parse_quic(&l5_packet, &header)) {
        printf("QUIC packet parsed successfully.\n");

        u8 decrypted_payload[MAX_PAYLOAD_LENGTH];
        if (decrypt_quic_payload(l5_packet.buf, l5_packet.len, &header, decrypted_payload)) {
            printf("QUIC payload decrypted successfully.\n");
            print_hex("Decrypted Payload", decrypted_payload, header.payload_length - QUIC_AEAD_TAG_LENGTH);
        } else {
            printf("QUIC payload decryption failed.\n");
        }
    } else {
        printf("QUIC packet parsing failed.\n");
    }

    return 0;
}
