#ifndef DOUBLETAKE_FAIRPLAY_V2_H
#define DOUBLETAKE_FAIRPLAY_V2_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum fairplay_v2_result {
    FAIRPLAY_V2_OK = 0,
    FAIRPLAY_V2_INVALID = -1,
    FAIRPLAY_V2_NOMEM = -2,
    FAIRPLAY_V2_CRYPTO = -3,
    FAIRPLAY_V2_UNSUPPORTED = -4
};

typedef struct fairplay_v2 fairplay_v2_t;

/* Create a receiver context with a fresh 128-byte SAP. */
fairplay_v2_t *fairplay_v2_new(void);

/* Deterministic constructor for tests and differential validation. */
fairplay_v2_t *fairplay_v2_new_with_receiver_sap(
    const uint8_t receiver_sap[128]);

void fairplay_v2_free(fairplay_v2_t *fairplay);

/* Process the fixed-size selector-2 /fp-setup records. */
int fairplay_v2_setup(fairplay_v2_t *fairplay,
                      const uint8_t request[16], uint8_t response[142]);
int fairplay_v2_handshake(fairplay_v2_t *fairplay,
                          const uint8_t request[164], uint8_t response[32]);

/* Decrypt and authenticate a selector-2 media key after the handshake. */
int fairplay_v2_decrypt_key(fairplay_v2_t *fairplay,
                            const uint8_t encrypted_key[72],
                            uint8_t raw_key[16]);

/* Normalized v2 SAP-body transforms, exposed for differential tests. */
int fairplay_v2_encrypt_sap(uint8_t mode, const uint8_t plaintext[128],
                            uint8_t encrypted[128]);
int fairplay_v2_decrypt_sap(uint8_t mode, const uint8_t encrypted[128],
                            uint8_t plaintext[128]);

#ifdef __cplusplus
}
#endif

#endif
