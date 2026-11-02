#ifndef DOUBLETAKE_FAIRPLAY_V2_HELPER_H
#define DOUBLETAKE_FAIRPLAY_V2_HELPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fairplay_v2_helper fairplay_v2_helper_t;

/*
 * Start the development-only Apple-emulation helper in receiver mode.
 * Returns NULL on unsupported platforms or process/protocol failure.
 */
fairplay_v2_helper_t *fairplay_v2_helper_new(const char *command,
                                             const char *hardware_id_hex);

int fairplay_v2_helper_exchange(fairplay_v2_helper_t *helper,
                                const uint8_t *request, size_t request_length,
                                uint8_t *response, size_t response_capacity,
                                size_t *response_length);

int fairplay_v2_helper_unwrap(fairplay_v2_helper_t *helper,
                              const uint8_t encrypted_key[72],
                              uint8_t raw_key[16]);

void fairplay_v2_helper_free(fairplay_v2_helper_t *helper);

#ifdef __cplusplus
}
#endif

#endif
