#include "fairplay_v2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

static int nibble(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static void decode(const char *hex, unsigned char *output, size_t length)
{
    size_t i;
    if (strlen(hex) != length * 2) {
        fprintf(stderr, "bad test vector length: got %zu, want %zu\n",
                strlen(hex), length * 2);
        exit(2);
    }
    for (i = 0; i < length; i++) {
        int high = nibble(hex[2 * i]);
        int low = nibble(hex[2 * i + 1]);
        if (high < 0 || low < 0) exit(2);
        output[i] = (unsigned char)((high << 4) | low);
    }
}

static void check_equal(const char *name, const unsigned char *actual,
                        const unsigned char *expected, size_t length)
{
    if (memcmp(actual, expected, length) != 0) {
        size_t i;
        fprintf(stderr, "FAIL: %s\n  actual:   ", name);
        for (i = 0; i < length; i++) fprintf(stderr, "%02x", actual[i]);
        fprintf(stderr, "\n  expected: ");
        for (i = 0; i < length; i++) fprintf(stderr, "%02x", expected[i]);
        fputc('\n', stderr);
        failures++;
    }
}

static void check_result(const char *name, int actual, int expected)
{
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s returned %d, want %d\n",
                name, actual, expected);
        failures++;
    }
}

static void test_sap_modes(void)
{
    static const char *const zero_vectors[4] = {
        "f2ea47372ed49f8bd77f804ac853c9b438483a7ed6d899de6acaee802cf7b5b7"
        "19b189ce403cc51bd519b791fd11293ed94701c2d402eaa6816bcdc23744a0c5"
        "284a0090e433c329c3b72f9278d907839f7fb78a2fc4f7dbd5eecf50287f9bf"
        "673445d3212f46b1e1c044ed7a75c7cfdec395e4d940afe01f7b4d3eb52d26ca5",
        "e46f4c7ddab8208ee82a08994d4ae797e1460e21cf6aee310fded400cfee03e2"
        "8958d878ff407395b13337e65a5ba5249b3dcce7f1e8600752bf86e81fd7098f"
        "eaaefaecc4c9ca93930af908cf592aa0858723995391cdbdee66df152db04a497"
        "f40a64c4671b395ecbc066a82d400c9ed763866345826a493707ce476242b8d",
        "a798489aa2ef20a3dd62e3f1dc3a6ecf130849fe367c18a8e7c80781f238c628"
        "96fdaafa26779fda5fb1ef24c8b7ac5b5faf7a3a810e59e55c66e59c6010028f"
        "ce8a08aa5776eb34ff1430df07a7c92b83ee08c6b8a608fea5af190938b5a60d"
        "d5a7736ff04f7d5d0fdd236c82e3ea3aff61224a2c75e1ffb7645dc71cf1fb50",
        "097b4fb80d3adb7e6ead2001134487e9aa3d5d5320ea72a5a28baf4ce06899a6"
        "a2a558dda7419e55578beb7f35c3640fe96b18bd9367f4c1baf48a866d3a036a"
        "f4a6090d142b57589be4ca0336df126552828b5f6d91f8119545a4156457320c"
        "032287d1cec75ab437acef52fdcf2284583a849d4a7b4a5c705e7982fe941f44"
    };
    unsigned char zero[128] = {0};
    unsigned char pattern[128], encrypted[128], decrypted[128], expected[128];
    unsigned mode, i;

    for (i = 0; i < sizeof(pattern); i++) pattern[i] = (unsigned char)i;
    for (mode = 0; mode < 4; mode++) {
        char name[64];
        decode(zero_vectors[mode], expected, sizeof(expected));
        snprintf(name, sizeof(name), "mode %u zero encrypt", mode);
        check_result(name, fairplay_v2_encrypt_sap((unsigned char)mode, zero,
                                                    encrypted), 0);
        check_equal(name, encrypted, expected, sizeof(expected));
        snprintf(name, sizeof(name), "mode %u zero decrypt", mode);
        check_result(name, fairplay_v2_decrypt_sap((unsigned char)mode,
                                                    encrypted, decrypted), 0);
        check_equal(name, decrypted, zero, sizeof(zero));

        snprintf(name, sizeof(name), "mode %u patterned round trip", mode);
        check_result(name, fairplay_v2_encrypt_sap((unsigned char)mode,
                                                    pattern, encrypted), 0);
        check_result(name, fairplay_v2_decrypt_sap((unsigned char)mode,
                                                    encrypted, decrypted), 0);
        check_equal(name, decrypted, pattern, sizeof(pattern));
    }
}

static void test_apple_handshake(void)
{
    static const char receiver_hex[] =
        "0001400b49ba706df04c577eb2cc8c0a7e09ecc52be8a564ea59923bb7611824c"
        "7d69fa721f0ff38553f7df1085f63d9ebd687b721661f0b49d997db95ed18736"
        "a72e8b376c9bc1454d17b4a5b6e266bdc9477e17dc848dba4b9ec27b25f2d1"
        "8085c06f8f56a811d5752643b3738b05a30389d695fda1e4eeedf736a9aadfafc";
    static const char m1_hex[] = "46504c590201010000000004020002bb";
    static const char m2_hex[] =
        "46504c590201020000000082020210aa74af856e08e4edee79177326246d0756"
        "494f1250d51338dbbee842e06d220db234def0cd8fdddca9930c2aa37241a021"
        "2ef85076dc60b6dd5f49db0e06aacadfd39447c828ad71fda65eb407c7bdbc6"
        "faafa86538fc0041acdf86862be069bbb75e521da8b20f5ae50e57c47c99b86"
        "0592a09eab354a73c69556a969c608";
    static const char m3_hex[] =
        "46504c590201030000000098028f1a9cff9b5507f10dc0fcff339eca1a67aa4e"
        "d7556ea081752f8beebfd2673454762c4db9ceb2d754d30e4e88f16f4ceaca67"
        "f51c3b6bb5741524bca8a330f16e4d1eca614985c3ad9765a2fa7c99ceddc29"
        "5e247a6afc24ebc9ee1f7973e3043a5b671c0a33895ea496a6098639114dd5e"
        "deda3d7d0b656b2db06bbc7d805e9a6548a7a12e4a03de0430551810b58b3a"
        "b107426784ff";
    static const char m4_hex[] =
        "46504c590201040000000014a7a12e4a03de0430551810b58b3ab107426784ff";
    static const char encrypted_key_hex[] =
        "46504c59010201000000003c00000000ccf15737e496774c0ffaf65bf567a1c6"
        "000000100bed89519a7aaee8fe37269d8da0325abe453205d7d8cf91641fc7a2"
        "2c52e852e58a5fc9";
    static const unsigned char expected_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    unsigned char receiver[128], m1[16], m2[142], m3[164], m4[32];
    unsigned char actual_m2[142], actual_m4[32], encrypted_key[72] = {0};
    unsigned char key[16];
    fairplay_v2_t *fairplay;

    decode(receiver_hex, receiver, sizeof(receiver));
    decode(m1_hex, m1, sizeof(m1));
    decode(m2_hex, m2, sizeof(m2));
    decode(m3_hex, m3, sizeof(m3));
    decode(m4_hex, m4, sizeof(m4));
    decode(encrypted_key_hex, encrypted_key, sizeof(encrypted_key));
    fairplay = fairplay_v2_new_with_receiver_sap(receiver);
    if (fairplay == NULL) {
        fprintf(stderr, "FAIL: allocate deterministic context\n");
        failures++;
        return;
    }

    check_result("Apple M1 -> M2", fairplay_v2_setup(fairplay, m1,
                                                      actual_m2), 0);
    check_equal("Apple M2", actual_m2, m2, sizeof(m2));
    check_result("Apple M3 -> M4", fairplay_v2_handshake(fairplay, m3,
                                                          actual_m4), 0);
    check_equal("Apple M4", actual_m4, m4, sizeof(m4));

    memset(key, 0xa5, sizeof(key));
    check_result("Apple v2 media-key unwrap",
                 fairplay_v2_decrypt_key(fairplay, encrypted_key, key),
                 FAIRPLAY_V2_OK);
    check_equal("Apple v2 raw media key", key, expected_key, sizeof(key));

    encrypted_key[36] ^= 1;
    memset(key, 0xa5, sizeof(key));
    check_result("reject tampered v2 key MAC",
                 fairplay_v2_decrypt_key(fairplay, encrypted_key, key),
                 FAIRPLAY_V2_INVALID);
    check_equal("bad MAC clears output", key,
                (const unsigned char[16]){0}, sizeof(key));
    encrypted_key[36] ^= 1;

    encrypted_key[71] ^= 1;
    memset(key, 0xa5, sizeof(key));
    check_result("reject tampered v2 ciphertext",
                 fairplay_v2_decrypt_key(fairplay, encrypted_key, key),
                 FAIRPLAY_V2_INVALID);
    check_equal("bad ciphertext clears output", key,
                (const unsigned char[16]){0}, sizeof(key));
    encrypted_key[71] ^= 1;

    encrypted_key[0] ^= 1;
    memset(key, 0xa5, sizeof(key));
    check_result("reject malformed v2 key record",
                 fairplay_v2_decrypt_key(fairplay, encrypted_key, key),
                 FAIRPLAY_V2_INVALID);
    check_equal("bad record clears output", key,
                (const unsigned char[16]){0}, sizeof(key));
    encrypted_key[0] ^= 1;

    m3[163] ^= 1;
    check_result("reject bad M3 confirmation",
                 fairplay_v2_handshake(fairplay, m3, actual_m4),
                 FAIRPLAY_V2_INVALID);
    fairplay_v2_free(fairplay);
}

int main(void)
{
    test_sap_modes();
    test_apple_handshake();
    if (failures != 0) {
        fprintf(stderr, "%d FairPlay v2 test(s) failed\n", failures);
        return 1;
    }
    puts("FairPlay v2 C vectors passed");
    return 0;
}
