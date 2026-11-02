#include "fairplay_v2_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int nibble(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static void decode(const char *hex, unsigned char *output, size_t length)
{
    size_t i;
    if (strlen(hex) != 2 * length) exit(2);
    for (i = 0; i < length; i++) {
        int high = nibble(hex[2 * i]), low = nibble(hex[2 * i + 1]);
        if (high < 0 || low < 0) exit(2);
        output[i] = (unsigned char)((high << 4) | low);
    }
}

static void require_equal(const char *name, const unsigned char *actual,
                          const unsigned char *expected, size_t length)
{
    if (memcmp(actual, expected, length) != 0) {
        fprintf(stderr, "%s mismatch\n", name);
        exit(1);
    }
}

int main(int argc, char **argv)
{
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
    static const char ekey_hex[] =
        "46504c59010201000000003c00000000ccf15737e496774c0ffaf65bf567a1c6"
        "000000100bed89519a7aaee8fe37269d8da0325abe453205d7d8cf91641fc7a22"
        "c52e852e58a5fc9";
    unsigned char m1[16], m2[142], m3[164], m4[32], ekey[72];
    unsigned char response[142], raw_key[16], expected_key[16];
    size_t response_length;
    fairplay_v2_helper_t *helper;
    unsigned i;

    if (argc != 2) {
        fprintf(stderr, "usage: %s /path/to/doubletake-fairplay-helper\n",
                argv[0]);
        return 2;
    }
    decode(m1_hex, m1, sizeof(m1));
    decode(m2_hex, m2, sizeof(m2));
    decode(m3_hex, m3, sizeof(m3));
    decode(m4_hex, m4, sizeof(m4));
    decode(ekey_hex, ekey, sizeof(ekey));
    for (i = 0; i < sizeof(expected_key); i++) expected_key[i] = (unsigned char)i;

    helper = fairplay_v2_helper_new(argv[1], "66778899aabb");
    if (helper == NULL) {
        fputs("failed to start receiver helper\n", stderr);
        return 1;
    }
    if (fairplay_v2_helper_exchange(helper, m1, sizeof(m1), response,
                                    sizeof(response), &response_length) != 0 ||
        response_length != sizeof(m2)) {
        fputs("M1 exchange failed\n", stderr);
        return 1;
    }
    require_equal("M2", response, m2, sizeof(m2));
    if (fairplay_v2_helper_exchange(helper, m3, sizeof(m3), response,
                                    sizeof(response), &response_length) != 0 ||
        response_length != sizeof(m4)) {
        fputs("M3 exchange failed\n", stderr);
        return 1;
    }
    require_equal("M4", response, m4, sizeof(m4));
    if (fairplay_v2_helper_unwrap(helper, ekey, raw_key) != 0) {
        fputs("key unwrap failed\n", stderr);
        return 1;
    }
    require_equal("raw key", raw_key, expected_key, sizeof(raw_key));
    fairplay_v2_helper_free(helper);
    puts("FairPlay v2 C/emulated receiver vectors passed");
    return 0;
}
