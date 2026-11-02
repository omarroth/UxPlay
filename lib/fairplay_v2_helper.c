#define _POSIX_C_SOURCE 200809L

#include "fairplay_v2_helper.h"
#include "fairplay_v2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

struct fairplay_v2_helper {
#ifdef _WIN32
    int unsupported;
#else
    pid_t pid;
    FILE *input;
    FILE *output;
#endif
};

#ifndef _WIN32
static char hex_digit(unsigned value)
{
    return "0123456789abcdef"[value & 15];
}

static int hex_value(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static void hex_encode(const uint8_t *input, size_t length, char *output)
{
    size_t i;
    for (i = 0; i < length; i++) {
        output[2 * i] = hex_digit(input[i] >> 4);
        output[2 * i + 1] = hex_digit(input[i]);
    }
    output[2 * length] = '\0';
}

static int helper_call(fairplay_v2_helper_t *helper, const char *request,
                       uint8_t *response, size_t response_capacity,
                       size_t *response_length)
{
    char *line = NULL;
    size_t line_capacity = 0;
    char *message, *end;
    size_t hex_length, i;
    int result = FAIRPLAY_V2_INVALID;

    if (helper == NULL || helper->input == NULL || helper->output == NULL ||
        request == NULL || response_length == NULL)
        return FAIRPLAY_V2_INVALID;
    *response_length = 0;
    if (fprintf(helper->input, "%s\n", request) < 0 ||
        fflush(helper->input) != 0)
        return FAIRPLAY_V2_CRYPTO;
    if (getline(&line, &line_capacity, helper->output) < 0)
        goto done;
    if (strstr(line, "\"error\":") != NULL)
        goto done;
    message = strstr(line, "\"message\":\"");
    if (message == NULL) {
        result = FAIRPLAY_V2_OK;
        goto done;
    }
    message += strlen("\"message\":\"");
    end = strchr(message, '"');
    if (end == NULL) goto done;
    hex_length = (size_t)(end - message);
    if ((hex_length & 1) != 0 || hex_length / 2 > response_capacity ||
        (hex_length != 0 && response == NULL))
        goto done;
    for (i = 0; i < hex_length / 2; i++) {
        int high = hex_value(message[2 * i]);
        int low = hex_value(message[2 * i + 1]);
        if (high < 0 || low < 0) goto done;
        response[i] = (uint8_t)((high << 4) | low);
    }
    *response_length = hex_length / 2;
    result = FAIRPLAY_V2_OK;

done:
    free(line);
    return result;
}
#endif

fairplay_v2_helper_t *fairplay_v2_helper_new(const char *command,
                                             const char *hardware_id_hex)
{
#ifdef _WIN32
    (void)command;
    (void)hardware_id_hex;
    return NULL;
#else
    int to_child[2], from_child[2];
    pid_t pid;
    fairplay_v2_helper_t *helper;
    char request[256];
    size_t response_length;
    size_t i;

    if (command == NULL || command[0] == '\0' || hardware_id_hex == NULL ||
        strlen(hardware_id_hex) != 12)
        return NULL;
    for (i = 0; i < 12; i++) {
        if (hex_value(hardware_id_hex[i]) < 0) return NULL;
    }
    if (pipe(to_child) != 0) return NULL;
    if (pipe(from_child) != 0) {
        close(to_child[0]);
        close(to_child[1]);
        return NULL;
    }
    pid = fork();
    if (pid == 0) {
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]);
        close(to_child[1]);
        close(from_child[0]);
        close(from_child[1]);
        execl(command, command, "serve", (char *)NULL);
        _exit(127);
    }
    close(to_child[0]);
    close(from_child[1]);
    if (pid < 0) {
        close(to_child[1]);
        close(from_child[0]);
        return NULL;
    }
    helper = (fairplay_v2_helper_t *)calloc(1, sizeof(*helper));
    if (helper == NULL) {
        close(to_child[1]);
        close(from_child[0]);
        waitpid(pid, NULL, 0);
        return NULL;
    }
    helper->pid = pid;
    helper->input = fdopen(to_child[1], "w");
    if (helper->input == NULL) {
        close(to_child[1]);
        close(from_child[0]);
        waitpid(pid, NULL, 0);
        free(helper);
        return NULL;
    }
    helper->output = fdopen(from_child[0], "r");
    if (helper->output == NULL) {
        fclose(helper->input);
        close(from_child[0]);
        waitpid(pid, NULL, 0);
        free(helper);
        return NULL;
    }
    snprintf(request, sizeof(request),
             "{\"operation\":\"initialize\",\"version\":2,"
             "\"role\":\"receiver\",\"hardware_id\":\"%s\"}",
             hardware_id_hex);
    if (helper_call(helper, request, NULL, 0, &response_length) !=
            FAIRPLAY_V2_OK || response_length != 0) {
        fairplay_v2_helper_free(helper);
        return NULL;
    }
    return helper;
#endif
}

int fairplay_v2_helper_exchange(fairplay_v2_helper_t *helper,
                                const uint8_t *request, size_t request_length,
                                uint8_t *response, size_t response_capacity,
                                size_t *response_length)
{
#ifdef _WIN32
    (void)helper; (void)request; (void)request_length; (void)response;
    (void)response_capacity; (void)response_length;
    return FAIRPLAY_V2_UNSUPPORTED;
#else
    char request_hex[164 * 2 + 1];
    char json[sizeof(request_hex) + 48];
    if (request == NULL || request_length > 164)
        return FAIRPLAY_V2_INVALID;
    hex_encode(request, request_length, request_hex);
    snprintf(json, sizeof(json),
             "{\"operation\":\"exchange\",\"message\":\"%s\"}",
             request_hex);
    return helper_call(helper, json, response, response_capacity,
                       response_length);
#endif
}

int fairplay_v2_helper_unwrap(fairplay_v2_helper_t *helper,
                              const uint8_t encrypted_key[72],
                              uint8_t raw_key[16])
{
#ifdef _WIN32
    (void)helper; (void)encrypted_key; (void)raw_key;
    return FAIRPLAY_V2_UNSUPPORTED;
#else
    char key_hex[72 * 2 + 1];
    char json[sizeof(key_hex) + 40];
    size_t response_length = 0;
    int result;
    if (encrypted_key == NULL || raw_key == NULL)
        return FAIRPLAY_V2_INVALID;
    hex_encode(encrypted_key, 72, key_hex);
    snprintf(json, sizeof(json),
             "{\"operation\":\"unwrap\",\"key\":\"%s\"}", key_hex);
    result = helper_call(helper, json, raw_key, 16, &response_length);
    if (result != FAIRPLAY_V2_OK || response_length != 16) {
        memset(raw_key, 0, 16);
        return result == FAIRPLAY_V2_OK ? FAIRPLAY_V2_INVALID : result;
    }
    return FAIRPLAY_V2_OK;
#endif
}

void fairplay_v2_helper_free(fairplay_v2_helper_t *helper)
{
    if (helper == NULL) return;
#ifndef _WIN32
    if (helper->input != NULL) {
        fclose(helper->input);
    }
    if (helper->output != NULL) fclose(helper->output);
    if (helper->pid > 0) waitpid(helper->pid, NULL, 0);
#endif
    free(helper);
}
