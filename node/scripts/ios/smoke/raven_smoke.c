/*
 * raven_smoke.c - the engine as an iOS app links it (RavenClient.xcframework),
 * run inside the iOS Simulator by simulator_smoke.sh (docs/IOS.md).
 *
 * One process, no raven-node program: a new profile in the iOS Keychain,
 * its card, the embedded node started, paused, a mail check while paused,
 * resumed, Tor set to Wi-Fi only on mobile data, stopped. It prints each answer and exits non-zero at the
 * first one that is not what an app expects. At the end it removes the
 * keychain items this smoke binary's access group holds.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "raven_client.h"

static int failures = 0;

/* One call; the answer must contain every `want` (NULL-terminated). */
static void call(const char *request, const char *const *want) {
    char *answer = raven_call(request);
    printf("> %s\n< %s\n", request, answer);
    for (; want && *want; want++) {
        if (!strstr(answer, *want)) {
            printf("!! missing %s\n", *want);
            failures++;
        }
    }
    raven_free(answer);
}

static void delete_service(CFStringRef service, CFStringRef group) {
    const void *keys[] = {kSecClass, kSecAttrService, kSecAttrAccessGroup};
    const void *values[] = {kSecClassGenericPassword, service, group};
    CFDictionaryRef q = CFDictionaryCreate(NULL, keys, values, 3,
                                           &kCFTypeDictionaryKeyCallBacks,
                                           &kCFTypeDictionaryValueCallBacks);
    SecItemDelete(q);
    CFRelease(q);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: raven_smoke <profile folder> <keychain access group>\n");
        return 2;
    }
    mkdir(argv[1], 0700);
    setenv("RAVEN_DATA_DIR", argv[1], 1);

    const char *ok[] = {"\"ok\":true", NULL};
    const char *ios[] = {"\"ok\":true", "\"platform\":\"ios\"", NULL};
    const char *running[] = {"\"ok\":true", "\"running\":true", "\"embedded\":true", NULL};
    const char *paused[] = {"\"ok\":true", "\"state\":\"paused\"", "\"was_running\":true", NULL};
    const char *checked[] = {"\"ok\":true", "\"started_node\":true", "\"completed\":true", NULL};
    const char *stopped[] = {"\"ok\":true", "\"stop\":\"stopped\"", NULL};

    call("{\"v\":1,\"op\":\"app.info\"}", ios);
    call("{\"v\":1,\"op\":\"settings.set\",\"args\":{\"receive\":false}}", ok);
    call("{\"v\":1,\"op\":\"identity.create\",\"args\":{\"display_name\":\"Smoke\"}}", ok);
    call("{\"v\":1,\"op\":\"identity.me\"}", ok);
    call("{\"v\":1,\"op\":\"profile.state\"}", ok);
    call("{\"v\":1,\"op\":\"node.start\"}", running);
    call("{\"v\":1,\"op\":\"node.pause\"}", paused);
    call("{\"v\":1,\"op\":\"mail.check\",\"args\":{\"budget_ms\":20000}}", checked);
    call("{\"v\":1,\"op\":\"node.resume\"}", running);
    /* Tor on Wi-Fi only, and the kind of network the app reports. */
    const char *wifi_only[] = {"\"ok\":true", "\"tor_wifi_only\":true", NULL};
    const char *cellular[] = {"\"ok\":true", "\"path\":\"cellular\"", NULL};
    call("{\"v\":1,\"op\":\"network.set\",\"args\":{\"tor_wifi_only\":true}}", wifi_only);
    call("{\"v\":1,\"op\":\"network.path\",\"args\":{\"type\":\"cellular\"}}", cellular);
    call("{\"v\":1,\"op\":\"node.stop\"}", stopped);

    /* The backend marker says where the identity is. */
    char marker_path[1024];
    snprintf(marker_path, sizeof marker_path, "%s/identity.backend", argv[1]);
    FILE *f = fopen(marker_path, "r");
    char marker[64] = {0};
    if (!f || !fgets(marker, sizeof marker, f) || strcmp(marker, "ios-keychain\n") != 0) {
        printf("!! identity.backend is not ios-keychain: %s\n", marker);
        failures++;
    }
    if (f) fclose(f);
    printf("identity.backend: %s", marker);

    CFStringRef group = CFStringCreateWithCString(NULL, argv[2], kCFStringEncodingUTF8);
    const char *services[] = {"app.raven.node.identity", "app.raven.node.atsam-indexed-session",
                              "app.raven.node.prekey-lifecycle", "app.raven.node.chat-history.v1"};
    for (size_t i = 0; i < sizeof services / sizeof *services; i++) {
        CFStringRef s = CFStringCreateWithCString(NULL, services[i], kCFStringEncodingUTF8);
        delete_service(s, group);
        CFRelease(s);
    }
    CFRelease(group);
    printf(failures ? "SMOKE FAILED (%d)\n" : "SMOKE OK\n", failures);
    return failures ? 1 : 0;
}
