/*
 * raven_client.h - the Raven desktop engine (node/crates/raven-client).
 *
 * One function, JSON in and out (desktop/api/API.md, contract v1):
 *
 *   request:  {"v": 1, "op": "<operation>", "args": { ... }}
 *   response: {"v": 1, "ok": true,  "result": { ... }}
 *             {"v": 1, "ok": false, "error": {"code", "message", "detail"}}
 *
 * - raven_call never returns NULL. A NULL or non-UTF-8 request is answered
 *   with the error BAD_REQUEST; a failure inside the engine with INTERNAL.
 * - Every string raven_call (or raven_watch_probe) returns must be passed
 *   to raven_free exactly once, and to nothing else (it is allocated by the
 *   engine).
 * - Thread-safe. raven_call may block (node.start can take a few seconds):
 *   call it off the UI thread. events.poll never blocks.
 * - Secrets never cross this boundary, and display text is sanitised.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#ifndef RAVEN_CLIENT_H
#define RAVEN_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

/* One request envelope (NUL-terminated UTF-8 JSON) in; one response
 * envelope out. Never NULL. Free the result with raven_free. */
char *raven_call(const char *request_json);

/* Frees a string returned by raven_call or raven_watch_probe. NULL is
 * ignored. */
void raven_free(char *response);

/* Lab builds only (debug builds with Tor in process): the Tor helper alone
 * in the calling process, for the iPhone app's tunnel extension to measure
 * Tor there (docs/IOS.md, section 8.1). It opens no profile and starts no
 * node. One JSON object in:
 *
 *   {"op": "start", "state_dir": "<absolute path>", "check_every_s": 300}
 *   {"op": "status"}
 *   {"op": "stop"}
 *
 * and one out: counts, times and fixed words (never an address), or
 * {"error": "<what>"}. Every other build answers
 * {"error": "not in this build"}. Never NULL. Free the result with
 * raven_free. */
char *raven_watch_probe(const char *request_json);

#ifdef __cplusplus
}
#endif

#endif /* RAVEN_CLIENT_H */
