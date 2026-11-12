#ifndef SFERA_MOBILE_H
#define SFERA_MOBILE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct SferaSession SferaSession;
SferaSession *sfera_session_new(void);
// A single worker runs the session. fd is borrowed and duplicated by the worker.
// The fd must preserve packet boundaries (TUN or a connected datagram socket).
int32_t sfera_session_run(SferaSession *session, int32_t fd, const char *host,
                          const char *peer, const char *token);
// Status: 0 connecting/reconnecting, 1 connected, 2 stopped, -1 failed.
int32_t sfera_session_status(const SferaSession *session);
void sfera_session_stop(const SferaSession *session);
// Free only after the worker and all status/stop calls have returned.
void sfera_session_free(SferaSession *session);
#ifdef __cplusplus
}
#endif
#endif
