#ifndef LIBNAAS_NATS_HELPER_H
#define LIBNAAS_NATS_HELPER_H

#include <nats/status.h>
#include <nats/nats.h>

const char *naas_natsStatus_GetText(natsStatus);
int naas_natsOptions_Create(natsOptions **);
void naas_natsOptions_Destroy(natsOptions *);
int naas_natsOptions_SetServers(natsOptions *, const char**, int);
int naas_natsConnection_Connect(natsConnection **, natsOptions *);
void naas_natsConnection_Destroy(natsConnection *);
void naas_nats_Close(void);
void naas_nats_Sleep(int64_t);
int naas_natsConnection_Request(natsMsg **, natsConnection *,
		const char *, const void *, int, int64_t);
int naas_natsConnection_RequestString(natsMsg **, natsConnection *,
		const char *, const char *, int64_t);
int naas_natsConnection_SubscribeSync(natsSubscription **, natsConnection *, const char *);
int naas_natsConnection_Subscribe(natsSubscription **, natsConnection *, const char *,
		natsMsgHandler, void *);
int naas_natsConnection_Publish(natsConnection *, const char *, const void *, int);
int naas_natsConnection_PublishString(natsConnection *nc, const char *subj, const char *str);
int naas_natsSubscription_SetPendingLimits(natsSubscription *, int, int);
int naas_natsSubscription_NextMsg(natsMsg **, natsSubscription *, int64_t);
void naas_natsSubscription_Destroy(natsSubscription *);
int naas_natsMsg_GetDataLength(const natsMsg *);
const char *naas_natsMsg_GetData(const natsMsg *);
const char* naas_natsMsg_GetReply(const natsMsg *);
void naas_natsMsg_Destroy(natsMsg *msg);

int naas_nats_init(natsConnection **, const char *);
void naas_nats_deinit(natsConnection *);

#endif // LIBNAAS_NATS_HELPER_H
