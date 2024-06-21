#include "log.h"
#include "nats_helper.h"

int
naas_natsOptions_Create(natsOptions **newOpts)
{
	int err;
	natsStatus s;

	s = natsOptions_Create(newOpts);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		naas_logf(LOG_ERR, err, "natsOptions_Create() failed");
		return -err;
	}
}

void
naas_natsOptions_Destroy(natsOptions *opts)
{
	natsOptions_Destroy(opts);
}

int
naas_natsOptions_SetServers(natsOptions *opts, const char** servers, int serversCount)
{
	int err;
	natsStatus s;

	s = natsOptions_SetServers(opts, servers, serversCount);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		naas_logf(LOG_ERR, err, "natsOptions_SetServers() failed");
		return -err;
	}
}

int
naas_natsConnection_Connect(natsConnection **nc, natsOptions *options)
{
	int err;
	natsStatus s;

	s = natsConnection_Connect(nc, options);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		naas_logf(LOG_ERR, err, "natsConnection_Connect() failed");
		return -err;
	}
}

void
naas_natsConnection_Destroy(natsConnection *nc)
{
	if (nc != NULL) {
		natsConnection_Destroy(nc);
	}
}

void
naas_nats_Close(void)
{
	nats_Close();
}

void
naas_nats_Sleep(int64_t sleepTime)
{
	nats_Sleep(sleepTime);
}

int
naas_natsConnection_Request(natsMsg **replyMsg, natsConnection *nc, const char *subj,
		const void *data, int dataLen, int64_t timeout)
{
	int err;
	natsStatus s;

	s = natsConnection_Request(replyMsg, nc, subj, data, dataLen, timeout);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		naas_logf(LOG_ERR, err, "natsConnection_Request('%s') failed", subj);
		return -err;
	}
}

int
naas_natsConnection_RequestString(natsMsg **replyMsg, natsConnection *nc,
		const char *subj, const char *str, int64_t timeout)
{
	int err;
	natsStatus s;

	s = natsConnection_RequestString(replyMsg, nc, subj, str, timeout);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		naas_logf(LOG_ERR, err, "natsConnection_Request('%s') failed", subj);
		return -err;
	}
}

int
naas_natsConnection_SubscribeSync(natsSubscription **sub, natsConnection *nc, const char *subject)
{
	int err;
	natsStatus s;

	s = natsConnection_SubscribeSync(sub, nc, subject);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		naas_logf(LOG_ERR, err, "natsConnection_SubscribeSync('%s') failed", subject);
		return -err;
	}
}

int
naas_natsConnection_Subscribe(natsSubscription **sub, natsConnection *nc,
		const char *subject, natsMsgHandler cb, void *cbClosure)
{
	int err;
	natsStatus s;

	s = natsConnection_Subscribe(sub, nc, subject, cb, cbClosure);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		naas_logf(LOG_ERR, err, "natsConnection_Subscribe('%s') failed", subject);
		return err;
	}
}

int
naas_natsConnection_Publish(natsConnection *nc, const char *subj, const void *data, int dataLen)
{
	int err;
	natsStatus s;

	s = natsConnection_Publish(nc, subj, data, dataLen);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		naas_logf(LOG_ERR, err, "natsConnection_Publish('%s') failed", subj);
		return -err;
	}
}

int
naas_natsConnection_PublishString(natsConnection *nc, const char *subj, const char *str)
{
	int err;
	natsStatus s;

	s = natsConnection_PublishString(nc, subj, str);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		naas_logf(LOG_ERR, err, "natsConnection_PublishString('%s', '%s') failed",
				subj, str);
		return -err;
	}
}

int
naas_natsSubscription_SetPendingLimits(natsSubscription *sub, int msgLimit, int bytesLimit)
{
	int err;
	natsStatus s;

	s = natsSubscription_SetPendingLimits(sub, msgLimit, bytesLimit);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		naas_logf(LOG_ERR, err, "natsSubscription_SetPendingLimits() failed");
		return -err;
	}
}

int
naas_natsSubscription_NextMsg(natsMsg **nextMsg, natsSubscription *sub, int64_t timeout)
{
	int err;
	natsStatus s;

	s = natsSubscription_NextMsg(nextMsg, sub, timeout);
	if (s == NATS_OK) {
		return 0;
	} else {
		err = naas_create_err(NAAS_ERR_NATS, s);
		if (s != NATS_TIMEOUT) {
			naas_logf(LOG_ERR, err, "natsSubscription_NextMsg() failed");
		}
		return -err;
	}
}

void
naas_natsSubscription_Destroy(natsSubscription *sub)
{
	natsSubscription_Destroy(sub);
}

int
naas_natsMsg_GetDataLength(const natsMsg *msg)
{
	return natsMsg_GetDataLength(msg);
}

const char *
naas_natsMsg_GetData(const natsMsg *msg)
{
	return natsMsg_GetData(msg);
}

const char*
naas_natsMsg_GetReply(const natsMsg *msg)
{
	return natsMsg_GetReply(msg);
}

void
naas_natsMsg_Destroy(natsMsg *msg)
{
	natsMsg_Destroy(msg);	
}

int
naas_nats_init(natsConnection **conn, const char *nats_server)
{
	int rc;
	natsOptions *opts;
	const char *servers[1];

	servers[0] = nats_server;
	opts = NULL;

	rc = naas_natsOptions_Create(&opts);
	if (rc < 0) {
                return rc;
        }

	rc = naas_natsOptions_SetServers(opts, servers, 1);
	if (rc < 0) {
		naas_natsOptions_Destroy(opts);
		return rc;
	}

	rc = naas_natsConnection_Connect(conn, opts);
	naas_natsOptions_Destroy(opts);
	return rc;
}

void
naas_nats_deinit(natsConnection *conn)
{
	naas_natsConnection_Destroy(conn);
	naas_nats_Close();
}

