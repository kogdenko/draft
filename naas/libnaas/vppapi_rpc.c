#include "log.h"
#include "vppapi_rpc.h"

static void
naas_vppapi_rpc_disconnect(struct naas_vppapi_client *client)
{
	char subj[128];
	struct naas_vppapi_rpc *rpc;

	rpc = naas_container_of(client, struct naas_vppapi_rpc, rpc_base);

	naas_thread_join(&rpc->rpc_subscribe_thread);

	snprintf(subj, sizeof(subj), "vppapi_disconnect_%d_%s", rpc->rpc_pod_id, rpc->rpc_id);
	naas_natsConnection_PublishString(rpc->rpc_request_conn, subj, "gone");

	natsConnection_Destroy(rpc->rpc_request_conn);
	natsConnection_Destroy(rpc->rpc_subscribe_conn);
}

static void
naas_vppapi_rpc_msg_free(struct naas_vppapi_client *client, void *data)
{
	free(data);
}

static int
naas_vppapi_rpc_call(struct naas_vppapi_client *client, 
		const void *req, int req_len, void *rpl, int rpl_buflen)
{
	int rc, rpl_len;
	char subj[128];
	natsMsg *msg;
	struct naas_vppapi_rpc *rpc;

	rpc = naas_container_of(client, struct naas_vppapi_rpc, rpc_base);

	if (!client->vppapi_client_connected) {
		return -ENOTCONN;
	}

	snprintf(subj, sizeof(subj), "vppapi_call_%d_%s", rpc->rpc_pod_id, rpc->rpc_id);
	rc = naas_natsConnection_Request(&msg, rpc->rpc_request_conn, subj, req, req_len, 5000);
	if (rc < 0) {
		naas_vppapi_deinit(client);
		return rc;
	}

	rpl_len = naas_natsMsg_GetDataLength(msg);
	if (rpl_len > rpl_buflen) {
		rc = -EPROTO;
	} else {
		memcpy(rpl, natsMsg_GetData(msg), rpl_len);
	}
	naas_natsMsg_Destroy(msg);

	return rpl_len;
}

int
naas_vppapi_rpc_invoke(struct naas_vppapi_client *client, char *msg,
		void *m, int mlen, void **r, int rlen)
{
	int rc, msg_len, req_len;
	struct naas_vppapi_invoke_req *req;

	msg_len = strlen(msg);
	req_len = sizeof(req) + mlen + msg_len + 1;

	req = naas_xmalloc(req_len);

	req->id = naas_hton32(NAAS_VPPAPI_PROC_INVOKE);
	req->mlen = naas_hton32(mlen);
	memcpy(req + 1, m, mlen);
	memcpy((u_char *)req + sizeof(*req) + mlen, msg, msg_len + 1);

	*r = naas_xmalloc(rlen);

	rc = naas_vppapi_rpc_call(client, req, req_len, *r, rlen);

	return rc;
}

static void
naas_vppapi_rpc_keepalive_ping(struct naas_vppapi_client *client)
{
	int rc;
	char subj[128];
	natsMsg *msg;
	struct naas_vppapi_rpc *rpc;

	rpc = naas_container_of(client, struct naas_vppapi_rpc, rpc_base);

	snprintf(subj, sizeof(subj), "vppapi_keepalive_%d_%s", rpc->rpc_pod_id, rpc->rpc_id);
	rc = naas_natsConnection_RequestString(&msg, rpc->rpc_request_conn, subj, "keep", 1000);
	if (rc < 0) {
		naas_logf(LOG_ERR, 0, "[VPPAPI][RPC] Keepalive failed, disconnecting");
		naas_vppapi_deinit(client);
	}

	naas_natsMsg_Destroy(msg);
}


static void *
rpc_subscribe_routine(struct naas_thread *thr)
{
	struct naas_vppapi_rpc *rpc;

	rpc = thr->thr_arg;

	while (rpc->rpc_base.vppapi_client_connected) {
		naas_nats_Sleep(10);
	}

	return NULL;
}

static void
on_pod_shutdown(natsConnection *conn, natsSubscription *sub, natsMsg *msg, void *closure)
{
	const char *data;
	char buf[32];
	int len, pod_id;
	struct naas_vppapi_rpc *rpc;
	struct naas_vppapi_client *client;

	rpc = closure;
	client = &rpc->rpc_base;

	len = naas_natsMsg_GetDataLength(msg);
	data = naas_natsMsg_GetData(msg);

	len = NAAS_MIN(len, sizeof(buf) - 1);
	memcpy(buf, data, len);
	buf[len] = '\0';
	pod_id = strtoul(buf, NULL, 10);

	naas_natsMsg_Destroy(msg);

	if (rpc->rpc_pod_id == pod_id) {
		naas_vppapi_lock(client);
		naas_vppapi_deinit(client);
		naas_vppapi_unlock(client);
	}
}

int
naas_vppapi_rpc_init(struct naas_vppapi_rpc *rpc, int pod_id, const char *nats_server)
{
	int rc, len;
	char subj[64];
	const char *reply;
	natsMsg *msg;
	struct naas_vppapi_client *client;

	client = &rpc->rpc_base;

	memset(rpc, 0, sizeof(*rpc));
	rpc->rpc_pod_id = pod_id;

	rc = naas_nats_init(&rpc->rpc_request_conn, nats_server);
	if (rc < 0) {
		return rc;
	}

	rc = naas_nats_init(&rpc->rpc_subscribe_conn, nats_server);
	if (rc < 0) {
		natsConnection_Destroy(rpc->rpc_request_conn);
		return rc;
	}

	snprintf(subj, sizeof(subj), "vppapi_connect_%d", rpc->rpc_pod_id);
	rc = naas_natsConnection_RequestString(&msg, rpc->rpc_request_conn, subj, "Hi", 5000);
	if (rc < 0) {
		natsConnection_Destroy(rpc->rpc_request_conn);
		natsConnection_Destroy(rpc->rpc_subscribe_conn);
		return rc;
	}

	reply = natsMsg_GetData(msg);
	len = natsMsg_GetDataLength(msg);
	if (reply == NULL || len < 3 || memcmp(reply, NAAS_STRSZ("ok"))) {
		naas_natsMsg_Destroy(msg);
		natsConnection_Destroy(rpc->rpc_request_conn);
		natsConnection_Destroy(rpc->rpc_subscribe_conn);
		return -ECONNREFUSED;
	}
	naas_strzcpy(rpc->rpc_id, reply + 3, sizeof(rpc->rpc_id));
	naas_natsMsg_Destroy(msg);

	rpc->rpc_base.vppapi_client_msg_free  = naas_vppapi_rpc_msg_free;
	rpc->rpc_base.vppapi_client_call = naas_vppapi_rpc_call;
	rpc->rpc_base.vppapi_client_invoke = naas_vppapi_rpc_invoke;
	rpc->rpc_base.vppapi_client_disconnect  = naas_vppapi_rpc_disconnect;
	rpc->rpc_base.vppapi_client_keepalive_ping  = naas_vppapi_rpc_keepalive_ping;

	naas_thread_init(&rpc->rpc_subscribe_thread);
	rc = naas_natsConnection_Subscribe(&rpc->rpc_pod_shutdown_sub, rpc->rpc_subscribe_conn,
			"pod-shutdown", on_pod_shutdown, rpc);
	if (rc < 0) {
		natsConnection_Destroy(rpc->rpc_request_conn);
		natsConnection_Destroy(rpc->rpc_subscribe_conn);
		return rc;
	}
	naas_thread_start(&rpc->rpc_subscribe_thread, rpc_subscribe_routine, rpc);

	naas_vppapi_init(client);

	naas_logf(LOG_NOTICE, 0, "[VPPAPI][RPC] Connected to pod %d with id %s",
			rpc->rpc_pod_id, rpc->rpc_id);

	return 0;
}
