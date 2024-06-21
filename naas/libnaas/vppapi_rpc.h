#ifndef LIBNAAS_VPPAPI_RPC_H
#define LIBNAAS_VPPAPI_RPC_H

#include "nats_helper.h"
#include "vppapi.h"

struct naas_vppapi_rpc {
	struct naas_vppapi_client rpc_base;
	int rpc_pod_id;
	char rpc_id[64];
	natsConnection *rpc_request_conn;
	natsConnection *rpc_subscribe_conn;
	struct naas_thread rpc_subscribe_thread;
	natsSubscription *rpc_pod_shutdown_sub;
};

int naas_vppapi_rpc_init(struct naas_vppapi_rpc *, int, const char *);

#endif // LIBNAAS_VPPAPI_RPC_H
