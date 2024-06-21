#include <libnaas/utils.h>
#include <libnaas/ike_tunnel.h>
#include <libnaas/inet.h>
#include <libnaas/log.h>
#include <libnaas/nats_helper.h>
#include <libnaas/vppapi.h>

#define DAEMON_NAME "naas-sswan-proxy"

enum {
	SUB_CALL,
	SUB_KEEPALIVE,
	SUB_DISCONNECT,
	SUB_NUM,
};

struct api_client {
	natsSubscription *sub[SUB_NUM];
	int connected;
	char id[64];
};

struct sswan_proxy {
	const char *nats_server;
	int pod_id;
	int fds[NAAS_IKE_PORTS_NUM];

	long id_time;

	struct naas_vppapi_vac api_vac;
	natsConnection *conn;
	natsSubscription *api_sub_connect;

	// TODO: Support multiple clients
	struct api_client client;
};

static void
api_client_disconnect(struct sswan_proxy *this, struct api_client *client)
{
	int i;
	char text[32];

	for (i = 0; i < SUB_NUM; ++i) {
		if (client->sub[i] != NULL) {
			natsSubscription_Unsubscribe(client->sub[i]);
			client->sub[i] = NULL;
		}
	}

	if (client->connected && this->conn != NULL) {
		naas_logf(LOG_ERR, 0, "Client disconnected, id:'%s'", client->id);

		snprintf(text, sizeof(text), "%d", this->pod_id);
		naas_natsConnection_PublishString(this->conn, "pod-shutdown", text);
	}

	client->connected = 0;
}

static void
on_api_call(natsConnection *conn, natsSubscription *sub, natsMsg *msg, void *closure)
{
	int rc, len;
	char reply[65536];
	struct sswan_proxy *this;
	struct naas_vppapi_client *vppapicli;

	this = closure;
	vppapicli = &this->api_vac.vac_base;

	len = naas_natsMsg_GetDataLength(msg);
	rc = naas_vppapi_call(vppapicli, naas_natsMsg_GetData(msg), len, reply, sizeof(reply));
	if (rc < 0) {
		*((be32_t *)reply) = naas_hton32(-rc);
		rc = sizeof(be32_t);
	}
	//msg_name = naas_xstrndup(naas_natsMsg_GetData(msg), len);
	//rc = naas_vppapi_get_msg_index(vppapicli, msg_name);
	rc = naas_natsConnection_Publish(conn, naas_natsMsg_GetReply(msg), reply, rc);
	if (rc < 0) {
		naas_logf(LOG_ERR, -rc, "[VPPAPI][SRV] 'call' failed");
	}
	naas_natsMsg_Destroy(msg);
}

static void
on_api_keepalive(natsConnection *conn, natsSubscription *sub, natsMsg *msg, void *closure)
{
	int rc;
	struct sswan_proxy *this;

	this = closure;
	NAAS_UNUSED(this);

	rc = naas_natsConnection_Publish(conn, naas_natsMsg_GetReply(msg), NAAS_STRSZ("alive"));
	if (rc < 0) {
		naas_logf(LOG_ERR, -rc, "[VPPAPI][SRV] 'keepalive' failed");
	}
	naas_natsMsg_Destroy(msg);
}

static void
on_api_disconnect(natsConnection *conn, natsSubscription *sub, natsMsg *msg, void *closure)
{
	struct sswan_proxy *this;

	this = closure;

	naas_dbg("client gone");

	api_client_disconnect(this, &this->client);

	naas_natsMsg_Destroy(msg);
}

static void
gen_uniq_id(struct sswan_proxy *this, char *id, int count)
{
	time_t t;

	t = time(NULL);
	while (this->id_time >= t) {
		t++;
	}
	this->id_time = t;
	snprintf(id, count, "%ld_%ld", (long)getpid(), this->id_time);
}

static void
on_api_connect(natsConnection *conn, natsSubscription *sub, natsMsg *msg, void *closure)
{
	char buf[128];
	char subj[128];
	int rc, len;
	struct sswan_proxy *this;
	struct api_client *client;

	this = closure;
	client = NULL;

	rc = 0;
	client = &this->client;
	if (client->connected) {
		naas_logf(LOG_ERR, 0, "[VPPAPI][SRV] Client already connected, refused");
		goto err;
	}

	gen_uniq_id(this, client->id, sizeof(client->id));

	snprintf(subj, sizeof(subj), "vppapi_call_%d_%s", this->pod_id, client->id);
	rc = naas_natsConnection_Subscribe(&client->sub[SUB_CALL],
			conn, subj, on_api_call, this);
	if (rc < 0) {
		goto err;
	}

	snprintf(subj, sizeof(subj), "vppapi_keepalive_%d_%s", this->pod_id, client->id);
	rc = naas_natsConnection_Subscribe(&client->sub[SUB_KEEPALIVE],
			conn, subj, on_api_keepalive, this);
	if (rc < 0) {
		goto err;
	}

	snprintf(subj, sizeof(subj), "vppapi_disconnect_%d_%s", this->pod_id, client->id);
	rc = naas_natsConnection_Subscribe(&client->sub[SUB_DISCONNECT],
			conn, subj, on_api_disconnect, this);
	if (rc < 0) {
		goto err;
	}


	len = snprintf(buf, sizeof(buf), "ok %s", client->id);
	rc = naas_natsConnection_Publish(conn, naas_natsMsg_GetReply(msg), buf, len);
	if (rc < 0) {
		goto err2;		
	}

	client->connected = 1;

	naas_logf(LOG_NOTICE, 0, "[VPPAPI][SRV] Client connected, id:'%s'", client->id);
	naas_natsMsg_Destroy(msg);
	return;

err:
	naas_natsConnection_Publish(conn, naas_natsMsg_GetReply(msg), NAAS_STRSZ("failed"));
err2:
	naas_logf(LOG_ERR, -rc, "[VPPAPI][SRV] 'connect' failed");
	naas_natsMsg_Destroy(msg);
	api_client_disconnect(this, client);
}

static void
vac_deinit_callback(struct naas_vppapi_client *client)
{
	struct sswan_proxy *this;

	this = client->vppapi_client_user;
	NAAS_UNUSED(this);

	// TODO: We couldn't reconnect to vac in same process,
	// there is some bug in VPP - after recconect VPP hold in vac_read,
	// so we need to restart sswan-proxy
	naas_die(0, "VPP seems gone, please, restart vpp and sswan-proxy");
}

static void
api_routine_once(struct sswan_proxy *this)
{
	int rc;
	char subj[64];
	char id[64];
	char vac_client_name[128];

	while (1) {
		rc = naas_vppapi_vac_wait_connect(2000);
		if (rc == 0) {
			break;
		}
	}

	gen_uniq_id(this, id, sizeof(id));

	snprintf(vac_client_name, sizeof(vac_client_name), "%s_%s", DAEMON_NAME, id);
	rc = naas_vppapi_vac_init(&this->api_vac, vac_client_name);
	if (rc) {
		return;
	}

	this->api_vac.vac_base.vppapi_client_deinit_notify = vac_deinit_callback;
	this->api_vac.vac_base.vppapi_client_user = this;

	snprintf(subj, sizeof(subj), "vppapi_connect_%d", this->pod_id);
	rc = naas_natsConnection_Subscribe(&this->api_sub_connect, this->conn, subj,
			on_api_connect, this);
	if (rc < 0) {
		naas_die(-rc, "Couldn't subscribe to '%s'", subj);
	}

	while (this->api_vac.vac_base.vppapi_client_connected) {
		naas_nats_Sleep(100);
	}

	natsSubscription_Unsubscribe(this->api_sub_connect);
	api_client_disconnect(this, &this->client);
}

static void *
api_routine(struct naas_thread *thr)
{
	int rc;
	struct sswan_proxy *this;

	this = thr->thr_arg;

	rc = naas_nats_init(&this->conn, this->nats_server);
	if (rc < 0) {
		return NULL;
	}

	while (1) {
		api_routine_once(this);
	}

	naas_nats_deinit(this->conn);
	this->conn = NULL;

	return NULL;
}

static void *
ike_inbox_routine(struct naas_thread *thr)
{
	struct sswan_proxy *this;

	this = thr->thr_arg;

	naas_ike_tunnel_pod_nats_loop(this->fds, this->pod_id, this->nats_server);

	return NULL;
}

static void *
ike_listen_routine(struct naas_thread *thr)
{
	struct sswan_proxy *this;

	this = thr->thr_arg;

	naas_ike_tunnel_pod_udp_loop(this->fds, this->pod_id, this->nats_server);

	return NULL;
}

static void
print_usage(void)
{
        printf(
	"Usage: %s [OPTION]\n"
	"\n"
	"Options\n"
	" -h,--help  Show this help\n"
	" -v,--version  Print NAAS build version\n"
	" -d,--daemonize  Run application in background\n"
	" -l,--log-level {err|warning|notice|info|debug}  Set log level, default: info\n"
	"--log-console  Write log to system console\n"
	"--pod {number}  Specify VPP pod number\n"
	"--nats-server {host}  Specify nats server host\n"
	"--ike-proxy {1/0}  Enable/Disable IKE packets proxy\n"
	"--api-proxy {1/0}  Enable/Disable VPP API proxy\n"
	"\n",
	DAEMON_NAME
        );
}

int
main(int argc, char **argv)
{
	int rc, opt, dflag, long_option_index, log_level;
	int ike_proxy, api_proxy;
	int pid_file_fd;
	const char *long_option_name;
	struct naas_thread ike_inbox_thread;
	struct naas_thread ike_listen_thread;
	struct naas_thread api_thread;
	naas_log_f log_fn;
	struct sswan_proxy this;
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h' },
		{"version", no_argument, 0, 'v' },
		{"daemonize", no_argument, 0, 'd' },
		{"log-level", required_argument, 0, 'l' },
		{"log-console", no_argument, 0, 0 },
		{"pod", required_argument, 0, 0 },
		{"nats-server", required_argument, 0, 0 },
		{"ike-proxy", required_argument, 0, 0 },
		{"api-proxy", required_argument, 0, 0 },
	};

	memset(&this, 0, sizeof(this));
	this.nats_server = "localhost";
	log_fn = naas_log_syslog;
	dflag = 0;
	ike_proxy = 1;
	api_proxy = 1;

	while ((opt = getopt_long(argc, argv, "hvdl:",
			long_options, &long_option_index)) != -1) {
		switch (opt) {
		case 0:
			long_option_name = long_options[long_option_index].name;
			if (!strcmp(long_option_name, "log-console")) {
				 log_fn = naas_log_stdout;
			} else if (!strcmp(long_option_name, "pod")) {
				this.pod_id = strtoul(optarg, NULL, 10);
			} else if (!strcmp(long_option_name, "nats-server")) {
				this.nats_server = optarg;
 			} else if (!strcmp(long_option_name, "ike-proxy")) {
				ike_proxy = strtoul(optarg, NULL, 10);
			} else if (!strcmp(long_option_name, "api-proxy")) {
				api_proxy = strtoul(optarg, NULL, 10);
			} 
			break;

		case 'v':
			printf("%s\n", NAAS_BUILD);
			return EXIT_SUCCESS;

		case 'd':
			dflag = 1;
			break;

		case 'l':
			log_level = naas_log_level_from_string(optarg);
			if (log_level < 0) {
				naas_print_invalidarg("-l", optarg);
				print_usage();
				return EXIT_FAILURE;
			}
			naas_set_log_level(log_level);
			break;

		default:
			print_usage();
			return EXIT_SUCCESS;
		}
	}

	if (log_fn == naas_log_syslog) {
		openlog(DAEMON_NAME, LOG_CONS, LOG_DAEMON);
	}
	naas_log_init(log_fn);

	rc = naas_pid_file_open(DAEMON_NAME);
	if (rc < 0) {
		return EXIT_FAILURE;
	}
	pid_file_fd = rc;

	if (dflag) {
		daemon(0, 0);
	}

	naas_thread_init(&api_thread);
	naas_thread_init(&ike_inbox_thread);
	naas_thread_init(&ike_listen_thread);

	if (api_proxy) {
		naas_thread_start(&api_thread, api_routine, &this);
	}

	if (ike_proxy) {
		rc = naas_ike_tunnel_pod_bind(this.fds);
		if (rc < 0) {
			return EXIT_FAILURE;
		}
		naas_thread_start(&ike_inbox_thread, ike_inbox_routine, &this);
		naas_thread_start(&ike_listen_thread, ike_listen_routine, &this);
	}

	naas_thread_join(&ike_listen_thread);
	naas_thread_join(&ike_inbox_thread);
	naas_thread_join(&api_thread);
	
	naas_pid_file_close(pid_file_fd, DAEMON_NAME);

	return EXIT_SUCCESS;
}
