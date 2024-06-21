#include "log.h"
#include "utils.h"
#include "vppapi.h"
#include "wrappers.h"

#define vl_endianfun
#include <vlibmemory/memclnt.api.h>
#undef vl_endianfun

#define VAC_STATS_SOCK_DIR "/run/vpp/"
#define VAC_STATS_SOCK_PATH "/run/vpp/stats.sock"

static void
vl_api_address_create(vl_api_address_t *address, int af, void *in)
{
	if (af == AF_INET) {
		address->af = ADDRESS_IP4;
		clib_memcpy(address->un.ip4, in, 4);
	} else {
		address->af = ADDRESS_IP6;
		clib_memcpy(address->un.ip6, in, 16);
	}
}

int
vl_api_address_2_in(vl_api_address_t *address, void *in)
{
	if (address->af == ADDRESS_IP4) {
		clib_memcpy(in, address->un.ip4, 4);
		return AF_INET;
	} else {
		clib_memcpy(in, address->un.ip6, 16);
		return AF_INET6;
	}
}

static const char *
naas_vppapi_sr_behavior_api_str(int behavior)
{
	switch (behavior) {
	case SR_BEHAVIOR_API_END: return "SR_BEHAVIOR_API_END";
	case SR_BEHAVIOR_API_X: return "SR_BEHAVIOR_API_X";
	case SR_BEHAVIOR_API_T: return "SR_BEHAVIOR_API_T";
	case SR_BEHAVIOR_API_DX2: return "SR_BEHAVIOR_API_DX2";
	case SR_BEHAVIOR_API_DX6: return "SR_BEHAVIOR_API_DX6";
	case SR_BEHAVIOR_API_DX4: return "SR_BEHAVIOR_API_DX4";
	case SR_BEHAVIOR_API_DT4: return "SR_BEHAVIOR_API_DT4";
	case SR_BEHAVIOR_API_DT6: return "SR_BEHAVIOR_API_DT6";
	default: return "\"Invalid ENUM\"";
	}
}

void
naas_vppapi_lock(struct naas_vppapi_client *client)
{
	pthread_mutex_lock(&client->vppapi_client_lock);
	client->vppapi_client_alive = 1;
}

void
naas_vppapi_unlock(struct naas_vppapi_client *client)
{
	pthread_mutex_unlock(&client->vppapi_client_lock);
}

static void
naas_vppapi_client_set_connected(struct naas_vppapi_client *client, int connected)
{
	client->vppapi_client_connected = connected;
	if (client->vppapi_client_deinit_notify) {
		(*client->vppapi_client_deinit_notify)(client);
	}
}

static void
naas_vac_disconnect_sm(struct naas_vppapi_vac *vac)
{
	stat_segment_disconnect_r(vac->vac_sm);
	stat_client_free(vac->vac_sm);
	vac->vac_sm = NULL;
}

static void
naas_vac_disconnect(struct naas_vppapi_vac *vac)
{
	naas_vac_disconnect_sm(vac);
	vac_disconnect();
	naas_logf(LOG_NOTICE, 0, "[VPPAPI] VAC disconnected");
}

static int
naas_vac_read(void **pdata, int timeout)
{
	int rc, len;

	*pdata = NULL;
	rc = vac_read((char **)pdata, &len, timeout);
	switch (rc) {
	case 0:
		break;
	case VAC_NOT_CONNECTED:
		return -ECONNREFUSED;
	case VAC_TIMEOUT:
		return -ETIMEDOUT;
	default:
		return -EINTR;
	}

	assert(*pdata != NULL);
	assert(len != 0);

	return len;
}

static int
naas_vac_write(const void *data, int len)
{
	int rc;

	rc = vac_write((void *)data, len);
	if (rc >= 0) {
		return 0;
	}
	switch (rc) {
	case VAC_NOT_CONNECTED:
		return -ECONNREFUSED;
	default:
		return -EINTR;
	}
}

static int
naas_vppapi_vac_read(struct naas_vppapi_vac *vac, void **data, int timeout)
{
	int rc;
	struct naas_vppapi_client *client;

	client = &vac->vac_base;

	if (!client->vppapi_client_connected) {
		return -ENOTCONN;
	}

	rc = naas_vac_read(data, timeout);
	if (rc < 0) {
		naas_vppapi_deinit(client);
	}
	return rc;
}

static int
naas_vppapi_vac_write(struct naas_vppapi_vac *vac, const void *data, int len)
{
	int rc;
	struct naas_vppapi_client *client;

	client = &vac->vac_base;

	if (!client->vppapi_client_connected) {
		return -ENOTCONN;
	}

	rc = naas_vac_write(data, len);
	if (rc < 0) {
		naas_vppapi_deinit(client);
	}
	return rc;
}

static void
naas_vppapi_vac_msg_free(struct naas_vppapi_client *client, void *data)
{
	vl_msg_api_free(data);
}

static int
naas_vppapi_vac_connect(struct naas_vppapi_vac *vac)
{
	int rc;
	static int clib_mem_inited = 0;
	struct naas_vppapi_client *client;

	client = &vac->vac_base;

	assert(!client->vppapi_client_connected);

	if (!clib_mem_inited) {
		clib_mem_inited = 1;
		clib_mem_init(0, 64 << 20); // 20 Mb
	}

	vac->vac_sm = stat_client_get();
	if (vac->vac_sm == NULL) {
		naas_logf(LOG_ERR, 0, "[VPPAPI] stat_client_get() failed");
		return -ENOTCONN;
	}
	rc = stat_segment_connect_r(VAC_STATS_SOCK_PATH, vac->vac_sm);
	if (rc != 0) {
		stat_client_free(vac->vac_sm);
		vac->vac_sm = NULL;
		naas_logf(LOG_ERR, 0, "[VPPAPI] stat_segment_connect_r(\"/run/vpp/stats.sock\") failed");
		return -ENOTCONN;
	}

	naas_logf(LOG_NOTICE, 0, "[VPPAPI] Connecting to VAC ...");
	rc = vac_connect(vac->vac_name, NULL, NULL, 1024);
	if (rc != 0) {
		naas_logf(LOG_ERR, -rc, "[VPPAPI] VAC connection failed");
		return rc;
	}
	
	naas_logf(LOG_NOTICE, 0, "[VPPAPI] VAC connected");

	return 0;
}

static int
naas_vppapi_vac_invoke(struct naas_vppapi_client *client, char *msg,
		void *m, int mlen, void **r, int rlen)
{
	int rc, len;
	void *data;
	struct naas_vppapi_vac *vac;

	vac = naas_container_of(client, struct naas_vppapi_vac, vac_base);

	*((be16_t *)m) = naas_hton16(vac_get_msg_index(msg));

	rc = naas_vppapi_vac_write(vac, m, mlen);
	if (rc < 0) {	
		return rc;
	}

	rc = naas_vppapi_vac_read(vac, &data, 5);
	if (rc < 0) {
		return rc;
	}
	len = rc;

	if (len < rlen) {
		vl_msg_api_free(data);
		return -EINVAL;
	}

	*r = data;
	return len;
}

static int
naas_vac_sa_stat(struct naas_vppapi_vac *vac, const struct naas_vppapi_sa_stat_req *req,
		struct naas_vppapi_sa_stat_reply *reply)
{
	int i, j;
	u8 **pattern;
	u32 *dir;
	uint32_t stat_index;
	uint64_t packets, bytes;
	stat_segment_data_t *res;
	struct naas_vppapi_client *client;

	client = &vac->vac_base;

	if (!client->vppapi_client_connected) {
		return -ENOTCONN;
	}

	stat_index = naas_ntoh32(req->stat_index);
	bytes = packets = 0;
	pattern = NULL;

	vec_add1(pattern, (u8 *)"/net/ipsec/sa");
	dir = stat_segment_ls_r((u8 **)pattern, vac->vac_sm);
	res = stat_segment_dump_r(dir, vac->vac_sm);

	for (i = 0; i < vec_len(res); ++i) {
		if (res[i].type != STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED) {
			continue;
		}

		if (res[i].combined_counter_vec == NULL) {
			continue;
		}
			
		for (j = 0; j < vec_len(res[i].combined_counter_vec); ++j) {
			if (stat_index > vec_len(res[i].combined_counter_vec[j])) {
				continue;
			}

			bytes += res[i].combined_counter_vec[j][stat_index].bytes;
			packets += res[i].combined_counter_vec[j][stat_index].packets;
		}
	}

	vec_free(pattern);
	vec_free(dir);
	stat_segment_data_free(res);

	reply->bytes = naas_ntoh64(bytes);
	reply->packets = naas_ntoh64(packets);

	return sizeof(*reply);
}

static void
get_sw_interface_index_handler(void * user, struct naas_vppapi_sw_interface *interface)
{
	struct naas_vppapi_sw_interface *ret;

	ret = user;
	memcpy(ret, interface, sizeof(*ret));
}

static int
naas_vppapi_vac_call_sw_interface_get(struct naas_vppapi_vac *vac,
		const struct naas_vppapi_sw_interface_get_req *req,
		struct naas_vppapi_sw_interface_get_reply *reply)
{
	const char *sw_if_name;
	struct naas_vppapi_sw_interface interface;

	interface.sw_if_index = ~0;
	sw_if_name = ((struct naas_vppapi_sw_interface_get_req *)req)->interface_name;
	naas_vppapi_sw_interface_dump(vac,  get_sw_interface_index_handler,
				&interface, sw_if_name);

	reply->sw_if_index = naas_hton32(interface.sw_if_index);
	reply->flags = naas_hton32(interface.flags);
	naas_strzcpy(reply->interface_name, interface.interface_name,
		sizeof(reply->interface_name));

	return sizeof(*reply);
}

static int
naas_vppapi_vac_call_invoke(struct naas_vppapi_client *client,
		const struct naas_vppapi_invoke_req *req, int req_len, void *rpl, int rpl_buflen)
{
	int rc, mlen, msg_len;
	char *msg;
	void *m, *data;

	if (req_len < sizeof(*req)) {
		return -EPROTO;
	}

	mlen = naas_ntoh32(req->mlen);
	if (req_len < sizeof(*req) + mlen + 1) {
		return -EPROTO;
	}

	m = (void *)(req + 1);
	msg = (char *)m + mlen;
	msg_len = req_len - sizeof(*req) - mlen;

	if (msg[msg_len] != '\0') {
		return -EPROTO;
	}

	rc = naas_vppapi_vac_invoke(client, msg, m, mlen, &data, 0);
	if (rc >= 0) {
		if (rc > rpl_buflen) {
			rc = -ENOBUFS;
		} else {
			memcpy(rpl, data, rc);
		}
		vl_msg_api_free(data);
	}

	return rc;
}

static int
naas_vppapi_vac_call(struct naas_vppapi_client *client,
		const void *req, int req_len, void *rpl, int rpl_len)
{
	int rc;
	uint32_t id;
	struct naas_vppapi_vac *vac;

	vac = naas_container_of(client, struct naas_vppapi_vac, vac_base);

	if (!client->vppapi_client_connected) {
		return -ENOTCONN;
	}

	id = *((const be32_t *)req);
	switch (naas_ntoh32(id)) {
	case NAAS_VPPAPI_PROC_SA_STAT:
		assert(req_len >= sizeof(struct naas_vppapi_sa_stat_req));
		assert(rpl_len >= sizeof(struct naas_vppapi_sa_stat_reply));
		rc = naas_vac_sa_stat(vac, req, rpl);
		break;

	case NAAS_VPPAPI_PROC_SW_INTERFACE_GET:
		assert(req_len >= sizeof(struct naas_vppapi_sw_interface_get_req));
		assert(rpl_len >= sizeof(struct naas_vppapi_sw_interface_get_reply));
		rc = naas_vppapi_vac_call_sw_interface_get(vac, req, rpl);
		break;

	case NAAS_VPPAPI_PROC_INVOKE:
		rc = naas_vppapi_vac_call_invoke(client, (void *)req, req_len, rpl, rpl_len);
		break;
	
	default:
		return -ENOTSUP;
	}

	return rc;
}


static void
naas_vppapi_vac_keepalive_ping(struct naas_vppapi_client *client)
{
	int rc;
	vl_api_control_ping_t mp;
	vl_api_control_ping_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.context = 100;
	vl_api_control_ping_t_endian(&mp);

	rc = naas_vppapi_vac_invoke(client, VL_API_CONTROL_PING_CRC,
			&mp, sizeof(mp), (void **)&rp, sizeof(*rp));
	if (rc < 0) {
		naas_logf(LOG_ERR, -rc, "[VPPAPI] Keepalive ping failed");
	}
}

static void *
naas_vppapi_keepalive(struct naas_thread *thread)
{
	int rc, fd;
	fd_set rfds;
	struct timeval to;
	struct naas_vppapi_client *client;

	client = naas_container_of(thread, struct naas_vppapi_client, vppapi_client_keepalive);

	fd = client->vppapi_client_pipe[0];

	while (1) {
		to.tv_sec = 2;
		to.tv_usec = 0;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		rc = select(fd + 1, &rfds, NULL, NULL, &to);
		if (FD_ISSET(fd, &rfds)) {
			break;
		}
		rc = pthread_mutex_trylock(&client->vppapi_client_lock);
		if (rc == 0) {
			if (!client->vppapi_client_alive) {
				if (client->vppapi_client_connected) {
					(*client->vppapi_client_keepalive_ping)(client);
				}
			}
			client->vppapi_client_alive = 0;
			pthread_mutex_unlock(&client->vppapi_client_lock);
		}
	}

	return NULL;
}

void
naas_vppapi_init(struct naas_vppapi_client *client)
{

	naas_mutex_init(&client->vppapi_client_lock);
	naas_thread_init(&client->vppapi_client_keepalive);
	naas_pipe(client->vppapi_client_pipe);

	naas_thread_start(&client->vppapi_client_keepalive, naas_vppapi_keepalive, NULL);
	naas_vppapi_client_set_connected(client, 1);
}

static void
naas_vppapi_vac_disconnect(struct naas_vppapi_client *client)
{
	struct naas_vppapi_vac *vac;

	vac = naas_container_of(client, struct naas_vppapi_vac, vac_base);

	naas_vac_disconnect(vac);
}

int
naas_vppapi_vac_init(struct naas_vppapi_vac *vac, const char *client_name)
{
	int rc;

	memset(vac, 0, sizeof(*vac));

	naas_strzcpy(vac->vac_name, client_name, sizeof(vac->vac_name));

	rc = naas_vppapi_vac_connect(vac);
	if (rc < 0) {
		return rc;
	}

	vac->vac_base.vppapi_client_msg_free = naas_vppapi_vac_msg_free;
	vac->vac_base.vppapi_client_call = naas_vppapi_vac_call;
	vac->vac_base.vppapi_client_invoke = naas_vppapi_vac_invoke;
	vac->vac_base.vppapi_client_disconnect = naas_vppapi_vac_disconnect;
	vac->vac_base.vppapi_client_keepalive_ping = naas_vppapi_vac_keepalive_ping;

	naas_vppapi_init(&vac->vac_base);

	return 0;
}

int
naas_vppapi_vac_wait_connect(int timeout_ms)
{
	int rc, fd, i, n_tries;
	struct sockaddr_un un;

	rc = naas_socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (rc < 0) {
		return rc;
	}
	fd = rc;

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	naas_strzcpy(un.sun_path, VAC_STATS_SOCK_PATH, sizeof(un.sun_path));

	n_tries = timeout_ms / 10;
	if (n_tries == 0) {
		n_tries = 1;
	}
	for (i = 0; i < n_tries; ++i) {
		rc = connect(fd, (struct sockaddr *)&un, sizeof(un));
		if (rc < 0) {
			rc = -errno;
			usleep(10 * 1000);
		} else {
			rc = 0;
			break;
		}
	}

	close(fd);
	return rc;
}

void
naas_vppapi_msg_free(struct naas_vppapi_client *client, void *data)
{
	if (data != NULL) {
		(*client->vppapi_client_msg_free)(client, data);
	}
}

int
naas_vppapi_call(struct naas_vppapi_client *client, const void *req, int req_len,
		void *rpl, int rpl_buflen)
{
	int rc;

	naas_vppapi_lock(client);
	rc = (*client->vppapi_client_call)(client, req, req_len, rpl, rpl_buflen);
	naas_vppapi_unlock(client);

	return rc;
}

void
naas_vppapi_deinit(struct naas_vppapi_client *client)
{
	int i;

	if (!client->vppapi_client_connected) {
		return;
	}

	naas_vppapi_client_set_connected(client, 0);

	naas_write(client->vppapi_client_pipe[1], "q", 1);
	naas_thread_join(&client->vppapi_client_keepalive);
	for (i = 0; i < NAAS_ARRAY_SIZE(client->vppapi_client_pipe); ++i) {
		close(client->vppapi_client_pipe[i]);
	}

	(*client->vppapi_client_disconnect)(client);

	naas_mutex_destroy(&client->vppapi_client_lock);
}

static uint16_t
naas_vppapi_vac_ping(struct naas_vppapi_vac *vac, u32 context)
{
	int rc;
	vl_api_control_ping_t mp;

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = vac_get_msg_index(VL_API_CONTROL_PING_CRC);
	mp.context = context;
	vl_api_control_ping_t_endian(&mp);
	rc = naas_vppapi_vac_write(vac, (void *)&mp, sizeof(mp));
	if (rc < 0) {
		return rc;
	}
	return vac_get_msg_index(VL_API_CONTROL_PING_REPLY_CRC);
}

int
naas_vppapi_invoke(struct naas_vppapi_client *client, char *msg,
		void *m, int mlen, void **r, int rlen)
{
	int rc;

	naas_vppapi_lock(client);
	rc = (*client->vppapi_client_invoke)(client, msg, m, mlen, r, rlen);
	naas_vppapi_unlock(client);

	return rc;
}

static int
naas_vppapi_dump_locked(struct naas_vppapi_vac *vac, void *mp, int mlen,
		char *details_msg_name, naas_vppapi_dump_handler_t handler,
		void *user0, void *user1)
{
	int rc, rlen, details_msg_id, pong_msg_id, data_msg_id;
	void *data;

	details_msg_id = vac_get_msg_index(details_msg_name); 

	rc = naas_vppapi_vac_write(vac, mp, mlen);
	if (rc < 0) {
		return rc;
	}

	do {
		rc = naas_vppapi_vac_ping(vac, 123);
	} while (rc < 0);

	pong_msg_id = rc;

	do {
		rc = naas_vppapi_vac_read(vac, &data, 5);
		if (rc < 0) {
			return rc;
		}
		rlen = rc;
		rc = 0;

		data_msg_id = ntohs(*((u16 *)data));

		if (data_msg_id == pong_msg_id) {
			;
		} else if (data_msg_id == details_msg_id) {
			rc = (handler)(user0, user1, data, rlen);
		} else {
			naas_logf(LOG_ERR, 0, "[VPPAPI][%s] Unexpected message: %d",
					details_msg_name, data_msg_id);
		}

		naas_vppapi_msg_free(&vac->vac_base, data);

	} while (data_msg_id != pong_msg_id && rc == 0);

	return rc;
}

int
naas_vppapi_dump(struct naas_vppapi_vac *vac, void *mp, int mlen,
		char *details_msg_name, naas_vppapi_dump_handler_t handler,
		void *user0, void *user1)
{
	int rc;

	naas_vppapi_lock(&vac->vac_base);
	rc = naas_vppapi_dump_locked(vac, mp, mlen, details_msg_name, handler, user0, user1);
	naas_vppapi_unlock(&vac->vac_base);

	return rc;
}

int
naas_vppapi_show_version(struct naas_vppapi_client *client, vl_api_show_version_reply_t *ver)
{
	int rc;
	vl_api_show_version_t mp;
	vl_api_show_version_reply_t *rp;
	
	clib_memset(&mp, 0, sizeof(mp));

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_SHOW_VERSION_CRC, mp, rp);
	if (rc < 0) {
		clib_memset(ver, 0, sizeof(ver));
	} else {
		memcpy(ver, rp, sizeof(*ver));
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_DEBUG, -rc,
"[VPPAPI][show_version] program=%s, version=%s, build_date=%s, build_directory=%s",
		ver->program, ver->version, ver->build_date, ver->build_directory);

	return rc;
}

static int
naas_vppapi_sw_interface_details(void *user0, void *user, void *data, int len)
{
	vl_api_sw_interface_details_t *details;
	naas_vppapi_sw_interface_dump_f handler;
	struct naas_vppapi_sw_interface interface;

	handler = user0;

	if (len != sizeof(*details)) {
		return -EINVAL;
	}
	details = data;

	interface.sw_if_index = ntohl(details->sw_if_index);
	interface.flags = details->flags;
	naas_strzcpy(interface.interface_name, (char *)details->interface_name,
			sizeof(interface.interface_name));

	if (handler != NULL) {
		(*handler)(user, &interface);
	}

	naas_logf(LOG_DEBUG, 0,
"[VPPAPI][sw_interface_dump] interfcae_name='%s', sw_if_index=%d",
			interface.interface_name, interface.sw_if_index);

	return 0;
}

typedef struct naas_vppapi_vl_api_sw_interface_dump {
	vl_api_sw_interface_dump_t base;
	char name_filter[NAAS_VPPAPI_INTERFACE_NAME_MAX];
} naas_vppapi_vl_api_sw_interface_dump_t;

int
naas_vppapi_sw_interface_dump(struct naas_vppapi_vac *vac,
		naas_vppapi_sw_interface_dump_f handler, void *user, const char *name_filter)
{
	int rc, name_filter_len, msg_id;
	naas_vppapi_vl_api_sw_interface_dump_t mp;

	msg_id = vac_get_msg_index(VL_API_SW_INTERFACE_DUMP_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp.base._vl_msg_id = ntohs(msg_id);

	if (name_filter == NULL) {
		name_filter_len = 0;
	} else {
		mp.base.name_filter_valid = true;
		name_filter_len = NAAS_MIN(strlen(name_filter), sizeof(mp.name_filter));
	}

  	mp.base.name_filter.length = htonl(name_filter_len);
	memcpy(mp.name_filter, name_filter, name_filter_len);

	rc = naas_vppapi_dump(vac, &mp, sizeof(mp), VL_API_SW_INTERFACE_DETAILS_CRC,
			naas_vppapi_sw_interface_details, handler, user);

	return rc;
}

int
naas_vppapi_create_loopback(struct naas_vppapi_client *client, uint32_t *p_sw_if_index)
{
	int rc;
	uint32_t sw_if_index;
	vl_api_create_loopback_t mp;
	vl_api_create_loopback_reply_t *rp;
	
	clib_memset(&mp, 0, sizeof(mp));

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_CREATE_LOOPBACK_CRC, mp, rp);
	if (rc < 0) {
		sw_if_index = ~0;
	} else {
		sw_if_index = ntohl(rp->sw_if_index);
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	*p_sw_if_index = sw_if_index;

	naas_logf(LOG_INFO, -rc, "[VPPAPI][create_loopback] sw_if_index=%u", sw_if_index);

	return rc;
}

int
naas_vppapi_create_loopback_instance(struct naas_vppapi_client *client, uint32_t instance,
		uint32_t *p_sw_if_index)
{
	int rc;
	uint32_t sw_if_index;
	vl_api_create_loopback_instance_t mp;
	vl_api_create_loopback_instance_reply_t *rp;
	
	clib_memset(&mp, 0, sizeof(mp));
	mp.is_specified = true;
	mp.user_instance = htonl(instance);

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_CREATE_LOOPBACK_INSTANCE_CRC, mp, rp);
	if (rc < 0) {
		sw_if_index = ~0;
	} else {
		sw_if_index = ntohl(rp->sw_if_index);
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	*p_sw_if_index = sw_if_index;

	naas_logf(LOG_INFO, -rc,
"[VPPAPI][create_loopback_instance] instance=%u, sw_if_index=%u",
			instance, sw_if_index);

	return rc;
}

int
naas_vppapi_sw_interface_set_flags(struct naas_vppapi_client *client,
		uint32_t sw_if_index, vl_api_if_status_flags_t flags)
{
	int rc;
	vl_api_sw_interface_set_flags_t mp;
	vl_api_sw_interface_set_flags_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.sw_if_index = htonl(sw_if_index);
	mp.flags = htonl(flags);

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_SW_INTERFACE_SET_FLAGS_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc, "[VPP][API][sw_interface_set_flags] sw_if_index=%u, flags=%x",
			sw_if_index, flags);

	return rc;
}

int
naas_vppapi_sw_interface_set_unnumbered(struct naas_vppapi_client *client,
		int is_add, uint32_t sw_if_index, uint32_t unnumbered_sw_if_index)
{
	int rc;
	vl_api_sw_interface_set_unnumbered_t mp;
	vl_api_sw_interface_set_unnumbered_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.is_add = is_add;
	mp.sw_if_index = htonl(sw_if_index);
	mp.unnumbered_sw_if_index = htonl(unnumbered_sw_if_index);

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_SW_INTERFACE_SET_UNNUMBERED_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc,
"[VPPAPI][sw_interface_set_unnumbered] is_add=%d, sw_if_index=%u, unnumbered_sw_if_index=%u",
			is_add, sw_if_index, unnumbered_sw_if_index);

	return rc;
}

typedef struct naas_vppapi_vl_api_ip_route_add_del {
	vl_api_ip_route_add_del_t base;
	vl_api_fib_path_t path;
} naas_vppapi_vl_api_ip_route_add_del_t;

int
naas_vppapi_ip_route_add_del(struct naas_vppapi_client *client, int is_add, int table_id,
		struct in_addr prefix, int prefixlen, int sw_if_index)
{
	int rc;
	naas_vppapi_vl_api_ip_route_add_del_t mp;
	vl_api_ip_route_add_del_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.base.is_add = is_add;
	mp.base.route.prefix.len = prefixlen;
	vl_api_address_create(&mp.base.route.prefix.address, AF_INET, &prefix);
	mp.base.route.n_paths = 1;
	mp.base.route.table_id = htonl(table_id);
	mp.path.table_id = htonl(table_id);
	mp.path.sw_if_index = htonl(sw_if_index);

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_IP_ROUTE_ADD_DEL_CRC, mp, rp);
	naas_vppapi_msg_free(client, rp);

	if (rc >= 0) {
		rc = 0;
	}

	naas_logf(LOG_INFO, -rc,
"[VPPAPI][ip_route_add_del] is_add=%d, prefix=%s/%u, sw_if_index=%u",
			is_add, inet_ntoa(prefix), prefixlen, sw_if_index);

	return rc;
}

// vat2: lcp_itf_pair_get; cursor = 0
static int
naas_vppapi_lcp_itf_pair_details(naas_vppapi_lcp_itf_pair_get_f handler, void *user,
		char *data, int len)
{
	int rc, host_if_index;
	uint32_t phy_sw_if_index;
	vl_api_lcp_itf_pair_details_t *details;

	if (len != sizeof(*details)) {
		return -EINVAL;
	}
	details = (void *)data;

	rc = if_nametoindex((const char *)details->host_if_name);
	if (rc == 0) {
		naas_logf(LOG_ERR, errno, "if_nametoindex('%s') failed",
				details->host_if_name);
		return 0;
	}
	host_if_index = rc;

	phy_sw_if_index = ntohl(details->phy_sw_if_index);
	if (handler != NULL) {
		(*handler)(user, phy_sw_if_index, host_if_index);
	}

	naas_logf(LOG_INFO, 0,
"[VPPAPI][lcp_itf_pair_get] host_if_name='%s', linux_if_index=%d, vpp_if_index=%d",
			details->host_if_name, rc, phy_sw_if_index);

	return 0;
}

static int
naas_vppapi_lcp_itf_pair_get_locked(struct naas_vppapi_vac *vac,
		naas_vppapi_lcp_itf_pair_get_f handler, void *user)
{
	int rc, len, msg_id, reply_msg_id, details_msg_id, data_msg_id;
	void *data;
	vl_api_lcp_itf_pair_get_t mp;
	vl_api_lcp_itf_pair_get_reply_t *reply;

	msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_CRC);
	reply_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_GET_REPLY_CRC);
	details_msg_id = vac_get_msg_index(VL_API_LCP_ITF_PAIR_DETAILS_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.cursor = htonl(0);

	rc = naas_vppapi_vac_write(vac, (void *)&mp, sizeof(mp));
	if (rc < 0) {
		return rc;
	}

	do {
		rc = naas_vppapi_vac_read(vac, &data, 5);
		if (rc < 0) {
			return rc;
		}
		len = rc;

		data_msg_id = ntohs(*((u16 *)data));
		if (data_msg_id == reply_msg_id) {
			if (len != sizeof(*reply)) {
				rc = -EINVAL;
			} else {
				reply = (void *)data;
				rc = ntohl(reply->retval);
				if (rc > 0) {
					rc = -EPROTO;
				} else if (rc < 0) {
					rc = naas_create_err(NAAS_ERR_VNET, -rc);
				}
			}
		} else if (data_msg_id == details_msg_id) {
			rc = naas_vppapi_lcp_itf_pair_details(handler, user, data, len);
		} else {
			rc = -EBADMSG;
		}

		naas_vppapi_msg_free(&vac->vac_base, data);
	} while (data_msg_id != reply_msg_id && rc == 0);

	return rc;
}

int
naas_vppapi_lcp_itf_pair_get(struct naas_vppapi_vac *vac,
		naas_vppapi_lcp_itf_pair_get_f handler, void *user)
{
	int rc;

	naas_vppapi_lock(&vac->vac_base);
	rc = naas_vppapi_lcp_itf_pair_get_locked(vac, handler, user);
	naas_vppapi_unlock(&vac->vac_base);

	return rc;
}


// set sr encaps source addr 2001:db8::1
int
naas_vppapi_set_sr_encaps_source_addr(struct naas_vppapi_client *client, struct in6_addr *addr)
{
	int rc;
	char addrstr[INET6_ADDRSTRLEN];
	vl_api_sr_set_encap_source_t mp;
	vl_api_sr_set_encap_source_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	clib_memcpy(mp.encaps_source, addr, 16);

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_SR_SET_ENCAP_SOURCE_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc, "[VPPAPI][set_sr_encaps_source_addr] tunsrc=%s",
			naas_inet6_ntop(addr, addrstr));

	return rc;
}

// linux:	ip link add dev VRF13 type vrf table 13
// vppctl: 	ip table add 13
//		ip6 table add 13
// vat2: 	'ip_table_add_del' is_add=true, is_ip6=false, table_id=13
int
naas_vppapi_ip_table_add_del(struct naas_vppapi_client *client,
		int is_add, int is_ip6, int table_id)
{
	int rc;
	vl_api_ip_table_add_del_t mp;
	vl_api_ip_table_add_del_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.table.table_id = ntohl(table_id);
	mp.table.is_ip6 = is_ip6;
	mp.is_add = is_add;

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_IP_TABLE_ADD_DEL_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc,
"[VPPAPI][ip_table_add_del] is_add=%s, is_ip6=%s, table_id=%d",
			naas_bool_str(is_ip6), naas_bool_str(is_add), table_id);

	return rc;
}

// linux:	ip l s dev ix1a master VRF13
// vppctl:	ip table add 13
int
naas_vppapi_sw_interface_set_table(struct naas_vppapi_client *client,
		int sw_if_index, int is_ip6, int table_id)
{
	int rc;
	vl_api_sw_interface_set_table_t mp;
	vl_api_sw_interface_set_table_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.sw_if_index = htonl(sw_if_index);
	mp.is_ipv6 = is_ip6;
	mp.vrf_id = htonl(table_id);

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_SW_INTERFACE_SET_TABLE_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc,
"[VPPAPI][sw_interface_set_table] is_ip6=%s, sw_if_index=%d, table_id=%d",
			naas_bool_str(is_ip6), sw_if_index, table_id);

	return rc;
}

// Linux:
// ip -6 route add 2000:aaa8:0:0:100::/128 encap seg6local action End.DT6 table 13 dev VRF13
// ip -6 route add 2000:aaa8:0:0:100::/128 encap seg6local action End.DT4 vrftable 13  dev VRF13 
// 
// VPP ctl:
// sr localsid address 2000:aaa8:0:0:100:: behavior end.dt6 13
//
// VPP api:
// 'sr_localsid_add_del' is_del=false, localsid=2000:aaa8:0:0:100::, behavior=SR_BEHAVIOR_API_DT6
int
naas_vppapi_sr_localsid_add_del(struct naas_vppapi_client *client,
		int is_add, int behavior, void *addr, int table_id)
{
	int rc;
	char localsid_addrstr[INET6_ADDRSTRLEN];
	vl_api_sr_localsid_add_del_t mp;
	vl_api_sr_localsid_add_del_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.is_del = !is_add;
	clib_memcpy(mp.localsid, addr, sizeof(mp.localsid));
	mp.sw_if_index = htonl(table_id);	
	mp.behavior = behavior;

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_SR_LOCALSID_ADD_DEL_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc,
"[VPPAPI][sr_localsid_add_del] is_del=%s, localsid=%s, sw_if_index=%d, behavior=\"%s\"",
			naas_bool_str(mp.is_del), naas_inet6_ntop(mp.localsid, localsid_addrstr),
			ntohl(mp.sw_if_index), naas_vppapi_sr_behavior_api_str(mp.behavior));

	return rc;
}

// VPP ctl:
// sr policy add bsid 2000:aaa2:0:0:101:: next 2000:aaa2:0:0:100:: encap
int
naas_vppapi_sr_policy_add(struct naas_vppapi_client *client,
		uint8_t *bsid, struct in6_addr *segments, int first_segment)
{
	int i, rc;
	char bsid_addrstr[INET6_ADDRSTRLEN];
	vl_api_sr_policy_add_t mp;
	vl_api_sr_policy_add_reply_t *rp;

	if (first_segment >= NAAS_ARRAY_SIZE(mp.sids.sids)) {
		naas_logf(LOG_ERR, 0, "[VPPAPI][sr_policy_add] failed (sids limit exceeded)");
		return -ERANGE;
	}

	clib_memset(&mp, 0, sizeof(mp));
	clib_memcpy(mp.bsid_addr, bsid, 16);
	mp.is_encap = true;
	mp.sids.num_sids = first_segment + 1;
	for (i = 0; i < mp.sids.num_sids; ++i) {
		clib_memcpy(mp.sids.sids[i], segments[i].s6_addr, 16);
	}
	
	rc = NAAS_VPPAPI_INVOKE(client, VL_API_SR_POLICY_ADD_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc, "[VPPAPI][sr_policy_add] bsid=%s",
			naas_inet6_ntop(bsid, bsid_addrstr));

	return rc;
}

int
naas_vppapi_sr_policy_del(struct naas_vppapi_client *client, uint8_t *bsid)
{
	int rc;
	char bsid_addrstr[INET6_ADDRSTRLEN];
	vl_api_sr_policy_del_t mp;
	vl_api_sr_policy_del_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	clib_memcpy(mp.bsid_addr, bsid, 16);

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_SR_POLICY_DEL_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc, "[VPPAPI][sr_policy_del] bsid=%s",
			naas_inet6_ntop(bsid, bsid_addrstr));

	return rc;
}

// Linux:
// ip r a 10.8.8.0/24 via inet6 fe80::5200:ff:fe03:3766 encap seg6 mode encap segs 2000:aaa2:0:0:100:: dev eth2 table 13
//
// VPP ctl:
// sr steer l3 10.8.8.0/24 via bsid 2000:aaa2:0:0:101:: fib-table 13
// show sr steering-policies
int
naas_vppapi_sr_steering_add_del(struct naas_vppapi_client *client,
		int is_add, int phy_sw_if_index,int family, void *prefix, int prefixlen,
		int table_id, const uint8_t *bsid)
{
	int rc;
	char bsid_addrstr[INET6_ADDRSTRLEN];
	vl_api_sr_steering_add_del_t mp;
	vl_api_sr_steering_add_del_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.is_del = !is_add;
	mp.table_id = htonl(table_id);
	clib_memcpy(mp.bsid_addr, bsid, 16);
	mp.prefix.len = prefixlen;
	mp.sw_if_index = phy_sw_if_index;
	vl_api_address_create(&mp.prefix.address, family, prefix);
	if (family == AF_INET) {
		mp.traffic_type = SR_STEER_API_IPV4;
	} else {
		mp.traffic_type = SR_STEER_API_IPV6;
	}

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_SR_STEERING_ADD_DEL_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc, "[VPPAPI][sr_steering_%s] bsid=%s, table_id=%d",
			is_add ? "add" : "del", naas_inet6_ntop(bsid, bsid_addrstr), table_id);

	return rc;
}

int
naas_vppapi_ipsec_spd_add_del(struct naas_vppapi_client *client, int is_add, uint32_t spd_id)
{
	int rc;
	vl_api_ipsec_spd_add_del_t mp;
	vl_api_ipsec_spd_add_del_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.is_add = is_add;
	mp.spd_id = htonl(spd_id);

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_IPSEC_SPD_ADD_DEL_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc, "[VPPAPI][ipsec_spd_%s] spd_id=%u",
			is_add ? "add" : "del", spd_id);

	return rc;
}

// ipsec itf create instance 10
int
naas_vppapi_ipsec_itf_create(struct naas_vppapi_client *client,
		int instance, uint32_t *p_sw_if_index)
{
	int rc;
	uint32_t sw_if_index;
	vl_api_ipsec_itf_create_t mp;
	vl_api_ipsec_itf_create_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.itf.mode =  TUNNEL_API_MODE_P2P;
	mp.itf.user_instance = htonl(instance);

	
	rc = NAAS_VPPAPI_INVOKE(client, VL_API_IPSEC_ITF_CREATE_CRC, mp, rp);
	if (rc < 0) {
		sw_if_index = ~0;
	} else {
		sw_if_index = ntohl(rp->sw_if_index);
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	if (p_sw_if_index != NULL) {
		*p_sw_if_index = sw_if_index;
	}

	naas_logf(LOG_INFO, -rc, "[VPPAPI][ipsec_itf_create] instance=%u", instance);

	return rc;
}

int
naas_vppapi_ipsec_itf_delete(struct naas_vppapi_client *client, uint32_t sw_if_index)
{
	int rc;
	vl_api_ipsec_itf_delete_t mp;
	vl_api_ipsec_itf_delete_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.sw_if_index = htonl(sw_if_index);

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_IPSEC_ITF_DELETE_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc, "[VPPAPI][ipsec_itf_delete] sw_if_index=%u", sw_if_index);

	return rc;
}

typedef struct naas_vppapi_vl_api_ipsec_tunnel_protect_update {
	vl_api_ipsec_tunnel_protect_update_t base;
	uint32_t sa_in;
} naas_vppapi_vl_api_ipsec_tunnel_protect_update_t;

int
naas_vppapi_ipsec_tunnel_protect_update(struct naas_vppapi_client *client,
		uint32_t sw_if_index, uint32_t sa_in, uint32_t sa_out)
{
	int rc;
	naas_vppapi_vl_api_ipsec_tunnel_protect_update_t mp;
	vl_api_ipsec_tunnel_protect_update_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.base.tunnel.sw_if_index = htonl(sw_if_index);
	mp.base.tunnel.sa_out = htonl(sa_out);
	mp.base.tunnel.n_sa_in = 1;
	mp.sa_in = htonl(sa_in);	

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_IPSEC_TUNNEL_PROTECT_UPDATE_CRC, mp, rp);
	if (rc >= 0) {
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	naas_logf(LOG_INFO, -rc,
"[VPPAPI][ipsec_tunnel_protect_update] sw_if_index=%u, sa_in=%u, sa_out=%u",
			sw_if_index, sa_in, sa_out);

	return rc;
}

typedef struct naas_vppapi_vl_api_ipsec_tunnel_protect_deatils {
	vl_api_ipsec_tunnel_protect_details_t base;
	uint32_t sa_in;
} naas_vppapi_vl_api_ipsec_tunnel_protect_details_t;

static int
naas_vppapi_ipsec_tunnel_protect_details(void *user0, void *user, void *data, int len)
{
	uint32_t *sa_in, *sa_out;
	naas_vppapi_vl_api_ipsec_tunnel_protect_details_t *details;

	sa_in = user0;
	sa_out = user;

	if (len != sizeof(*details)) {
		return -EINVAL;
	}
	details = data;
	*sa_out = ntohl(details->base.tun.sa_out);
	*sa_in = ntohl(details->sa_in);

	naas_logf(LOG_INFO, 0,
"[VPPAPI][ipsec_tunnel_protect_dump] sw_if_index=%u, sa_in=%u, sa_out=%u",
			ntohl(details->base.tun.sw_if_index), *sa_in, *sa_out);

	return 0;
}

int
naas_vppapi_ipsec_tunnel_protect_dump(struct naas_vppapi_vac *vac,
		uint32_t sw_if_index, uint32_t *sa_in, uint32_t *sa_out)
{
	int rc, msg_id;
	vl_api_ipsec_tunnel_protect_dump_t mp;

	msg_id = vac_get_msg_index(VL_API_IPSEC_TUNNEL_PROTECT_DUMP_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);
	mp.sw_if_index = htonl(sw_if_index);

	rc = naas_vppapi_dump(vac, &mp, sizeof(mp), VL_API_IPSEC_TUNNEL_PROTECT_DETAILS_CRC,
			naas_vppapi_ipsec_tunnel_protect_details, sa_in, sa_out);

	return rc;
}

// VPP ctl:
// show ipsec sa
static int
naas_vppapi_ipsec_sa_details(void *user0, void *user, void *data, int len)
{
	uint32_t sad_id, spi;
	naas_vppapi_ipsec_sa_dump_f handler;
	vl_api_ipsec_sa_details_t *details;

	if (len != sizeof(*details)) {
		return -EINVAL;
	}

	handler = user0;
	details = (void *)data;
	sad_id = ntohl(details->entry.sad_id);
	spi = ntohl(details->entry.spi);
	if (handler != NULL) {
		(*handler)(user, sad_id, spi);
	}

	naas_logf(LOG_DEBUG, 0, "[VPPAPI][ipsec_sa_dump] sad_id=%u, spi=%x", sad_id, spi);
	return 0;
}

int
naas_vppapi_ipsec_sa_dump(struct naas_vppapi_vac *vac,
		naas_vppapi_ipsec_sa_dump_f handler, void *user)
{
	int rc, msg_id;
	vl_api_ipsec_sa_dump_t mp;

	msg_id = vac_get_msg_index(VL_API_IPSEC_SA_DUMP_CRC);

	clib_memset(&mp, 0, sizeof(mp));
	mp._vl_msg_id = ntohs(msg_id);

	rc = naas_vppapi_dump(vac, &mp, sizeof(mp), VL_API_IPSEC_SA_DETAILS_CRC,
			naas_vppapi_ipsec_sa_details, handler, user);

	return rc;
}

int
naas_vppapi_ipip_add_tunnel(struct naas_vppapi_client *client,
		int instance, struct in_addr src, struct in_addr dst, uint32_t *p_sw_if_index)
{
	int rc;
	uint32_t sw_if_index;
	char srcbuf[INET_ADDRSTRLEN];
	char dstbuf[INET_ADDRSTRLEN];
	vl_api_ipip_add_tunnel_t mp;
	vl_api_ipip_add_tunnel_reply_t *rp;

	clib_memset(&mp, 0, sizeof(mp));
	mp.tunnel.instance = htonl(instance);
	mp.tunnel.src.af = ADDRESS_IP4;
	clib_memcpy(mp.tunnel.src.un.ip4, &src.s_addr, 4);
	mp.tunnel.dst.af = ADDRESS_IP4;
	clib_memcpy(mp.tunnel.dst.un.ip4, &dst.s_addr, 4);
	mp.tunnel.mode = TUNNEL_API_MODE_P2P;

	rc = NAAS_VPPAPI_INVOKE(client, VL_API_IPIP_ADD_TUNNEL_CRC, mp, rp);
	if (rc < 0) {
		sw_if_index = ~0;
	} else {
		sw_if_index = ntohl(rp->sw_if_index);
		rc = 0;
	}
	naas_vppapi_msg_free(client, rp);

	if (p_sw_if_index != NULL) {
		*p_sw_if_index = sw_if_index;
	}

	naas_logf(LOG_INFO, -rc,
"[VPPAPI][ipip_add_tunnel] instance=%u, src=%s, dst=%s, sw_if_index=%u",
			instance, naas_inet_ntoa(&src, srcbuf), naas_inet_ntoa(&dst, dstbuf),
			sw_if_index);

	return rc;
}

int
naas_vppapi_sw_interface_get(struct naas_vppapi_client *client, const char *sw_if_name,
		struct naas_vppapi_sw_interface *interface)
{
	int rc;
	struct naas_vppapi_sw_interface_get_req req;
	struct naas_vppapi_sw_interface_get_reply reply;

	req.id = naas_hton32(NAAS_VPPAPI_PROC_SW_INTERFACE_GET);
	naas_strzcpy(req.interface_name, sw_if_name, sizeof(req.interface_name));

	rc = (*client->vppapi_client_call)(client, &req, sizeof(req), &reply, sizeof(reply));

	if (rc >= 0) {
		rc = 0;
		interface->sw_if_index = naas_ntoh32(reply.sw_if_index);
		interface->flags = naas_ntoh32(reply.flags);
		naas_strzcpy(interface->interface_name, reply.interface_name,
			sizeof(interface->interface_name));
	}

	return rc;
}

int
naas_vppapi_sa_stat(struct naas_vppapi_client *client, uint32_t stat_index,
		uint64_t *res_packets, uint64_t *res_bytes)
{
	int rc;
	uint64_t packets, bytes;
	struct naas_vppapi_sa_stat_req req;
	struct naas_vppapi_sa_stat_reply reply;

	req.id = naas_hton32(NAAS_VPPAPI_PROC_SA_STAT);
	req.stat_index = naas_hton32(stat_index);
	
	rc = (*client->vppapi_client_call)(client, &req, sizeof(req), &reply, sizeof(reply));
	if (rc >= 0) {
		rc = 0;
	}

	packets = naas_ntoh64(reply.packets);
	bytes = naas_ntoh64(reply.bytes);

	if (res_packets != NULL) {
		*res_packets = packets;
	}

	if (res_bytes != NULL) {
		*res_bytes = bytes;
	}

	naas_logf(LOG_INFO, -rc,
"[VPPAPI][sa_stat] stat_index=%u, packets=%"PRIu64", bytes=%"PRIu64"",
			stat_index, packets, bytes);

	return rc;
}
