#include <vlibmemory/api.h>

#include <daemon.h>
#include <processing/jobs/callback_job.h>
#include <collections/hashtable.h>

#include <libnaas/log.h>
#include <libnaas/vppapi.h>
#include <libnaas/vppapi_rpc.h>
#include <libnaas/ike_tunnel.h>

struct kernel_vpp_ipsec;

typedef struct kernel_vpp_plugin_t kernel_vpp_plugin_t;

struct kernel_vpp_plugin_t {
	plugin_t plugin;
};

typedef struct kernel_vpp_listener {
	listener_t public;
	struct kernel_vpp_ipsec *ipsec;
} kernel_vpp_listener_t;

typedef struct kernel_vpp_pod {
	struct naas_vppapi_rpc rpc;
	struct naas_vppapi_client *vppapicli;
	void *ipsec;
} kernel_vpp_pod_t;

typedef struct kernel_vpp_ipsec {
	kernel_ipsec_t interface;

	refcount_t next_sad_id;

	pthread_mutex_t mutex;

	hashtable_t *sas;
	hashtable_t *tunnels;

	kernel_vpp_listener_t *listener;

	refcount_t nextspi;

	uint32_t mixspi;

	natsConnection *nats_conn;

	struct naas_vppapi_vac vac;

	bool rekey_can_update_config;
	unsigned int announce_pod;
	int loop_instance;
	const char *nats_server;
	const char *netns;
	int remote_api;

	struct naas_thread ike_tunnel_nats_thread;
	struct naas_thread ike_tunnel_pcap_thread;

	hashtable_t *pods;
	kernel_vpp_pod_t pod_instances[NAAS_PODS_MAX];
} kernel_vpp_ipsec_t;

#define LOCK(this) pthread_mutex_lock(&(this)->mutex)
#define UNLOCK(this) pthread_mutex_unlock(&(this)->mutex)

typedef struct kernel_vpp_child_sa {
	uint32_t id;
	uint32_t stat_index;
	uint32_t peer_spi;
	uint32_t unique_id;
	uint32_t pod_id;
} kernel_vpp_child_sa_t;

typedef struct kernel_vpp_tunnel {
	uint32_t sw_if_index;
	uint16_t vrf;
	uint16_t pod_id;
	linked_list_t *remote_ts;
} kernel_vpp_tunnel_t;

typedef struct private_kernel_vpp_plugin {
  	kernel_vpp_plugin_t public;
} private_kernel_vpp_plugin_t;

static int
pod_get_pod_id(kernel_vpp_ipsec_t *this, kernel_vpp_pod_t *pod)
{
	return pod - this->pod_instances;
}

static u_int
pod_hash(const void *key)
{
	chunk_t chunk;
	const struct ike_tunnel_hdr *hdr;

	hdr = key;

	chunk = chunk_create((u_char *)hdr, 2 * sizeof(be32_t) + 2 * sizeof(be16_t)); 

	return chunk_hash(chunk); 
}

static bool
pod_equals(const void *key, const void *other_key)
{
	const struct ike_tunnel_hdr *hdr, *other_hdr;

	hdr = key;
	other_hdr = other_key;

	return hdr->saddr == other_hdr->saddr &&
			hdr->daddr == other_hdr->daddr &&
			hdr->sport == other_hdr->sport &&
			hdr->dport == other_hdr->dport;
}

static int
put_pod_id(void *udata, struct ike_tunnel_hdr *hdr)
{
	kernel_vpp_ipsec_t *this;
	struct ike_tunnel_hdr *key;
	uintptr_t pod_id;

	this = udata;
	pod_id = naas_ntoh32(hdr->pod_id);
	key = naas_xmemdup(hdr, sizeof(*hdr));
	LOCK(this);
	this->pods->put(this->pods, key, (void *)(pod_id + 1));
	UNLOCK(this);
	return pod_id;
}

static int
get_pod_id(void *udata, struct ike_tunnel_hdr *hdr)
{
	kernel_vpp_ipsec_t *this;
	int pod_id;
	uintptr_t val;

	this = udata;
	LOCK(this);
	if (this->netns != NULL) {
		val = (uintptr_t)this->pods->get(this->pods, hdr);
		pod_id = (int)val - 1;
	} else {
		pod_id = this->announce_pod;
	}
	UNLOCK(this);
	return pod_id;
}

static u_int
sa_hash(const void *key)
{
	const kernel_ipsec_sa_id_t *sa;

	sa = key;

	return chunk_hash_inc(
			sa->src->get_address (sa->src),
			chunk_hash_inc(
				sa->dst->get_address (sa->dst),
				chunk_hash_inc(chunk_from_thing (sa->spi),
					chunk_hash(chunk_from_thing(sa->proto)))));
}

static bool
sa_equals(const void *key, const void *other_key)
{
	const kernel_ipsec_sa_id_t *sa, *other_sa;

	sa = key;
	other_sa = other_key;

	return sa->src->ip_equals(sa->src, other_sa->src) &&
			sa->dst->ip_equals(sa->dst, other_sa->dst) &&
			sa->spi == other_sa->spi && sa->proto == other_sa->proto;
}

static u_int
permute(u_int x, u_int p)
{
	u_int qr;

	x = x % p;
	qr = ((uint64_t) x * x) % p;
	if (x <= p / 2) {
		return qr;
	}
	return p - qr;
}

static uint32_t
get_ts_addr(traffic_selector_t *ts, bool from)
{
	chunk_t chunk;
	host_t *host;
	struct sockaddr_in * addr;

	if (from) {
		chunk = ts->get_from_address(ts);
	} else {
		chunk = ts->get_to_address(ts);
	}
	host = host_create_from_chunk(AF_INET, chunk, 0);
	addr = (struct sockaddr_in *)host->get_sockaddr(host);
	return addr->sin_addr.s_addr;
}

static int
get_ts_net(traffic_selector_t *ts, struct in_addr *prefix, int *prefixlen)
{
	uint64_t from, to, num_addresses;

	if (ts->get_type(ts) != TS_IPV4_ADDR_RANGE) {
		return -EINVAL;
	}

	from = get_ts_addr(ts, true);
	to = get_ts_addr(ts, false);

	prefix->s_addr = from;

	from = ntohl(from);
	to = ntohl(to);
	if (to < from) {
		return -EINVAL;
	}
	num_addresses = to - from + 1;

	*prefixlen = 32 - __builtin_ctzll(num_addresses);

	return 0;
}

static void
destroy_list_ts(linked_list_t *list_ts)
{
	list_ts->destroy_offset(list_ts, offsetof(traffic_selector_t, destroy));
}

static int
list_get_count(linked_list_t *list)
{
	return list->get_count(list);
}

static void
nats_publish(kernel_vpp_ipsec_t *this, int pod_id, int is_up, uint32_t vrf, uint32_t unique_id,
		struct in_addr prefix, int prefixlen)
{
	const char *subj;
	char buf[128];
	int len;
	
	len = snprintf(buf, sizeof(buf), "%u %u %u %s/%u", pod_id, vrf, unique_id,
			inet_ntoa(prefix), prefixlen);

	if (is_up) {
		subj = "tunnel-up";
	} else {
		subj = "tunnel-down";
	}

	naas_natsConnection_Publish(this->nats_conn, subj, buf, len);
}

static void
pod_deinit_callback(struct naas_vppapi_client *client)
{
	int pod_id;
	void *pod_value, *tunnel_key;
	kernel_vpp_pod_t *pod;
	kernel_vpp_ipsec_t *this;
	kernel_ipsec_sa_id_t *id;
	kernel_vpp_child_sa_t *sa;
	kernel_vpp_tunnel_t *tunnel;
	enumerator_t *enumerator;
	struct ike_tunnel_hdr *pod_key;

	pod = client->vppapi_client_user;
	this = pod->ipsec;

	pod_id = pod_get_pod_id(this, pod);

	naas_logf(LOG_NOTICE, 0, "pod %d gone", pod_id);

	LOCK(this);
	pod->vppapicli = NULL;

	enumerator = this->pods->create_enumerator(this->pods);
	while (enumerator->enumerate(enumerator, &pod_key, &pod_value)) {
		if ((uintptr_t)pod_value - 1 != pod_id) {
			continue;
		}
		this->pods->remove(this->pods, pod_key);
		free(pod_key);
	}
	enumerator->destroy(enumerator);

	enumerator = this->tunnels->create_enumerator(this->tunnels);
	while (enumerator->enumerate(enumerator, &tunnel_key, &tunnel)) {
		if (tunnel->pod_id != pod_id) {
			continue;
		}
		this->tunnels->remove(this->tunnels, tunnel_key);
		free(tunnel);
	}

	enumerator = this->sas->create_enumerator(this->sas);
	while (enumerator->enumerate(enumerator, &id, &sa)) {
		if (sa->pod_id != pod_id) {
			continue;
		}
		charon->kernel->expire(charon->kernel, id->proto, id->spi, id->dst, TRUE);
		/*this->sas->remove(this->sas, id);
		if (id->src) {
			id->src->destroy (id->src);
		}
		if (id->dst) {
			id->dst->destroy (id->dst);
		}
		free(id);*/
	}
	enumerator->destroy(enumerator);

	UNLOCK(this);
}

static kernel_vpp_pod_t *
get_pod(kernel_vpp_ipsec_t *this, int pod_id)
{
	int rc;
	kernel_vpp_pod_t *pod;

	if ((u_int)pod_id >= NAAS_ARRAY_SIZE(this->pod_instances)) {
		return NULL;
	}

	pod = &this->pod_instances[pod_id];

	if (pod->vppapicli == NULL) {
		naas_logf(LOG_INFO, 0, "Connecting to pod %d", pod_id);

		if (this->remote_api || this->netns != NULL) {
			rc = naas_vppapi_rpc_init(&pod->rpc, pod_id, this->nats_server);
			if (rc < 0) {
				naas_logf(LOG_ERR, -rc, "Connection to VPP RPC server failed (pod:%d)",
						pod_id);
				return NULL;
			}
			pod->vppapicli = &pod->rpc.rpc_base;
		} else {
			rc = naas_vppapi_vac_init(&this->vac, "kernel_vpp_plugin");
			if (rc < 0) {
				naas_logf(LOG_ERR, -rc, "Connection to VAC failed");
				return NULL;
			}
			pod->vppapicli = &this->vac.vac_base;
		}

		pod->ipsec = this;
		pod->vppapicli->vppapi_client_deinit_notify = pod_deinit_callback;
		pod->vppapicli->vppapi_client_user = pod;
	}

	return pod;
}

// Initialize seeds for SPI generation
static int
init_spi(kernel_vpp_ipsec_t *this)
{
	rng_t *rng;
	bool ok;

	rng = lib->crypto->create_rng(lib->crypto, RNG_STRONG);
	if (!rng) {
		return -EINVAL;
	}
	ok = rng->get_bytes(rng, sizeof (this->nextspi), (uint8_t *)&this->nextspi);
	if (ok) {
		ok = rng->get_bytes(rng, sizeof (this->mixspi), (uint8_t *)&this->mixspi);
	}
	rng->destroy(rng);
	return ok ? 0 : -EINVAL;
}

static uint32_t
get_other_id(ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	u_char c;
	int i;
	uint32_t id;
	identification_t* peer_id;
	host_t *src, *dst;
	id_type_t peer_id_type;
	chunk_t chunk;

	peer_id = ike_sa->get_other_id(ike_sa);
	peer_id_type = peer_id->get_type(peer_id);
	if (peer_id_type != ID_KEY_ID) {
		goto err;
	}

	chunk = peer_id->get_encoding(peer_id);
	if (chunk.len < 1 || chunk.len > 4) {
		goto err;
	}

	// TODO: Find implementation of this algorithm in strongswan and call api
	id = 0;
	for (i = 0; i < chunk.len; ++i) {
		id *= 10;
		c = chunk.ptr[i];
		if (c < '0' || c > '9') {
			goto err;
		}
		id += c - '0';
	}

	return id;

err:
	src = ike_sa->get_my_host(ike_sa);
	dst = ike_sa->get_other_host(ike_sa);
	DBG1(DBG_KNL, "SA_CHILD %#H == %#H with SPI %.8x has invalid peerid type %d",
			src, dst, child_sa->get_spi(child_sa, TRUE) ,peer_id_type);
	return ~0;
}

static uint32_t
get_sw_interface_index(struct naas_vppapi_client *c, const char *name)
{
	struct naas_vppapi_sw_interface interface;

	interface.sw_if_index = ~0;
	naas_vppapi_sw_interface_get(c, name, &interface);

	return interface.sw_if_index;
}

static uint32_t
create_ipsec_interface(kernel_vpp_pod_t *pod, kernel_vpp_ipsec_t *this,
		uint32_t unique_id, uint32_t vrf)
{
	int rc, is_ip6;
	uint32_t sw_if_index, loop_sw_if_index;
	char loop[64];

	sw_if_index = ~0;

	snprintf(loop, sizeof(loop), "loop%d", this->loop_instance);
	loop_sw_if_index = get_sw_interface_index(pod->vppapicli, loop);
	if (loop_sw_if_index == ~0) {
		naas_vppapi_create_loopback_instance(pod->vppapicli,
				this->loop_instance, &loop_sw_if_index);
		if (loop_sw_if_index == ~0) {
			goto err;
		}
	}

	rc = naas_vppapi_ipsec_itf_create(pod->vppapicli, unique_id, &sw_if_index);
	if (rc < 0) {
		goto err;
	}

	rc = naas_vppapi_sw_interface_set_unnumbered(pod->vppapicli, 1,
			loop_sw_if_index, sw_if_index);
	if (rc < 0) {
		goto err;
	}

	for (is_ip6 = 0; is_ip6 <= 1; ++is_ip6) {
		rc = naas_vppapi_sw_interface_set_table(pod->vppapicli, sw_if_index, is_ip6, vrf);
		if (rc < 0) {
			goto err;
		}
	}

	rc = naas_vppapi_sw_interface_set_flags(pod->vppapicli,
			sw_if_index, IF_STATUS_API_FLAG_ADMIN_UP);
	if (rc < 0) {
		goto err;
	}

	return sw_if_index;

err:
	if (sw_if_index != ~0) {
		naas_vppapi_ipsec_itf_delete(pod->vppapicli, sw_if_index);
		sw_if_index = ~0;
	}
	return sw_if_index;
}

METHOD(kernel_ipsec_t, ipsec_get_features, kernel_feature_t, kernel_vpp_ipsec_t *this)
{
	return KERNEL_ESP_V3_TFC;
}

METHOD(kernel_ipsec_t, get_spi, status_t, kernel_vpp_ipsec_t *this,
		host_t *src, host_t *dst, uint8_t protocol, uint32_t *spi)
{
	static const u_int p = 268435399;
	static const u_int offset = 0xc0000000;

	*spi = htonl (offset + permute (ref_get (&this->nextspi) ^ this->mixspi, p));
	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t, kernel_vpp_ipsec_t *this,
		host_t *src, host_t *dst, uint16_t *cpi)
{
	DBG1(DBG_KNL, "get_cpi is not supported!!!!!!!!!!!!!!!!!!!!!!!!");
	return NOT_SUPPORTED;
}

typedef struct {
	kernel_vpp_ipsec_t *manager;
	kernel_ipsec_sa_id_t *sa_id;
	// 0 if this is a hard expire, otherwise the offset in s (soft->hard)
	uint32_t hard_offset;
} vpp_sa_expired_t;

static void
expire_data_destroy(vpp_sa_expired_t *data)
{
	free(data);
}

static job_requeue_t
sa_expired(vpp_sa_expired_t *expired)
{
	kernel_vpp_ipsec_t *this = expired->manager;
	kernel_vpp_child_sa_t *sa;
	kernel_ipsec_sa_id_t *id;

	this = expired->manager;
	id = expired->sa_id;

	LOCK(this);
	sa = this->sas->get(this->sas, id);

	if (sa) {
		charon->kernel->expire(charon->kernel, id->proto, id->spi, id->dst, FALSE);
	}

	if (id->src) {
		id->src->destroy (id->src);
	}
	if (id->dst) {
		id->dst->destroy (id->dst);
	}
	free(id);

	UNLOCK(this);
	return JOB_REQUEUE_NONE;
}


// Schedule a job to handle IPsec SA expiration
static void
schedule_sa_expiration(kernel_vpp_ipsec_t *this, lifetime_cfg_t *lifetime,
		kernel_ipsec_sa_id_t *entry2)
{
	vpp_sa_expired_t *expired;
	callback_job_t *job;
	uint32_t timeout;
	kernel_ipsec_sa_id_t *id;

	if (!lifetime->time.life) { 
		// no expiration at all
		return;
	}

	INIT(id,
		.src = entry2->src->clone(entry2->src),
		.dst = entry2->dst->clone(entry2->dst),
		.spi = entry2->spi,
		.proto = entry2->proto,
	);

	INIT(expired,
		.manager = this,
		.sa_id = id,
	);

	// schedule a rekey first, a hard timeout will be scheduled then, if any
	expired->hard_offset = lifetime->time.life - lifetime->time.rekey;
	timeout = lifetime->time.rekey;

	if (lifetime->time.life <= lifetime->time.rekey || lifetime->time.rekey == 0) {
		// no rekey, schedule hard timeout
		expired->hard_offset = 0;
		timeout = lifetime->time.life;
	}

	job = callback_job_create((callback_job_cb_t)sa_expired, expired,
		(callback_job_cleanup_t)expire_data_destroy, NULL);
	lib->scheduler->schedule_job (lib->scheduler, (job_t *) job, timeout);
}

static kernel_vpp_child_sa_t *
kernel_vpp_sa_create(kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id, int pod_id)
{
	kernel_vpp_child_sa_t *sa;
	kernel_ipsec_sa_id_t *key;

	INIT(key,
		.src = id->src->clone(id->src),
		.dst = id->dst->clone(id->dst),
		.spi = id->spi,
		.proto = id->proto,
	);

	INIT(sa,
		.id = ~0,
		.stat_index = ~0,
		.peer_spi = ~0,
		.unique_id = ~0,
		.pod_id = pod_id,
	);

	DBG1(DBG_KNL, "put SA_CHILD %#H == %#H with SPI %.8x",
			key->src, key->dst, htonl(key->spi));
	this->sas->put(this->sas, key, sa);

	return sa;
}

METHOD(kernel_ipsec_t, add_sa, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data)
{
	vl_api_ipsec_sad_entry_add_del_t mp;
	vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
	int rc, key_len, pod_id;
	uint8_t ca, ia;
	uint32_t sad_id, stat_index;
	chunk_t src, dst;
	kernel_ipsec_sa_id_t sa_key;
	kernel_vpp_child_sa_t *sa;
	kernel_vpp_pod_t *pod;

	pod = NULL;
	ca = ia = 0;
	key_len = data->enc_key.len;
	sad_id = ref_get(&this->next_sad_id); 

	if ((data->enc_alg == ENCR_AES_CTR) || (data->enc_alg == ENCR_AES_GCM_ICV8) ||
		(data->enc_alg == ENCR_AES_GCM_ICV12) || (data->enc_alg == ENCR_AES_GCM_ICV16)) {
		// See how enc_size is calculated at keymat_v2.derive_child_keys
		static const int SALT_SIZE = 4; 
		key_len = key_len - SALT_SIZE;
	}
	memset(&mp, 0, sizeof (mp));
	mp.is_add = 1;
	mp.entry.sad_id = htonl(sad_id);
	mp.entry.spi = id->spi;
	mp.entry.protocol = id->proto == IPPROTO_ESP ? htonl (IPSEC_API_PROTO_ESP) :
			htonl (IPSEC_API_PROTO_AH);

	switch (data->enc_alg) {
	case ENCR_NULL:
		ca = IPSEC_API_CRYPTO_ALG_NONE;
		break;
	case ENCR_AES_CBC:
		switch (key_len * 8) {
		case 128:
			ca = IPSEC_API_CRYPTO_ALG_AES_CBC_128;
			break;
		case 192:
			ca = IPSEC_API_CRYPTO_ALG_AES_CBC_192;
			break;
		case 256:
			ca = IPSEC_API_CRYPTO_ALG_AES_CBC_256;
			break;
		default:
			DBG1(DBG_KNL, "Key length %d is not supported by VPP!", key_len * 8);
			return FAILED;
		}
		break;
	case ENCR_AES_CTR:
		switch (key_len * 8) {
		case 128:
			ca = IPSEC_API_CRYPTO_ALG_AES_CTR_128;
			break;
		case 192:
			ca = IPSEC_API_CRYPTO_ALG_AES_CTR_192;
			break;
		case 256:
			ca = IPSEC_API_CRYPTO_ALG_AES_CTR_256;
			break;
		default:
			DBG1(DBG_KNL, "Key length %d is not supported by VPP!", key_len * 8);
			return FAILED;
		}
		break;
	case ENCR_AES_GCM_ICV8:
	case ENCR_AES_GCM_ICV12:
	case ENCR_AES_GCM_ICV16:
		switch (key_len * 8) {
		case 128:
			ca = IPSEC_API_CRYPTO_ALG_AES_GCM_128;
			break;
		case 192:
			ca = IPSEC_API_CRYPTO_ALG_AES_GCM_192;
			break;
		case 256:
			ca = IPSEC_API_CRYPTO_ALG_AES_GCM_256;
			break;
		default:
			DBG1 (DBG_KNL, "Key length %d is not supported by VPP!", key_len * 8);
			return FAILED;
		}
		break;
	case ENCR_DES:
		ca = IPSEC_API_CRYPTO_ALG_DES_CBC;
		break;
	case ENCR_3DES:
		ca = IPSEC_API_CRYPTO_ALG_3DES_CBC;
		break;
	default:
		DBG1(DBG_KNL, "algorithm %N not supported by VPP!",
				encryption_algorithm_names, data->enc_alg);
		return FAILED;
	}

	mp.entry.crypto_algorithm = htonl(ca);
	mp.entry.crypto_key.length = key_len < 128 ? key_len : 128;
	memcpy(mp.entry.crypto_key.data, data->enc_key.ptr, mp.entry.crypto_key.length);

	// copy salt for AEAD algorithms
	if ((data->enc_alg == ENCR_AES_CTR) ||
			(data->enc_alg == ENCR_AES_GCM_ICV8) ||
			(data->enc_alg == ENCR_AES_GCM_ICV12) ||
			(data->enc_alg == ENCR_AES_GCM_ICV16)) {
		memcpy (&mp.entry.salt, data->enc_key.ptr + mp.entry.crypto_key.length, 4);
	}

	switch (data->int_alg) {
		case AUTH_UNDEFINED:
		ia = IPSEC_API_INTEG_ALG_NONE;
		break;
	case AUTH_HMAC_MD5_96:
		ia = IPSEC_API_INTEG_ALG_MD5_96;
		break;
	case AUTH_HMAC_SHA1_96:
		ia = IPSEC_API_INTEG_ALG_SHA1_96;
		break;
	case AUTH_HMAC_SHA2_256_96:
		ia = IPSEC_API_INTEG_ALG_SHA_256_96;
		break;
	case AUTH_HMAC_SHA2_256_128:
		ia = IPSEC_API_INTEG_ALG_SHA_256_128;
		break;
	case AUTH_HMAC_SHA2_384_192:
		ia = IPSEC_API_INTEG_ALG_SHA_384_192;
		break;
	case AUTH_HMAC_SHA2_512_256:
		ia = IPSEC_API_INTEG_ALG_SHA_512_256;
		break;
	default:
		DBG1 (DBG_KNL, "algorithm %N not supported by VPP!",
				integrity_algorithm_names, data->int_alg);
		return FAILED;
	}

	mp.entry.integrity_algorithm = htonl(ia);
	mp.entry.integrity_key.length = data->int_key.len < 128 ? data->int_key.len : 128;
	memcpy(mp.entry.integrity_key.data,
			data->int_key.ptr, mp.entry.integrity_key.length);

	int flags = IPSEC_API_SAD_FLAG_NONE;
	if (data->inbound)
		flags |= IPSEC_API_SAD_FLAG_IS_INBOUND;
	// like the kernel-netlink plugin, anti-replay can be disabled with zero
	// replay_window, but window size cannot be customized for vpp
	if (data->replay_window)
		flags |= IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY;
	if (data->esn)
		flags |= IPSEC_API_SAD_FLAG_USE_ESN;

	if (data->mode == MODE_TUNNEL) {
		if (id->src->get_family (id->src) == AF_INET6) {
			flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
		} else {
			flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL;
		}
    	}

	struct sockaddr_in *src_sockaddr;
	struct sockaddr_in *dst_sockaddr;
	struct ike_tunnel_hdr key;

	if (id->src->get_family(id->src) == AF_INET6) {
		naas_logf(LOG_ERR, 0, "adding SA with SPI %.8x failed (IPv6 not supported)",
				htonl(id->spi));
		goto err;
	}

	src_sockaddr = (struct sockaddr_in *)id->src->get_sockaddr(id->src);
	dst_sockaddr = (struct sockaddr_in *)id->dst->get_sockaddr(id->dst);

	if (data->encap) {
		flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;
		if (id->src->get_family(id->src) != AF_INET ||
				id->dst->get_family(id->dst) != AF_INET) {
			DBG1(DBG_KNL, "UDP encap not IPv4");
		} else {
			mp.entry.udp_src_port = src_sockaddr->sin_port;
			mp.entry.udp_dst_port = dst_sockaddr->sin_port;
		}

	}
	mp.entry.flags = htonl(flags);

	bool is_ipv6 = false;
	if (id->src->get_family(id->src) == AF_INET6) {
		is_ipv6 = true;
		mp.entry.tunnel_src.af = htonl(ADDRESS_IP6);
		mp.entry.tunnel_dst.af = htonl(ADDRESS_IP6);
	} else {
		mp.entry.tunnel_src.af = htonl(ADDRESS_IP4);
		mp.entry.tunnel_dst.af = htonl(ADDRESS_IP4);
	}

	src = id->src->get_address(id->src);
	memcpy(is_ipv6 ? mp.entry.tunnel_src.un.ip6 : mp.entry.tunnel_src.un.ip4,
			src.ptr, src.len);
	dst = id->dst->get_address(id->dst);
	memcpy(is_ipv6 ? mp.entry.tunnel_dst.un.ip6 : mp.entry.tunnel_dst.un.ip4,
			dst.ptr, dst.len);

	LOCK(this);

	if (data->inbound) {
		key.saddr = src_sockaddr->sin_addr.s_addr;
		key.daddr = dst_sockaddr->sin_addr.s_addr;
		key.sport = src_sockaddr->sin_port;
		key.dport = dst_sockaddr->sin_port;
	} else {
		key.saddr = dst_sockaddr->sin_addr.s_addr;
		key.daddr = src_sockaddr->sin_addr.s_addr;
		key.sport = dst_sockaddr->sin_port;
		key.dport = src_sockaddr->sin_port;
	}
	pod_id = get_pod_id(this, &key);
	pod = get_pod(this, pod_id);
	if (pod == NULL) {
		goto err;
	}

	rc = NAAS_VPPAPI_INVOKE(pod->vppapicli, VL_API_IPSEC_SAD_ENTRY_ADD_DEL_CRC, mp, rmp);
	if (rmp) {
		stat_index = ntohl(rmp->stat_index);
	}
	naas_vppapi_msg_free(pod->vppapicli, rmp);
	if (rc < 0) {
		naas_logf(LOG_ERR, -rc, "adding SA with SPI %.8x failed", htonl(id->spi));
		goto err;
	}

	sa_key.src = id->src;
	sa_key.dst = id->dst;
	sa_key.spi = id->spi;
	sa_key.proto = id->proto;

	sa = this->sas->get(this->sas, &sa_key);
	if (sa == NULL) {
		sa = kernel_vpp_sa_create(this, &sa_key, pod_id);
		sa->id = sad_id;
	}

	sa->stat_index = stat_index;

	schedule_sa_expiration(this, data->lifetime, id);
	UNLOCK(this);

	return SUCCESS;

err:
	UNLOCK(this);
	return FAILED;
}

METHOD(kernel_ipsec_t, query_sa, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_sa_id_t *id, kernel_ipsec_query_sa_t *data,
		uint64_t *bytes, uint64_t *packets, time_t *time)
{
	int rc;
	kernel_vpp_pod_t *pod;
	kernel_vpp_child_sa_t *sa;

	LOCK(this);
	sa = this->sas->get(this->sas, id);
	if (!sa) {
		naas_logf(LOG_ERR, 0, "query_sa: CHILD_SA with SPI %.8x not found", htonl(id->spi));
		UNLOCK(this);
		return NOT_FOUND;
	}

	pod = get_pod(this, sa->pod_id);
	if (pod == NULL) {
		UNLOCK(this);
		return FAILED;
	}

	rc = naas_vppapi_sa_stat(pod->vppapicli, sa->stat_index, packets, bytes);
	if (rc < 0) {
		UNLOCK(this);
		return FAILED;
	}

	if (time) {
		*time = 0;
	}

	UNLOCK(this);
	return SUCCESS;
}

status_t
kernel_vpp_del_sa(kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id)
{
	int rc;
	vl_api_ipsec_sad_entry_add_del_t mp;
	vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
	status_t rv;
	kernel_vpp_child_sa_t *sa;
	kernel_vpp_pod_t *pod;

	rv = FAILED;

	LOCK(this);
	sa = this->sas->get(this->sas, id);
	if (!sa) {
		naas_logf(LOG_ERR, 0, "SA_CHILD with SPI %.8x not found", htonl(id->spi));
		rv = NOT_FOUND;
		goto err;
	}

	pod = get_pod(this, sa->pod_id);
	if (pod == NULL) {
		rv = FAILED;
		goto err;
	}

	memset (&mp, 0, sizeof (mp));
	mp.is_add = 0;
	mp.entry.sad_id = htonl(sa->id);

	rc = NAAS_VPPAPI_INVOKE(pod->vppapicli, VL_API_IPSEC_SAD_ENTRY_ADD_DEL_CRC, mp, rmp);
	naas_vppapi_msg_free(pod->vppapicli, rmp);
	if (rc < 0) {
		naas_logf(LOG_ERR, -rc, "del SA_CHILD with SPI %.8x failed", htonl(id->spi));
		goto err;
	}

	this->sas->remove(this->sas, id);
	free(sa);
	UNLOCK(this);

	return SUCCESS;

err:
	UNLOCK(this);
	return rv;
}

METHOD(kernel_ipsec_t, del_sa, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_sa_id_t *id, kernel_ipsec_del_sa_t *data)
{
	return kernel_vpp_del_sa(this, id);
}

METHOD(kernel_ipsec_t, update_sa, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_sa_id_t *id, kernel_ipsec_update_sa_t *data)
{
	DBG1(DBG_KNL, "update SA_CHILD %#H == %#H with SPI %.8x to %#H == %#H not supported",
			id->src, id->dst, htonl(id->spi),
			data->new_src, data->new_dst);

	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, flush_sas, status_t, kernel_vpp_ipsec_t *this)
{
	int rc;
	enumerator_t *enumerator;
	vl_api_ipsec_sad_entry_add_del_t mp;
	vl_api_ipsec_sad_entry_add_del_reply_t *rmp;
	kernel_vpp_child_sa_t *sa;
	kernel_vpp_pod_t *pod;
	status_t rv;

	LOCK(this);
	enumerator = this->sas->create_enumerator(this->sas);
	while (enumerator->enumerate(enumerator, &sa)) {
		pod = get_pod(this, sa->pod_id);
		if (pod == NULL) {
			continue;
		}

		memset(&mp, 0, sizeof(mp));
		mp.entry.sad_id = htonl(sa->id);
		mp.is_add = 0;
		rc = NAAS_VPPAPI_INVOKE(pod->vppapicli, VL_API_IPSEC_SAD_ENTRY_ADD_DEL_CRC,
				mp, rmp);
		naas_vppapi_msg_free(pod->vppapicli, rmp);
		if (rc < 0) {
			naas_logf(LOG_ERR, -rc, "flush_sas: Failed to DEL sa:%d in pod:%d",
					sa->id, pod_get_pod_id(this, pod));
			rv = FAILED;
			goto error;
		}
		this->sas->remove_at(this->sas, enumerator);
		free(sa);
	}
	rv = SUCCESS;

error:
	enumerator->destroy(enumerator);
	UNLOCK(this);
	return rv;
}

METHOD(kernel_ipsec_t, add_policy, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
		kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
		kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t, kernel_vpp_ipsec_t *this,
		kernel_ipsec_policy_id_t *id, kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t, kernel_vpp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool, kernel_vpp_ipsec_t *this, int fd, int family)
{
	return FALSE;
}

METHOD (kernel_ipsec_t, enable_udp_decap, bool,
		kernel_vpp_ipsec_t *this, int fd, int family, u_int16_t port)
{
	return TRUE;
}

METHOD(kernel_ipsec_t, ipsec_destroy, void, kernel_vpp_ipsec_t *this)
{
	// TODO: Destroy all pod_instances
	int i;
	kernel_vpp_pod_t *pod;

	naas_logf(LOG_ERR, 0, "ipsec_destroy");

	for (i = 0; i < NAAS_ARRAY_SIZE(this->pod_instances); ++i) {
		pod = this->pod_instances + i;
		if (pod->vppapicli != NULL) {
			naas_vppapi_deinit(pod->vppapicli);
			pod->vppapicli = NULL;
		}	
	}

	if (this->nats_conn != NULL) {
		natsConnection_Destroy(this->nats_conn);
		nats_Close();
	}
	if (this->listener != NULL) {
		charon->bus->remove_listener(charon->bus, &this->listener->public);
		free(this->listener);
	}
	naas_mutex_destroy(&this->mutex);
	this->sas->destroy(this->sas);
	this->tunnels->destroy(this->tunnels);
	this->pods->destroy(this->pods);
	free(this);
}

METHOD(listener_t, ike_updown, bool, kernel_vpp_listener_t *this, ike_sa_t *ike_sa, bool up) 
{
	naas_logf(LOG_NOTICE, 0, "ike_%s", up ? "up" : "down");
	return TRUE;
}

METHOD(listener_t, child_state_change, bool,
	kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
	child_sa_state_t state)
{
	return TRUE;
}

static int
update_routes(kernel_vpp_ipsec_t *this, kernel_vpp_pod_t *pod,
		int is_add, uint32_t sw_if_index,
		uint32_t vrf, uint32_t unique_id, linked_list_t *remote_ts)
{
	int rc, prefixlen;
	struct in_addr prefix;
	enumerator_t *e;
	traffic_selector_t *ts;

	rc = 0;
	e = remote_ts->create_enumerator(remote_ts);
	while (e->enumerate(e, &ts)) {
		rc = get_ts_net(ts, &prefix, &prefixlen);
		if (rc < 0) {
			naas_logf(LOG_ERR, 0, "Invalid traffic selector");
			continue;
		}
		rc = naas_vppapi_ip_route_add_del(pod->vppapicli,
				is_add, vrf, prefix, prefixlen, sw_if_index);
		if (rc < 0) {
			break;
		}
		nats_publish(this, pod_get_pod_id(this, pod), is_add, vrf, unique_id,
				prefix, prefixlen);
	}
	e->destroy(e);
	return rc;
}

static int
tunnel_update_remote_ts(kernel_vpp_ipsec_t *this,
		kernel_vpp_pod_t *pod, kernel_vpp_tunnel_t *tunnel,
		uint32_t vrf, uint32_t unique_id, linked_list_t *remote_ts_new)
{
	int rc;
	bool found;
	linked_list_t *remote_ts_old, *remote_ts_add;
	enumerator_t *e_old, *e_new;
	traffic_selector_t *ts_old, *ts_new;

	remote_ts_old = tunnel->remote_ts;
	tunnel->remote_ts = remote_ts_new;

	remote_ts_add = linked_list_create();

	e_new = remote_ts_new->create_enumerator(remote_ts_new);
	e_old = remote_ts_old->create_enumerator(remote_ts_old);

	while (e_new->enumerate(e_new, &ts_new)) {
		found = false;
		while (e_old->enumerate(e_old, &ts_old)) {
			if (ts_old->equals(ts_old, ts_new)) {
				remote_ts_old->remove_at(remote_ts_old, e_old);
				found = true;
				break;
			}
		}
		if (!found) {
			remote_ts_add->insert_last(remote_ts_add, ts_new);
		}
		remote_ts_old->reset_enumerator(remote_ts_old, e_old);
	}
	e_new->destroy(e_new);
	e_old->destroy(e_old);

	rc = 0;
	if (list_get_count(remote_ts_add) || list_get_count(remote_ts_old)) {
		rc = update_routes(this, pod, 1, tunnel->sw_if_index, vrf,
				unique_id, remote_ts_add);
		if (rc >= 0) {
			rc = update_routes(this, pod, 0, tunnel->sw_if_index, vrf,
					unique_id, remote_ts_old);
		}
	}

	destroy_list_ts(remote_ts_old);
	remote_ts_add->destroy(remote_ts_add);

	return rc;
}

static int
tunnel_set_remote_ts(kernel_vpp_ipsec_t *this, kernel_vpp_pod_t *pod, kernel_vpp_tunnel_t *tunnel,
		uint32_t vrf, uint32_t unique_id, linked_list_t *remote_ts_new)
{
	int rc;

	tunnel->remote_ts = remote_ts_new;
	rc = update_routes(this, pod, 1, tunnel->sw_if_index, vrf, unique_id, tunnel->remote_ts);
	return rc;
}

static void
kernel_vpp_child_down(kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	int rc;
	uint32_t vrf;
	uintptr_t unique_id;
	kernel_vpp_pod_t *pod;
	kernel_vpp_tunnel_t *tunnel;

	unique_id = ike_sa->get_unique_id(ike_sa);
	tunnel = this->ipsec->tunnels->get(this->ipsec->tunnels, (void *)unique_id);
	if (tunnel == NULL) {
		return;
	}
	pod = get_pod(this->ipsec, tunnel->pod_id);
	if (pod == NULL) {
		return;
	}
	vrf = tunnel->vrf;
	this->ipsec->tunnels->remove(this->ipsec->tunnels, (void *)unique_id);

	rc = update_routes(this->ipsec, pod, 0, tunnel->sw_if_index, vrf,
			unique_id, tunnel->remote_ts);
	if (rc >= 0) {
		naas_vppapi_ipsec_itf_delete(pod->vppapicli, tunnel->sw_if_index);
	}

	tunnel->remote_ts->destroy_offset(tunnel->remote_ts,
			offsetof(traffic_selector_t, destroy));
	free(tunnel);
}

static	linked_list_t *
get_traffic_selectors(child_sa_t *child_sa, bool is_local)
{
	child_cfg_t* cfg;
	linked_list_t *list_ts;
	enumerator_t *enumerator;
	traffic_selector_t *my_ts, *other_ts;

	// Traffic selectors from IKE
	enumerator = child_sa->create_policy_enumerator(child_sa);
	list_ts = linked_list_create();
	while (enumerator->enumerate(enumerator, &my_ts, &other_ts)) {
		list_ts->insert_first(list_ts, other_ts->clone(other_ts));
	}

	return list_ts;

	// Traffic selectors from config
	cfg = child_sa->get_config(child_sa);
	return cfg->get_traffic_selectors(cfg, is_local, NULL, NULL, false);
}

static void
kernel_vpp_child_up(kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	int rc, pod_id;
	uint32_t sw_if_index, i_spi, o_spi, vrf;
	uintptr_t unique_id;
	struct sockaddr_in *src, *dst;
	protocol_id_t proto;
	linked_list_t *remote_ts;
	host_t *my_host, *other_host;
	kernel_vpp_tunnel_t *tunnel;
	kernel_ipsec_sa_id_t o_key, i_key;
	kernel_vpp_child_sa_t *i_sa, *o_sa;
	kernel_vpp_pod_t *pod;
	struct ike_tunnel_hdr key;

	vrf = get_other_id(ike_sa, child_sa);
	if (vrf == ~0) {
		return;
	}

	proto = child_sa->get_protocol(child_sa);

	unique_id = ike_sa->get_unique_id(ike_sa);
	my_host = ike_sa->get_my_host(ike_sa);
	other_host = ike_sa->get_other_host(ike_sa);

	o_key.src = my_host;
	o_key.dst = other_host;
	o_key.proto = proto == PROTO_ESP ? IPPROTO_ESP : IPPROTO_AH;
	o_spi = child_sa->get_spi(child_sa, FALSE);
	o_key.spi = o_spi;
	o_sa = this->ipsec->sas->get(this->ipsec->sas, &o_key);

	i_key.src = other_host;
	i_key.dst = my_host;
	i_key.proto = proto == PROTO_ESP ? IPPROTO_ESP : IPPROTO_AH;
	i_spi = child_sa->get_spi(child_sa, TRUE);
	i_key.spi = i_spi;
	i_sa = this->ipsec->sas->get(this->ipsec->sas, &i_key);

	unique_id = ike_sa->get_unique_id(ike_sa);
	tunnel = this->ipsec->tunnels->get(this->ipsec->tunnels, (void *)unique_id);

	if (o_sa != NULL) {
		pod_id = o_sa->pod_id;
	} else if (i_sa != NULL) {
		pod_id = i_sa->pod_id;
	} else if (tunnel != NULL) {
		pod_id = tunnel->pod_id;
	} else {
		src = (struct sockaddr_in *)other_host->get_sockaddr(other_host);
		dst = (struct sockaddr_in *)my_host->get_sockaddr(my_host);
		key.saddr = src->sin_addr.s_addr;
		key.daddr = dst->sin_addr.s_addr;
		key.sport = src->sin_port;
		key.dport = dst->sin_port;
		pod_id = get_pod_id(this->ipsec, &key);
	}

	pod = get_pod(this->ipsec, pod_id);
	if (pod == NULL) {
		return;
	}

	if (tunnel == NULL) {
		sw_if_index = create_ipsec_interface(pod, this->ipsec, unique_id, vrf);
		if (sw_if_index == ~0) {
			naas_logf(LOG_ERR, 0, "child_up for ike_sa (%s) failed (couldn't create ipsec interface)",
					ike_sa->get_name(ike_sa));
			return;
		}
		INIT(tunnel);
		tunnel->sw_if_index = sw_if_index;
		tunnel->remote_ts = NULL;
		tunnel->vrf = vrf;
		tunnel->pod_id = pod_id;
		this->ipsec->tunnels->put(this->ipsec->tunnels, (void *)unique_id, tunnel);
	} else {
		sw_if_index = tunnel->sw_if_index;
	}

	if (o_sa != NULL && i_sa != NULL) {
		assert(o_sa->pod_id == i_sa->pod_id);
		rc = naas_vppapi_ipsec_tunnel_protect_update(pod->vppapicli,
				sw_if_index, i_sa->id, o_sa->id);
		if (rc < 0) {
			kernel_vpp_child_down(this, ike_sa, child_sa);
			return;
		}
	} else {
		if (o_sa == NULL) {
			o_sa = kernel_vpp_sa_create(this->ipsec, &o_key, pod_id);
		}
		if (i_sa == NULL) {
			i_sa = kernel_vpp_sa_create(this->ipsec, &i_key, pod_id);
		}
		
		o_sa->unique_id = i_sa->unique_id = unique_id;
		o_sa->peer_spi = i_spi;
		i_sa->peer_spi = o_spi;
	}

	if (tunnel->remote_ts == NULL) {
		remote_ts = get_traffic_selectors(child_sa, false);
		tunnel_set_remote_ts(this->ipsec, pod, tunnel, vrf, unique_id, remote_ts);
	} else if (this->ipsec->rekey_can_update_config) {
		remote_ts = get_traffic_selectors(child_sa, false);
		tunnel_update_remote_ts(this->ipsec, pod, tunnel, vrf, unique_id, remote_ts);
	}
}

METHOD(listener_t, child_updown, bool,
		kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa, bool up)
{
	uint32_t i_spi, o_spi;

	i_spi = child_sa->get_spi(child_sa, TRUE);
	o_spi = child_sa->get_spi(child_sa, FALSE);

	naas_logf(LOG_NOTICE, 0, "child_%s %.8x_i %.8x_o", up ? "up" : "down",
			ntohl(i_spi), ntohl(o_spi));

	LOCK(this->ipsec);
	if (up) {
		kernel_vpp_child_up(this, ike_sa, child_sa);
	} else {
		kernel_vpp_child_down(this, ike_sa, child_sa);
	}
	UNLOCK(this->ipsec);

	return TRUE;
}

METHOD(listener_t, child_rekey, bool,
		kernel_vpp_listener_t *this, ike_sa_t *ike_sa, child_sa_t *old, child_sa_t *new)
{
	uint32_t new_i_spi, new_o_spi, old_i_spi, old_o_spi;

	new_i_spi = new->get_spi(new, TRUE);
	new_o_spi = new->get_spi(new, FALSE);
	old_i_spi = old->get_spi(old, TRUE);
	old_o_spi = old->get_spi(old, FALSE);

	naas_logf(LOG_NOTICE, 0, "child_rekey %.8x_i %.8x_o => %.8x_i %.8x_o",
			ntohl(old_i_spi), ntohl(old_o_spi), ntohl(new_i_spi), ntohl(new_o_spi));

	LOCK(this->ipsec);
	kernel_vpp_child_up(this, ike_sa, new);
	UNLOCK(this->ipsec);

	return TRUE;
}

kernel_vpp_listener_t *
kernel_vpp_listener_create(kernel_vpp_ipsec_t *ipsec)
{
	kernel_vpp_listener_t *this;

	INIT(this,
		.public = {
			.ike_updown = _ike_updown,
			.child_state_change = _child_state_change,
			.child_updown = _child_updown,
			.child_rekey = _child_rekey,
		},
		.ipsec = ipsec,
	);

	return this;
}

static void *
ike_tunnel_nats_routine(struct naas_thread *thr)
{
	int rc;
	kernel_vpp_ipsec_t *this;

	this = naas_container_of(thr, kernel_vpp_ipsec_t, ike_tunnel_nats_thread);
	
	rc = naas_ike_tunnel_sswan_nats_loop(put_pod_id, this, this->nats_server, this->netns);
	if (rc < 0) {
		naas_logf(LOG_ERR, -rc, "ike_tunnel_sswan_nats_loop() failed");
	}

	return NULL;
}

static void *
ike_tunnel_pcap_routine(struct naas_thread *thr)
{
	int rc;
	kernel_vpp_ipsec_t *this;

	this = naas_container_of(thr, kernel_vpp_ipsec_t, ike_tunnel_pcap_thread);

	rc = naas_ike_tunnel_sswan_pcap_loop(get_pod_id, this, this->nats_server, this->netns);
	if (rc < 0) {
		naas_logf(LOG_ERR, -rc, "ike_tunnel_sswan_pcap_loop() failed");
	}

	return NULL;
}

kernel_vpp_ipsec_t *
kernel_vpp_ipsec_create()
{
	int rc;
	kernel_vpp_ipsec_t *this;

	this = naas_xmalloc(sizeof(*this));
	memset(this, 0, sizeof(*this));
	this->interface.get_features = _ipsec_get_features;
	this->interface.get_spi = _get_spi;
	this->interface.get_cpi = _get_cpi;
	this->interface.add_sa  = _add_sa;
	this->interface.update_sa = _update_sa;
	this->interface.query_sa = _query_sa;
	this->interface.del_sa = _del_sa;
	this->interface.flush_sas = _flush_sas;
	this->interface.add_policy = _add_policy;
	this->interface.query_policy = _query_policy;
	this->interface.del_policy = _del_policy;
	this->interface.flush_policies = _flush_policies;
	this->interface.bypass_socket = _bypass_socket;
	this->interface.enable_udp_decap = _enable_udp_decap;
	this->interface.destroy = _ipsec_destroy;

	this->next_sad_id = 0;
	naas_mutex_init(&this->mutex);
	this->sas = hashtable_create(sa_hash, sa_equals, 32);
	this->tunnels = hashtable_create(hashtable_hash_ptr, hashtable_equals_ptr, 16);
	this->pods = hashtable_create(pod_hash, pod_equals, 4);
	this->rekey_can_update_config = lib->settings->get_bool(lib->settings,
			"%s.plugins.kernel-vpp.rekey_can_update_config", false, lib->ns);
	this->announce_pod = lib->settings->get_int(lib->settings,
			"%s.plugins.kernel-vpp.announce_pod", 0, lib->ns);
	this->loop_instance = lib->settings->get_int(lib->settings,
			"%s.plugins.kernel-vpp.loop_instance", 99, lib->ns);
	this->nats_server = lib->settings->get_str(lib->settings,
			"%s.plugins.kernel-vpp.nats_server", "localhost", lib->ns);
	this->netns = lib->settings->get_str(lib->settings,
			"%s.plugins.kernel-vpp.netns", NULL, lib->ns);
	this->remote_api = lib->settings->get_bool(lib->settings,
			"%s.plugins.kernel-vpp.remote_api", false, lib->ns);

	if (this->announce_pod >= NAAS_PODS_MAX) {
		DBG1(DBG_KNL, "Invalid 'announce_pod', should be less then %d", NAAS_PODS_MAX);
		ipsec_destroy(this);
		return NULL;
	}

	if (this->netns != NULL) {
		naas_thread_start(&this->ike_tunnel_nats_thread,
				ike_tunnel_nats_routine, NULL);
		naas_thread_start(&this->ike_tunnel_pcap_thread,
				ike_tunnel_pcap_routine, NULL);
	}

	if (init_spi(this)) {
		DBG1(DBG_KNL, "Failed to initialize spis");
		ipsec_destroy(this);
		return NULL;
	}

	rc = naas_nats_init(&this->nats_conn, this->nats_server);
	if (rc < 0) {
		naas_logf(LOG_ERR, -rc, "Connection to nats failed");
		ipsec_destroy(this);
		return NULL;
	}

	this->listener = kernel_vpp_listener_create(this);
	charon->bus->add_listener(charon->bus, &this->listener->public);

	naas_logf(LOG_NOTICE, 0, "kernel-vpp initialized, version=%s", NAAS_BUILD);

	return this;
}

METHOD(plugin_t, get_name, char *, private_kernel_vpp_plugin_t *this)
{
	return "kernel-vpp";
}

METHOD(plugin_t, get_features, int, private_kernel_vpp_plugin_t *this,
		plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, kernel_vpp_ipsec_create),
		PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, plugin_destroy, void, private_kernel_vpp_plugin_t *this)
{
	free(this);
}

static void
strongswan_log(int level, const char *s)
{
	switch (level) {
	case LOG_EMERG:
	case LOG_ALERT:
	case LOG_CRIT:
		DBG0(DBG_KNL, "%s", s);
		break;

	case LOG_ERR:
		DBG1(DBG_KNL, "%s", s);
		break;

	case LOG_WARNING:
		DBG2(DBG_KNL, "%s", s);
		break;

	case LOG_NOTICE:
		DBG3(DBG_KNL, "%s", s);
		break;

	default:
		DBG4(DBG_KNL, "%s", s);
		break;
	}
}

plugin_t *
kernel_vpp_plugin_create()
{
	private_kernel_vpp_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _plugin_destroy,
			},
		},
	);

	naas_log_init(strongswan_log);
	naas_set_log_level(LOG_DEBUG);

	return &this->public.plugin;
}
