#ifndef LIBNAAS_VPPAPI_H
#define LIBNAAS_VPPAPI_H

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp-api/client/vppapiclient.h>
#include <vpp/api/vpe.api_types.h>
#include <vnet/interface.api_types.h>
#include <vnet/ip/ip.api_enum.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/srv6/sr.api_enum.h>
#include <vnet/srv6/sr.api_types.h>
#include <vnet/ipsec/ipsec.api_types.h>
#include <vnet/ipip/ipip.api_types.h>
#include <vpp-api/client/stat_client.h>
#include <vpp_plugins/linux_cp/lcp.api_types.h>

#include "utils.h"

#define NAAS_VPPAPI_INTERFACE_NAME_MAX 64

#define NAAS_VPPAPI_PROC_SA_STAT 1
struct naas_vppapi_sa_stat_req {
	be32_t id;
	be32_t stat_index;
} __attribute__((packed));

struct naas_vppapi_sa_stat_reply {
	be32_t error;
	be64_t packets;
	be64_t bytes;
} __attribute__((packed));

#define NAAS_VPPAPI_PROC_SW_INTERFACE_GET 2
struct naas_vppapi_sw_interface_get_req {
	be32_t id;
	char interface_name[NAAS_VPPAPI_INTERFACE_NAME_MAX];
} __attribute__((packed));

struct naas_vppapi_sw_interface_get_reply {
	be32_t sw_if_index;
	be32_t flags;
	char interface_name[NAAS_VPPAPI_INTERFACE_NAME_MAX];
} __attribute__((packed));

#define NAAS_VPPAPI_PROC_INVOKE 3
struct naas_vppapi_invoke_req {
	be32_t id;
	be32_t mlen;
} __attribute__((packed));


struct naas_vppapi_client {
	struct naas_thread vppapi_client_keepalive;
	int vppapi_client_pipe[2];
	int vppapi_client_alive;
	int vppapi_client_connected;
	pthread_mutex_t vppapi_client_lock;

	void (*vppapi_client_msg_free)(struct naas_vppapi_client *, void *);
	int (*vppapi_client_call)(struct naas_vppapi_client *, const void *, int, void *, int);
	int (*vppapi_client_invoke)(struct naas_vppapi_client *, char *, void *, int, void **, int);
	void (*vppapi_client_disconnect)(struct naas_vppapi_client *);
	void (*vppapi_client_keepalive_ping)(struct naas_vppapi_client *);

	void (*vppapi_client_deinit_notify)(struct naas_vppapi_client *);
	void *vppapi_client_user;
};

struct naas_vppapi_vac {
	struct naas_vppapi_client vac_base;
	stat_client_main_t *vac_sm;
	char vac_name[64];
};


void naas_vppapi_lock(struct naas_vppapi_client *client);
void naas_vppapi_unlock(struct naas_vppapi_client *client);

void naas_vppapi_init(struct naas_vppapi_client *client);

int naas_vppapi_vac_init(struct naas_vppapi_vac *, const char *);
int naas_vppapi_vac_wait_connect(int timeout_ms);

void naas_vppapi_msg_free(struct naas_vppapi_client *, void *);
int naas_vppapi_call(struct naas_vppapi_client *, const void *, int, void *, int);
void naas_vppapi_deinit(struct naas_vppapi_client *);

int naas_vppapi_invoke(struct naas_vppapi_client *, char *, void *, int, void **, int);

#define NAAS_VPPAPI_INVOKE4(client, msg, mp, mlen, rp) \
({ \
	int rc; \
	i32 retval; \
\
	rp = NULL; \
	rc = naas_vppapi_invoke(client, msg, mp, mlen, (void **)&rp, sizeof(*rp)); \
	if (rc >= 0) { \
		retval = ntohl(rp->retval); \
		if (retval > 0) { \
			rc = -EPROTO; \
		} else if (retval < 0) { \
			rc = -naas_create_err(NAAS_ERR_VNET, -retval); \
		} \
	} \
	rc; \
})

#define NAAS_VPPAPI_INVOKE(client, msg, mp, rp) \
	NAAS_VPPAPI_INVOKE4(client, msg, &mp, sizeof(mp), rp)

typedef int (naas_vppapi_dump_handler_t)(void *, void *, void *, int);
int naas_vppapi_dump(struct naas_vppapi_vac *, void *, int,
		char *details_msg_name,	naas_vppapi_dump_handler_t, void *, void *);

int naas_vppapi_show_version(struct naas_vppapi_client *, vl_api_show_version_reply_t *);

struct naas_vppapi_sw_interface {
	uint32_t sw_if_index;
	vl_api_if_status_flags_t flags;
	char interface_name[NAAS_VPPAPI_INTERFACE_NAME_MAX];
};
typedef void (*naas_vppapi_sw_interface_dump_f)(void *,	struct naas_vppapi_sw_interface *);
int naas_vppapi_sw_interface_dump(struct naas_vppapi_vac *,
		naas_vppapi_sw_interface_dump_f, void *, const char *);

int naas_vppapi_create_loopback(struct naas_vppapi_client *, uint32_t *);

int naas_vppapi_create_loopback_instance(struct naas_vppapi_client *, uint32_t, uint32_t *);

int naas_vppapi_sw_interface_set_flags(struct naas_vppapi_client *,
		uint32_t, vl_api_if_status_flags_t);

int naas_vppapi_sw_interface_set_unnumbered(struct naas_vppapi_client *,
		int, uint32_t, uint32_t);

int naas_vppapi_ip_route_add_del(struct naas_vppapi_client *,
		int, int, struct in_addr, int, int);

typedef void (*naas_vppapi_lcp_itf_pair_get_f)(void *, int, int);
int naas_vppapi_lcp_itf_pair_get(struct naas_vppapi_vac *,
		naas_vppapi_lcp_itf_pair_get_f, void *);

int naas_vppapi_set_sr_encaps_source_addr(struct naas_vppapi_client *, struct in6_addr *);

int naas_vppapi_ip_table_add_del(struct naas_vppapi_client *, int, int, int);

int naas_vppapi_sw_interface_set_table(struct naas_vppapi_client *, int, int, int);

int naas_vppapi_sr_localsid_add_del(struct naas_vppapi_client *, int, int, void *, int);

int naas_vppapi_sr_policy_add(struct naas_vppapi_client *,
		uint8_t *, struct in6_addr *, int);

int naas_vppapi_sr_policy_del(struct naas_vppapi_client *, uint8_t *);

int naas_vppapi_sr_steering_add_del(struct naas_vppapi_client *,
		int, int, int, void *, int, int, const uint8_t *);

int naas_vppapi_ipsec_spd_add_del(struct naas_vppapi_client *, int, uint32_t);

int naas_vppapi_ipsec_itf_create(struct naas_vppapi_client *, int, uint32_t *);

int naas_vppapi_ipsec_itf_delete(struct naas_vppapi_client *, uint32_t);

int naas_vppapi_ipsec_spd_add_del(struct naas_vppapi_client *, int, uint32_t);

int naas_vppapi_ipsec_tunnel_protect_dump(struct naas_vppapi_vac *,
		uint32_t, uint32_t *, uint32_t *);

int naas_vppapi_ipsec_tunnel_protect_update(struct naas_vppapi_client *,
		uint32_t, uint32_t, uint32_t);

typedef void (*naas_vppapi_ipsec_sa_dump_f)(void *, uint32_t, uint32_t);
int naas_vppapi_ipsec_sa_dump(struct naas_vppapi_vac *,
		naas_vppapi_ipsec_sa_dump_f, void *);

int naas_vppapi_ipip_add_tunnel(struct naas_vppapi_client *,
		int, struct in_addr, struct in_addr, uint32_t *);

int naas_vppapi_sa_stat(struct naas_vppapi_client *, uint32_t, uint64_t *, uint64_t *);

int naas_vppapi_sw_interface_get(struct naas_vppapi_client *client, const char *sw_if_name,
		struct naas_vppapi_sw_interface *interface);

#endif // LIBNAAS_VPPAPI_H
