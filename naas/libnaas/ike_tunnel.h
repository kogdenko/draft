//
//  ___________    LISTEN     _____                _______   SEND RAW    ___________
// |           |---IKE_REQ-->|     |---NATS_MSG-->|       |---IKE_REQ-->|           |
// | initiator |             | pod |              | sswan |             | responder |
// |           | SEND DGRAM  |     |              |       |    PCAP     |           |
// |___________|<--IKE_RPL---|_____|<--NATS_MSG---|_______|<--IKE_RPL---|___________|
//                                              
#ifndef LIBNAAS_IKE_TUNNEL_H
#define LIBNAAS_IKE_TUNNEL_H

#include "utils.h"

#define NAAS_IKE_PORTS_NUM 2

struct ike_tunnel_hdr {
	be32_t saddr;
	be32_t daddr;
	be16_t sport;
	be16_t dport;
	be32_t pod_id;
} __attribute__((packed));

typedef int (*naas_ike_tunnel_msg_f)(void *, struct ike_tunnel_hdr *);

int naas_ike_tunnel_pod_bind(int *fds);
int naas_ike_tunnel_pod_udp_loop(int *fds, int pod_id, const char *nats_server);
int naas_ike_tunnel_pod_nats_loop(int *fds, int pod_id, const char *nats_server);

int naas_ike_tunnel_sswan_nats_loop(naas_ike_tunnel_msg_f put_pod_id, void *udata,
		const char *nats_server, const char *netns);
int naas_ike_tunnel_sswan_pcap_loop(naas_ike_tunnel_msg_f get_pod_id, void *udata,
		const char *nats_server, const char *netns);

#endif
