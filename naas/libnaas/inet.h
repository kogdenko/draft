#ifndef LIBNAAS_INET_H
#define LIBNAAS_INET_H

#include "utils.h"

#define NAAS_ETHADDR_LEN 6

#define NAAS_ETHTYPE_IP4 0x0800
#define NAAS_ETHTYPE_IP4_BE naas_hton16(NAAS_ETHTYPE_IP4)
#define NAAS_ETHTYPE_IP6 0x86DD
#define NAAS_ETHTYPE_IP6_BE naas_hton16(NAAS_ETHTYPE_IP6)
#define NAAS_ETHTYPE_ARP 0x0806
#define NAAS_ETHTYPE_ARP_BE naas_hton16(NAAS_ETHTYPE_ARP)

#define NAAS_IP4_VER_IHL (0x40|0x05)

#define naas_ip4_hdrlen(ver_ihl) (((ver_ihl) & 0x0f) << 2)

struct naas_eth_addr {
	u_char ea_bytes[NAAS_ETHADDR_LEN];
} __attribute__((packed));

struct naas_eth_hdr {
	struct naas_eth_addr eh_daddr;
	struct naas_eth_addr eh_saddr;
	be16_t eh_type;
} __attribute__((packed));

struct naas_ip4_hdr {
	uint8_t ih_ver_ihl;
	uint8_t ih_tos;
	be16_t ih_total_len;
	be16_t ih_id;
	be16_t ih_frag_off;
	uint8_t ih_ttl;
	uint8_t ih_proto;
	uint16_t ih_cksum;
	be32_t ih_saddr;
	be32_t ih_daddr;
} __attribute__((packed));

struct naas_udp_hdr {
	be16_t uh_sport;
	be16_t uh_dport;
	be16_t uh_len;
	uint16_t uh_cksum;
} __attribute__((packed));

struct naas_tcp_hdr {
	be16_t th_sport;
	be16_t th_dport;
	be32_t th_seq;
	be32_t th_ack;
	uint8_t th_data_off;
	uint8_t th_flags;
	be16_t th_win_size;
	uint16_t th_cksum;
	be16_t th_urgent_ptr;
} __attribute__((packed));


void naas_ip4_set_cksum(struct naas_ip4_hdr *ih, void *l4h);

#endif // LIBNAAS_INET_H
