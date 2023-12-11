#include "inet.h"

#define ip4_l4len(ih) (naas_ntoh16((ih)->ih_total_len) - naas_ip4_hdrlen((ih)->ih_ver_ihl))

struct ip4_pseudo_hdr {
	be32_t ihp_saddr;
	be32_t ihp_daddr;
	uint8_t ihp_pad;
	uint8_t ihp_proto;
	be16_t ihp_len;
} __attribute__((packed));

static uint64_t
cksum_add(uint64_t sum, uint64_t x)
{
	sum += x;
	if (sum < x) {
		++sum;
	}
	return sum;
}

static uint64_t
cksum_raw(const u_char *b, size_t size)
{
	uint64_t sum;

	sum = 0;
	while (size >= sizeof(uint64_t)) {
		sum = cksum_add(sum, *((uint64_t *)b));
		size -= sizeof(uint64_t);
		b += sizeof(uint64_t);
	}
	if (size >= 4) {
		sum = cksum_add(sum, *((uint32_t *)b));
		size -= sizeof(uint32_t);
		b += sizeof(uint32_t);
	}
	if (size >= 2) {
		sum = cksum_add(sum, *((uint16_t *)b));
		size -= sizeof(uint16_t);
		b += sizeof(uint16_t);
	}
	if (size) {
		assert(size == 1);
		sum = cksum_add(sum, *b);
	}
	return sum;
}

static uint16_t
cksum_reduce(uint64_t sum)
{
	uint64_t mask;
	uint16_t reduced;

	mask = 0xffffffff00000000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 32) & ~mask);
	}
	mask = 0xffffffffffff0000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 16) & ~mask);
	}
	reduced = ~((uint16_t)sum);
	if (reduced == 0) {
		reduced = 0xffff;
	}
	return reduced;
}

static uint16_t
ip4_calc_cksum(struct naas_ip4_hdr *ih)
{
	int ih_len;
	uint64_t sum;
	uint16_t reduce;

	ih_len = naas_ip4_hdrlen(ih->ih_ver_ihl);
	sum = cksum_raw((void *)ih, ih_len);
	reduce = cksum_reduce(sum);
	return reduce;
}

static uint64_t
ip4_pseudo_calc_cksum(struct naas_ip4_hdr *ih, uint16_t l4_len)
{	
	uint64_t sum;
	struct ip4_pseudo_hdr ih_pseudo;

	memset(&ih_pseudo, 0, sizeof(ih_pseudo));
	ih_pseudo.ihp_saddr = ih->ih_saddr;
	ih_pseudo.ihp_daddr = ih->ih_daddr;
	ih_pseudo.ihp_pad = 0;
	ih_pseudo.ihp_proto = ih->ih_proto;
	ih_pseudo.ihp_len = naas_hton16(l4_len);
	sum = cksum_raw((void *)&ih_pseudo, sizeof(ih_pseudo));
	return sum;
}

static uint16_t
ip4_udp_calc_cksum(struct naas_ip4_hdr *ih, void *uh, int l4_len)
{
	uint64_t sum, pseudo_cksum;

	sum = cksum_raw(uh, l4_len);
	pseudo_cksum = ip4_pseudo_calc_cksum(ih, l4_len);
	sum = cksum_add(sum, pseudo_cksum);
	sum = cksum_reduce(sum);
	return sum;
}

void
naas_ip4_set_cksum(struct naas_ip4_hdr *ih, void *l4h)
{
	uint16_t ip4_cksum, udp_cksum;
	struct naas_udp_hdr *uh;
	struct naas_tcp_hdr *th;

	ip4_cksum = ip4_calc_cksum(ih);
	udp_cksum = ip4_udp_calc_cksum(ih, l4h, ip4_l4len(ih));

	ih->ih_cksum = ip4_cksum;
	switch (ih->ih_proto) {
	case IPPROTO_UDP:
		uh = l4h;
		uh->uh_cksum = udp_cksum;
		break;
	case IPPROTO_TCP:
		th = l4h;
		th->th_cksum = udp_cksum;
		break;
	}
}
