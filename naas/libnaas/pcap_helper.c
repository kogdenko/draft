#include "log.h"
#include "pcap_helper.h"
#include <pcap.h>

struct pcap *
naas_pcap_open(const char *interface, const char *filter_exp)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	pcap_t *pcap;

	pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		naas_logf(LOG_ERR, 0, "pcap_open_live(%s) failed (%s)", interface, errbuf);
		return NULL;
	}

	//int linktype;
	//linktype = pcap_datalink(pcap);
	//printf("linktype=%d\n", linktype);

	if (pcap_set_datalink(pcap, DLT_LINUX_SLL)) {
		naas_logf(LOG_ERR, 0, "pcap_set_datalink(%s, DLT_EN10MB) failed (%s)",
				interface, pcap_geterr(pcap));
		pcap_close(pcap);
		return  NULL;
	}

	if (pcap_compile(pcap, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		naas_logf(LOG_ERR, 0, "pcap_compile(%s) failed (%s)",
				filter_exp, pcap_geterr(pcap));
		pcap_close(pcap);
		return  NULL;
	}

	if (pcap_setfilter(pcap, &fp) == -1) {
		naas_logf(LOG_ERR, 0, "pcap_setfilter(%s) failed (%s)",
				filter_exp, pcap_geterr(pcap));
		pcap_close(pcap);
		return NULL;
	}

	
	return pcap;
}

#define SLL_ADDRLEN 8
struct sll_header {
	be16_t sll_pkttype;
	be16_t sll_hatype;
	be16_t sll_halen;
	u_char sll_addr[SLL_ADDRLEN];
	be16_t sll_protocol;
} __attribute__((packed));

int
naas_pcap_read(pcap_t *pcap, struct naas_pcap_data *data)
{
	struct sll_header *sll;
	struct pcap_pkthdr packet_header;
	u_char *packet;

	packet = (u_char *)pcap_next(pcap, &packet_header);

	if (packet == NULL) {
		return -EINVAL;
	}

	if (packet_header.len < sizeof(*sll)) {
		return -EPROTO;
	}

	sll = (struct sll_header *)packet;
	data->pcap_data = packet + sizeof(*sll);
	data->pcap_datalen = packet_header.len - sizeof(*sll);
	data->pcap_pkttype = sll->sll_pkttype;
	data->pcap_protocol = sll->sll_protocol;

	return 0;
}

void
naas_pcap_close(struct pcap *pcap)
{
	pcap_close(pcap);
}

