#ifndef LIBNAAS_PCAP_H
#define LIBNAAS_PCAP_H

struct pcap;

#define NAAS_PCAP_HOST		0
#define NAAS_PCAP_BROADCAST	1
#define NAAS_PCAP_MULTICAST	2
#define NAAS_PCAP_OTHERHOST	3
#define NAAS_PCAP_OUTGOING	4

struct naas_pcap_data {
	void *pcap_data;
	int pcap_datalen;
	be16_t pcap_pkttype;
	be16_t pcap_protocol;
};
struct pcap *naas_pcap_open(const char *, const char *);
int naas_pcap_read(struct pcap *, struct naas_pcap_data *);
void naas_pcap_close(struct pcap *);

#endif // LIBNAAS_PCAP_H
