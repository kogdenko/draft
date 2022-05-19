#define _GNU_SOURCE
#include <poll.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <pthread.h>
#ifndef __linux__
#include <pthread_np.h>
typedef cpuset_t cpu_set_t;
#endif

#define SNAPLEN 65536

static int dflag = 0;

struct device {
	const char *d_ifname;
	pcap_t *d_pcap;
	int d_fd;
};

static void
usage()
{
	printf("pcap-l2fwd [-hd] [-a cpu ] { -i ifa } [ -i ifb ]\n");
}

void
die(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}

static void
read_packets(struct device *dev_dst, struct device *dev_src)
{
	int rc;
	struct pollfd pfd;
	struct pcap_pkthdr *pkt_hdr;
	const u_char *pkt_dat;

	while (1) {
		rc = pcap_next_ex(dev_src->d_pcap, &pkt_hdr, &pkt_dat);
		if (rc == 1) {
			if (pkt_hdr->len > pkt_hdr->caplen) {
				printf("%s: Packet len (%d) > caplen (%d), dropping\n",
					dev_src->d_ifname, pkt_hdr->len, pkt_hdr->caplen);
				continue;
			}
inject:
			rc = pcap_inject(dev_dst->d_pcap, pkt_dat, pkt_hdr->len);
			if (rc == -1) {
				pfd.fd = dev_dst->d_fd;
				pfd.events = POLLOUT;
				pfd.revents = 0;
				poll(&pfd, 1, -1);
				goto inject;
			} else if (rc < 0) {
				die("pcap_inject('%s') failed (%s)",
					dev_dst->d_ifname,
					pcap_geterr(dev_dst->d_pcap));
			}
		} else if (rc < 0) {
			die("pcap_next_ex('%s') failed (%s)",
				dev_src->d_ifname,
				pcap_geterr(dev_src->d_pcap));
		} else {
			assert(rc == 0);
			break;
		}
	}
}

static void
init_device(struct device *dev, const char *ifname)
{
	int i, rc, fd, *dlt_buf;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;

	if (0) {
		pcap = pcap_open_live(ifname, SNAPLEN, 1, -1, errbuf);
		if (pcap == NULL) {
			die("pcap_open_live('%s') failed (%s)", ifname, errbuf);
		}
	} else {
		pcap = pcap_create(ifname, errbuf);
		if (pcap == NULL) {
			die("pcap_create('%s') failed (%s)", ifname, errbuf);
		}
		rc = pcap_set_immediate_mode(pcap, 1);
		if (rc < 0) {
			die("pcap_set_immediate_mode('%s', 1) failed (%s)",
				ifname, pcap_geterr(pcap));
		}
		rc = pcap_set_promisc(pcap, 1);
		if (rc < 0) {
			die("pcap_set_promisc('%s', 1) failed (%s)",
				ifname, pcap_geterr(pcap));
		}
		rc = pcap_set_snaplen(pcap, SNAPLEN);
		if (rc < 0) {
			die("pcap_set_snaplen('%s', %d) failed (%s)",
				ifname, SNAPLEN, pcap_geterr(pcap));
		}
		rc = pcap_activate(pcap);
		if (rc != 0) {
			die("pcap_activate('%s') failed (%s)",
				ifname, pcap_geterr(pcap));
		}
	}
	rc = pcap_list_datalinks(pcap, &dlt_buf);
	if (rc < 0) {
		die("pcap_list_datatlinks('%s') failed (%s)",
			ifname, pcap_geterr(pcap));
	}
	if (dflag) {
		printf("%s data links:\n", ifname);
		for (i = 0; i < rc; ++i) {
			printf("\t%s: %s\n", pcap_datalink_val_to_name(dlt_buf[i]),
				pcap_datalink_val_to_description(dlt_buf[i]));
		}
	}
	for (i = 0; i < rc; ++i) {
		if (dlt_buf[i] == DLT_EN10MB) {
			break;
		}
	}
	if (i == rc) {
		die("%s doesn't support DLT_EN10MB datalink type", ifname);
	}
	pcap_free_datalinks(dlt_buf);
	if (0) {
		// Not supported on netmap
		rc = pcap_setdirection(pcap, PCAP_D_IN);
		if (rc < 0) {
			die("%d pcap_setdirection('%s', PCAP_D_IN) failed (%s)",
				rc, ifname, pcap_geterr(pcap));
		}
	}
	rc = pcap_setnonblock(pcap, 1, errbuf);
	if (rc < 0) {
		die("pcap_setnonblock('%s') failed (%s)", ifname, errbuf);
	}
	fd = pcap_get_selectable_fd(pcap);
	if (fd < 0) {
		die("pcap_get_selectable_fd('%s') failed (%s)",
			ifname, pcap_geterr(pcap));
	}
	dev->d_ifname = ifname;
	dev->d_pcap = pcap;
	dev->d_fd = fd;
}

static void
deinit_device(struct device *dev)
{
	if (dev->d_pcap != NULL) {
		pcap_close(dev->d_pcap);
		dev->d_pcap = NULL;
	}
}

static void
set_affinity(int cpu_id)
{
	int rc;
	cpu_set_t cpumask;

	CPU_ZERO(&cpumask);
	CPU_SET(cpu_id, &cpumask);
	rc = pthread_setaffinity_np(pthread_self(), sizeof(cpumask), &cpumask);
	if (rc != 0) {
		die("pthread_setaffinity_np(%d) failed (%s)",
			cpu_id, strerror(errno));
	}
}

int
main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *ifa, *ifb;
	int rc, opt, affinity;
	struct pollfd pfd[2];
	struct device devices[2], *deva, *devb;

	ifa = ifb = NULL;
	affinity = -1;
	while ((opt = getopt(argc, argv, "hda:i:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return 0;
		case 'd':
			dflag = 1;
			break;
		case 'a':
			affinity = strtoul(optarg, NULL, 10);
			break;
		case 'i':
			ifa = optarg;
			break;
		}
	}
	if (ifa == NULL) {
		usage();
		return 1;
	}
	rc = pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf);
	if (rc != 0) {
		die("pcap_init() failed (%s)", errbuf);
	}
	deva = devices;
	init_device(deva, ifa);
	if (ifb == NULL) {
		devb = deva;
	} else {
		devb = devices + 1;
		init_device(devb, ifb);
	}
	if (affinity != -1) {
		set_affinity(affinity);
	}
	while (1) {
		pfd[0].fd = deva->d_fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].revents = 0;
		if (devb != deva) {
			pfd[1].fd = devb->d_fd;
			pfd[1].events = POLLIN;
		}
		rc = poll(pfd, devb == NULL ? 1 : 2, -1);
		if (rc == -1) {
			die(0, "poll() failed (%s)", strerror(errno));
		}
		if (pfd[0].revents | POLLIN) {
			read_packets(deva, devb);
		}
		if (pfd[1].revents | POLLIN) {
			read_packets(devb, deva);
		}
	}
	deinit_device(deva);
	deinit_device(devb);
	return 0;
}
