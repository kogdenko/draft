//TODO comment:
//	ip netns exec cut iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP

#include "wrappers.h"
#include "inet.h"
#include "ike_tunnel.h"
#include "nats_helper.h"
#include "pcap_helper.h"
#include "strbuf.h"

#define IKE_INBOX_SSWAN "ike_inbox_sswan"
#define IKE_INBOX_PODf "ike_inbox_%d"

static int naas_ike_ports[NAAS_IKE_PORTS_NUM] = { 500, 4500 };

static int
enter_netns(const char *netns)
{
	int fd;
	char path[PATH_MAX];

	if (netns == NULL) {
		return -EAGAIN;
	}

	snprintf(path, sizeof(path), "/var/run/netns/%s", netns);

	fd = naas_open(path, O_RDONLY);
	if (fd >= 0) {
		setns(fd, CLONE_NEWNET);
	}

	return fd;
}

static void
leave_netns(int fd)
{
	if (fd >= 0) {
		close(fd);
	}
}

int
naas_ike_tunnel_pod_bind(int *fds)
{
	int i, rc, opt;
	struct sockaddr_in sin;

	for (i = 0; i < NAAS_IKE_PORTS_NUM; ++i) {
		fds[i] = -1;
	}

	for (i = 0; i < NAAS_IKE_PORTS_NUM; ++i) {
		rc = naas_socket(AF_INET, SOCK_DGRAM, 0);
		if (rc < 0) {
			goto err;
		}
		fds[i] = rc;

		naas_set_nonblock(fds[i], 1);

		opt = 1;
		naas_setsockopt(fds[i], IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt));

		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		sin.sin_port = naas_hton16(naas_ike_ports[i]);
		rc = naas_bind(fds[i], (struct sockaddr *)&sin, sizeof(sin));
		if (rc < 0) {
			goto err;
		}
	}

	return 0;

err:
	for (i = 0; i < NAAS_IKE_PORTS_NUM; ++i) {
		if (fds[i] >= 0) {
			close(fds[i]);
		}
	}
	return rc;
}

static int
ike_tunnel_recvmsg(int fd, int lport, int pod_id, struct ike_tunnel_hdr *hdr, int packet_size)
{
	int rc, len;
	char cmbuf[0x100];
	struct sockaddr_in peer;
	struct iovec iov;
	struct cmsghdr *cmsg;
	struct msghdr mh;
	struct in_pktinfo *pi;

	iov.iov_base = hdr + 1;
	iov.iov_len = packet_size - sizeof(*hdr);

	memset(&mh, 0, sizeof(mh));
	mh.msg_name = &peer;
	mh.msg_namelen = sizeof(peer);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	mh.msg_control = cmbuf;
	mh.msg_controllen = sizeof(cmbuf);

	rc = recvmsg(fd, &mh, 0);
	if (rc < 0) {
		return -errno;
	}
	len = rc;

	hdr->dport = naas_hton16(lport);

	hdr->pod_id = naas_hton32(pod_id);
	hdr->saddr = peer.sin_addr.s_addr;
	hdr->sport = peer.sin_port;

	for (cmsg = CMSG_FIRSTHDR(&mh); cmsg != NULL; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IP || cmsg->cmsg_type != IP_PKTINFO) {
			continue;
		}
		pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
		hdr->daddr = pi->ipi_spec_dst.s_addr;
	}

	return len + sizeof(*hdr);
}

static void
log_send(struct ike_tunnel_hdr *hdr, int len, const char *from, const char *to)
{
	char srcbuf[INET_ADDRSTRLEN];
	char dstbuf[INET_ADDRSTRLEN];
	struct in_addr src, dst;

	src.s_addr = hdr->saddr;
	dst.s_addr = hdr->daddr;
	naas_logf(LOG_INFO, 0, "[IKE][%s][%s:%hu>%s:%hu] Send %d bytes to %s",
			from,
			inet_ntop(AF_INET, &src, srcbuf, sizeof(srcbuf)),
			naas_ntoh16(hdr->sport),
			inet_ntop(AF_INET, &dst, dstbuf, sizeof(dstbuf)),
			naas_ntoh16(hdr->dport),
			len, to);
}

int
naas_ike_tunnel_pod_udp_loop(int *fds, int pod_id, const char *nats_server)
{
	int i, rc, fdmax;
	struct ike_tunnel_hdr *hdr;
	char from[32];
	char packet[65536 + sizeof(*hdr)];
	fd_set rfds;
	natsConnection *conn;

	conn = NULL;
	fdmax = 0;
	snprintf(from, sizeof(from), "pod %d", pod_id);

	rc = naas_nats_init(&conn, nats_server);
	if (rc < 0) {
		return rc;
	}

	while (1) {
		FD_ZERO(&rfds);
		for (i = 0; i < NAAS_IKE_PORTS_NUM; ++i) {
			FD_SET(fds[i], &rfds);
			fdmax = NAAS_MAX(fdmax, fds[i]);
		}

		rc = select(fdmax + 1, &rfds, NULL, NULL, NULL);
		for (i = 0; i < NAAS_IKE_PORTS_NUM; ++i) {
			if (!FD_ISSET(fds[i], &rfds)) {
				continue;
			}

			hdr = (struct ike_tunnel_hdr *)packet;

			rc = ike_tunnel_recvmsg(fds[i], naas_ike_ports[i], pod_id,
					hdr, sizeof(packet));
			if (rc > 0) {
				log_send(hdr, rc - sizeof(*hdr), from, "sswan");
				naas_natsConnection_Publish(conn, IKE_INBOX_SSWAN, packet, rc);
			}
		}
	}

	return 0;
}

int
naas_ike_tunnel_pod_nats_loop(int *fds, int pod_id, const char *nats_server)
{
	u_char *data;
	char subj[64];
	char srcbuf[INET_ADDRSTRLEN];
	char dstbuf[INET_ADDRSTRLEN];
	int i, rc, fd, len;
	struct sockaddr_in dst;
	struct ike_tunnel_hdr *hdr;
	natsConnection *conn;
	natsSubscription *sub;
	natsMsg *msg;

	sub = NULL;
	conn = NULL;

	rc = naas_nats_init(&conn, nats_server);
	if (rc < 0) {
		goto out;
	}

	snprintf(subj, sizeof(subj), IKE_INBOX_PODf, pod_id);
	rc = naas_natsConnection_SubscribeSync(&sub, conn, subj);
	if (rc < 0) {
		goto out;
	}

	naas_natsSubscription_SetPendingLimits(sub, -1, -1);

	while (1) {
		rc = naas_natsSubscription_NextMsg(&msg, sub, 10000);
		if (rc < 0) {
			continue;
		}
		len = naas_natsMsg_GetDataLength(msg);
		data = (void *)naas_natsMsg_GetData(msg);

		if (len < sizeof(*hdr)) {
			naas_logf(LOG_ERR, 0, "[IKE][%s] Recv Msg with invalid len (%d)", subj, len);
			goto next;
		}
		hdr = (struct ike_tunnel_hdr *)data;
		len -= sizeof(*hdr);
		data += sizeof(*hdr);

		fd = -1;
		for (i = 0; i < NAAS_IKE_PORTS_NUM; ++i) {
			if (naas_ike_ports[i] == naas_ntoh16(hdr->sport)) {
				fd = fds[i];
				break;
			}
		}
		if (fd == -1) {
			goto next;
		}

		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = hdr->daddr;
		dst.sin_port = hdr->dport;

		naas_logf(LOG_INFO, 0, "[IKE][%s][%s:%hu>%s:%hu] Recv %d bytes from sswan",
				subj,
				inet_ntop(AF_INET, &hdr->saddr, srcbuf, sizeof(srcbuf)),
				naas_ntoh16(hdr->sport),
				inet_ntop(AF_INET, &hdr->daddr, dstbuf, sizeof(dstbuf)),
				naas_ntoh16(hdr->dport),
				len);

		naas_sendto(fd, data, len, 0, (struct sockaddr *)&dst, sizeof(dst));

next:
		naas_natsMsg_Destroy(msg);
	}

	rc = 0;

out:
	naas_natsSubscription_Destroy(sub);
	naas_natsConnection_Destroy(conn);

	return rc;
}

static int
is_ike_port(int port)
{
	int i;

	for (i = 0; i < NAAS_ARRAY_SIZE(naas_ike_ports); ++i) {
		if (naas_ike_ports[i] == port) {
			return 1;
		}
	}
	return 0;
}

int
naas_ike_tunnel_sswan_nats_loop(naas_ike_tunnel_msg_f put_pod_id, void *udata,
		const char *nats_server, const char *netns)
{
	u_char *data;
	char from[64];
	char srcbuf[INET_ADDRSTRLEN];
	char dstbuf[INET_ADDRSTRLEN];
	u_char ip_packet[65536];
	int rc, fd, hl, netns_fd, len;
	struct sockaddr_in dst;
	struct ike_tunnel_hdr *hdr;
	struct naas_ip4_hdr *ih;
	struct naas_udp_hdr *uh;
	natsConnection *conn;
	natsSubscription *sub;
	natsMsg *msg;

	sub = NULL;
	conn = NULL;
	fd = -1;
	netns_fd = -1;

	rc = naas_nats_init(&conn, nats_server);
	if (rc < 0) {
		goto out;
	}

	rc = naas_natsConnection_SubscribeSync(&sub, conn, IKE_INBOX_SSWAN);
	if (rc < 0) {
		goto out;
	}

	naas_natsSubscription_SetPendingLimits(sub, -1, -1);

	netns_fd = enter_netns(netns);

	rc = naas_socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (rc < 0) {
		goto out;
	}
	fd = rc;

	hl = sizeof(*ih) + sizeof(*uh);

	while (1) {
		rc = naas_natsSubscription_NextMsg(&msg, sub, 10000);
		if (rc < 0) {
			continue;
		}
		len = naas_natsMsg_GetDataLength(msg);
		data = (void *)naas_natsMsg_GetData(msg);

		if (len < sizeof(*hdr) || len - sizeof(*hdr) > sizeof(ip_packet) - hl) {
			naas_logf(LOG_ERR, 0, "[IKE] Recv Msg with invalid len (%d)", len);
			goto next;
		}
		hdr = (struct ike_tunnel_hdr *)data;
		len -= sizeof(*hdr);
		data += sizeof(*hdr);

		ih = (struct naas_ip4_hdr *)ip_packet;
		uh = (struct naas_udp_hdr *)(ih + 1);
		memset(ih, 0, hl);
		memcpy(uh + 1, data, len);

		ih->ih_ver_ihl = NAAS_IP4_VER_IHL;
		ih->ih_tos = 0;
		ih->ih_total_len = naas_hton16(hl + len);
		ih->ih_id = 0;
		ih->ih_frag_off = 0;
		ih->ih_ttl = 64;
		ih->ih_proto = IPPROTO_UDP;
		ih->ih_saddr = hdr->saddr;
		ih->ih_daddr = hdr->daddr;

		uh->uh_sport = hdr->sport;
		uh->uh_dport = hdr->dport;
		uh->uh_len = naas_hton16(sizeof(*uh) + len);

		naas_ip4_set_cksum(ih, uh);

		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = ih->ih_daddr;
		dst.sin_port = uh->uh_dport;

		if (put_pod_id != NULL) {
			(*put_pod_id)(udata, hdr);
		}

		snprintf(from, sizeof(from), "pod %d", naas_ntoh32(hdr->pod_id));

		naas_logf(LOG_INFO, 0, "[IKE][sswan][%s:%hu>%s:%hu] Recv %d bytes from %s",
				inet_ntop(AF_INET, &ih->ih_saddr, srcbuf, sizeof(srcbuf)),
				naas_ntoh16(uh->uh_sport),
				inet_ntop(AF_INET, &ih->ih_daddr, dstbuf, sizeof(dstbuf)),
				naas_ntoh16(uh->uh_dport),
				len, from);

		naas_sendto(fd, ip_packet, hl + len, 0,	(struct sockaddr *)&dst, sizeof(dst));

next:
		naas_natsMsg_Destroy(msg);
	}

	rc = 0;

out:
	if (fd >= 0) {
		close(fd);
	}
	leave_netns(netns_fd);
	naas_natsSubscription_Destroy(sub);
	naas_natsConnection_Destroy(conn);

	return rc;
}

int
naas_ike_tunnel_sswan_pcap_loop(naas_ike_tunnel_msg_f get_pod_id, void *udata,
		const char *nats_server, const char *netns)
{
	int rc, len, netns_fd, ih_len, total_len, pod_id;
	char subj[64];
	char to[64];
	be32_t saddr, daddr;
	be16_t sport, dport;
	struct pcap *pcap;
	natsConnection *conn;
	struct naas_ip4_hdr *ih;
	struct naas_udp_hdr *uh;
	struct naas_pcap_data pd;
	struct ike_tunnel_hdr *hdr;

	conn = NULL;
	netns_fd = -1;
	pcap = NULL;

	rc = naas_nats_init(&conn, nats_server);
	if (rc < 0) {
		goto out;
	}

	netns_fd = enter_netns(netns);

	pcap = naas_pcap_open("any", "udp && (port 4500 || port 500)");
	if (pcap == NULL) {
		rc = -EINVAL;
		goto out;
	}

	while (1) {
		rc = naas_pcap_read(pcap, &pd);
		if (rc < 0) {
			continue;
		}

		if (naas_ntoh16(pd.pcap_pkttype) != NAAS_PCAP_HOST) {
			continue;
		}

		len = pd.pcap_datalen;

		if (pd.pcap_protocol != NAAS_ETHTYPE_IP4_BE) {
			continue;
		}

		ih = (struct naas_ip4_hdr *)pd.pcap_data;
		if (len < sizeof(*ih)) {
			continue;
		}
		if (ih->ih_proto != IPPROTO_UDP) {
			continue;
		}

		ih_len = naas_ip4_hdrlen(ih->ih_ver_ihl);
		if (ih_len < sizeof(*ih)) {
			continue;
		}
		if (len < ih_len) {
			continue;
		}
		total_len = naas_ntoh16(ih->ih_total_len);
		if (len < total_len) {
			continue;
		}
		len = total_len;
		len -= ih_len;

		uh = (struct naas_udp_hdr *)(ih + 1);
		if (len < sizeof(*uh)) {
			continue;
		}
		len -= sizeof(*uh);

		saddr = ih->ih_saddr;
		daddr = ih->ih_daddr;
		sport = uh->uh_sport;
		dport = uh->uh_dport;

		if (!is_ike_port(naas_ntoh16(sport))) {
			continue;
		}

		hdr = (struct ike_tunnel_hdr *)((u_char *)(uh + 1) - sizeof(*hdr));
		hdr->saddr = daddr;
		hdr->daddr = saddr;
		hdr->sport = dport;
		hdr->dport = sport;

		pod_id = get_pod_id(udata, hdr);

		naas_swap(hdr->saddr, hdr->daddr);
		naas_swap(hdr->sport, hdr->dport);
		hdr->pod_id = naas_hton32(pod_id);

		snprintf(subj, sizeof(subj), IKE_INBOX_PODf, pod_id);
		if (pod_id >= 0) {
			snprintf(to, sizeof(to), "pod %d", pod_id);
			naas_natsConnection_Publish(conn, subj, hdr, sizeof(*hdr) + len);
		} else {
			naas_strzcpy(to, "/dev/null", sizeof(to));
		}

		log_send(hdr, len, "sswan", to);
	}

	rc = 0;

out:
	naas_pcap_close(pcap);
	leave_netns(netns_fd);
	naas_natsConnection_Destroy(conn);

	return rc;
}
