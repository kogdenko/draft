#define NETMAP_WITH_LIBS
#include <stdio.h>
#include <assert.h>
#include <poll.h>
#include <unistd.h>
#include <net/netmap_user.h>

static void
rx(struct nm_desc *nmd)
{
	int i, j, n;
	struct pollfd pfd;
	struct netmap_ring *rxr;
	pfd.events = POLLIN;
	pfd.fd = NETMAP_FD(nmd);
	printf("rx: first=%d, last=%d\n", nmd->first_rx_ring, nmd->last_rx_ring);
	while (1) {
		poll(&pfd, 1, -1);
		for (i = nmd->first_rx_ring; i <= nmd->last_tx_ring; ++i) {
			rxr = NETMAP_RXRING(nmd->nifp, i);
			n = nm_ring_space(rxr);
			printf("rx: ring=%d, space=%d\n", i, n);
			for (j = 0; j < n; ++j) {
				rxr->cur = rxr->head = nm_ring_next(rxr, rxr->cur);
			}
		}
	}
}

static void
tx(struct nm_desc *nmd)
{
	int i;
	struct pollfd pfd;
	struct netmap_slot *slot;
	struct netmap_ring *txr;
	pfd.fd = NETMAP_FD(nmd);
	pfd.events = POLLOUT;
	printf("tx: first=%d, last=%d\n", nmd->first_tx_ring, nmd->last_tx_ring);
	while (1) {
		for (i = nmd->first_tx_ring; i <= nmd->last_tx_ring; ++i) {
			txr = NETMAP_TXRING(nmd->nifp, i);
			if (nm_ring_empty(txr)) {
				printf("tx: %d empty!\n", i);
				continue;
			}
			slot = txr->slot + txr->cur;
			slot->flags = 0;
			slot->len = 60;
			txr->cur = txr->head = nm_ring_next(txr, txr->cur);
			printf("tx: %d\n", i);
		}
		poll(&pfd, 1, 1000);
		sleep(1);
	}
}

int
main(int argc, char **argv)
{
	// master side
	char ifname[IFNAMSIZ];
	int opt, n, txorrx, flags, ringid, use_old;
	struct nmreq nmr;
	struct nm_desc *nmd;
	ringid = -1;
	txorrx = 0;
	n = 1;
	use_old = 0;
	memset(&nmr, 0, sizeof(nmr));
	while ((opt = getopt(argc, argv, "tI:n:i:0")) != -1) {
		switch (opt) {
		case 't':
			txorrx = 1;
			break;
		case 'I':
			strcpy(nmr.nr_name, optarg);
			break;
		case 'n':
			n = strtoul(optarg, NULL, 10);
			break;
		case 'i':
			ringid = strtoul(optarg, NULL, 10);
			break;

		case '0':
			use_old = 1;
		}
	}
	nmr.nr_rx_rings = n;
	nmr.nr_tx_rings = n;
	nmr.nr_ringid = ringid;
	nmr.nr_rx_slots = 512;
	nmr.nr_tx_slots = 512;
	flags = NM_OPEN_RING_CFG;
	if (!use_old) {
		flags |= NM_OPEN_IFNAME;
	}
	if (ringid != -1) {
		nmr.nr_flags |= NR_REG_ONE_NIC;
	} else {
		nmr.nr_flags |= NR_REG_ALL_NIC;
	}
	snprintf(ifname, sizeof(ifname), "netmap:%s", nmr.nr_name);
	nmd = nm_open(ifname, &nmr, flags, NULL);
	if (nmd == NULL) {
		printf("nm_open('%s') failed\n", ifname);
		return 1;
	}
	printf("nm_open('%s'), nr_rx_rings=%d, nr_tx_rings=%d\n",
		nmr.nr_name,
		nmd->req.nr_rx_rings,
		nmd->req.nr_tx_rings);
	if (txorrx) {
		tx(nmd);
	} else {
		rx(nmd);
	}
	return 0;
}
