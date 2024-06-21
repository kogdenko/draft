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
		poll(&pfd, 1, 5000);
		for (i = nmd->first_rx_ring; i <= nmd->last_tx_ring; ++i) {
			rxr = NETMAP_RXRING(nmd->nifp, i);
			n = nm_ring_space(rxr);
			printf("rx: ring=%d, space=%d\n", i, n);
			n = 1;
			for (j = 0; j < n; ++j) {
				rxr->cur = rxr->head = nm_ring_next(rxr, rxr->cur);
			}
		}
	}
}

int
main(int argc, char **argv)
{
	char ifname[IFNAMSIZ];
	int opt, flags;
	struct nmreq nmr;
	struct nm_desc *nmd;
	memset(&nmr, 0, sizeof(nmr));
	while ((opt = getopt(argc, argv, "i:")) != -1) {
		switch (opt) {
		case 'i':
			strcpy(nmr.nr_name, optarg);
			break;
		}
	}
	flags = NM_OPEN_IFNAME;
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
	rx(nmd);
	return 0;
}
