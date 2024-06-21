// License: GPLv2
#define _GNU_SOURCE
#define NETMAP_WITH_LIBS
#include <stdarg.h>
#include <strings.h>
#include <getopt.h>
#include <assert.h>
#include <inttypes.h>
#include <poll.h>
#include <time.h>
#include <limits.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <immintrin.h>
#include <net/netmap_user.h>
#ifdef __linux__
#else
#include <pthread_np.h>
#include <sys/param.h>
#include <sys/cpuset.h>
#endif

typedef uint64_t be64_t;
typedef uint32_t be32_t;
typedef uint16_t be16_t;

struct list {
	struct list *next;
	struct list *prev;
};

#define TIMER_RING_SHIFT 12
#define TIMER_RING_SIZE (1 << TIMER_RING_SHIFT)
#define TIMER_RING_MASK (TIMER_RING_SIZE - 1)

struct timer_ring {
	int shift;
	int size;
	int cur;
	int nr_timers;
	struct list buffer[TIMER_RING_SIZE];
};

struct timer;

typedef void (*timer_f)(struct timer *);

struct timer {
	struct list list;
	timer_f fn;
};

#define ETH_ADDR_LEN 6
#define ETH_TYPE_IP4 0x0800
#define ETH_TYPE_IP4_BE CPU_TO_BE16(ETH_TYPE_IP4)
#define ETH_TYPE_IP6 0x86DD
#define ETH_TYPE_IP6_BE CPU_TO_BE16(ETH_TYPE_IP6)
#define ETH_TYPE_ARP  0x0806
#define ETH_TYPE_ARP_BE  CPU_TO_BE16(ETH_TYPE_ARP)

struct eth_addr {
	uint8_t bytes[ETH_ADDR_LEN];
} __attribute__((packed));

struct eth_hdr {
	struct eth_addr daddr;
	struct eth_addr saddr;
	be16_t type;
} __attribute__((packed));

struct arp_ip4 {
	struct eth_addr sha;
	be32_t sip;
	struct eth_addr tha;
	be32_t tip;
} __attribute__((packed));

struct arp_hdr {
	be16_t hrd;
	be16_t pro;
	uint8_t hlen;
	uint8_t plen;
	be16_t op;
	struct arp_ip4 data;
} __attribute__((packed));

#define ARP_HRD_ETH 1
#define ARP_HRD_ETH_BE CPU_TO_BE16(ARP_HRD_ETH)

#define ARP_OP_REQUEST 1
#define ARP_OP_REQUEST_BE CPU_TO_BE16(ARP_OP_REQUEST)
#define ARP_OP_REPLY 2
#define ARP_OP_REPLY_BE CPU_TO_BE16(ARP_OP_REPLY)

struct ip4_hdr {
	uint8_t ver_ihl;
	uint8_t type_of_svc;
	be16_t total_len;
	be16_t id;
	be16_t frag_off;
	uint8_t ttl;
	uint8_t proto;
	uint16_t cksum;
	be32_t saddr;
	be32_t daddr;
} __attribute__((packed));

struct ip4_pseudo_hdr {
	be32_t saddr;
	be32_t daddr;
	uint8_t pad;
	uint8_t proto;
	be16_t len;
} __attribute__((packed));

#define IP4_VER_IHL (0x40|0x05)
#define IP4_FRAG_MASK 0xFF3F

#define IP4_FLAG_DF (1 << 6)
#define IP4_FLAG_MF (1 << 5)

struct tcp_hdr {
	be16_t sport;
	be16_t dport;
	be32_t seq;
	be32_t ack;
	uint8_t data_off;
	uint8_t flags;
	be16_t win_size;
	uint16_t cksum;
	be16_t urgent_ptr;
} __attribute__((packed));
 
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

struct tcp_opt_ts {
	uint32_t val;
	uint32_t ecr;
};

struct tcp_opt_field {
	uint8_t kind;
	uint8_t len;
};

struct tcp_opt {
	long flags;
	uint16_t mss;
	uint8_t wscale;
	uint8_t sack_permited;
	struct tcp_opt_ts ts;
};

#define TCP_OPT_EOL 0
#define TCP_OPT_NOP 1
#define TCP_OPT_MSS 2
#define TCP_OPT_WSCALE 3
#define TCP_OPT_SACK_PERMITED 4
#define TCP_OPT_TIMESTAMPS 8
#define TCP_OPT_MAX 9

struct spinlock {
	volatile int locked;
};

struct pktbuf {
	uint16_t len;
	uint16_t off;
	struct netmap_ring *txr;
	struct netmap_slot *src;
	void *data;
};

struct sock_key {
	be32_t laddr;
	be32_t raddr;
	be16_t lport;
	be16_t rport;
};

struct bind_entry {
	struct list list;
	be32_t laddr;
	be16_t lport;
};

#define DIR_RECV 0
#define DIR_SEND 1

#define D_MODE_CLIENT 0
#define D_MODE_SERVER 1

struct packet_node {
	struct list list;
	struct list children;
	struct spinlock lock;
	struct eth_addr r_hwaddr;
	uint32_t seq;
	uint32_t ack;
	uint16_t win_size;
	uint16_t data_len;
	uint8_t tcp_flags;
	uint8_t dir;
	struct tcp_opt tcp_opt;
	uint8_t *data;
};

// Sample socket
struct s_sock {
	int inited;
	struct sock_key key;
	uint32_t isn[2];
	int fin[2];
	uint32_t fin_seq[2];
	struct packet_node *current;
	struct packet_node *first;
	struct packet_node *parent;
};

struct s_sock_bucket {
	struct spinlock lock;
	struct s_sock entry;
};

// Duplicate socket
struct d_sock {
	struct list list;
	struct list tx_list;
	struct sock_key key;
	uint32_t isn[2];
	uint8_t ack_isn_inited;
	uint8_t in_txq;
	uint16_t ip_id;
	struct timer timer;
	struct packet_node *current; // Last received/sent packet
	struct bind_entry *bind;
};

struct dev {
	struct nm_desc *nmd;
	int qid;
	int cur_tx_ring;
	int tx_full;
	int tx_epoch;
	uint64_t cnt_rx;
	uint64_t cnt_rx_RST;
	uint64_t cnt_tx;
	uint64_t cnt_tx_RST;
	uint64_t cnt_tx_drop;
	struct list txq;
	struct list d_sock_pool;
	struct list *d_sock_hash;
	struct list ephemeral_ports;
	char ifname[IFNAMSIZ];
};

#ifdef __linux__
typedef cpu_set_t cpuset_t;
#endif

static int done;
static int print_packet_tree;
static uint64_t epoch;
static struct dev devs[2];
static struct s_sock_bucket *s_sock_hash;
static int s_sock_hash_size;
static int s_sock_hash_mask;
static int d_sock_hash_size;
static int d_sock_hash_mask;
static be32_t s_sock_laddr;
static be32_t s_sock_raddr;
static be16_t s_sock_rport;
static be32_t d_sock_laddr;
static uint64_t d_requests;
static uint64_t d_requests_max;
static struct eth_addr s_hwaddr;
static int d_mode;
static struct packet_node root;
static uint32_t hash_random;
static struct timespec start_ts;
static struct timespec now_ts;
static struct timer_ring timer_ring;
static uint32_t msec;
static uint32_t msec_prev;
static uint64_t d_requests_prev;
static uint64_t rx_prev;
static uint64_t tx_prev;
static uint64_t rx_RST_prev;
static uint64_t tx_RST_prev;

static struct tcp_opt_field tcp_opt_fields[TCP_OPT_MAX] = {
	[TCP_OPT_MSS] = {
		.kind = TCP_OPT_MSS,
		.len = 4,
	},
	[TCP_OPT_WSCALE] = {
		.kind = TCP_OPT_WSCALE,
		.len = 3,
	},
	[TCP_OPT_SACK_PERMITED] = {
		.kind = TCP_OPT_SACK_PERMITED,
		.len = 2,
	},
	[TCP_OPT_TIMESTAMPS] = {
		.kind = TCP_OPT_TIMESTAMPS,
		.len = 10,
	},
};

#define BURST_SIZE 32

#define UNUSED(x) ((void)(&x))

#define BSWAP16(x) \
	(((((uint16_t)(x)) & ((uint16_t)0x00FF)) << 8) | \
	 ((((uint16_t)(x)) & ((uint16_t)0xFF00)) >> 8))
 
#define BSWAP32(x) \
	(((((uint32_t)(x)) & ((uint32_t)0x000000FF)) << 24) | \
	 ((((uint32_t)(x)) & ((uint32_t)0x0000FF00)) <<  8) | \
	 ((((uint32_t)(x)) & ((uint32_t)0x00FF0000)) >>  8) | \
	 ((((uint32_t)(x)) & ((uint32_t)0xFF000000)) >> 24))

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define CPU_TO_BE16(x) ((uint16_t)(x))
#define CPU_TO_BE32(x) ((uint32_t)(x))
#define BE16_TO_CPU(x) ((uint16_t)(x))
#define BE32_TO_CPU(x) ((uint32_t)(x))
#else  // __BIG_ENDIAN
#define CPU_TO_BE16(x) ((uint16_t)BSWAP16(x))
#define CPU_TO_BE32(x) ((uint32_t)BSWAP32(x))
#define BE16_TO_CPU(x) ((uint16_t)BSWAP16(x))
#define BE32_TO_CPU(x) ((uint32_t)BSWAP32(x))
#endif // __BIG_ENDIAN

#define UVAR_CAT3(x, res) res
#define UVAR_CAT2(x, y) UVAR_CAT3(~, x##y)
#define UVAR_CAT(x, y) UVAR_CAT2(x, y)
#define UVAR(n) UVAR_CAT(n, __LINE__)

#define DEV_IS_HOST(dev) ((dev)->qid < 0)

#define DEV_FOREACH_RXRING(rxr, dev) \
	for (int UVAR(i) = (dev)->nmd->first_rx_ring; \
		UVAR(i) <= (dev)->nmd->last_rx_ring && \
		((rxr = NETMAP_RXRING((dev)->nmd->nifp, UVAR(i))), 1); \
		++UVAR(i))

#define DEV_FOREACH_TXRING(txr, dev) \
	for (int UVAR(i) = (dev)->nmd->first_tx_ring; \
		UVAR(i) <= (dev)->nmd->last_tx_ring && \
		((txr = NETMAP_TXRING((dev)->nmd->nifp, UVAR(i))), 1); \
		++UVAR(i))

#define DEV_FOREACH_TXRING_CONTINUE(i, txr, dev) \
	for (; i <= (dev)->nmd->last_tx_ring && \
		((txr = NETMAP_TXRING((dev)->nmd->nifp, i)), 1); \
		++i)

#define MEM_PREFETCH(ptr) \
	__builtin_prefetch(ptr)

#define DEV_PREFETCH(ring) \
	MEM_PREFETCH(NETMAP_BUF((ring), \
		((ring)->slot + nm_ring_next(ring, (ring)->cur))->buf_idx))

#define DEV_TX_PREFETCH(txr) DEV_PREFETCH(txr)
#define DEV_RX_PREFETCH(rxr) DEV_PREFETCH(rxr)

#define PACKET_OK 0
#define PACKET_INVALID 1
#define PACKET_RST 2

#define dbg printf("D %u\n", __LINE__)
#define P(...) do { \
	printf("%-20s:%-5d: ", __func__, __LINE__); \
	printf(__VA_ARGS__); \
	printf("\n");\
} while (0)

#define D_RL(f, ...) do { \
	static uint32_t UVAR(last); \
	static int UVAR(n); \
	UVAR(n)++; \
	if (msec - UVAR(last) >= 1000) { \
		UVAR(last) = msec; \
		printf("%-20s %-4d ", __func__, __LINE__); \
		printf(f, ##__VA_ARGS__); \
		printf(" (%d times)\n", UVAR(n)); \
		UVAR(last) = msec; \
		UVAR(n) = 0; \
	} \
} while (0)

static void die(int errnum, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

static int eth_in(struct dev *dev, struct netmap_ring *rxr,
                  struct netmap_slot *src);

#ifndef container_of
#define field_off(type, field) ((intptr_t)&((type *)0)->field)
#define container_of(ptr, type, field) \
	(type *)((intptr_t)(ptr) - field_off(type, field))
#endif

#define list_foreach(var, head) \
	for (var = (head)->next; var != (head); var = var->next)

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
ip4_cksum_raw64(const uint8_t *b, size_t size)
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
ip4_cksum_reduce64(uint64_t sum)
{
	uint64_t mask;

	mask = 0xffffffff00000000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 32) & ~mask);
	}
	mask = 0xffffffffffff0000lu;
	while (sum & mask) {
		sum = cksum_add(sum & ~mask, (sum >> 16) & ~mask);
	}
	return ~((uint16_t)sum);
}

static size_t
ip4_hdr_len(uint8_t ver_ihl)
{
	return (ver_ihl & 0x0f) << 2;
}

uint16_t
ip4_cksum(struct ip4_hdr *ip4_h)
{
	int ip4_h_len;
	uint64_t sum;

	ip4_h_len = ip4_hdr_len(ip4_h->ver_ihl);
	sum = ip4_cksum_raw64((void *)ip4_h, ip4_h_len);
	return ip4_cksum_reduce64(sum);
}

static uint64_t
ip4_pseudo_cksum(struct ip4_hdr *ip4_h, uint16_t len)
{
	struct ip4_pseudo_hdr ip4_pseudo_h;

	memset(&ip4_pseudo_h, 0, sizeof(ip4_pseudo_h));
	ip4_pseudo_h.saddr = ip4_h->saddr;
	ip4_pseudo_h.daddr = ip4_h->daddr;
	ip4_pseudo_h.pad = 0;
	ip4_pseudo_h.proto = ip4_h->proto;
	ip4_pseudo_h.len = CPU_TO_BE16(len);
	return ip4_cksum_raw64((void *)&ip4_pseudo_h, sizeof(ip4_pseudo_h));
}

uint16_t
ip4_udp_cksum(struct ip4_hdr *ip4_h)
{
	int ip4_h_len;
	uint16_t total_len, len;
	uint64_t sum;
	void *udp_h;

	total_len = BE16_TO_CPU(ip4_h->total_len);
	ip4_h_len = ip4_hdr_len(ip4_h->ver_ihl);
	len = total_len - ip4_h_len;
	udp_h = ((uint8_t *)ip4_h) + ip4_h_len;
	sum = ip4_cksum_raw64(udp_h, len);
	sum = cksum_add(sum, ip4_pseudo_cksum(ip4_h, len));
	return ip4_cksum_reduce64(sum);
}

#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }

static uint32_t
murmur(const void * key, int len, uint32_t init_val)
{
	int r;
	unsigned int k, l, m, h, t;
	uint8_t *data;

	r = 24;
	m = 0x5bd1e995;
	l = len;
	h = init_val;
	t = 0;
	data = (uint8_t *)key;
	while (len >= 4) {
		k = *(u_int *)data;
		mmix(h, k);
		data += 4;
		len -= 4;
	}
	switch(len) {
	case 3: t ^= data[2] << 16;
	case 2: t ^= data[1] << 8;
	case 1: t ^= data[0];
	};
	mmix(h, t);
	mmix(h, l);
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;
	return h;
}

static uint32_t
upper_pow_of_2_32(uint32_t x)
{
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	x++;
	return x;
}

static int
test_bit(long l, size_t i)
{
	assert(i < CHAR_BIT * sizeof(l));
	return l & (1l << i);
}

static int
set_bit(long *l, size_t i)
{
	if (test_bit(*l, i)) {
		return 1;
	} else {
		(*l) |= (1l << i);
		return 0;
	}
}

static int
unset_bit(long *l, size_t i)
{
	if (test_bit(*l, i)) {
		(*l) &= ~(1l << i);
		return 1;
	} else {
		return 0;
	}
}

static void
die(int errnum, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (errnum) {
		fprintf(stderr, " (%d:%s)\n", errnum, strerror(errnum));
	} else {
		fprintf(stderr, "\n");
	}
	abort();
}

char *
strzcpy(char *dst, const char *src, size_t n)
{
	int i;

	for (i = 0; i < n - 1; ++i) {
		dst[i] = src[i];
		if (dst[i] == '\0') {
			break;
		}
	}
	dst[i] = '\0';
	return dst;
}

void *
xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		die(0, "malloc(%zu) failed", size);
	}
	return ptr;
}

static uint32_t
hash_sock_key(struct sock_key *key)
{
	uint32_t hash;

	hash = murmur(key, sizeof(*key), hash_random);
	return hash;
}

static void
list_init(struct  list *head)
{
	head->next = head->prev = head;
}

int
list_size(struct list *head)
{
	int size;
	struct list *cur;

	size = 0;
	list_foreach(cur, head) {
		size++;
	}
	return size;
}

static int
list_empty(struct list *head)
{
	return head->next == head;
}

struct list *
list_first(struct list *head)
{
	return head->next;
}

struct list *
list_last(struct list *head)
{
	return head->prev;
}

static void
list_insert_head(struct list *head, struct list *l)
{
	l->next = head->next;
	l->prev = head;
	head->next->prev = l;
	head->next = l;
}

static void
list_insert_tail(struct list *head, struct list *l)
{
	l->next = head;
	l->prev = head->prev;
	head->prev->next = l;
	head->prev = l;
}

static void
list_remove(struct list *list)
{
	list->next->prev = list->prev;
	list->prev->next = list->next;
}

#define LIST_HEAD(head, var, field) \
	((head) == &((var)->field))

#define LIST_FIRST(head, type, field) \
	container_of((head)->next, type, field)

#define LIST_LAST(head, type, field) \
	container_of((head)->prev, type, field)

#define LIST_NEXT(var, field) \
	container_of((var)->field.next, __typeof__(*(var)), field)

#define LIST_INSERT_HEAD(head, var, field) \
	list_insert_head(head, &((var)->field))

#define LIST_INSERT_TAIL(head, var, field) \
	list_insert_tail(head, &((var)->field))

#define LIST_REMOVE(var, field) \
	list_remove(&(var)->field)

#define LIST_FOREACH(var, head, field) \
	for (var = LIST_FIRST(head, __typeof__(*(var)), field); \
		&((var)->field) != (head); \
		var = LIST_NEXT(var, field))

#define LIST_FOREACH_CONTINUE(pos, head, field) \
	for (; &((pos)->field) != (head); \
		pos = LIST_NEXT(pos, field))

#define LIST_FOREACH_SAFE(var, head, field, tvar) \
	for (var = LIST_FIRST(head, __typeof__(*(var)), field); \
		(&((var)->field) != (head)) && \
		((tvar = LIST_NEXT(var, field)), 1); \
		var = tvar)

void
spinlock_init(struct spinlock *sl)
{
	sl->locked = 0;
}

static void
spinlock_lock(struct spinlock *sl)
{
	while (__sync_lock_test_and_set(&sl->locked, 1)) {
		while (sl->locked) {
			_mm_pause();
		}
	}
}

static void
spinlock_unlock(struct spinlock *sl)
{
	__sync_lock_release(&sl->locked);
}

static void
init_timers()
{
	int i;

	timer_ring.shift = 5;
	timer_ring.size = 1 << timer_ring.shift;
	timer_ring.cur = msec >> timer_ring.shift;
	timer_ring.nr_timers = 0;
	for (i = 0; i < TIMER_RING_SIZE; ++i) {
		list_init(timer_ring.buffer + i);
	}
}

static int
timer_is_running(struct timer *timer)
{
	return timer->fn != 0;
}

static void
timer_del(struct timer *timer)
{
	if (timer_is_running(timer)) {		
		timer_ring.nr_timers--;
		assert(timer_ring.nr_timers >= 0);
		LIST_REMOVE(timer, list);
		timer->fn = NULL;
	}
}

void
timer_init(struct timer *timer)
{
	timer->fn = NULL;
}

static void
timer_set(struct timer *timer, uint32_t expire_ms, timer_f fn)
{
	uint64_t shift, pos;
	struct list *head;

	timer_del(timer);
	shift = expire_ms >> timer_ring.shift;
	if (shift >= TIMER_RING_SIZE) {
		shift = TIMER_RING_SIZE - 1;
	}
	pos = timer_ring.cur + shift;
	head = timer_ring.buffer + (pos & TIMER_RING_MASK);
	timer_ring.nr_timers++;
	timer->fn = fn;
	LIST_INSERT_HEAD(head, timer, list);
}

static void
call_timers(struct list *queue)
{
	struct timer *timer;
	timer_f fn;

	while (!list_empty(queue)) {
		timer = LIST_FIRST(queue, struct timer, list);
		LIST_REMOVE(timer, list);
		fn = timer->fn;
		timer->fn = NULL;
		(*fn)(timer);
	}
}

static void
check_timers()
{
	int i;
	uint64_t pos;
	struct timer *timer;
	struct list *head;
	struct list queue;

	list_init(&queue);
	pos = timer_ring.cur;
	timer_ring.cur = (msec >> timer_ring.shift);
	for (i = 0; pos <= timer_ring.cur && i < TIMER_RING_SIZE; ++pos, ++i) {
		head = timer_ring.buffer + (pos & TIMER_RING_MASK);
		while (!list_empty(head)) {
			timer_ring.nr_timers--;
			assert(timer_ring.nr_timers >= 0);
			timer = LIST_FIRST(head, struct timer, list);
			LIST_REMOVE(timer, list);
			LIST_INSERT_HEAD(&queue, timer, list);
		}
		if (timer_ring.nr_timers == 0) {
			break;
		}
	}
	call_timers(&queue);
}

static struct bind_entry *
alloc_ephemeral_port(struct dev *dev)
{
	struct bind_entry *x;

	if (list_empty(&dev->ephemeral_ports)) {
		return NULL;
	}
	x = LIST_FIRST(&dev->ephemeral_ports, struct bind_entry, list);
	LIST_REMOVE(x, list);
	return x;
}

static void
free_ephemeral_port(struct dev *dev, struct bind_entry *x)
{
	LIST_INSERT_TAIL(&dev->ephemeral_ports, x, list);
}

void
rx_ring_next(struct dev *dev, struct netmap_ring *rxr)
{
	rxr->head = rxr->cur = nm_ring_next(rxr, rxr->cur);
	dev->cnt_rx++;
}

static struct netmap_ring *
not_empty_txr(struct dev *dev)
{
	struct netmap_ring *txr;

	if (dev->tx_full) {
		return NULL;
	}
	if (dev->tx_epoch != epoch) {
		dev->tx_epoch = epoch;
		dev->cur_tx_ring = dev->nmd->first_tx_ring;
	}
	DEV_FOREACH_TXRING_CONTINUE(dev->cur_tx_ring, txr, dev) {
		if (!nm_ring_empty(txr)) {
			return txr;
		}
	}
	dev->tx_full = 1;
	return NULL;
}

static void
pktbuf_init(struct pktbuf *buf, struct netmap_ring *txr)
{
	buf->txr = txr;	
	buf->src = txr->slot + txr->cur;
	buf->data = NETMAP_BUF(txr, buf->src->buf_idx);
}

static void
transmit(struct dev *dev, struct pktbuf *pkt)
{
	struct netmap_slot *dst;
	struct netmap_ring *txr;

	txr = pkt->txr;
	assert(txr != NULL);
	assert(pkt->len != -1);
	dst = txr->slot + txr->cur;
	dst->len = pkt->len;
	txr->head = txr->cur = nm_ring_next(txr, txr->cur);
	dev->cnt_tx++;
}

static void
zerocopy(struct dev *dev, struct netmap_slot *src)
{
	int tmp;
	struct netmap_ring *txr;
	struct netmap_slot *dst;

	txr = not_empty_txr(dev);
	if (txr == NULL) {
		dev->cnt_tx_drop++;
	} else {
		dst = txr->slot + txr->cur;
		dst->len = src->len;
		tmp = dst->buf_idx;
		dst->buf_idx = src->buf_idx;
		dst->flags = NS_BUF_CHANGED;
		src->buf_idx = tmp;
		src->flags = NS_BUF_CHANGED;
		txr->head = txr->cur = nm_ring_next(txr, txr->cur);
		dev->cnt_tx++;
	}
}

static void
bypass(struct dev *idev, struct netmap_slot *src)
{
	int x;
	struct dev *odev;

	x = idev - devs;
	odev = devs + (1 - x);
	zerocopy(odev, src);
}

static void
init_dev(struct dev *dev, const char *ifname,
         int concurrency, int qid)
{
	int i;
	struct d_sock *buf;
	struct list *bucket;

	memset(dev, 0, sizeof(*dev));
	if (qid < 0) {
		snprintf(dev->ifname, sizeof(dev->ifname), "%s^", ifname);
	} else {
		strzcpy(dev->ifname, ifname, sizeof(dev->ifname));
	}
	dev->nmd = nm_open(dev->ifname, NULL, 0, NULL);
	dev->qid = qid;
	if (dev->nmd == NULL) {
		die(errno, "nm_open('%s') failed", dev->ifname);
	}
	dev->cur_tx_ring = dev->nmd->first_tx_ring;
	if (qid < 0) {
		return;
	}
	dev->d_sock_hash = xmalloc(d_sock_hash_size * sizeof(*bucket));
	for (i = 0; i < d_sock_hash_size; ++i) {
		bucket = dev->d_sock_hash + i;
		list_init(bucket);
	}
	list_init(&dev->d_sock_pool);
	list_init(&dev->txq);
	buf = xmalloc(sizeof(struct d_sock) * concurrency);
	for (i = 0; i < concurrency; ++i) {
		LIST_INSERT_HEAD(&dev->d_sock_pool, buf + i, list);
	}
	list_init(&dev->ephemeral_ports);
}

static struct packet_node *
new_node(struct packet_node *x)
{
	struct packet_node *cp;

	cp = xmalloc(sizeof(*cp) + x->data_len);
	memcpy(cp, x, sizeof(*cp));
	cp->data = ((uint8_t *)cp) + sizeof(*cp);
	memcpy(cp->data, x->data, x->data_len);
	list_init(&cp->children);
	spinlock_init(&cp->lock);
	return cp;
}

static struct packet_node *
first_child(struct packet_node *node)
{
	struct packet_node *child;

	assert(!list_empty(&node->children));
	child = LIST_FIRST(&node->children, struct packet_node, list);
	return child;
}

static void
del_node(struct packet_node *x)
{
	struct packet_node *child;

	if (x == NULL) {
		return;
	}
	while (!list_empty(&x->children)) {
		child = first_child(x);
		LIST_REMOVE(child, list);
		del_node(child);
	}
	free(x);
}

#define PRINT_TCP_FLAG(flags, flag, s) \
	if (flags & flag) { \
		printf("%c", s); \
	}

static void
print_node(struct packet_node *x, int depth)
{
	int i;

	if (x == NULL) {
		return;
	}
	for (i = 0; i < depth; ++i) {
		printf("  ");
	}
	printf("%c ", x->dir == DIR_RECV ? '!' : '>');
	printf("[");
	PRINT_TCP_FLAG(x->tcp_flags, TCP_FLAG_SYN, 'S');
	PRINT_TCP_FLAG(x->tcp_flags, TCP_FLAG_ACK, '.');
	PRINT_TCP_FLAG(x->tcp_flags, TCP_FLAG_PSH, 'P');
	PRINT_TCP_FLAG(x->tcp_flags, TCP_FLAG_URG, 'U');
	PRINT_TCP_FLAG(x->tcp_flags, TCP_FLAG_FIN, 'F');
	PRINT_TCP_FLAG(x->tcp_flags, TCP_FLAG_RST, 'R');
	printf("], seq %u", x->seq);
	if (x->tcp_flags & TCP_FLAG_ACK) {
		printf(", ack %u", x->ack);
	}
	printf(", win_size %u", x->win_size);
	if (x->data_len) {
		printf(", len %u", x->data_len);
	}
	printf("\n");
}

static void
print_branch(struct packet_node *x, int depth)
{
	struct packet_node *child;

	print_node(x, depth);
	if (x != NULL) {
		LIST_FOREACH(child, &x->children, list) {
			print_branch(child, depth + 1);
		}
	}
}

static int
node_is_equal(struct packet_node *x, struct packet_node *y, int check_sn)
{
	if (x->dir != y->dir) {
		return 0;
	}
	if (x->tcp_flags != y->tcp_flags) {
		return 0;
	}
	if (check_sn) {
		if (x->seq != y->seq) {
			return 0;
		}
		if (x->tcp_flags & TCP_FLAG_ACK) {
			if (x->ack != y->ack) {
				return 0;
			}
		}
	}
	if ((x->win_size == 0 ? 0 : 1) != (y->win_size == 0 ? 0 : 1)) {
		return 0;
	}
	if (x->data_len != y->data_len) {
		return 0;
	}
	return 1;
}

static int
process_duplicate(struct packet_node *pkt, struct d_sock *dso,
                  struct packet_node *node)
{
	int rc, ack_isn_inited;

	assert(pkt->dir == DIR_RECV);
	if (node->dir != DIR_RECV) {
		return 0;
	}
	if (pkt->ack != dso->isn[DIR_SEND] + node->ack) {
		//P("ack %u %u %u", pkt->ack, dso->isn[DIR_SEND], node->ack);
		return 0;
	}
	if (pkt->tcp_flags & TCP_FLAG_ACK) {
		ack_isn_inited = 1;
		if (dso->ack_isn_inited) {
			if (pkt->seq != dso->isn[DIR_RECV] + node->seq) {
				//P("seq %u %u %u", pkt->seq, dso->isn[DIR_RECV], node->seq);
				return 0;
			}
		}
	} else {
		ack_isn_inited = 0;
	}
	rc = node_is_equal(pkt, node, 0);
	if (rc) {
		if (dso->ack_isn_inited == 0 && ack_isn_inited) {
			dso->ack_isn_inited = 1;
			dso->isn[DIR_RECV] = pkt->seq;
		}
	}
	return rc;
}

static void
merge_script(struct packet_node *parent, struct packet_node *chain)
{
	int rc;
	struct packet_node *child, *next;

	spinlock_lock(&parent->lock);
	LIST_FOREACH(child, &parent->children, list) {
		rc = node_is_equal(child, chain, 1);
		if (rc) {
			spinlock_unlock(&parent->lock);
			if (!list_empty(&chain->children)) {
				next = first_child(chain);
				LIST_REMOVE(next, list);
				assert(list_empty(&chain->children));
				free(chain);
				merge_script(child, next);
			}
			return;
		} else {
			break;
		}
	}
	LIST_INSERT_HEAD(&parent->children, chain, list);
	spinlock_unlock(&parent->lock);
}

static void
s_sodel(struct s_sock *sso)
{
	if (sso != NULL) {
		del_node(sso->first);
		memset(sso, 0, sizeof(*sso));
	}
}

static struct d_sock *
d_soget(struct dev *dev, struct sock_key *key, uint32_t hash)
{
	struct d_sock *dso;
	struct list *bucket;

	bucket = dev->d_sock_hash + (hash & d_sock_hash_mask);
	LIST_FOREACH(dso, bucket, list) {
		if (!memcmp(&dso->key, key, sizeof(*key))) {
			return dso; 
		}
	}
	return NULL;
}

static void
d_sotx(struct dev *dev, struct d_sock *dso)
{
	assert(dso->in_txq == 0);
	dso->in_txq = 1;
	LIST_INSERT_TAIL(&dev->txq, dso, tx_list);
}

static struct d_sock *
d_sonew(struct dev *dev, struct sock_key *key, uint32_t hash, struct packet_node *cur)
{
	struct d_sock *dso;
	struct list *bucket;

	if (list_empty(&dev->d_sock_pool)) {
		return NULL;
	}
	dso = LIST_FIRST(&dev->d_sock_pool, struct d_sock, list);
	LIST_REMOVE(dso, list);
	dso->key = *key;
	dso->current = cur;
	bucket = dev->d_sock_hash + (hash & d_sock_hash_mask);
	LIST_INSERT_HEAD(bucket, dso, list);
	dso->ack_isn_inited = 0;
	dso->isn[DIR_RECV] = 0;
	dso->isn[DIR_SEND] = 100;
	dso->ip_id = 1;
	dso->in_txq = 0;
	dso->bind = NULL;
	timer_init(&dso->timer);
	return dso;
}

static struct d_sock *
d_sonew_client(struct dev *dev)
{
	uint32_t hash;
	struct bind_entry *bind;
	struct d_sock *dso;
	struct packet_node *syn;
	struct sock_key key;

	assert(!list_empty(&root.children));
	syn = first_child(&root);
	assert(syn->dir == DIR_SEND);
	assert(syn->tcp_flags == TCP_FLAG_SYN);
	bind = alloc_ephemeral_port(dev);
	if (bind == NULL) {
		return NULL;
	}
	key.laddr = bind->laddr;
	key.lport = bind->lport;
	key.raddr = s_sock_raddr;
	key.rport = s_sock_rport;
	hash = hash_sock_key(&key);
	dso = d_sonew(dev, &key, hash, syn);
	if (dso == NULL) {
		free_ephemeral_port(dev, bind);
	} else {
		dso->bind = bind;
		d_sotx(dev, dso);
	}
	return dso;
}

static void
d_sodel(struct dev *dev, struct d_sock *dso)
{
	if (dso->in_txq) {
		LIST_REMOVE(dso, tx_list);
	}
	LIST_REMOVE(dso, list);
	if (dso->bind) {
		free_ephemeral_port(dev, dso->bind);
	}
	timer_del(&dso->timer);
	LIST_INSERT_HEAD(&dev->d_sock_pool, dso, list);
	d_requests++;
	if (d_mode == D_MODE_CLIENT) {
		d_sonew_client(dev);
	}
}

static uint8_t *
fill_be16(uint8_t *ptr, be16_t x)
{
	*((be16_t *)ptr) = x;
	return ptr + sizeof(x);
}

static uint8_t *
fill_be32(uint8_t *ptr, be32_t x)
{
	*((be32_t *)ptr) = x;
	return ptr + sizeof(x);
}

static int
fill_tcp_opt_field(uint8_t *buf, struct tcp_opt *tcp_opt, int kind)
{
	uint8_t *ptr;
	const struct tcp_opt_field *field;

	field = tcp_opt_fields + kind;
	if (field->kind == 0) {
		return 0;
	}
	ptr = buf;
	*ptr++ = field->kind;
	*ptr++ = field->len;
	switch (kind) {
	case TCP_OPT_MSS:
		ptr = fill_be16(ptr, CPU_TO_BE16(tcp_opt->mss));
		break;
	case TCP_OPT_WSCALE:
		*ptr++ = tcp_opt->wscale;
		break;
	case TCP_OPT_SACK_PERMITED:
		break;
	case TCP_OPT_TIMESTAMPS:
		ptr = fill_be32(ptr, CPU_TO_BE32(tcp_opt->ts.val));
		ptr = fill_be32(ptr, CPU_TO_BE32(tcp_opt->ts.ecr));
		break;
	}
	assert(ptr - buf == field->len);
	while ((ptr - buf) & 0x3) {
		*ptr++ = TCP_OPT_NOP;
	}
	return ptr - buf;
}

static int
fill_tcp_opt(void *buf, struct tcp_opt *tcp_opt)
{
	uint8_t *ptr;
	int kind, len;

	len = 0;
	for (kind = 0; kind < TCP_OPT_MAX; ++kind) {
		if (test_bit(tcp_opt->flags, kind)) {
			ptr = (uint8_t *)buf + len;
			len += fill_tcp_opt_field(ptr, tcp_opt, kind);
		}
	}
	return len;
}

struct tcb {
	struct eth_addr *d_hwaddr;
	uint8_t tcp_flags;
	be16_t win_size;
	be32_t seq;
	be32_t ack;
	struct tcp_opt *tcp_opt;
	int data_len;
	void *data;
};

static void
send_packet(struct d_sock *dso, struct tcb *tcb,
            struct dev *dev, struct netmap_ring *txr)
{
	int rc, tcp_h_len, total_len;
	struct eth_hdr *eth_h;
	struct ip4_hdr *ip4_h;
	struct tcp_hdr *tcp_h;
	struct pktbuf buf;

	pktbuf_init(&buf, txr);
	eth_h = (struct eth_hdr *)buf.data;
	eth_h->type = ETH_TYPE_IP4_BE;
	eth_h->saddr = s_hwaddr;
	eth_h->daddr = *tcb->d_hwaddr;
	ip4_h = (struct ip4_hdr *)(eth_h + 1);
	tcp_h = (struct tcp_hdr *)(ip4_h + 1);
	if (tcb->tcp_opt != NULL) {
		rc = fill_tcp_opt(tcp_h + 1, tcb->tcp_opt);
	} else {
		rc = 0;
	}
	tcp_h_len = sizeof(*tcp_h) + rc;
	total_len = sizeof(*ip4_h) + tcp_h_len + tcb->data_len;
	ip4_h->ver_ihl = IP4_VER_IHL;
	ip4_h->type_of_svc = 0;
	ip4_h->total_len = CPU_TO_BE16(total_len);
	ip4_h->id = CPU_TO_BE16(dso->ip_id);
	dso->ip_id++;
	ip4_h->frag_off = 0;
	ip4_h->ttl = 64;
	ip4_h->proto = IPPROTO_TCP;
	ip4_h->cksum = 0;
	ip4_h->saddr = dso->key.laddr;
	ip4_h->daddr = dso->key.raddr;
	tcp_h->sport = dso->key.lport;
	tcp_h->dport = dso->key.rport;
	tcp_h->seq = tcb->seq;
	tcp_h->ack = tcb->ack;
	tcp_h->data_off = tcp_h_len << 2;
	tcp_h->flags = tcb->tcp_flags;
	tcp_h->win_size = tcb->win_size;
	tcp_h->cksum = 0;
	tcp_h->urgent_ptr = 0;
	memcpy((uint8_t *)tcp_h + tcp_h_len, tcb->data, tcb->data_len);
	ip4_h->cksum = ip4_cksum(ip4_h);
	tcp_h->cksum = ip4_udp_cksum(ip4_h);
	buf.len = sizeof(*eth_h) + total_len;
	transmit(dev, &buf);
}

static void
send_current(struct d_sock *dso, struct dev *dev, struct netmap_ring *txr)
{
	struct tcb tcb;
	struct packet_node *pkt;

	pkt = dso->current;
	assert(pkt != NULL);
	tcb.d_hwaddr = &pkt->r_hwaddr;
	tcb.seq = CPU_TO_BE32(dso->isn[DIR_SEND] + pkt->seq);
	tcb.ack = CPU_TO_BE32(dso->isn[DIR_RECV] + pkt->ack);
	tcb.tcp_flags = pkt->tcp_flags;
	tcb.win_size = CPU_TO_BE16(pkt->win_size);
	tcb.tcp_opt = &pkt->tcp_opt;
	tcb.data_len = pkt->data_len;
	tcb.data = pkt->data;
	send_packet(dso, &tcb, dev, txr);
}

static void
send_RST(struct d_sock *dso, struct packet_node *pkt, struct dev *dev)
{
	struct netmap_ring *txr;
	struct tcb tcb;

	txr = not_empty_txr(dev);
	if (txr == NULL) {
		dev->cnt_tx_drop++;
		return;
	}
	dev->cnt_tx_RST++;
	tcb.d_hwaddr = &pkt->r_hwaddr;
	if (pkt->dir == DIR_SEND) {
		tcb.seq = CPU_TO_BE32(pkt->seq);
		tcb.ack = CPU_TO_BE32(pkt->ack);
	} else {
		tcb.seq = CPU_TO_BE32(pkt->ack);
		tcb.ack = CPU_TO_BE32(pkt->seq);
	}
	tcb.tcp_flags = TCP_FLAG_RST;
	tcb.win_size = 0;
	tcb.tcp_opt = NULL;;
	tcb.data_len = 0;
	tcb.data = NULL;
	send_packet(dso, &tcb, dev, txr);
}

static void
rx_dev(struct dev *dev)
{
	int i, n, rc;
	struct netmap_ring *rxr;
	struct netmap_slot *src;

	DEV_FOREACH_RXRING(rxr, dev) {
		n = nm_ring_space(rxr);
		if (n > BURST_SIZE) {
			n = BURST_SIZE;
		}
		for (i = 0; i < n; ++i) {
			DEV_RX_PREFETCH(rxr);
			src = rxr->slot + rxr->cur;
			rc = eth_in(dev, rxr, src);
			if (!rc) {
				bypass(dev, src);
			}
			rx_ring_next(dev, rxr);
		}
	}
}

static void
process_sample_FIN(struct s_sock *sso, struct packet_node *x)
{
	if ((x->tcp_flags & TCP_FLAG_FIN) && sso->fin[x->dir] < 2) {
		sso->fin[x->dir] = 1;
		sso->fin_seq[x->dir] = x->seq;
	}
	if ((x->tcp_flags & TCP_FLAG_ACK) && sso->fin[1 - x->dir] == 1) {
		if (x->ack == sso->fin_seq[1 - x->dir] + 1) {
			sso->fin[1 - x->dir] = 2;
			if (sso->fin[0] == 2 && sso->fin[1] == 2) {
				if (sso->first != NULL) {
					merge_script(sso->parent, sso->first);
					sso->first = NULL;
				}
				s_sodel(sso);
			}
		}
	}
}

static void
process_sample(struct s_sock *sso, struct packet_node *pkt)
{
	int rc;
	struct packet_node *child, *x;

	if (pkt->tcp_flags & TCP_FLAG_SYN) {
		sso->isn[pkt->dir] = pkt->seq;
	}
	pkt->seq -= sso->isn[pkt->dir];
	if (pkt->tcp_flags & TCP_FLAG_ACK) {
		pkt->ack -= sso->isn[1 - pkt->dir];
	}
	if (sso->current == NULL) {
		sso->current = &root;
	} else {
		if (pkt->tcp_flags == TCP_FLAG_SYN) {
			return;
		}
		rc = node_is_equal(pkt, sso->current, 1);
		if (rc) {
			return;
		}
	}
	LIST_FOREACH(child, &sso->current->children, list) {
		rc = node_is_equal(pkt, child, 1);
		if (rc) {
			sso->current = child;
			process_sample_FIN(sso, sso->current);
			return;
		}
	}
	x = new_node(pkt);
	if (sso->first == NULL) { 
		sso->first = x;
		sso->parent = sso->current;
	} else {
		LIST_INSERT_HEAD(&sso->current->children, x, list);
	}
	sso->current = x;
	process_sample_FIN(sso, sso->current);
}

static int
try_process_sample(struct dev *dev, int pkt_type, struct sock_key *key,
                   uint32_t hash, struct packet_node *pkt)
{
	int hit;
	struct s_sock *sso;
	struct s_sock_bucket *bucket;

	bucket = s_sock_hash + (hash & s_sock_hash_mask);
	sso = &bucket->entry;
	// Firstly try without locks
	if (sso->inited == 0) {
		if (pkt->tcp_flags != TCP_FLAG_SYN) {
			return 0;
		}
	} else {
		if (memcmp(key, &sso->key, sizeof(*key))) {
			return 0;
		}
	}
	spinlock_lock(&bucket->lock);
	hit = 0;
	if (sso->inited) {
		hit = !memcmp(key, &sso->key, sizeof(*key));
	}
	if (pkt_type != PACKET_OK) {
		if (hit) {
			s_sodel(sso);
		}
	} else {
		if (sso->inited == 0) {
			if (pkt->tcp_flags == TCP_FLAG_SYN &&
			    ((pkt->dir == DIR_RECV &&
			      d_mode == D_MODE_SERVER) ||
			     (pkt->dir == DIR_SEND &&
			      d_mode == D_MODE_CLIENT))) {
				sso->inited = 1;
				sso->key = *key;
				hit = 1;
			}
		}
		if (hit) {
			process_sample(sso, pkt);
		}
	}
	spinlock_unlock(&bucket->lock);
	return 0;
}

static void
timeout(struct timer *timer)
{
	struct d_sock *dso;
	struct dev *dev;

	dso = container_of(timer, struct d_sock, timer);
	dev = devs + 0;
	send_RST(dso, dso->current, dev);
	d_sodel(dev, dso);
}

static void
next_duplicate(struct dev *dev, struct d_sock *dso)
{
	struct packet_node *node;

	if (list_empty(&dso->current->children)) {
		d_sodel(dev, dso);
		return;
	}
	LIST_FOREACH(node, &dso->current->children, list) {
		if (node->dir == DIR_SEND) {
			if (!dso->in_txq) {
				dso->current = node;
				d_sotx(dev, dso);
			}
			return;
		}
	}
	timer_set(&dso->timer, 2000, timeout);
}

static int
try_process_duplicate(struct dev *dev, int pkt_type, struct sock_key *key,
                      uint32_t hash, struct packet_node *pkt)
{
	int rc;
	struct d_sock *dso;
	struct packet_node *node;

	dso = d_soget(dev, key, hash);
	if (dso != NULL) {
		switch (pkt_type) {
		case PACKET_INVALID:
			goto rst;
		case PACKET_RST:
			dev->cnt_rx_RST++;
			d_sodel(dev, dso);
			return 1;
		default:
			break;
		}
		LIST_FOREACH(node, &dso->current->children, list) {
			rc = process_duplicate(pkt, dso, node);
			if (rc) {
				dso->current = node;
				timer_del(&dso->timer);
				next_duplicate(dev, dso);
				return 1;
			}
		}
rst:
		send_RST(dso, pkt, dev);
		d_sodel(dev, dso);
		return 1;
	}
	if (pkt_type != PACKET_OK) {
		return 0;
	}
	if (d_mode == D_MODE_CLIENT) {
		return 0;
	}
	if (pkt->tcp_flags != TCP_FLAG_SYN) {
		return 0;
	}
	if (list_empty(&dev->d_sock_pool)) {
		return 0;
	}
	LIST_FOREACH(node, &root.children, list) {
		rc = process_duplicate(pkt, dso, node);
		if (rc) {
			dso = d_sonew(dev, key, hash, node);
			if (dso == NULL) {
				return 0;
			}
			next_duplicate(dev, dso);
			return 1;
		}
	}
	return 0;
}

static int
process_packet(struct dev *dev, int pkt_type,
               struct sock_key *key, struct packet_node *pkt)
{
	int rc, hash_computed;
	uint32_t hash;

	if (s_sock_raddr != 0 && key->raddr != s_sock_raddr) {
		return 0;
	}
	hash_computed = 0;
	if (d_sock_hash_size &&
	    (d_mode == D_MODE_SERVER ||
	     (d_mode == D_MODE_CLIENT &&
	      key->laddr == d_sock_laddr &&
	      key->rport == s_sock_rport))) {
		hash_computed = 1;
		hash = hash_sock_key(key);
		rc = try_process_duplicate(dev, pkt_type, key, hash, pkt);
		if (rc) {
			return rc;
		}
	}
	if (key->laddr != s_sock_laddr) {
		return 0;
	}
	if (!hash_computed) {
		hash_computed = 1;
		hash = hash_sock_key(key);
	}
	rc = try_process_sample(dev, pkt_type, key, hash, pkt);
	return rc;
}

static int
tcp_opt_in(struct tcp_opt *tcp_opt, const struct tcp_hdr *tcp_h, size_t tcp_h_len)
{
	int i, len, opts_len;
	uint8_t *opts, *data, kind;
	const struct tcp_opt_field *field;

	assert(sizeof(*tcp_h) <= tcp_h_len);
	tcp_opt->flags = 0;
	opts = (uint8_t *)(tcp_h + 1);
	opts_len = tcp_h_len - sizeof(*tcp_h);
	if (opts_len == 0) {
		return 0;
	}
	if (opts_len % sizeof(uint32_t)) {
		return -EINVAL;
	}
	i = 0;
	while (i < opts_len) {
		kind = opts[i++];
		if (kind == TCP_OPT_EOL) {
			if (i != opts_len) {
				return -EINVAL;
			}
			break;
		} else if (kind == TCP_OPT_NOP) {
			continue;
		}
		if (i == opts_len) {
			return -EINVAL;
		}
		len = opts[i++];
		if (len < 2) {
			return -EINVAL;
		}
		if (i + len - 2 > opts_len) {
			return -EINVAL;
		}
		data = opts + i;
		i += len - 2;
		if (kind >= TCP_OPT_MAX) {
			continue;
		}
		field = tcp_opt_fields + kind;
		if (field->kind == 0) {
			continue;
		}
		if (len != field->len) {
			return -EINVAL;
		}
		switch (kind) {
		case TCP_OPT_MSS:
			tcp_opt->mss = BE16_TO_CPU(*((uint16_t *)data));
			break;
		case TCP_OPT_WSCALE:
			tcp_opt->wscale = *data;
			break;
		case TCP_OPT_SACK_PERMITED:
			tcp_opt->sack_permited = 1;
			break;
		case TCP_OPT_TIMESTAMPS:
			tcp_opt->ts.val = BE32_TO_CPU(*((uint32_t *)data + 0));
			tcp_opt->ts.ecr = BE32_TO_CPU(*((uint32_t *)data + 1));
			break;
		default:
			printf("Unknown tcp option %d\n", kind);
			break;
		}
		set_bit(&tcp_opt->flags, kind);
	}
	return 0;
}

static void
arp_reply(struct dev *dev, struct netmap_ring *rxr, struct netmap_slot *src)
{
	be32_t sip;
	struct eth_hdr *eth_h;
	struct arp_hdr *arp_h;

	eth_h = (struct eth_hdr *)NETMAP_BUF(rxr, src->buf_idx);
	eth_h->daddr = eth_h->saddr;
	eth_h->saddr = s_hwaddr;
	arp_h = (struct arp_hdr *)(eth_h + 1);
	sip = arp_h->data.sip;
	arp_h->op = ARP_OP_REPLY_BE;
	arp_h->hrd = ARP_HRD_ETH_BE;
	arp_h->pro = ETH_TYPE_IP4_BE;
	arp_h->hlen = sizeof(struct eth_addr);
	arp_h->plen = sizeof(be32_t);
	arp_h->data.tip = sip;
	arp_h->data.sip = d_sock_laddr;
	arp_h->data.sha = s_hwaddr;
	arp_h->data.tha = eth_h->daddr;
	src->len = sizeof(*eth_h) + sizeof(*arp_h);
	zerocopy(dev, src);
}

static int
eth_in(struct dev *dev, struct netmap_ring *rxr, struct netmap_slot *src)
{
	int rc, rem, dir, ip4_h_len, tcp_h_len, total_len, data_len, pkt_type;
	struct eth_hdr *eth_h;
	struct arp_hdr *arp_h;
	struct ip4_hdr *ip4_h;
	struct tcp_hdr *tcp_h;
	struct sock_key key;
	struct packet_node node;

	if (DEV_IS_HOST(dev)) {
		dir = DIR_SEND;
	} else {
		dir = DIR_RECV;
	}
	eth_h = (struct eth_hdr *)NETMAP_BUF(rxr, src->buf_idx);
	rem = src->len;
	if (rem < sizeof(*eth_h)) {
		return 0;
	}
	rem -= sizeof(*eth_h);
	if (eth_h->type == ETH_TYPE_ARP_BE) {
		if (dir == DIR_SEND) {
			return 0;
		}
		if (d_sock_laddr == 0) {
			return 0;
		}
		arp_h = (struct arp_hdr *)(eth_h + 1);
		if (arp_h->op != ARP_OP_REQUEST_BE) {
			return 0;
		}
		if (arp_h->data.tip != d_sock_laddr) {
			return 0;
		}
		arp_reply(dev, rxr, src);
		return 1;
	} else if (eth_h->type != ETH_TYPE_IP4_BE) {
		return 0;
	}
	ip4_h = (struct ip4_hdr *)(eth_h + 1);
	ip4_h_len = ip4_hdr_len(ip4_h->ver_ihl);
	if (ip4_h_len < sizeof(*ip4_h)) {
		return 0;
	}
	if (ip4_h->frag_off & IP4_FRAG_MASK) {
		return 0;
	}
	if (rem < ip4_h_len) {
		return 0;
	}
	rem -= ip4_h_len;
	if (ip4_h->proto != IPPROTO_TCP) {
		return 0;
	}
	if (rem < sizeof(*tcp_h)) {
		return 0;
	}
	tcp_h = (struct tcp_hdr *)(((uint8_t *)ip4_h) + ip4_h_len);
	memset(&key, 0, sizeof(key));
	node.dir = dir;
	if (dir == DIR_SEND) {
		key.laddr = ip4_h->saddr;
		key.lport = tcp_h->sport;
		key.raddr = ip4_h->daddr;
		key.rport = tcp_h->dport;
		s_hwaddr = eth_h->saddr;
		node.r_hwaddr = eth_h->daddr;
	} else {
		key.laddr = ip4_h->daddr;
		key.lport = tcp_h->dport;
		key.raddr = ip4_h->saddr;
		key.rport = tcp_h->sport;
		s_hwaddr = eth_h->daddr;
		node.r_hwaddr = eth_h->saddr;
	}
	node.seq = BE32_TO_CPU(tcp_h->seq);
	node.ack = BE32_TO_CPU(tcp_h->ack);
	node.win_size = BE16_TO_CPU(tcp_h->win_size);
	node.tcp_flags = tcp_h->flags;
	if (tcp_h->flags & TCP_FLAG_RST) {
		pkt_type = PACKET_RST;
		goto out;
	}
	pkt_type = PACKET_INVALID;
	total_len = BE16_TO_CPU(ip4_h->total_len);
	if (total_len < ip4_h_len) {
		goto out;
	}
	data_len = total_len - ip4_h_len;
	if (data_len > rem) {
		goto out;
	}
	tcp_h_len = (tcp_h->data_off & 0xf0) >> 2;
	if (tcp_h_len < sizeof(*tcp_h)) {
		goto out;
	}
	if (tcp_h_len > data_len) {
		goto out;
	}
	data_len -= tcp_h_len;
	rc = tcp_opt_in(&node.tcp_opt, tcp_h, tcp_h_len);
	if (rc) {
		goto out;
	}
	unset_bit(&node.tcp_opt.flags, TCP_OPT_TIMESTAMPS);
	node.data = (uint8_t *)(tcp_h) + tcp_h_len;
	node.data_len = data_len;
	pkt_type = PACKET_OK;
out:
	rc = process_packet(dev, pkt_type, &key, &node);
	return rc;
}

static void
tx_flush(struct dev *dev)
{
	struct netmap_ring *txr;
	struct d_sock *dso;

	while (!list_empty(&dev->txq)) {
		dso = LIST_FIRST(&dev->txq, struct d_sock, tx_list);
		txr = not_empty_txr(dev);
		if (txr == NULL) {
			return;
		}
		DEV_TX_PREFETCH(txr);
		LIST_REMOVE(dso, tx_list);
		assert(dso->in_txq);
		dso->in_txq = 0;
		send_current(dso, dev, txr);
		next_duplicate(dev, dso);
	}
}

static void
active_open(int concurrency)
{
	int i;
	struct d_sock *dso;
	struct dev *dev;

	dev = devs + 0;
	for (i = 0; i < concurrency; ++i) {
		dso = d_sonew_client(dev);
		if (dso == NULL) {
			break;
		}
	}
}

static void
init_random()
{
	uint32_t seed, t, pid;

	t = time(NULL);
	pid = getpid();
	seed = murmur(&t, sizeof(t), 0);
	seed = murmur(&pid, sizeof(pid), seed);
	srand48(seed);
}

static void
init_ephemeral_ports()
{
	int i, j, n, min, max;
	struct bind_entry *buf, *cur, tmp;
	struct dev *dev;

	dev = devs + 0;
	min = 1024;
	max = 65535;
	n = max - min + 1;
	// Init
	buf = xmalloc(sizeof(struct bind_entry) * n);
	for (i = 0; i < n; ++i) {
		cur = buf + i;
		cur->laddr = d_sock_laddr;
		cur->lport = CPU_TO_BE16(i + min);
	}
	// Shuffle
	for (i = 0; i < n; ++i) {
		j = lrand48() % n;
		tmp = buf[j];
		buf[j] = buf[i];
		buf[i] = tmp;
	}
	// Add
	for (i = 0; i < n; ++i) {
		cur = buf + i;
		LIST_INSERT_HEAD(&dev->ephemeral_ports, cur, list);
	}
}

static void
get_time()
{
	clock_gettime(CLOCK_MONOTONIC, &now_ts);
	now_ts.tv_sec -= start_ts.tv_sec;
	now_ts.tv_nsec -= start_ts.tv_nsec;
	msec = now_ts.tv_sec * 1000 + now_ts.tv_nsec / 10000000llu;
}

static void
set_affinity(int cpu_id)
{
	int rc;
	cpuset_t x;

	CPU_ZERO(&x);
	CPU_SET(cpu_id, &x);
	rc = pthread_setaffinity_np(pthread_self(), sizeof(x), &x);
	if (rc) {
		die(rc, "pthread_setaffinity_np(%d) failed", cpu_id);
	}
}

static void
print_report(struct timer *timer)
{
	static int n;
	uint64_t rps, ipps, opps, irpps, orpps, dt;
	time_t sec;
	struct tm *tm;
	struct dev *dev;

	dev = devs + 0;
	get_time();
	dt = msec - msec_prev;
	msec_prev = msec;
	rps = 1000 * (d_requests - d_requests_prev) / dt;
	ipps = 1000 * (dev->cnt_rx - rx_prev) / dt;
	opps = 1000 * (dev->cnt_tx - tx_prev) / dt;
	irpps = 1000 * (dev->cnt_rx_RST - rx_RST_prev) / dt;
	orpps = 1000 * (dev->cnt_tx_RST - tx_RST_prev) / dt;
	sec = now_ts.tv_sec;
	if (now_ts.tv_nsec < 500000000llu) {
		dt = 1000 - now_ts.tv_nsec / 1000000;
	} else {
		sec++;
		dt = 2000 - now_ts.tv_nsec / 1000000;
	}
	tm = localtime(&sec);
	if (n == 0 || n > 20) {
		n = 0;
		printf("%-10s%-10s%-10s%-10s%-10s%-10s\n",
		       "time", "rps", "ipps", "opps", "irpps", "orpps");
	}
	n++;
	printf("%02d:%02d:%02d  %-10d%-10d%-10d%-10d%-10d\n",
	       tm->tm_hour, tm->tm_min, tm->tm_sec,
	       (int)rps, (int)ipps, (int)opps, (int)irpps, (int)orpps);
	d_requests_prev = d_requests;
	rx_prev = dev->cnt_rx;
	tx_prev = dev->cnt_tx;
	rx_RST_prev = dev->cnt_rx_RST;
	tx_RST_prev = dev->cnt_tx_RST;
	timer_set(timer, dt, print_report);
}

static void
sig_handler(int signum)
{
	switch (signum) {
	case SIGINT:
		done = 1;
		break;
	case SIGUSR1:
		print_packet_tree = 1;
		break;
	}
}

static void
invalid_argument(int opt, const char *val)
{
	die(0, "invalid argument '-%c': %s", opt, val);
}

static void
usage()
{
	printf(
	"Usage:\n"
	"  Server mode:\n"
	"    tcpdup [options] {-i ifname} {-l ip-addr}\n"
	"  Client mode:\n"
	"    tcpdup [options] {-i ifname} {-l ip-addr}\n"
	"           {-L ip-addr} {-p port}\n"
	"  Options:\n"
	"    -h              Print this help\n"
	"    -i interface    Interface name\n"
	"    -l ip-addr      Local ip address\n"
	"    -L ip-addr\n"
	"    -r ip-addr\n"
	"    -p port\n"
	"    -n requests     number of requests to process as sample\n"
	"    -N requests     number of requests to perform as duplicate\n"
	"    -c concurrency  Number of multiple sample sockets to process at time\n"
	"    -C concurrency\n"
	"    -P\n"
	);
}

int
main(int argc, char **argv)
{
	int i, j, rc, opt, sent, Pflag;
	int concurrency;
	const char *ifname;
	struct timer report_timer;
	struct pollfd pfds[2];
	struct dev *dev;

	sent = 0;
	Pflag = 0;
	ifname = NULL;
	concurrency = 1;
	s_sock_hash_size = 8;
	d_requests_max = -1;
	while ((opt = getopt(argc, argv, "hi:a:l:L:r:p:n:N:c:C:P")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return EXIT_SUCCESS;
		case 'i':
			ifname = optarg;
			break;
		case 'a':
			set_affinity(strtoul(optarg, NULL, 10));
			break;
		case 'l':
			rc = inet_pton(AF_INET, optarg, &s_sock_laddr);
			if (rc != 1) {
				invalid_argument(opt, optarg);
			}
			break;
		case 'L':
			rc = inet_pton(AF_INET, optarg, &d_sock_laddr);
			if (rc != 1) {
				invalid_argument(opt, optarg);
			}
			d_mode = D_MODE_CLIENT;
			break;
		case 'r':
			rc = inet_pton(AF_INET, optarg, &s_sock_raddr);
			if (rc != 1) {
				invalid_argument(opt, optarg);
			}
			break;
		case 'p':
			rc = strtoul(optarg, NULL, 10);
			if (rc == 0) {
				invalid_argument(opt, optarg);
			}
			d_mode = D_MODE_CLIENT;
			s_sock_rport = CPU_TO_BE16(rc);
			break;
		case 'n':
			break;
		case 'N':
			rc = strtoul(optarg, NULL, 10);
			if (rc == 0) {
				invalid_argument(opt, optarg);
			}
			d_requests_max = rc;
			break;
		case 'c':
			rc = strtoul(optarg, NULL, 10);
			if (rc == 0) {
				invalid_argument(opt, optarg);
			}
			s_sock_hash_size = upper_pow_of_2_32(rc);
			break;
		case 'C':
			rc = strtoul(optarg, NULL, 10);
			concurrency = rc;
			break;
		case 'P':
			Pflag = 1;
			break;
		}
	}
	if (ifname == NULL || s_sock_laddr == 0) {
		usage();
		return EXIT_FAILURE;
	}
	if (d_mode == D_MODE_CLIENT &&
	    (s_sock_raddr == 0 || s_sock_rport == 0 || d_sock_laddr == 0)) {
		usage();
		return EXIT_FAILURE;
	}
	s_sock_hash_mask = s_sock_hash_size - 1;
	s_sock_hash = xmalloc(s_sock_hash_size * sizeof(struct s_sock_bucket));
	memset(s_sock_hash, 0, s_sock_hash_size * sizeof(struct s_sock_bucket));
	d_sock_hash_size = upper_pow_of_2_32(3 * concurrency / 2);
	d_sock_hash_mask = d_sock_hash_size - 1;
	list_init(&root.children);
	spinlock_init(&root.lock);
	init_random();
	clock_gettime(CLOCK_MONOTONIC, &start_ts);
	get_time();
	init_timers();
	hash_random = lrand48();
	init_dev(devs + 0, ifname, concurrency, 0);
	init_dev(devs + 1, ifname, concurrency, -1);
	timer_init(&report_timer);
	timer_set(&report_timer, 1000, print_report);
	if (d_mode == D_MODE_CLIENT) {
		init_ephemeral_ports();
	}
	for (i = 0; i < 2; ++i) {
		pfds[i].fd = devs[i].nmd->fd;
	}
	signal(SIGINT, sig_handler);
	signal(SIGUSR1, sig_handler);
	j = 0;
	while (!done) {
		for (i = 0; i < 2; ++i) {
			pfds[i].events = POLLIN;
			pfds[i].revents = 0;
			if (devs[i].tx_full) {
				pfds[i].events |= POLLOUT;
			}
		}
		poll(pfds, 2, 10);
		epoch++;
		j++;
		if (j == 10) {
			j = 0;
			get_time();
			check_timers();
		}
		for (i = 0; i < 2; ++i) {
			dev = devs + i;
			if (pfds[i].revents & POLLIN) {
				rx_dev(dev);
			}
			if (pfds[i].revents & POLLOUT) {
				dev->tx_full = 0;
			}
		}
		if (print_packet_tree) {
			print_packet_tree = 0;
			print_branch(&root, 0);
		}
		if (sent == 0 &&
		    s_sock_hash_size &&
		    d_mode == D_MODE_CLIENT &&
		    !list_empty(&root.children)) {
			sent = 1;
			active_open(concurrency);
		}
		tx_flush(devs + 0);
	}
	if (Pflag) {
		printf("\n");
		print_branch(&root, 0);
	}
	return EXIT_SUCCESS;
}
