#ifndef LIBNAAS_UTILS_H
#define LIBNAAS_UTILS_H

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#define NAAS_PODS_MAX 256

#define NAAS_ERR_ERRNO 0 // errno by default
#define NAAS_ERR_VNET 1
#define NAAS_ERR_NATS 2

#define NAAS_MAX(a, b) ((a) > (b) ? (a) : (b))

#define naas_swap(a, b) do { \
	typeof(a) tmp = a; \
	a = b; \
	b = tmp; \
} while (0)

#define naas_bswap16(x) \
	(((((uint16_t)(x)) & ((uint16_t)0x00FF)) << 8) | \
	 ((((uint16_t)(x)) & ((uint16_t)0xFF00)) >> 8))

#define naas_bswap32(x) \
	(((((uint32_t)(x)) & ((uint32_t)0x000000FF)) << 24) | \
	 ((((uint32_t)(x)) & ((uint32_t)0x0000FF00)) <<  8) | \
	 ((((uint32_t)(x)) & ((uint32_t)0x00FF0000)) >>  8) | \
	 ((((uint32_t)(x)) & ((uint32_t)0xFF000000)) >> 24))


#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define naas_hton16(x) ((uint16_t)(x))
#define naas_hton32(x) ((uint32_t)(x))
#define naas_ntoh16(x) ((uint16_t)(x))
#define naas_ntoh32(x) ((uint32_t)(x))
#else  // __BIG_ENDIAN
#define naas_hton16(x) ((uint16_t)naas_bswap16(x))
#define naas_hton32(x) ((uint32_t)naas_bswap32(x))
#define naas_ntoh16(x) ((uint16_t)naas_bswap16(x))
#define naas_ntoh32(x) ((uint32_t)naas_bswap32(x))
#endif // __BIG_ENDIAN

#define naas_ntoh64 be64toh
#define naas_hton64 htobe64

#define naas_barrier() __asm__ __volatile__("": : :"memory")

#define naas_field_off(type, field) ((intptr_t)&((type *)0)->field)

#define naas_container_of(ptr, type, field) \
	((type *)((intptr_t)(ptr) - naas_field_off(type, field)))

#define NAAS_READ_ONCE(x) \
({ \
	union { \
		typeof(x) val; \
		uint8_t data[1]; \
	} u; \
	naas_read_once(&(x), u.data, sizeof(x)); \
	u.val; \
})

#define NAAS_WRITE_ONCE(x, v) \
({ \
	union { \
		typeof(x) val; \
		uint8_t data[1]; \
	} u = { \
		.val = (typeof(x))(v) \
	}; \
	naas_write_once(&(x), u.data, sizeof(x)); \
	u.val; \
})

#define naas_rcu_assign_pointer(p, v) \
({ \
	naas_barrier(); \
	NAAS_WRITE_ONCE(p, v); \
})

#define NAAS_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define NAAS_MIN(a, b) ((a) < (b) ? (a) : (b))

#define NAAS_STRSZ(s) (s), (sizeof(s) - 1)

#define NAAS_UNUSED(x) ((void)x)

#define naas_inet_ntoa(src, dst) inet_ntop(AF_INET, src, dst, INET_ADDRSTRLEN)

#define naas_assert(err, expr) \
	if (!(expr)) { \
		naas_assertion_failed(err, #expr); \
	}

#define naas_dbg(format, ...) do { \
	printf("dbg: %s:%u: ", __FILE__, __LINE__); \
	printf(format, ##__VA_ARGS__); \
	printf("\n"); \
} while (0)

typedef uint16_t be16_t;
typedef uint32_t be32_t;
typedef uint64_t be64_t;

// System utilities
void *naas_xmalloc(size_t);
void *naas_xmemdup(void *ptr, size_t size);
char *naas_strzcpy(char *, const char *, size_t);
char *naas_xstrndup(const char *, size_t);

#define NAAS_SOCKADDRSTRLEN PATH_MAX

const char *naas_sockaddr_str(char *dst, int count,
		const struct sockaddr *addr, socklen_t addrlen);

int naas_pipe(int[2]);
int naas_bind(int, const struct sockaddr *, socklen_t);
int naas_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
ssize_t naas_read(int fd, void *buf, size_t count);
ssize_t naas_write(int, const void *, size_t);
ssize_t naas_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen);
int naas_set_nonblock(int, int);

const char *naas_inet_ntop(int, const void *, char *);
#define naas_inet4_ntop(in4, addrstr) naas_inet_ntop(AF_INET, in4, addrstr)
#define naas_inet6_ntop(in6, addrstr) naas_inet_ntop(AF_INET6, in6, addrstr)
int naas_inet_aton(const char *, struct in_addr *, unsigned int *);
const char *naas_bool_str(int);
void naas_print_invalidarg(const char *, const char *);
void naas_print_unspecifiedarg(const char *);
void naas_assertion_failed(int, const char *);

#define naas_err_get_type(err) (((err) >> 16) & 0x0000ffff)
#define naas_err_get_num(err) ((err) & 0x0000ffff)
#define naas_create_err(type, num) (((type) << 16) | (num))

// PID file section
int naas_pid_file_open(const char *daemon);
void naas_pid_file_close(int fd, const char *daemon);

// Thread section
struct naas_thread {
	pthread_t thr_thread;
	pthread_attr_t thr_attr;
	int thr_started;
	volatile int thr_done;
	void *thr_arg;
};

typedef void *(*naas_pthread_f)(void *);
typedef void *(*naas_thread_f)(struct naas_thread *);

void naas_thread_init(struct naas_thread *);
void naas_thread_start(struct naas_thread *, naas_thread_f, void *);
void naas_thread_join(struct naas_thread *);
void naas_mutex_init(pthread_mutex_t *);
void naas_mutex_destroy(pthread_mutex_t *);

// Inlines
static inline void
naas_read_once(const volatile void *p, void *data, int size)
{
	switch (size) {
	case 1: *(uint8_t *)data = *(volatile uint8_t *)p; break;
	case 2: *(uint16_t *)data = *(volatile uint16_t *)p; break;
	case 4: *(uint32_t *)data = *(volatile uint32_t *)p; break;
	case 8: *(uint64_t *)data = *(volatile uint64_t *)p; break;
	}
}

static inline void
naas_write_once(volatile void *p, void *data, int size)
{
	switch (size) {
	case 1: *(volatile uint8_t *)p = *(uint8_t *)data; break;
	case 2: *(volatile uint16_t *)p = *(uint16_t *)data; break;
	case 4: *(volatile uint32_t *)p = *(uint32_t *)data; break;
	case 8: *(volatile uint64_t *)p = *(uint64_t *)data; break;
	}
}

#endif // LIBNAAS_UTILS_H
