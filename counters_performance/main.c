#define _GNU_SOURCE
#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#include <pthread.h>

int g_n_threads;
int g_n_counters;
uint64_t *g_counters;

void *
xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		printf("Out Of Memory\n");
		exit(2);
	}
	return ptr;
}

static uint64_t *
counter_ptr(int cid)
{
	return g_counters + cid*g_n_threads;
}

static void
counters_init()
{
	size_t size;

	size = g_n_counters * g_n_threads * sizeof(uint64_t);
	g_counters = xmalloc(size);
	memset(g_counters, 0, size);
}

static void
counter_inc(int cid, int tid)
{
	counter_ptr(cid)[tid]++;
}

static uint64_t
counter_get(int cid)
{
	int i;
	uint64_t accum;

	accum = 0;
	for (i = 0; i < g_n_threads; ++i) {
		accum += counter_ptr(cid)[i];
	}
	return accum;
}

void
print_counter(int cid)
{
	int i;

	for (i = 0; i < g_n_threads; ++i) {
		printf("%"PRIu64" ", counter_ptr(cid)[i]);
	}
	printf("\n");
}

static void *
worker(void *udata)
{
	int i, tid;

	tid = (uintptr_t)udata;
	printf("tid=%d\n", tid);

	for (;;) {
		for (i = 0; i < g_n_counters; ++i) {
			counter_inc(i, tid);
		}
	}

	return NULL;
}

static uint64_t
timeval_to_usec(struct timeval *tv)
{
	return tv->tv_sec * 1000000 + tv->tv_usec;
}

int
main(int argc, char**argv)
{
	int i, rc, opt, step;
	uint64_t data, cycles, cycles_prev, time, time_prev;
	struct timeval tv;
	pthread_t t;
	cpu_set_t cpuset;

	step = 1;
	g_n_threads = 2;
	g_n_counters = 1;

	while ((opt = getopt(argc, argv, "c:s:t:")) != -1) {
		switch (opt) {
		case 'c':
			g_n_counters = strtoul(optarg, NULL, 10);
			if (g_n_counters < 1) {
				g_n_counters = 1;
			}
			break;

		case 's':
			step = strtoul(optarg, NULL, 10);
			if (step < 1) {
				step = 1;
			}
			break;

		case 't':
			g_n_threads = strtoul(optarg, NULL, 10);
			if (g_n_threads < 2) {
				g_n_threads = 2;
			}
			break;
		}
	}
	
	counters_init();

	for (i = 1; i < g_n_threads; ++i) {
		rc = pthread_create(&t, NULL, worker, (void *)((uintptr_t)i));
		if (rc) {
			printf("pthread_create() failed (%s)\n", strerror(rc));
			exit(1);
		}
		CPU_ZERO(&cpuset);
		CPU_SET(i, &cpuset);
		rc = pthread_setaffinity_np(t, sizeof(cpuset), &cpuset);
		if (rc) {
			printf("pthread_setaffinity_np() failed (%s)\n", strerror(rc));
			exit(1);
		}
	}

	t = pthread_self();
	CPU_ZERO(&cpuset);
	CPU_SET(0, &cpuset);
	pthread_setaffinity_np(t, sizeof(cpuset), &cpuset);

	cycles_prev = 0;
	gettimeofday(&tv, NULL);
	time_prev = timeval_to_usec(&tv);
	for (;;) {
		sleep(1);
		data = 0;
		for (i = 0; i < g_n_counters; i += step) {
			data += counter_get(i);
		}
		cycles = counter_get(0);
		gettimeofday(&tv, NULL);
		time = timeval_to_usec(&tv);
		printf("%"PRIu64" %"PRIu64"\n",
				1000000 * (cycles - cycles_prev) / (time - time_prev), data);
		print_counter(0);
		cycles_prev = cycles;
		time_prev = time;
	}
	return 0;
}
