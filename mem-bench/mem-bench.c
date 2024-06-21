#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <stdarg.h>
#include <fcntl.h>

#ifndef CACHE_LINE_SIZE
#define CACHE_LINE_SIZE 64
#endif

#define WORKING_SET_SIZE_MIN 14
#define WORKING_SET_SIZE_MAX 33

#define L_SIZE_MIN ((int)(sizeof(struct l) + sizeof(long int)))
#define L_SIZE_MAX ((int)(1llu << WORKING_SET_SIZE_MIN))

#define DEF_L_SIZE L_SIZE_MIN
#define DEF_WORKING_SET_SIZE_MIN WORKING_SET_SIZE_MIN 
#define DEF_WORKING_SET_SIZE_MAX 31


#define DURATION 2000

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

struct l {
	struct l *n;
	volatile long int pad[0];
};

enum prefetch {
	FOLLOW,
	INC,
	ADDNEXT0,
};

struct thread {
	pthread_t thread_id;
	pthread_attr_t attr;	
};

struct task {
	struct thread thread;
	int cpu;
	struct l *head;
	size_t count;
	uint32_t cycles;
	enum prefetch prefetch;
};

union tsc {
	uint64_t tsc_64;
	struct {
		uint32_t lo_32;
		uint32_t hi_32;
	};
};

static volatile uint32_t done = 0;
static char hugetlbfs[PATH_MAX];
static int hugetlbfs_fd = -1;
static size_t hugetlbfs_size = 0;

static void
die(int err_num, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));

const char *
die_strerror(int err_num)
{
	return strerror(err_num);
}
	
static void
die(int err_num, const char *format, ...)
{
	va_list ap;

	fprintf(stderr, "mem-bench: ");

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);

	if (err_num)
		fprintf(stderr, " (%d:%s)\n", err_num, die_strerror(err_num));
	else
		fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static void
die_Invalid_parameter_Range(int opt, int min, int max)
{
	die(0, "Invalid parameter '%c' [Range %d..%d]", opt, min, max);
}

static void
die_Out_of_memory(size_t size)
{
	return die(0, "Out of memory (%d mbytes)", (int)(size / (1024 * 1024)));
}

static inline uint64_t
rdtsc()
{
	union tsc tsc;

	asm volatile("rdtsc" :
		"=a" (tsc.lo_32),
		"=d" (tsc.hi_32));

	return tsc.tsc_64;
}

static void *
xmalloc(size_t size)
{
	void *ptr;

	if ((ptr = malloc(size)) == NULL)
		die_Out_of_memory(size);

	return ptr;
}

static inline struct l *
l_of(void *buf, size_t size, size_t i)
{
	return (struct l *)((char *)buf + size * i);
}

struct l *
init_sequental_order(void *buf, size_t size, size_t count)
{
	size_t i;
	struct l *cur, *head, *prev;

	head = prev = cur = l_of(buf, size, 0);

	for (i = 1; i < count; ++i) {
		cur = l_of(buf, size, i);

		prev->n = cur;
		prev = cur;
	}

	cur->n = head;

	return head;
}

static uint64_t
rand64()
{
	return (lrand48() + (lrand48() << 32));
}

struct l *
init_random_order(void *buf, size_t size, size_t count)
{
	size_t i;
	struct l **p, *cur, *head, *prev;

	p = xmalloc(count * sizeof(struct l *));

	for (i = 0; i < count; ++i)
		p[i] = l_of(buf, size, i);

	head = prev = cur = p[--count];

	while (count) {
		i =  rand64() % count;

		cur = p[i];

		prev->n = cur;
		prev = cur;

		p[i] = p[--count];
	}

	cur->n = head;

	free(p);

	return head;
}

static void
thread_set_affinity(struct thread *thread, int cpu)
{
	int err_num;
	cpu_set_t cpu_set;
	
	CPU_ZERO(&cpu_set);
	CPU_SET(cpu, &cpu_set);

	err_num = pthread_setaffinity_np(thread->thread_id, sizeof(cpu_set), &cpu_set);

	if (err_num != 0)
		die(err_num, "pthread_setaffinity() failed cpu:%d", cpu);
}

static inline void
loop(struct task *task, size_t n)
{
	size_t i;
	volatile uint64_t ticks;
	volatile struct l *cur;

	ticks = rdtsc();

	cur = task->head;
	i = 0;

	switch (task->prefetch) {
	case FOLLOW:
		for (; i < n && done == 0; ++i) {
			cur = cur->n;
		}
		break;

	case INC:
		for (; i < n && done == 0; ++i) {
			++cur->pad[0];
			cur = cur->n;
		}
		break;

	case ADDNEXT0:
		for (; i < n && done == 0; ++i) {
			cur->pad[0] += cur->n->pad[0];
			cur = cur->n;
		}
		break;

	default:
		break;
	}

	if (i)
		task->cycles = (rdtsc() - ticks) / i;
}

static void *
start_routine(void *arg)
{
	size_t n, ms;
	struct timeval tv, tv2;
	struct task *task;

	task = (struct task *)arg;

	thread_set_affinity(&task->thread, task->cpu);	

	n = MAX(task->count, 65536);

	gettimeofday(&tv, NULL);
	loop(task, n);
	gettimeofday(&tv2, NULL);

	ms = (tv2.tv_sec - tv.tv_sec) * 1000 + (tv2.tv_usec - tv.tv_usec) / 1000 + 1;

	if (ms > DURATION)
		return NULL;

	n = n * DURATION / ms;

	loop(task, n);	

	return NULL;
}

static void
thread_create(struct thread *thread, void *udata)
{
	int err_num;

	if ((err_num = pthread_attr_init(&thread->attr)) != 0)
		die(err_num, "pthread_attr_init() failed");

	err_num = pthread_create(&thread->thread_id, &thread->attr, start_routine, udata);

	if (err_num != 0)
		die(err_num, "pthread_create() failed");	
}

static void
thread_join(struct thread *thread)
{
	int err_num;
	
	if ((err_num = pthread_join(thread->thread_id, NULL)) != 0)
		die(err_num, "pthread_join() failed");

	pthread_attr_destroy(&thread->attr);
}

static int
bench(struct l *head, size_t count, uint64_t cpu_set, enum prefetch prefetch)
{
	int i, nr_tasks;
	uint64_t cycles;
	struct task *task, tasks[64];

	nr_tasks = 0;
	for (i = 0; i < 64; ++i) {
		if (cpu_set & (1llu << i)) {
			task = tasks + nr_tasks++;
			task->cpu = i;
			task->head = head;
			task->count = count;
			task->prefetch = prefetch;

			thread_create(&task->thread, task);
		}
	}

	cycles = 0;
	for (i = 0; i < nr_tasks; ++i) {
		task = tasks + i;

		thread_join(&task->thread);

		cycles += task->cycles;
	}

	return cycles / nr_tasks;
}

static void
sig_handler(int signo)
{
	switch (signo) {
	case SIGTERM:
	case SIGQUIT:
	case SIGINT:
		done = 1;
		break;
	}
}

static void
init()
{
	int i;
	struct sigaction act;
	sigset_t set;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_handler;
	sigfillset(&act.sa_mask);
	act.sa_flags = SA_RESTART;

	sigfillset(&set);

	for (i = 0; i < sizeof(set) * CHAR_BIT; ++i) {
		if (!sigaction(i, &act, NULL))
			sigdelset(&set, i);
	}

	if (sigprocmask(SIG_BLOCK, &set, NULL))
		die(errno, "sigprocmask() failed");

	srand48(time(NULL));
}

static void
reset_hugetlbfs()
{
//	if (strcmp(hugetlbfs, "2m") && 
	unlink(hugetlbfs);
	hugetlbfs_fd = -1;
	hugetlbfs_size = 0;
}

static void *
init_mem(size_t bytes)
{
	int err_num;
	void *buf;

	if (hugetlbfs[0] == '\0') {
		err_num = posix_memalign(&buf, CACHE_LINE_SIZE, bytes);
		if (err_num != 0)
			die(err_num, "posix_memalign(%u, %zu) failed", CACHE_LINE_SIZE, bytes);
	} else {
		reset_hugetlbfs();

		hugetlbfs_fd = open(hugetlbfs, O_CREAT|O_RDWR, 0755);
		if (hugetlbfs_fd == -1) 
			die(errno, "open(\"%s\") failed", hugetlbfs);

		hugetlbfs_size = bytes;

		buf = mmap(NULL, hugetlbfs_size, PROT_READ|PROT_WRITE,
			MAP_ANONYMOUS|MAP_PRIVATE|MAP_HUGETLB, hugetlbfs_fd, 0);

		if (buf == MAP_FAILED)
			die(errno, "mmap(%zu) failed", bytes);
	}

	return buf;
}

static void
release_mem(void *buf)
{
	if (hugetlbfs[0] == '\0') {
		free(buf);
	} else {
		munmap(buf, hugetlbfs_size);
		close(hugetlbfs_fd);
		reset_hugetlbfs();
	}
}

static void
check_opt_range(int val, int opt, int min, int max)
{
	if (val < min || val > max)
		die_Invalid_parameter_Range(opt, min, max);
}

static void
print_usage()
{
	printf(
		"Usage: mem-bench [-hRfia] [ -n minworkingsetsize ] [ -N maxworkingsetsize ]\n"
		"                 [ -s elementsize ] [ -c cpumask ] [ -T hugetlbfs ]\n"
		"\n"
		"\t-h                    print this help\n"
		"\t-R                    do random access benchmarks (sequental by default)\n"
		"\t-i                    use \"Increment\" access pattern\n"
		"\t-a                    use \"Addnext0\"  access pattern\n"
		"\t-n minworkingsetsize  specify minimal working set size (default: %d)\n"
		"\t-N maxworkingsetsize  specify maximal working set size (default: %d)\n"
		"\t-s elementsize        in bytes (default: %d)\n"
		"\t-c cpumask            set affinity of all benchmark threads\n"
		"\t-T hugetlbfs          path to hugetlbfs mount point\n",
		DEF_WORKING_SET_SIZE_MIN, DEF_WORKING_SET_SIZE_MAX, DEF_L_SIZE);
}

int
main(int argc, char **argv)
{
	int n, N, opt, l_size, is_random;
	void *buf;
	size_t bytes, count;
	uint64_t cpu_set;
	struct l *head;
	enum prefetch prefetch;

	l_size = DEF_L_SIZE;
	is_random = 0;
	cpu_set = 0;
	n = DEF_WORKING_SET_SIZE_MIN;
	N = DEF_WORKING_SET_SIZE_MAX;
	prefetch = FOLLOW;

	while ((opt = getopt(argc, argv, "hn:N:Rs:c:T:ia")) != -1) {
		switch (opt) {
		case 'h':
			print_usage();
			return EXIT_SUCCESS;

		case 'n':
			n = strtoul(optarg, NULL, 10);

			check_opt_range(n, 'n', WORKING_SET_SIZE_MIN, WORKING_SET_SIZE_MAX);
			break;

		case 'N':
			N = strtoul(optarg, NULL, 10);

			check_opt_range(N, 'N', WORKING_SET_SIZE_MIN, WORKING_SET_SIZE_MAX);
			break;

		case 'R':
			is_random = 1;
			break;

		case 's':
			l_size = strtoul(optarg, NULL, 10);
			check_opt_range(l_size, 's', L_SIZE_MIN, L_SIZE_MAX);
			break;

		case 'c':
			cpu_set = strtoul(optarg, NULL, 16);
			break;

		case 'T':
			snprintf(hugetlbfs, sizeof(hugetlbfs), "%s/pages", optarg);
			break;

		case 'i':
			prefetch = INC;
			break;

		case 'a':
			prefetch = ADDNEXT0;
			break;
		}
	}

	if (n > N)
		n = N;

	if (cpu_set == 0)
		cpu_set = 1;

	bytes = 1llu << N;

	buf = init_mem(bytes);

	init();

	for (; n <= N && done == 0; ++n) {
		bytes = 1llu << n;
		count = bytes / l_size;

		if (is_random)
			head = init_random_order(buf, l_size, count);
		else
			head = init_sequental_order(buf, l_size, count);

		fprintf(stdout, "%d %d\n", n, bench(head, count, cpu_set, prefetch));
	}

	release_mem(buf);

	return EXIT_SUCCESS;
}
