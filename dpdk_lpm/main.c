#include <assert.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <rte_eal.h>
#include <rte_lpm.h>
// /build/l2fwd -l 0 --no-huge --no-pci
static int
parse_net(char *s, struct in_addr *in)
{
	int rc, len;
	char *p, *endptr;
	p = strchr(s, '/');
	if (p == NULL) {
		len = 32;
	} else {
		len = strtoul(p + 1, &endptr, 10);
		*p = '\0';
	}
	rc = inet_aton(s, in);
	if (p != NULL) {
		*p = '/';
	}
	if (rc != 1) {
		return -1;
	}
	if (*endptr != '\0' && strchr("\r\n\t ", *endptr) == NULL) {
		return -1;
	}
	if (len > 32) {
		return -1;
	}
	return len;
}
#define XXX(x) ntohl(x)
static void
search_file(struct rte_lpm *lpm, const char *filename)
{
	char buf[256];
	char *s;
	int i, rc, line, nr_keys, found;
	uint8_t next_hop;
	struct in_addr in;
	struct timeval tv0, tv1;
	FILE *file;
	uint32_t *keys;
	file = fopen(filename, "r");
	if (file == NULL) {
		fprintf(stderr, "fopen('%s') failed (%s)\n",
			filename, strerror(errno));
		return;
	}
	found = 0;
	nr_keys = 0;
	keys = malloc(10000 * sizeof(uint32_t));
	line = 0;
	while ((s = fgets(buf, sizeof(buf), file)) != NULL) {
		line++;
		rc = parse_net(s, &in);
		if (rc == -1) {
			fprintf(stderr, "error at '%s':%d\n", filename, line);
			continue;
		}
		if (nr_keys == 10000) {
			break;
		}
		keys[nr_keys++] = XXX(in.s_addr);
	}
	fclose(file);
	gettimeofday(&tv0, NULL);
	for (i = 0; i < nr_keys; ++i) {
		rc = rte_lpm_lookup(lpm, keys[i], &next_hop);
		if (rc == 0) {
			found++;
		}
	}
	gettimeofday(&tv1, NULL);
	free(keys);
	printf("found=%d(%d), dt=%luus\n", found, nr_keys,
		1000000 * (tv1.tv_sec - tv0.tv_sec) + tv1.tv_usec - tv0.tv_usec);
}
static void
add_file(struct rte_lpm *lpm, const char *filename)
{
	char buf[256];
	char *s;
	int rc, line;
	struct in_addr in;
	FILE *file;
	file = fopen(filename, "r");
	if (file == NULL) {
		fprintf(stderr, "fopen('%s') failed (%s)\n",
			filename, strerror(errno));
		return;
	}
	line = 0;
	while ((s = fgets(buf, sizeof(buf), file)) != NULL) {
		line++;
		rc = parse_net(s, &in);
		if (rc == -1) {
			fprintf(stderr, "error at '%s':%d\n", filename, line);
			continue;
		}
		rc = rte_lpm_add(lpm, XXX(in.s_addr), rc, 0);
		if (rc != 0) {
			fprintf(stderr, "add failed at '%s':%d\n", filename, line);
		}
	}
	fclose(file);
}

int
main(int argc, char **argv)
{
	int rc, opt;
	struct rte_lpm *lpm;
	rc = 0;
	rc = rte_eal_init(argc, argv);
	assert(rc >= 0);
	argc -= rc;
	argv += rc;
	lpm = rte_lpm_create("x", 0, 10000, 0);
	assert(lpm);
	printf("lpm=%p\n", lpm);
	while ((opt = getopt(argc, argv, "A:S:")) != -1) {
		switch (opt) {
		case 'A':
			add_file(lpm, optarg);
			break;
		case 'S':
			search_file(lpm, optarg);
			break;
		}
	}
	return 0;
}
