#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#define MY_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct my_ipaddr {
	int af;
	uint32_t as_u32[4];
};

static void
my_ipaddr_swap(struct my_ipaddr *dst, struct my_ipaddr *src)
{
	int i, len;

	dst->af = src->af;

	len = dst->af == AF_INET ? 1 : 4;

	for (i = 0; i < len; ++i) {
		dst->as_u32[i] = htonl(src->as_u32[len - 1 - i]);
	}
}

static int
my_ipaddr_parse(struct my_ipaddr *a, const char *s)
{
	int i, rc;
	int af[2] = { AF_INET, AF_INET6 };
	struct my_ipaddr tmp;

	memset(a, 0, sizeof(*a));
	for (i = 0; i < MY_ARRAY_SIZE(af); ++i) {
		rc = inet_pton(af[i], s, tmp.as_u32);
		if (rc == 1) {
			a->af = tmp.af = af[i];
			my_ipaddr_swap(a, &tmp);
			return 0;
		}
	}

	return -EINVAL;
}

static void
my_ipaddr_print(struct my_ipaddr *a)
{
	struct my_ipaddr tmp;
	char s[INET6_ADDRSTRLEN];

	my_ipaddr_swap(&tmp, a);

	inet_ntop(a->af, &tmp.as_u32, s, sizeof(s));

	printf("%s\n", s);

	//for (int i = 0; i < MY_IPADDR_LEN(a); ++i) {
	//	printf("%x ", a->as_u32[i]);
	//}
	//printf("\n");
}

static void
my_ipaddr_add_ipaddr(struct my_ipaddr *l, struct my_ipaddr *r)
{
	int i;
	uint64_t rem;

	rem = 0;
	for (i = 0; i < 4; ++i) {
		rem += (uint64_t)l->as_u32[i] + (uint64_t)r->as_u32[i];
		//printf("rem=%"PRIx64"\n", rem);
		l->as_u32[i] = rem;
		rem >>= 32;
	}
}

static void
my_ipaddr_add_u32(struct my_ipaddr *l, uint32_t r)
{
	int i;
	uint64_t rem;

	rem = r;
	for (i = 0; i < 4; ++i) {
		rem += (uint64_t)l->as_u32[i];
		//printf("rem=%"PRIx64"\n", rem);
		l->as_u32[i] = rem;
		rem >>= 32;
	}
}

static void
usage()
{
	printf("ip-math-add {ipaddr} {ipaddr|u32}\n");
}

int
main(int argc, char **argv)
{
	int rc;
	uint32_t ru32;
	char *endptr;
	struct my_ipaddr lip, rip;

	if (argc < 3) {
		goto err;
	}

	rc = my_ipaddr_parse(&lip, argv[1]);
	if (rc < 0) {
		goto err;
	}

	ru32 = strtoul(argv[2], &endptr, 10);
	if (*endptr == '\0') {
		my_ipaddr_add_u32(&lip, ru32);
	} else {
		rc = my_ipaddr_parse(&rip, argv[2]);
		if (rc < 0) {
			goto err;
		}

		if (lip.af != rip.af) {
			goto err;
		}

		my_ipaddr_add_ipaddr(&lip, &rip);
	}

	my_ipaddr_print(&lip);

	return 0;

err:
	usage();
	return EXIT_FAILURE;
}
