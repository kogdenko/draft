#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#define MY_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MY_IPADDR_SIZE 4

struct my_ipaddr {
	int af;
	uint32_t as_u32[MY_IPADDR_SIZE];
};

static void
my_ipaddr_swap(struct my_ipaddr *dst, struct my_ipaddr *src)
{
	int i;

	for (i = 0; i < MY_IPADDR_SIZE; ++i) {
		dst->as_u32[i] = htonl(src->as_u32[MY_IPADDR_SIZE - 1 - i]);
	}
}

static int
my_ipaddr_parse(struct my_ipaddr *a, const char *s)
{
	int i, rc;
	int af[2] = { AF_INET, AF_INET6 };
	struct my_ipaddr tmp;

	for (i = 0; i < MY_ARRAY_SIZE(af); ++i) {
		rc = inet_pton(af[i], s, tmp.as_u32);
		if (rc == 1) {
			a->af = af[i];
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
my_ipaddr_add(struct my_ipaddr *l, struct my_ipaddr *r)
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
usage()
{
	printf("ip-math-add ip ip\n");
}

int
main(int argc, char **argv)
{
	int i, rc;
	struct my_ipaddr a[2];

	if (argc < 3) {
		usage();
		return EXIT_FAILURE;
	}

	for (i = 0; i < 2; ++i) {
		rc = my_ipaddr_parse(a + i, argv[i + 1]);
		if (rc < 0) {
			usage();
			return EXIT_FAILURE;
		}
	}

	if (a[0].af != a[1].af) {
		goto err;
	}

	//my_ipaddr_print(a);
	//my_ipaddr_print(a + 1);

	my_ipaddr_add(a, a + 1);

	my_ipaddr_print(a);

	return 0;

err:
	usage();
	return EXIT_FAILURE;
}
