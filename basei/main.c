#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <getopt.h>

static int lflag;

static void
usage()
{
	printf(
"Usage: basei [-hl] [-i {2,8,10,16}] [-o {2,8,10,16}] { -n number }\n"
	);
}

static long long
scan2(const char *s)
{
	int i, z;
	long long num;

	num = 0;
	z = 1;
	for (i = 0; s[i] != '\0'; i++) {
		if (s[i] == '1') {
			z = 0;
			num <<= 1;
			num |= 1;
		} else if (s[i] == '0') {
			if (!z) {
				num <<= 1;
			}
		} else {
			return 0;
		}
	}
	return num;
}

static int
getb(long long num, int i)
{
	return (num & (1ll << i)) ? 1 : 0;
}

static void
print2(long long num)
{
	int i, b, is_leading;

	i = CHAR_BIT*sizeof(num) - 1;
	if (lflag) {
		b = getb(num, i);
		is_leading = 1;
		i--;
	} else {
		is_leading = 0;
	}
	for (; i >= 0; i--) {
		if (is_leading && getb(num, i) != b)
			is_leading = 0;
		if (!is_leading)
			printf("%d", getb(num, i));
	}
	if (is_leading)
		printf("%d", b);
	printf("\n");
}

int
main(int argc, char **argv)
{
	int opt, basei, baseo;
	char *s;
	long long num;

	basei = 10;
	baseo = 16;
	s = NULL;
	while ((opt = getopt(argc, argv, "hli:o:n:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return 0;
		case 'l':
			lflag = 1;
			break;
		case 'i':
			basei = strtoul(optarg, NULL, 10);
			break;
		case 'o':
			baseo = strtoul(optarg, NULL, 10);
			break;
		case 'n':
			s = optarg;
			break;
		}
	}
	if (s == NULL) {
		usage();
		return 1;
	}
	switch (basei) {
	case 2:
		num = scan2(s);
		break;
	case 8:
		sscanf(s, "%llo", &num);
		break;
	case 10:
		sscanf(s, "%lld", &num);
		break;
	case 16:
		sscanf(s, "%llx", &num);
		break;
	default:
		usage();
		return 2;
	}
	switch (baseo) {
	case 2:
		print2(num);
		break;
	case 8:
		printf("%llo\n", num);
		break;
	case 10:
		printf("%lld\n", num);
		break;
	case 16:
		printf("%llx\n", num);
		break;
	}
	return 0;
}
