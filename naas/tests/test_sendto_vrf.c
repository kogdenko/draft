#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

static void
usage(const char *prog)
{
	printf("%s [-h] [-V vrf] {-D dst-addr} {-d dst-port} {-x packet}\n"
			"\tFormat of packet is hex dump. Example: 56af74..\n",
			prog);
}

static void
log_verrorf(int errnum, const char *format, va_list ap)
{
	vfprintf(stderr, format, ap);
	if (errnum) {
		fprintf(stderr, " (%d:%s)\n", errnum, strerror(errnum));
	} else {
		fprintf(stderr, "\n");
	}
}

static void
log_errorf(int errnum, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_verrorf(errnum, format, ap);
	va_end(ap);
}

static int
parse_hexdump(u_char *dst, int size, const char *dump)
{
	int i, rc, len, off;
	char hhx[3], *endptr;

	len = strlen(dump);
	if (len & 1) {
		return -EINVAL;
	}

	hhx[2] = '\0';
	off = 0;
	for (i = 0; i < len; i += 2) {
		hhx[0] = dump[i];
		hhx[1] = dump[i + 1];

		rc = strtoul(hhx, &endptr, 16);
		if (*endptr != '\0') {
			return -EINVAL;
		}
		
		if (off == size) {
			return -ENOBUFS;
		}
		dst[off++] = rc;
	}

	return off;
}

int
main(int argc, char **argv)
{
	int rc, fd, opt, len;
	const char *vrf;
	u_char packet[65536];
	struct sockaddr_in dst;


	vrf = NULL;
	len  = 0;
	memset(&dst, 0, sizeof(dst));

	while ((opt = getopt(argc, argv, "hV:D:d:x:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return EXIT_SUCCESS;

		case 'V':
			vrf = optarg;
			break;

		case 'D':
			rc = inet_aton(optarg, &dst.sin_addr);
			if (rc != 1) {
				log_errorf(0, "-D: Invalid format");
				usage(argv[0]);
				return EXIT_FAILURE;
			}

		case 'd':
			dst.sin_port = htons(strtoul(optarg, NULL, 10));
			break;

		case 'x':
			rc = parse_hexdump(packet, sizeof(packet), optarg);
			if (rc < 0) {
				log_errorf(-rc, "-x: Invalid format");
				goto err;
			}
			len = rc;
			break;
		}
	}

	if (dst.sin_addr.s_addr == 0) {
		log_errorf(0, "-D: Not specified");
		goto err;
	}

	if (dst.sin_port == 0) {
		log_errorf(0, "-d: Not specified");
		goto err;
	}

	if (!len) {
		log_errorf(0, "-x: Not specified");
		goto err;
	}
	
	rc = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (rc == -1) {
		log_errorf(errno, "socket() failed");
		goto err;
	}
	fd = rc;

	if (vrf != NULL) {
		rc = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, vrf, strlen(vrf) + 1);
		if (rc == -1) {
			log_errorf(errno, "setsockopt(SOL_SOCKET, SO_BINDTODEVICE, %s) failed",
					vrf);
			goto err;
		}
	}

	rc = sendto(fd, packet, len, 0, (struct sockaddr *)&dst, sizeof(dst));
	if (rc == -1) {
		log_errorf(errno, "sendto(%s:%hu) failed",
				inet_ntoa(dst.sin_addr), ntohs(dst.sin_port));
		goto err;
	}


	return EXIT_SUCCESS;

err:
	usage(argv[0]);
	return EXIT_FAILURE;
}
