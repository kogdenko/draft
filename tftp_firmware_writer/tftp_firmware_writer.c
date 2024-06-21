#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>

#define OPCODE_RPQ 1
#define OPCODE_WRQ 2
#define OPCODE_DATA 3
#define OPCODE_ACK 4
#define OPCODE_ERROR 5

int src_fd;
int verbose;

static void die(int errnum, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

static void info(const char *format, ...)
	__attribute__((format(printf, 1, 2)));

static void
die(int errnum, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	if (errnum) {
		fprintf(stderr, " (%d:%s)", errnum, strerror(errnum));
	}
	fprintf(stderr, "\n");
	exit(EXIT_FAILURE);
}

static void
info(const char *format, ...)
{
	va_list ap;

	if (verbose) {
		va_start(ap, format);
		vprintf(format, ap);
		va_end(ap);
	}
}

static void
send_DATA(int fd, struct sockaddr_in *peer, int block)
{
	int rc, len;
	struct stat stat;
	uint8_t buf[1024];

	if (fstat(src_fd, &stat) == -1) {
		die(errno, "fstat() failed");
	}
	*((uint16_t *)buf + 0) = htons(OPCODE_DATA);
	*((uint16_t *)buf + 1) = htons(block + 1);
	if (stat.st_size <= block * 512) {
		len = 0;
	} else {
		rc = lseek(src_fd, block * 512, SEEK_SET);
		if (rc == -1) {
			die(errno, "lseek() failed");
		}
		len = read(src_fd, buf + 4, 512);
		if (len == -1) {
			die(errno, "read() failed");
		}
	}
	info("snd DATA: block=%u, len=%d\n", block + 1, len);
	rc = sendto(fd, buf, 4 + len, 0, (struct sockaddr *)peer, sizeof(*peer));
	if (rc == -1) {
		die(0, "sendto(%s:%hu) failed",
			inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
	}
}

static void
process_RPQ(int fd, struct sockaddr_in *peer, uint8_t *rpq, int rpq_len)
{
	char *filename;
	int i;

	filename = NULL;
	for (i = 2; i < rpq_len; ++i) {
		if (rpq[i] == '\0') {
			filename = (char *)rpq + 2;
			break;
		}
	}
	if (filename != NULL) {
		info("rcv RPQ: filename='%s'\n", filename);
		send_DATA(fd, peer, 0);
	}
}

static void
process_ACK(int fd, struct sockaddr_in *peer, uint8_t *ack, int ack_len)
{
	uint16_t acked;

	acked = ntohs(*((uint16_t *)ack + 1));
	info("rcv ACK: block=%u\n", acked);
	send_DATA(fd, peer, acked);
}

static void
process(int fd)
{
	uint8_t buf[1024];
	int len;
	uint16_t opcode;
	socklen_t addrlen;
	struct sockaddr_in addr;

	addrlen = sizeof(addr);
	len = recvfrom(fd, buf, sizeof(buf), 0,
		(struct sockaddr *)&addr, &addrlen);
	if (len == -1) {
		die(errno, "recvfrom() failed");
	}
	info("rcv %d bytes\n", len);
	if (len < 4) {
		return;
	}
	opcode = ntohs(*((uint16_t *)buf));
	if (addrlen > sizeof(addr) || addr.sin_family != AF_INET) {
		return;
	}
	switch (opcode) {
	case OPCODE_RPQ:
		process_RPQ(fd, &addr, buf, len);
		break;
	case OPCODE_ACK:
		process_ACK(fd, &addr, buf, len);
		break;
	}
}

static void
usage()
{
	printf(
		"Usage: tftp_fwwr [options] {fw_file}\n"
		"\n"
		"\tOptions:\n"
		"\t-h       Print this help\n"
		"\t-v       Be vebose\n"
		"\t-b ip    Bind to ip (default: 0.0.0.0)\n"
		"\t-p port  Bind to port (default: 69)\n"
	);
}

int
main(int argc, char **argv)
{
	int fd, rc, opt;
	struct pollfd pfd;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(69);
	addr.sin_addr.s_addr = 0;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		die(errno, "socket(AF_INET, SOCK_DGRAM) failed");
	}
	while ((opt = getopt(argc, argv, "hvb:p:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return 0;
		case 'v':
			verbose = 1;
			break;
		case 'b':
			rc = inet_aton(optarg, &addr.sin_addr);
			if (rc != 1) {
				die(0, "invalid ip address: '%s'", optarg);
			}
			break;
		case 'p':
			addr.sin_port = htons(strtoul(optarg, NULL, 10));
			break;
		}
	}
	if (optind >= argc) {
		usage();
		return 1;
	}
	src_fd = open(argv[optind], O_RDONLY);
	if (src_fd == -1) {
		die(0, "open('%s') failed", argv[optind]);
	}
	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (rc == -1) {
		die(errno, "bind(%s:%hu) failed",
			inet_ntoa(addr.sin_addr),
			ntohs(addr.sin_port));
	}
	pfd.fd = fd;
	pfd.events = POLLIN;
	while (1) {
		rc = poll(&pfd, 1, 500);
		if (rc == -1) {
			die(errno, "poll() failed");
		}
		if (pfd.revents & (POLLERR|POLLNVAL|POLLHUP)) {
			break;			
		}
		if (pfd.revents & POLLIN) {
			process(fd);
		}
	}
	close(src_fd);
	close(fd);
	return 0;
}
