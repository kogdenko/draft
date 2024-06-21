#include "log.h"
#include "utils.h"
#include "wrappers.h"

void *
naas_xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (ptr == NULL) {
		naas_die(errno, "malloc(%zu) failed", size);
	}
	return ptr;
}

void *
naas_xmemdup(void *ptr, size_t size)
{
	void *cp;

	cp = naas_xmalloc(size);
	memcpy(cp, ptr, size);
	return cp;
}

char *
naas_strzcpy(char *dest, const char *src, size_t n)
{                                                                                          
	size_t i;
                                             
	for (i = 0; i < n - 1; ++i) {
		if (src[i] == '\0') {
			break;
		}
		dest[i] = src[i];
	}
	dest[i] = '\0';
	return dest;
}

char *
naas_xstrndup(const char *s, size_t n)
{
	size_t len;
	char *cp;

	len = strnlen(s, n);
	cp = naas_xmalloc(len + 1);
	memcpy(cp, s, len);
	cp[len] = '\0';
	return cp;
}

const char *
naas_sockaddr_str(char *dst, int count, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in *si;
	struct sockaddr_un *su; 

	switch (addr->sa_family) {
	case AF_INET:
		if (addrlen >= sizeof(*addr)) {
			si = (struct sockaddr_in *)addr;
			snprintf(dst, count, "%s:%hu", inet_ntoa(si->sin_addr),
					naas_ntoh16(si->sin_port));
			return dst;
		} else {
			return "AF_INET";
		}
		break;

	case AF_UNIX:
		su = (struct sockaddr_un *)addr;
		snprintf(dst, count, "\"%s\"", su->sun_path);
		return dst;

	default:
		snprintf(dst, count, "sa_family=%d", addr->sa_family);
		return dst;
	}
}

int
naas_pipe(int pipefd[2])
{
	int rc;

	rc = pipe(pipefd);
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, -rc, "[SYS] pipe() failed");
	}
	return rc;
}

int
naas_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;
	char addrstr[NAAS_SOCKADDRSTRLEN];

	rc = connect(sockfd, addr, addrlen);
	if (rc == 0) {
		return rc;
	}

	rc = -errno;
	if (rc == -EINPROGRESS) {
		return rc;
	}

	naas_logf(LOG_ERR, -rc, "[SYS] connect(fd:%d, '%s')", sockfd,
			naas_sockaddr_str(addrstr, sizeof(addrstr), addr, addrlen));

	return rc;
}

int
naas_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int rc;
	char addrstr[NAAS_SOCKADDRSTRLEN];

	rc = bind(sockfd, addr, addrlen);
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, -rc, "[SYS] bind(fd:%d, '%s') failed", sockfd,
				naas_sockaddr_str(addrstr, sizeof(addrstr), addr, addrlen));
	}

	return rc;
}

ssize_t
naas_read(int fd, void *buf, size_t count)
{
	ssize_t rc;

	rc = read(fd, buf, count);
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, -rc, "[SYS] read(fd:%d) failed", fd);
	}
	return rc;
}

ssize_t
naas_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;

	rc = write(fd, buf, count);
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, -rc, "[SYS] write(fd:%d) failed", fd);
	}
	return rc;
}

ssize_t
naas_sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	int errnum, log_level;
	ssize_t rc;
	const char *msg;
	const struct sockaddr_in *sin;

	rc = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	if (rc >= 0) {
		errnum = 0;
		log_level = LOG_INFO;
		msg = "ok";
		
	} else {
		errnum = errno;
		rc = -errnum;
		log_level = LOG_ERR;
		msg = "failed";
	}

	sin = NULL;

	if (addrlen >= sizeof(*sin)) {
		sin = (const struct sockaddr_in *)dest_addr;
		if (sin->sin_family != AF_INET) {
			sin = NULL;
		}
	}

	if (sin != NULL) {
		naas_logf(log_level, errnum, "[SYS] sendto(fd:%d, len:%zu, %s:%hu) %s",
				sockfd, len, inet_ntoa(sin->sin_addr), naas_ntoh16(sin->sin_port),
				msg);
	} else {
		naas_logf(log_level, errnum, "[SYS] sendto(fd:%d, len:%zu) %s",
				sockfd, len, msg);
	}
	
	naas_log_hexdump_ascii(LOG_DEBUG, buf, len);

	return rc;
}

int
naas_set_nonblock(int fd, int nonblock)
{
	int rc, old_flags, new_flags;

	rc = naas_fcntl(fd, F_GETFL);
	if (rc < 0) {
		return rc;
	}
	old_flags = rc;
	if (nonblock) {
		new_flags = old_flags | O_NONBLOCK;
	} else {
		new_flags = old_flags & ~O_NONBLOCK;
	}
	if (new_flags == old_flags) {
		return 0;
	} else {
		return naas_fcntl(fd, F_SETFL, new_flags);
	}
}

const char *
naas_inet_ntop(int af, const void *in6, char *addrstr)
{
	return inet_ntop(af, in6, addrstr, INET6_ADDRSTRLEN);
}

int
naas_inet_aton(const char *cp, struct in_addr *inp, unsigned int *maskp)
{
	char buf[INET_ADDRSTRLEN + 16];
	unsigned int mask;
	char *delim, *endptr;

	naas_strzcpy(buf, cp, sizeof(buf));

	delim = strchr(buf, '/');
	if (delim == NULL) {
		mask = 32;
	} else {
		*delim = '\0';
		mask = strtoul(delim + 1, &endptr, 10);
		if (*endptr != '\0' || mask > 32) {
			return -EINVAL;
		}
	}

	if (maskp != NULL) {
		*maskp = mask;
	}

	if (inet_aton(buf, inp) == 0) {
		return -errno;
	} else {
		return 0;
	}
}

const char *
naas_bool_str(int b)
{
	return b ? "true" : "false";
}

void
naas_print_invalidarg(const char *opt, const char *optarg)
{
	fprintf(stderr, "'%s': Invalid argument: '%s'\n", opt, optarg);
}


void
naas_print_unspecifiedarg(const char *opt)
{
	fprintf(stderr, "Unspecified argument: '%s'\n", opt);
}

void
naas_assertion_failed(int err, const char *expr)
{
	naas_logf(LOG_ERR, err, "'%s' failed", expr);
	abort();
}

int
naas_pid_file_open(const char *daemon)
{
	int fd, rc, len;
	char path[PATH_MAX];
	char buf[32];

	snprintf(path, sizeof(path), "/var/run/%s.pid", daemon);

	rc = open(path, O_CREAT|O_RDWR, 0666);
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, -rc, "open('%s') failed", path);
		return rc;
	}
	fd = rc;
	rc = flock(fd, LOCK_EX|LOCK_NB);
	if (rc == -1) {
		rc = -errno;
	}
	if (rc == -EWOULDBLOCK) {
		naas_logf(LOG_ERR, 0, "Daemon already running");
		return rc;
	} else if (rc < 0) {
		naas_logf(LOG_ERR, -rc, "flock('%s') failed", path);
		close(fd);
		return rc;
	}
	len = snprintf(buf, sizeof(buf), "%d", (int)getpid());
	rc = write(fd, buf, len);
	if (rc == -1) {
		rc = -errno;
		naas_logf(LOG_ERR, -rc, "write('%s') failed", path);
		close(fd);
		return rc;
	} else {
		return fd;
	}
}


void
naas_pid_file_close(int fd, const char *daemon)
{
	close(fd);
}

void
naas_thread_init(struct naas_thread *thr)
{
	thr->thr_started = 0;
}

void
naas_thread_start(struct naas_thread *thr, naas_thread_f fn, void *arg)
{
	int rc;

	NAAS_WRITE_ONCE(thr->thr_done, 0);
	thr->thr_arg = arg;

	rc = pthread_attr_init(&thr->thr_attr);
	if (rc) {
		assert(rc > 0);
		rc = -rc;
		naas_die(-rc, "[SYS] pthread_attr_init() failed");
	}

	rc = pthread_create(&thr->thr_thread, &thr->thr_attr, (naas_pthread_f)fn, thr);
	if (rc) {
		assert(rc > 0);
		rc = -rc;
		naas_die(-rc, "[SYS] pthread_create() failed");
		pthread_attr_destroy(&thr->thr_attr);
	}

	thr->thr_started = 1;
}

void
naas_thread_join(struct naas_thread *thr)
{
	if (thr->thr_started) {
		pthread_join(thr->thr_thread, NULL);
		pthread_attr_destroy(&thr->thr_attr);
		thr->thr_started = 0;
	}
}

void
naas_mutex_init(pthread_mutex_t *mutex)
{
	int rc;
	pthread_mutexattr_t attr;

	rc = pthread_mutexattr_init(&attr);
	if (rc) {
		assert(rc > 0);
		rc = -rc;
		naas_die(-rc, "[SYS] pthread_mutexattr_init() failed");
	}

	rc = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	if (rc) {
		assert(rc > 0);
		rc = -rc;
		naas_die(-rc, "[SYS] pthread_mutexattr_settype(PTHREAD_MUTEX_RECURSIVE) failed");
	}

	rc = pthread_mutex_init(mutex, &attr);
	if (rc) {
		assert(rc > 0);
		rc = -rc;
		naas_die(-rc, "[SYS] pthread_mutex_init() failed");
	}
}

void
naas_mutex_destroy(pthread_mutex_t *mutex)
{
	pthread_mutex_destroy(mutex);
}
