#ifndef LIBNAAS_WRAPPERS_H
#define LIBNAAS_WRAPPERS_H

#include "log.h"

#define naas_open(pathname, flags, ...) \
({ \
	int rc; \
	rc = open(pathname, flags, ##__VA_ARGS__); \
	if (rc == -1) { \
		rc = -errno; \
		naas_logf(LOG_ERR, -rc, "[SYS] open(%s, %s) failed", #pathname, #flags); \
	} \
	rc; \
})

#define naas_socket(domain, type, protocol) \
({ \
	int rc; \
	rc = socket(domain, type, protocol); \
	if (rc == -1) { \
		rc = -errno; \
		naas_logf(LOG_ERR, -rc, "[SYS] socket(%s, %s, %s) failed", \
				#domain, #type, #protocol); \
	} \
	rc; \
})

#define naas_fcntl(fd, cmd, ...) \
({ \
	int rc; \
	rc = fcntl(fd, cmd, ##__VA_ARGS__); \
	if (rc == -1) { \
		rc = -errno; \
		naas_logf(LOG_ERR, -rc, "[SYS] fcntl(fd:%d, %s) failed", fd, #cmd); \
	} \
	rc; \
})

#define naas_setsockopt(sockfd, level, optname, optval, optlen) \
({ \
	int rc; \
	rc = setsockopt(sockfd, level, optname, optval, optlen); \
	if (rc == -1) { \
		rc = -errno; \
		naas_logf(LOG_ERR, -rc, "[SYS] setsockopt(fd:%d, %s, %s) failed", \
				sockfd, #level, #optname); \
	} \
	rc; \
})

#endif // LIBNAAS_WRAPPERS_H
