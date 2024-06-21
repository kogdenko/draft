#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

int
main(int argc, char **argv)
{
	int fd, rc, pid;
	socklen_t addrlen;
	struct sockaddr_un addr;

	pid = getpid();
	printf("%d\n", pid);
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(fd != -1);
	addr.sun_family = AF_UNIX;
	sprintf(addr.sun_path, "/tmp/%d", pid);
	unlink(addr.sun_path);
	rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	assert(rc == 0);
	if (argc > 1) {
		strcpy(addr.sun_path, argv[1]);
		rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
		printf("connect %d\n", rc);
		if (rc == 0) {
			while (1) {
				read(fd, &rc, sizeof(rc));
			}
		}
	} else {
		rc = listen(fd, 5);
		assert(rc == 0);
		addrlen = sizeof(addr);
		rc = accept(fd, (struct sockaddr *)&addr, &addrlen);
		printf("accept %d\n", rc);
		if (rc >= 0) {
			printf("%s\n", addr.sun_path);
		}
	}
	return 0;
}
