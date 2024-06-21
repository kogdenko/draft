#define _GNU_SOURCE
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>

int done;

void
sig_handler(int n)
{
	done = 1;
}

static __thread int counter = 0;

int
fn(void *x)
{
	int i;
	sigset_t mask;

	sigfillset(&mask);
	sigprocmask(SIG_SETMASK, &mask, NULL);
	for (i = 0; i < 10; ++i) {
		printf("works! %d\n", counter);
		usleep(500 * 1000);
	}
	printf("clone done\n");
	return 1;
}

int
main(int argc, char **argv)
{
	int rc, flags, stack_size, status, clone_pid;
	uint8_t *stack;

	printf("pid=%d\n", (int)getpid());
	signal(SIGUSR1, sig_handler);
	stack_size = 1024 * 1024;
	stack = malloc(stack_size);
	stack += stack_size;
	flags = 0;
	flags |= CLONE_VM;
//	flags |= CLONE_THREAD;
//	flags |= CLONE_SIGHAND;
	flags |= CLONE_FILES;
	rc = clone(fn, stack, flags, NULL);
	assert(rc != -1);
	clone_pid = rc;
	printf("clone_pid=%d\n", clone_pid);
	int clone_done = 0;
	while (!done) {
		usleep(500*1000);
		counter++;
		printf("master %d\n", counter);
		if (0 && clone_done == 0) {
			rc = waitpid(clone_pid, &status, /*__WALL*/0);
			if (rc == -1) {
				perror("waitpid");
			} else {
				printf("status=%d\n", status);
				clone_done = 1;
			}
		}
	}
	printf("done\n");
	return 0;
}
