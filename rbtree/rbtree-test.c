#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/queue.h>
#include "rbtree.h"

#define PROG_NAME "rbtree-test"

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

CIRCLEQ_HEAD(entry_head, entry);

struct entry {
	struct rbtree_node node;
	CIRCLEQ_ENTRY(entry) list;
	int key;
	int is_del;
};

static int
write_nointr(int fd, const char *buf, size_t count)
{
	ssize_t rc;
	size_t offset;

	offset = 0;

	while (offset < count) {
		if ((rc = write(fd, buf + offset, count - offset)) >= 0)
			offset += rc;
		else if (errno != EINTR)
			return -1;
	}

	return 0;
}

void *
xmalloc(size_t size)
{
	char buf[256];
	void *ptr;
	int len;

	if ((ptr = malloc(size)) == NULL) {
		len = snprintf(buf, sizeof(buf), "malloc(%zu) failed\n", size);
		write_nointr(STDERR_FILENO, buf, len);
		exit(EXIT_FAILURE);
	}

	return ptr;
}

static void
ins_or_del(struct rbtree_node **root, struct entry *entry)
{
	struct rbtree_node **node, *parent;
	struct entry *cur;

	node = root;
	parent = RB_NIL;

	while (*node != RB_NIL) {
		cur = container_of(*node, struct entry, node);

		if (entry->key == cur->key) {
			if (entry->is_del) {
				rbtree_delete(*node, root);
				return;
			}
			break;
		}

		parent = *node;

		if (entry->key > cur->key)
			node = &((*node)->r);
		else
			node = &((*node)->l);
	}
	
	rbtree_insert(&entry->node, root, parent, node);
}

//
//   A   
//   +--B
//   |  +--C
//   |  |  +--E
//   |  |  +--F
//   |  |
//   |  +--D
//   |     +--G
//   |     +--H
//   |
//   +--E
//
static void
print_tail(struct rbtree_node *node)
{
	if (node->p == RB_NIL)
		return;

	print_tail(node->p);

	if (node == node->p->l)
		printf("|  ");
	else
		printf("   ");
}

static void
print_node(struct rbtree_node *node, int width)
{
	int i, nb_children;
	struct rbtree_node *children[2];
	struct entry *entry;

	entry = container_of(node, struct entry, node);

	printf("%*d(%c)\n", width, entry->key, node->color == RB_RED ? 'R' : 'B');

	nb_children = 0;
	if (node->l != RB_NIL)
		children[nb_children++] = node->l;
	if (node->r != RB_NIL)
		children[nb_children++] = node->r;

	for (i = 0; i < nb_children; ++i) {
		print_tail(node);
		printf("+--");
		print_node(children[i], width);
	}
}

static void
add_entry(struct entry_head *head, unsigned int key, int is_del)
{
	struct entry *entry;

	entry = xmalloc(sizeof(*entry));

	entry->key = key;
	entry->is_del = is_del;

	CIRCLEQ_INSERT_TAIL(head, entry, list);
}

static int
add_entries(struct entry_head *head, const char *string, int is_del)
{
	char *ptr, *endptr;
	int done;
	unsigned int cur, prev;

	done = 0;
	prev = -1;
	ptr = (char *)string;

	while (!done && *ptr != '\0') {
		cur = strtoul(ptr, &endptr, 10);

		switch (*endptr) {
		case '\0':
			done = 1;
		case ',':
			if (prev == -1) {
				add_entry(head, cur, is_del);
			} else {
				for (; prev <= cur; ++prev) 
					add_entry(head, prev, is_del);
				prev = -1;
			}
			break;

		case '-':
			prev = cur;
			break;

		default:
			return -1;
		}

		ptr = endptr + 1;
	}

	return 0;
}

static void
print_usage()
{
	printf(
	"Usage: "PROG_NAME" [-h] [-i keys-to-insert ] [ -d keys-to-delete ] [ -w width]\n"
	);
}

int
main(int argc, char **argv)
{
	int rc, opt, width;
	struct entry_head head;
	struct rbtree_node *root;
	struct entry *entry;

	rbtree_init(&root);
	CIRCLEQ_INIT(&head);

	width = 0;
	rc = EXIT_SUCCESS;

	while ((opt = getopt(argc, argv, "hi:d:w:")) != -1) {
		switch (opt) {
		case 'h':
			print_usage();
			goto out;

		case 'i':
			if (add_entries(&head, optarg, 0) == -1)
				goto err;
			break;

		case 'd':
			if (add_entries(&head, optarg, 1) == -1)
				goto err;
			break;

		case 'w':
			width = strtoul(optarg, NULL, 10);
			break;
		}
	}

	CIRCLEQ_FOREACH(entry, &head, list) 
		ins_or_del(&root, entry);

	print_node(root, width);

	goto out;

err:
	printf(PROG_NAME": Invalid option '%c': \"%s\"\n", opt, optarg);
	rc = EXIT_FAILURE;

out:
	while (!CIRCLEQ_EMPTY(&head)) {
		entry = CIRCLEQ_FIRST(&head);
		CIRCLEQ_REMOVE(&head, entry, list);
		free(entry);
	}
	
	return rc;
}
