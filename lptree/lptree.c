#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct rule;

LIST_HEAD(rule_head, rule);

struct rule {
	LIST_ENTRY(rule) list;
	struct node *node;
	uint32_t key;
	uint32_t k;
	int depth;
	int d;
};

struct node {
	union {
		struct {
			uint32_t children[256];
			struct rule_head rules;
			struct rule *rule;
			struct node *parent;
		};
		LIST_ENTRY(node) list;
	};
};

LIST_HEAD(node_head, node);

struct lptree {
	struct rule *rules;
	struct node *nodes;
	struct node *root;
	int nr_nodes;
	int nr_rules;
	struct node_head free_nodes;
	struct rule_head free_rules;
};

#define RULE_FLAG 0x80000000

static int
get_node_id(struct lptree *tree, struct node *node)
{
	return node - tree->nodes;
}

static int
get_rule_id(struct lptree *tree, struct rule *rule)
{
	uint32_t idx;
	idx = rule - tree->rules;
	return idx | RULE_FLAG;
}

static struct node *
get_node(struct lptree *tree, uint32_t node_id)
{
	assert(node_id);
	return tree->nodes + node_id;
}

static struct rule *
get_rule(struct lptree *tree, uint32_t rule_id)
{
	uint32_t idx;
	assert(rule_id & RULE_FLAG);
	idx = (rule_id & (~RULE_FLAG));
	return tree->rules + idx;
}

static struct node *
alloc_node(struct lptree *tree, struct node *parent)
{
	struct node *node;
	assert(!LIST_EMPTY(&tree->free_nodes));	
	node = LIST_FIRST(&tree->free_nodes);
	LIST_REMOVE(node, list);
	memset(node, 0, sizeof(*node));
	LIST_INIT(&node->rules);
	node->parent = parent;
	tree->nr_nodes++;
	return node;
}

void
free_node(struct lptree *tree, struct node *node)
{
	assert(LIST_EMPTY(&node->rules));
	LIST_INSERT_HEAD(&tree->free_nodes, node, list);
	tree->nr_nodes--;
}

static void
free_rule(struct lptree *tree, struct rule *rule)
{
	LIST_INSERT_HEAD(&tree->free_rules, rule, list);
	tree->nr_rules--;
}

static void *
to_erule(struct rule *irule)
{
	if (irule == NULL) {
		return NULL;
	}
	return irule + 1;
}

static struct rule *
to_irule(void *erule)
{
	if (erule == NULL) {
		return NULL;
	}
	return (struct rule *)(((uint8_t *)erule) - sizeof(struct rule));
}

static int
get_or_create_rule(struct lptree *tree, struct rule **prule,
                   struct node *node, int create,
                   uint32_t key, int depth)
{
	int rc;
	struct rule *rule, *after;
	after = NULL;
	rc = 0;
	LIST_FOREACH(rule, &node->rules, list) {
		if (rule->depth == depth) {
			if (rule->key == key) {
				rc = -EEXIST;
				break;
			}
		} else if (depth < rule->depth) {
			break;
		} else {
			after = rule;
		}
	}
	if (rc == 0 && create) {
		assert(!LIST_EMPTY(&tree->free_rules));	
		rule = LIST_FIRST(&tree->free_rules);
		LIST_REMOVE(rule, list);
		rule->key = key;
		rule->depth = depth;
		rule->node = node;
		tree->nr_rules++;
		if (after == NULL) {
			LIST_INSERT_HEAD(&node->rules, rule, list);
		} else {
			LIST_INSERT_AFTER(after, rule, list);
		}
	}
	*prule = rule;
	return rc;
}

static int
lptree_init(struct lptree *tree, int n, int rule_size)
{
	int i;
	struct node *node;
	struct rule *rule;
	assert(n);
	LIST_INIT(&tree->free_nodes);
	LIST_INIT(&tree->free_rules);
	tree->nr_nodes = 0;
	tree->nr_rules = 0;
	tree->nodes = malloc(n * sizeof(*node));
	assert(tree->nodes != NULL);
	tree->rules = malloc(n * (sizeof(*rule) + rule_size));
	assert(tree->rules != NULL);
	for (i = 0; i < n; ++i) {
		node = tree->nodes + i;
		rule = tree->rules + i;
		LIST_INSERT_HEAD(&tree->free_nodes, node, list);
		LIST_INSERT_HEAD(&tree->free_rules, rule, list);
	}
	tree->root = alloc_node(tree, NULL);
	return 0;
}

//static uint32_t


static int
lptree_search(struct lptree *tree, void **perule, uint32_t key)
{
	int i;
	uint32_t k, id;
	struct node *node;
	struct rule *rule;
	node = tree->root;
	for (i = 0; i < 4; ++i) {
		k = (key >> ((3 - i) << 3)) & 0x000000FF;
		id = node->children[k];
		if (id == 0) {
			break;
		} else if (id & RULE_FLAG) {
			rule = get_rule(tree, id);
			goto found;
		} else {
			node = get_node(tree, id);
		}
	}
	if (node->rule != NULL) {
		rule = node->rule;
		goto found;
	}
	return -ESRCH;
found:
	if (perule != NULL) {
		*perule = to_erule(rule);
	}
	return 0;
}

static struct node *
set_node(struct lptree *tree, struct node *parent, int idx)
{
	uint32_t id;
	struct node *node;
	struct rule *rule;
	id = parent->children[idx];
	if (id & RULE_FLAG) {
		rule = get_rule(tree, id);
		node = alloc_node(tree, parent);
		node->rule = rule;
	} else {
		if (id == 0) {
			node = alloc_node(tree, parent);
		} else {
			node = get_node(tree, id);
		}
	}
	parent->children[idx] = get_node_id(tree, node);
	return node;
}

static void
unset_node(struct lptree *tree, struct node *node)
{
	int i;
	uint32_t node_id, id;
	struct node *parent;
	parent = node->parent;
	node_id = get_node_id(tree, node);
	for (i = 0; i < 256; ++i) {
		if (parent->children[i] == node_id) {
			if (node->rule != NULL) {
				id = get_rule_id(tree, node->rule);
			} else {
				id = 0;
			}
			parent->children[i] = id;
			break;
		}
	}
}

static void
set_rule(struct lptree *tree, struct rule *new)
{
	int i, n;
	uint32_t *pid, id, rule_id;
	struct node *node;
	struct rule *rule;
	rule_id = get_rule_id(tree, new);
	n = 1 << (8 - new->d);
	assert(new->k + n <= 256);
	for (i = 0; i < n; ++i) {
		pid = new->node->children + new->k + i;
		id = *pid;
		if (id & RULE_FLAG) {
			rule = get_rule(tree, id);
			if (new->depth > rule->depth) {
				*pid = rule_id;
			}
		} else if (id == 0) {
			*pid = rule_id;
		} else {
			node = get_node(tree, id);
			rule = node->rule;
			if (rule == NULL || new->depth > rule->depth) {
				node->rule = new;
			}
		}
	}
}

static void
unset_rule(struct lptree *tree, struct node *node, struct rule *rule)
{
	int i;
	uint32_t rule_id, id;
	struct node *child;
	rule_id = get_rule_id(tree, rule);
	for (i = 0; i < 256; ++i) {
		id = node->children[i];
		if (id & RULE_FLAG) {
			if (id == rule_id) {
				node->children[i] = 0;
			}
		} else if (id) {
			child = get_node(tree, id);
			if (child->rule == rule) {
				child->rule = NULL;
			}
		}
	}
}

static int
node_empty(struct node *node)
{
	uint32_t id;
	int i;
	if (node->parent == NULL) {
		return 0;
	}
	if (!LIST_EMPTY(&node->rules)) {
		return 0;
	}
	for (i = 0; i < 256; ++i) {
		id = node->children[i];
		assert((id & RULE_FLAG) == 0);
		if (id) {
			return 0;
		}
	}
	return 1;
}

static void
del_node(struct lptree *tree, struct node *node)
{
	int i;
	uint32_t id;
	struct node *parent, *child;
	struct rule *rule;
	parent = node->parent;
	unset_node(tree, node);
	for (i = 0; i < 256; ++i) {
		id = node->children[i];
		if (id != 0 && (id & RULE_FLAG) == 0) {
			child = get_node(tree, id);
			del_node(tree, child);
		}
	}
	while (!LIST_EMPTY(&node->rules)) {
		rule = LIST_FIRST(&node->rules);
		LIST_REMOVE(rule, list);
		free_rule(tree, rule);
	}
	if (parent == NULL) {
		// This is root
		memset(node->children, 0, sizeof(node->children));
	} else {
		free_node(tree, node);
		if (node_empty(parent)) {
			del_node(tree, parent);
		}
	}
}

static void
lptree_del(struct lptree *tree, void *erule)
{
	struct node *node;
	struct rule *rule, *cur;
	rule = to_irule(erule);
	LIST_REMOVE(rule, list);
	node = rule->node;
	unset_rule(tree, node, rule);
	LIST_FOREACH(cur, &node->rules, list) {
		if (cur->depth < rule->depth) {
			set_rule(tree, cur);
		} else {
			break;
		}
	}
	free_rule(tree, rule);
	if (node_empty(node)) {
		del_node(tree, node);
	}
}

static int
create_dryrun(struct lptree *tree)
{
	int n;
	struct node *node;
	if (LIST_EMPTY(&tree->free_rules)) {
		return -ENOMEM;
	}
	n = 0;
	LIST_FOREACH(node, &tree->free_nodes, list) {
		++n;
		if (n == 4) {
			return 0;
		}
	}
	return -ENOMEM;
}

static int
lptree_get_or_add(struct lptree *tree, void **perule,
                    int create, uint32_t key, int depth)
{
	int i, d, rc;
	uint32_t k, m;
	struct node *node;
	struct rule *rule;
	assert(depth > 0);
	assert(depth <= 32);
	if (create) {
		rc = create_dryrun(tree);
		if (rc) {
			return rc;
		}
	}
	node = tree->root;
	for (i = 0; i < 4; ++i) {
		k = (key >> ((3 - i) << 3)) & 0x000000FF;
		d = depth - (i << 3);
		assert(d);
		assert(k < 256);
		if (d > 8) {
			node = set_node(tree, node, k);
		} else {
			m = (0xff << (8 - d));
			k &= m;
			break;
		}
	}
	rc = get_or_create_rule(tree, &rule, node, create, key, depth);
	if (perule != NULL) {
		*perule = to_erule(rule);
	}
	if (create == 0) {
		switch (-rc) {
		case EEXIST:
			return 0;
		case 0:
			return -ESRCH;
		default:
			return rc;
		}
	} else {
		if (rc) {
			return rc;
		}
		rule->k = k;
		rule->d = d;
		set_rule(tree, rule);
		return 0;
	}
}

int
lptree_get(struct lptree *tree, void **perule,
             uint32_t key, int depth)
{
	return lptree_get_or_add(tree, perule, 0, key, depth);
}

int
lptree_add(struct lptree *tree, void **perule,
             uint32_t key, int depth)
{
	return lptree_get_or_add(tree, perule, 1, key, depth);
}

uint32_t
lptree_rule_key(void *erule)
{
	struct rule *rule;
	rule = to_irule(erule);
	return rule->key;
}

int
lptree_rule_depth(void *erule)
{
	struct rule *rule;
	rule = to_irule(erule);
	return rule->depth;
}
//===========================================================
static int
parse_net(char *s, struct in_addr *in)
{
	int rc, len;
	char *p, *endptr;
	p = strchr(s, '/');
	if (p == NULL) {
		len = 32;
	} else {
		len = strtoul(p + 1, &endptr, 10);
		*p = '\0';
	}
	rc = inet_aton(s, in);
	if (p != NULL) {
		*p = '/';
	}
	if (rc != 1) {
		return -1;
	}
	if (*endptr != '\0' && strchr("\r\n\t ", *endptr) == NULL) {
		return -1;
	}
	if (len > 32) {
		return -1;
	}
	return len;
}

static void
read_file(struct lptree *tree, const char *filename, int action)
{
	char buf[256];
	char *s;
	void *rule;
	int rc, line;
	struct in_addr in;
	FILE *file;
	file = fopen(filename, "r");
	if (file == NULL) {
		fprintf(stderr, "fopen('%s') failed (%s)\n",
			filename, strerror(errno));
		return;
	}
	line = 0;
	while ((s = fgets(buf, sizeof(buf), file)) != NULL) {
		line++;
		rc = parse_net(s, &in);
		if (rc == -1) {
			fprintf(stderr, "error at '%s':%d\n", filename, line);
			continue;
		}
		if (action) {
			rc = lptree_add(tree, NULL, ntohl(in.s_addr), rc);
			if (rc != 0) {
				fprintf(stderr, "add failed at '%s':%d (%s)\n",
					filename, line, strerror(-rc));
			}
		} else {
			rc = lptree_get(tree, &rule, ntohl(in.s_addr), rc);
			if (rc < 0) {
				fprintf(stderr, "del failed at '%s':%d\n",
					filename, line);
				continue;
			}
			lptree_del(tree, rule);
		}
	}
	fclose(file);
}

static void
search_file(struct lptree *tree, const char *filename)
{
	char buf[256];
	char *s;
	void *rule;
	int i, rc, line, nr_keys, found;
	struct in_addr in;
	struct timeval tv0, tv1;
	FILE *file;
	uint32_t *keys;
	file = fopen(filename, "r");
	if (file == NULL) {
		fprintf(stderr, "fopen('%s') failed (%s)\n",
			filename, strerror(errno));
		return;
	}
	found = 0;
	nr_keys = 0;
	keys = malloc(10000 * sizeof(uint32_t));
	line = 0;
	while ((s = fgets(buf, sizeof(buf), file)) != NULL) {
		line++;
		rc = parse_net(s, &in);
		if (rc == -1) {
			fprintf(stderr, "error at '%s':%d\n", filename, line);
			continue;
		}
		if (nr_keys == 10000) {
			break;
		}
		keys[nr_keys++] = ntohl(in.s_addr);
	}
	fclose(file);
	gettimeofday(&tv0, NULL);
	for (i = 0; i < nr_keys; ++i) {
		if (lptree_search(tree, &rule, keys[i]) == 0) {
			found++;
		}
	}
	gettimeofday(&tv1, NULL);
	free(keys);
	printf("found=%d(%d), dt=%luus\n", found, nr_keys,
		1000000 * (tv1.tv_sec - tv0.tv_sec) + tv1.tv_usec - tv0.tv_usec);
}

static void
invalid_arg(int opt, char *arg)
{
	printf("Invalid argument '-%c': '%s'\n", opt, arg);
	exit(1);
}

int
main(int argc, char **argv)
{
	int rc, len, opt, idx;
	void *rule;
	struct in_addr in;
	struct lptree tree;
	//int x, y, z;
	//x = strtoul(argv[1], NULL, 10);
	//y = strtoul(argv[2], NULL, 10);
	//z = x ^ y;
	//printf("%x^%x=%x\n", x, y, z);
	//return 0;
	//printf("%d\n", fls(strtoul(argv[1], NULL, 10)));
	//return 0;
	idx = 1;
	lptree_init(&tree, 10000, 0);
//	assert(0);
	while ((opt = getopt(argc, argv, "a:A:d:D:s:S:p")) != -1) {
		switch (opt) {
		case 'a':
			len = parse_net(optarg, &in);
			if (len == -1) {
				invalid_arg(opt, optarg);
			}
			rc = lptree_add(&tree, &rule, ntohl(in.s_addr), len);
			idx++;
			printf("Add: %s/%d (%d)\n", inet_ntoa(in), len, rc);
			break;
		case 'A':
			read_file(&tree, optarg, 1);
			break;
		case 'd':
			len = parse_net(optarg, &in);
			if (len == -1) {
				invalid_arg(opt, optarg);
			}
			rc = lptree_get(&tree, &rule, ntohl(in.s_addr), len);
			printf("Remove: %s/%d (%d)\n", inet_ntoa(in), len, rc);
			lptree_del(&tree, rule);
			break;
		case 'D':
			read_file(&tree, optarg, 0);
			break;
		case 's':
			rc = inet_aton(optarg, &in);
			if (rc != 1) {
				invalid_arg(opt, optarg);
			}
			rc = lptree_search(&tree, &rule, ntohl(in.s_addr));
			printf("Search: %d", rc);
			if (rc == 0) {
				in.s_addr = htonl(lptree_rule_key(rule));
				printf(": %s/%d", inet_ntoa(in),
					lptree_rule_depth(rule));
			} else {
				printf(" (%s)", strerror(-rc));
			}
			printf("\n");
			break;
		case 'S':
			search_file(&tree, optarg);
			break;
//		case 'p':
//			lptree_print(&tree);
//			break;
		}
	}

	printf("Number of nodes: %d\n", tree.nr_nodes);

	return 0;
}
