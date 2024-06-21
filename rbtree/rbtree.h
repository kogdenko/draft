#ifndef RBTREE_H
#define RBTREE_H

#define RB_NIL (&rbtree_nil)
#define RB_BLACK 0
#define RB_RED 1

#ifndef container_of
#define container_of(ptr, type, member) \
	(type *)((char *)ptr - (char *)&((type *)(0))->member)
#endif

extern struct rbtree_node rbtree_nil;

struct rbtree_node {
	struct rbtree_node *l, *r, *p;
	int color;
};

void
rbtree_init(struct rbtree_node **root);

struct rbtree_node *
rbtree_min(struct rbtree_node *x);

struct rbtree_node *
rbtree_next(struct rbtree_node *x);

void
rbtree_insert(struct rbtree_node *z, struct rbtree_node **root,
	struct rbtree_node *p, struct rbtree_node **new);

void
rbtree_delete(struct rbtree_node *z, struct rbtree_node **root);

#endif
