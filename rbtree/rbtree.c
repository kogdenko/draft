#ifdef RBTREE_DEBUG
#include <assert.h>
#endif
#include "rbtree.h"

#ifdef RBTREE_DEBUG
#define rb_assert(expression) assert(expression)
#else
#define rb_assert(expression) 
#endif

struct rbtree_node rbtree_nil = {
	.l = RB_NIL,
	.r = RB_NIL,
	.p = RB_NIL,
	.color = RB_BLACK
};

void
rbtree_init(struct rbtree_node **root)
{
	*root = RB_NIL;
}

static void
rbtree_lrotate(struct rbtree_node *x, struct rbtree_node **root)
{
	struct rbtree_node *y;

	y = x->r;

	rb_assert(y != RB_NIL);

	if (y->l != RB_NIL)
		y->l->p = x;

	x->r = y->l;
	y->l = x;

	if (x->p == RB_NIL)
		*root = y;
	else if (x->p->l == x)
		x->p->l = y;
	else
		x->p->r = y;

	y->p = x->p;
	x->p = y;
}

static void
rbtree_rrotate(struct rbtree_node *x, struct rbtree_node **root)
{
	struct rbtree_node *y;

	y = x->l;

	rb_assert(y != RB_NIL);

	if (y->r != RB_NIL)
		y->r->p = x;

	x->l = y->r;
	y->r = x;

	if (x->p == RB_NIL)
		*root = y;
	else if (x->p->l == x)
		x->p->l = y;
	else
		x->p->r = y;

	y->p = x->p;
	x->p = y;
}

int
rbtree_red_odd(struct rbtree_node *node)
{
	if (node->color == RB_RED) {
		if (node->l->color != RB_BLACK || node->r->color != RB_BLACK)
			return 0;
	}

	return node == RB_NIL || (rbtree_red_odd(node->l) && rbtree_red_odd(node->r));
}

int
rbtree_black_depth(struct rbtree_node *node)
{
	int l_bd, r_bd, bd;

	if (node == RB_NIL) {
		return 0;
	} else {
		if ((l_bd = rbtree_black_depth(node->l)) < 0 ||
		    (r_bd = rbtree_black_depth(node->r)) < 0 || l_bd != r_bd) {

			return -1;
		}

		bd = l_bd;

		if (node->color == RB_BLACK)
			++bd;

		return bd;
	}
}

static inline void
rbtree_check_invariant(struct rbtree_node *root)
{
	rb_assert(rbtree_black_depth(root) >= 0);
	rb_assert(rbtree_red_odd(root));
}

void
rbtree_insert(struct rbtree_node *z, struct rbtree_node **root,
	struct rbtree_node *p, struct rbtree_node **new)
{
	struct rbtree_node *y;

	rb_assert(*new == RB_NIL);

	*new = z;

	z->p = p;
	z->l = z->r = RB_NIL;
	z->color = RB_RED;

	while (z->p->color == RB_RED) {
		if (z->p == z->p->p->l) {
			y = z->p->p->r;
			if (y->color == RB_RED) {
				z->p->color = RB_BLACK;
				y->color = RB_BLACK;
				z->p->p->color = RB_RED;
				z = z->p->p;
			} else {
				if (z == z->p->r) {
					z = z->p; 
					rbtree_lrotate(z, root);
				}
				z->p->color = RB_BLACK;
				z->p->p->color = RB_RED;
				rbtree_rrotate(z->p->p, root);
			}
		} else {
			y = z->p->p->l;
			if (y->color == RB_RED) {
				z->p->color = RB_BLACK;
				y->color = RB_BLACK;
				z->p->p->color = RB_RED;
				z = z->p->p;
			} else {
				if (z == z->p->l) {
					z = z->p; 
					rbtree_rrotate(z, root);
				}
				
				z->p->color = RB_BLACK;
				z->p->p->color = RB_RED;
				rbtree_lrotate(z->p->p, root);
			}
		}
	}

	(*root)->color = RB_BLACK;

	rbtree_check_invariant(*root);
}

struct rbtree_node *
rbtree_min(struct rbtree_node *x)
{
	while (x->l != RB_NIL)
		x = x->l;

	return x;
}

struct rbtree_node *
rbtree_next(struct rbtree_node *x)
{
	struct rbtree_node *y;

	if (x->r != RB_NIL)
		return rbtree_min(x->r);

	y = x->p;

	while (y != RB_NIL || x == y->r) {
		x = y;
		y = y->p;
	}

	return y;
}

static void
rbtree_delete_rebalance(struct rbtree_node *x, struct rbtree_node **root)
{
	struct rbtree_node *w;

	while (x != *root && x->color == RB_BLACK) {
		if (x == x->p->l) {
			w = x->p->r;
			if (w->color == RB_RED) {
				w->color = RB_BLACK;
				x->p->color = RB_RED;
				rbtree_lrotate(x->p, root);
				w = x->p->r;
			}
			if (w->l->color == RB_BLACK && w->r->color == RB_BLACK) {
				w->color = RB_RED;
				x = x->p;
			} else {
				if (w->r->color == RB_BLACK) {
					w->l->color = RB_BLACK;
					w->color = RB_RED;
					rbtree_rrotate(w, root);
					w = x->p->r;
				}
				w->color = x->p->color;
				x->p->color = RB_BLACK;
				w->r->color = RB_BLACK;
				rbtree_lrotate(x->p, root);
				x = *root;
			}
		} else {
			w = x->p->l;
			if (w->color == RB_RED) {
				w->color = RB_BLACK;
				x->p->color = RB_RED;
				rbtree_rrotate(x->p, root);
				w = x->p->l;
			}
			if (w->r->color == RB_BLACK && w->l->color == RB_BLACK) {
				w->color = RB_RED;
				x = x->p;
			} else {
				if (w->l->color == RB_BLACK) {
					w->r->color == RB_BLACK;
					w->color = RB_RED;
					rbtree_lrotate(w, root);
					w= x->p->l;
				}
				w->color = x->p->color;
				x->p->color = RB_BLACK;
				w->l->color = RB_BLACK;
				rbtree_rrotate(x->p, root);
				x = *root;
			}
		}
	}

	x->color = RB_BLACK;
}

void
rbtree_delete(struct rbtree_node *z, struct rbtree_node **root)
{
	struct rbtree_node *x, *y;

	if (z->l == RB_NIL || z->r == RB_NIL)
		y = z;
	else
		y = rbtree_next(z);

	if (y->l != RB_NIL)
		x = y->l;
	else
		x = y->r;

	x->p = y->p;

	if (y->p == RB_NIL)
		*root = x;
	else if (y == y->p->l)
		y->p->l = x;
	else
		y->p->r = x;

	if (y != z) {
		y->p = z->p;

		if (z->p == RB_NIL)
			*root = y;
		else if (z == z->p->l)
			z->p->l = y;
		else
			z->p->r = y;
	}

	if (y->color == RB_BLACK)
		rbtree_delete_rebalance(x, root);

	rbtree_check_invariant(*root);
}
