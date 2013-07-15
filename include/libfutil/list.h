#ifndef LIST_H
#define LIST_H 1

typedef struct hnode_t hnode_t;
typedef struct hlist_t hlist_t;

/* Node/List Functions */
struct hnode_t
{
	hnode_t		*next,		/* Next in the list */
			*prev;		/* Previous in the list */
};

struct hlist_t
{
	hnode_t		*head,		/* The beginning of the list */
			*tail,		/* The tail of the list */
			*tailprev;	/* The previous of the tail
					   of the list */
	mutex_t		mutex;		/* Mutex */
	cond_t		cond;		/* Condition */
	uint64_t	locks;		/* Number of locks */
	uint64_t	id;		/* List ID */
	uint64_t	items;		/* Items */
};

bool list_isempty(hlist_t *l);

void list_init(hlist_t *l);

void list_destroy(hlist_t *l);

void list_addtail(hlist_t *l, hnode_t *n);
void list_addtail_l(hlist_t *l, hnode_t *n);

void list_remove(hlist_t *l, hnode_t *n);
void list_remove_l(hlist_t *l, hnode_t *n);

void list_lock(hlist_t *l);
void list_unlock(hlist_t *l);

#define list_id(l) ((l) ? (l)->id : 0)
#define LIST_ID "[l%" PRIu64 "]"

void node_init(hnode_t *n);
void node_destroy(hnode_t *n);

hnode_t *list_pop(hlist_t *l);
hnode_t *list_getnext(hlist_t *l);

/* Loop through all the items of a list */
#define list_for(_l, _n, _n2, _t)				\
for								\
(								\
	(_n) = (_t)(_l)->head;					\
	(_n2 = (_t)((hnode_t *)(_n))->next);			\
	(_n) = (_t)(_n2)					\
)

#endif /* LIST_H */

