#include <libfutil/misc.h>

/* Toggle to 1 to get debug output */
#if 0
#if 1
#define LD(t,a) logline(log_DEBUG_, t, a)
#define LD2(t,a,b) logline(log_DEBUG_, t, a, b)
#define LD3(t,a,b,c) logline(log_DEBUG_, t, a, b, c)
#else
#define LD(t,a) fprintf(stderr, "%s: " t "\n", __func__ a)
#define LD2(t,a,b) fprintf(stderr, "%s: " t "\n", __func__ a, b)
#define LD3(t,a,b,c) fprintf(stderr, "%s: " t "\n", __func__ a, b, c)
#endif
#else
#define LD(t,a) {}
#define LD2(t,a,b) {}
#define LD3(t,a,b,c) {}
#endif

/* Toggle to 1 to get precise list_lock/unlock details */
#if 0
#define LDV(t,a) LD(t,a)
#else
#define LDV(t,a) {}
#endif

/* Is the list empty? */
bool
list_isempty_l(hlist_t *l);
bool
list_isempty_l(hlist_t *l) {
	return (((hlist_t *)(l->tailprev)) == l);
}

bool
list_isempty(hlist_t *l) {
	bool e;

	fassert(l);
	if (!l)
		return (true);

	list_lock(l);
	e = list_isempty_l(l);
	list_unlock(l);

	return (e);
}

/* Create a new list */
void
list_init(hlist_t *l) {
	static uint64_t l_id = 0;

	l->id = ++l_id;

	LD2("%p - " LIST_ID, (void *)l, list_id(l));

	l->tailprev	= (hnode_t *)&l->head;
	l->tail		= NULL;
	l->head		= (hnode_t *)&l->tail;

	mutex_init(l->mutex);
	cond_init(l->cond);
}

/* Destroy a list, does not empty it (it does not know how) */
void
list_destroy(hlist_t *l) {
	LD(LIST_ID, list_id(l));

	l->head		= NULL;
	l->tail		= NULL;
	l->tailprev	= NULL;

	mutex_destroy(l->mutex);
	cond_destroy(l->cond);
}

void
node_init(hnode_t *n) {
	memzero(n, sizeof *n);
}

void
node_destroy(hnode_t *n) {
	memzero(n, sizeof *n);
}

/* Remove a node from a list */
/* List is locked by caller */
void
list_remove(hlist_t *l, hnode_t *n) {
	fassert(l->locks == 1);

	LD3(LIST_ID ", %p, %" PRIu64, list_id(l), (void *)n, l->items);

	/* Not on a list */
	if (n->prev == NULL)
		return;

	fassert(n->next);

	n->prev->next = n->next;
	n->next->prev = n->prev;
	n->next	= NULL;
	n->prev	= NULL;

	fassert(l->items > 0);
	l->items--;

#ifndef _WIN32
	/* Signal at least one wanting to know that something got removed */
	pthread_cond_broadcast(&l->cond);
#else
	/* XXX: Use Windows Events for broadcasting signals */
#endif

	fassert(l->locks == 1);
}

void
list_remove_l(hlist_t *l, hnode_t *n) {
	list_lock(l);
	list_remove(l, n);
	list_unlock(l);
}

/* Returns either NULL or a locked node */
hnode_t *
list_pop_l(hlist_t *l);
hnode_t *
list_pop_l(hlist_t *l) {
	hnode_t *n;

	if (!list_isempty_l(l)) {
		n = l->head;
		list_remove(l, n);
	} else {
		n = NULL;
	}

	return (n);
}

hnode_t *
list_pop(hlist_t *l) {
	hnode_t *n;

	list_lock(l);
	n = list_pop_l(l);
	list_unlock(l);

	return (n);
}

hnode_t *
list_getnext(hlist_t *l) {
	hnode_t		*node = NULL;
#ifndef _WIN32
	struct timespec	timeout;
	int		rc;
#endif

	LD2(LIST_ID " %" PRIu64, list_id(l), l->items);

	/* Lock her up */
	list_lock(l);

	while (thread_keep_running()) {

		LD(LIST_ID " [a]", list_id(l));

		/* Try popping one off the list */
		node = list_pop_l(l);
		if (node) {
			list_unlock(l);
			return (node);
		}

		/* Nothing yet, thus wait for it */
		LD(LIST_ID " [b] nothing yet", list_id(l));
#ifndef _WIN32
		set_timeout(&timeout, 5000);

		/*
		 * pthread_cond_timedwait() unlocks the mutex temporarily
		 * this allows multiple threads to wait for the condition
		 */
		l->locks--;

		rc = pthread_cond_timedwait(&l->cond, &l->mutex, &timeout);
		LD2(LIST_ID " [c] waited 5, rc = %d", list_id(l), rc);

		if (rc == 0) {
			/* We got the lock again */
			l->locks++;

			/* Try getting one from the list */
			LD(LIST_ID " [d] more", list_id(l));
			continue;
		}

		/* Timeouts are normal */
		if (rc == ETIMEDOUT) {
			/* Timeout locks the mutex */
			LD(LIST_ID " [e] timeout", list_id(l));
			l->locks++;
			continue;
		}

		/* Some kind of trouble thus get out */
		logline(log_ERR_, "cond_timedwait returned %d", rc);
		fassert(false);
#else
		/* XXX: Add support for conditional breaking (win32) */
		Sleep(5000);
#endif
		break;
	}

	list_unlock(l);

	LD2("exit " LIST_ID " = %p", list_id(l), (void *)node);

	return (node);
}

/* Add a item at the end of a list */
/* List must be locked by caller */
void
list_addtail(hlist_t *l, hnode_t *n) {
	hnode_t *o;

	LD3(LIST_ID ", %p, %" PRIu64, list_id(l), (void *)n, l->items);

	fassert(n != NULL);
	fassert(l != NULL);

	fassert(n->next == NULL);
	fassert(n->prev == NULL);

	o = l->tailprev;
	n->next = o->next;
	o->next->prev = n;
	n->prev = o;
	o->next = n;

	l->items++;

#ifndef _WIN32
	/* Signal at least one wanting to know that something got added */
	pthread_cond_broadcast(&l->cond);
#endif
}

void
list_addtail_l(hlist_t *l, hnode_t *n) {
	list_lock(l);
	list_addtail(l, n);
	list_unlock(l);
}

void
list_lock(hlist_t *l) {
	mutex_lock(l->mutex);
	LDV(LIST_ID, list_id(l));
	fassert(l->locks == 0);
	l->locks++;
}

void
list_unlock(hlist_t *l) {
	LDV(LIST_ID, list_id(l));
	fassert(l->locks == 1);
	l->locks--;
	mutex_unlock(l->mutex);
}

