#ifndef THREAD_H
#define THREAD_H 1

#include "misc.h"

enum thread_states {
	thread_state_dying = 0,
	thread_state_running,
	thread_state_sleeping,
	thread_state_io_read,
	thread_state_io_write,
	thread_state_io_wait,
	thread_state_io_next
};

typedef uint64_t thread_status_t;

typedef struct {
	hnode_t		node;		/* List of all threads */
	mutex_t		mutex;		/* Thread lock */
	char		*description;	/* Description of this thread */
	os_thread_t	thread;		/* The thread */
	os_thread_id	thread_id;	/* Thread Identifier */
	uint64_t	thread_num;	/* Thread number */
	thread_status_t	state;		/* Sleeping? */
	time_t		starttime;	/* Time thread started */
	cond_t		cond;		/* Condition variable */
	bool		cancelable;	/* Cancel this thread at exit? */
	uint64_t	served;		/* Requests served */

        /* The routine we are going to call with its argument */
	void		*(*start_routine)(void *);
	void		*arg;
} mythread_t;

bool thread_init(void);
void thread_exit(void);
void thread_stopall(bool force);

bool thread_add(const char *description, void *(*start_routine)(void *),
		void *arg);
bool thread_setstate(thread_status_t state);
bool thread_sleep(unsigned int seconds, unsigned int nsecondss);
mythread_t *thread_getthis(void);

void thread_serve(void);

typedef void (*thread_list_f)(void		*cbdata,
			      uint64_t		tid,
			      const char	*starttime,
			      uint64_t		runningsecs,
			      const char	*description,
			      bool		thisthread,
			      const char	*state,
			      uint64_t		served);

unsigned int thread_list(thread_list_f cb, void *cbdata);

void thread_stop_running(void);
bool thread_keep_running(void);

#endif /* THREAD_H */
