#ifndef THREAD_H
#define THREAD_H 1

#include "misc.h"

#ifdef _DARWIN
#define THREAD_IDn "tr %" PRIx64 ""
#else
#define THREAD_IDn "tr %" PRIu64 ""
#endif

#define THREAD_ID "[" THREAD_IDn "]"

enum thread_states {
	thread_state_dying = 0,
	thread_state_running,
	thread_state_sleeping,
	thread_state_io_read,
	thread_state_io_write,
	thread_state_select,
	thread_state_list_next
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
	uint64_t	starttime;	/* Time thread started */
	cond_t		cond;		/* Condition variable */
	bool		cancelable;	/* Cancel this thread at exit? */
	uint64_t	served;		/* Requests served */
	char		message[128];	/* Short 'status' message */

        /* The routine we are going to call with its argument */
	void		*(*start_routine)(void *);
	void		*arg;
} mythread_t;

CHKRESULT bool thread_init(void);
void thread_exit(void);
void thread_stopall(bool force);

CHKRESULT bool
thread_add(	const char *description,
		void *(*start_routine)(void *),
		void *arg);

bool thread_setstate(thread_status_t state);
bool thread_setmessage(const char* fmt, ...) ATTR_FORMAT(printf, 1, 2);

CHKRESULT bool thread_sleep(unsigned int msec);

CHKRESULT mythread_t *thread_getthis(void);

void thread_serve(void);

typedef void (*thread_list_f)(void		*cbdata,
			      uint64_t		tnum,
			      uint64_t		tid,
			      const char	*starttime,
			      uint64_t		runningsecs,
			      const char	*description,
			      bool		thisthread,
			      const char	*state,
			      const char	*message,
			      uint64_t		served);

CHKRESULT unsigned int thread_list(thread_list_f cb, void *cbdata);

CHKRESULT int thread_daemonize(const char *pidfile, const char *username);

void thread_stop_running(void);
bool thread_keep_running(void);

typedef uint64_t myprocess_num_t;

typedef struct {
	hnode_t		node;		/* List of all threads */
	myprocess_num_t	num;		/* Process Number */
	uint64_t	pid;		/* PID */
	uint64_t	starttime;	/* Time started */
	const char	*description;	/* Name of process */
	const char	*logfile;	/* Logfile location */
} myprocess_t;

void process_terminate(myprocess_num_t process_num, bool force);
void process_cmdline(char * const argv[], char *cmdline, unsigned int len);

CHKRESULT myprocess_num_t
process_spawn(char * const argv[], const char *logfile);

typedef void (*process_list_f)(void		*cbdata,
			      uint64_t		num,
			      uint64_t		pid,
			      const char	*starttime,
			      uint64_t		runningsecs,
			      const char	*description,
			      const char	*state,
			      const char	*logfile);

CHKRESULT unsigned int process_list(process_list_f cb, void *cbdata);

#endif /* THREAD_H */
