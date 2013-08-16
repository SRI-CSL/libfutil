#include <libfutil/misc.h>

/* Debugging */
/* #define DD(x) {} */
#define DD(x) x

/* List of all the threads */
hlist_t *g_threads = NULL;
bool g_keep_running = true;
bool g_threads_initialized = false;

const char *ts_names[20] = {
	"dying",
	"running",
	"sleeping",
	"io_read",
	"io_write",
	"select",
	"list_next"
};

static void
thread_lock(mythread_t *t) {
	mutex_lock(t->mutex);
}

static void
thread_unlock(mythread_t *t) {
	mutex_unlock(t->mutex);
}

#ifndef _WIN32
static void
thread_signal(int i) {
	/* Ignore the signal, we might otherwise be in this function twice... */
	signal(i, SIG_IGN);

	/* Indicate that we should stop running */
	thread_stop_running();

	/* Reset the signal */
	signal(i, &thread_signal);
}
#else
static bool
thread_signal(DWORD UNUSED sig) {
	logline(log_ERR_, "Terminating due to CTRL event");
	thread_stop_running();
	return (true);
}
#endif /* _WIN32 */

bool
thread_init(void) {
	g_threads = mcalloc(sizeof *g_threads, "g_threads");
	if (!g_threads) {
		logline(log_ERR_, "Could not add main thread!?");
		return (false);
	}

	list_init(g_threads);

	if (!thread_add("Main", NULL, NULL)) {
		logline(log_ERR_, "Could not add main thread!?");
		return (false);
	}

#ifndef _WIN32
	/* Handle a SIGHUP/SIGTERM/SIGINT to cleanly exit when rang */
	signal(SIGHUP,	&thread_signal);
	signal(SIGTERM,	&thread_signal);
	signal(SIGINT,	&thread_signal);
#else
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)thread_signal, true);
#endif

	/* We have liftoff */
	g_threads_initialized = true;

	return (true);
}

/* Get & Lock current thread handle */
static mythread_t *
thread_getbyid(os_thread_id thread_id);
static mythread_t *
thread_getbyid(os_thread_id thread_id) {
	mythread_t *t, *tn, *tf = NULL;

	if (!g_threads_initialized)
		return (NULL);

	list_lock(g_threads);

	list_for(g_threads, t, tn, mythread_t *) {
		if (t->thread_id != thread_id)
			continue;

		tf = t;
		thread_lock(tf);
		break;
	}

	list_unlock(g_threads);

	return (tf);
}

mythread_t *
thread_getthis(void) {
	return (thread_getbyid(getthisthreadid()));
}

/*
 * Remove a thread from the thread list
 * This is automatically called by the threading
 * code when it returns from the calling function
*/
void
thread_remove(mythread_t *t);
void
thread_remove(mythread_t *t) {

	fassert(t);

	logline(log_DEBUG_, "Thread %s started", t->description);

	list_remove_l(g_threads, &t->node);
}

void
thread_destroy(mythread_t *t);
void
thread_destroy(mythread_t *t) {
	mfreestrdup(t->description, "thread_description");

	cond_destroy(t->cond);
	node_destroy(&t->node);
	mfree(t, "thread", sizeof *t);
}

bool
thread_setstate(thread_status_t state) {
	mythread_t *t;

	t = thread_getthis();
	if (!t)
		return (false);

	t->state = state;

	thread_unlock(t);

	return (true);
}

bool
thread_setmessage(const char *fmt, ...) {
	mythread_t *t;
	va_list ap;

	t = thread_getthis();
	if (!t)
		return (false);

	va_start(ap, fmt);
	vsnprintf(t->message, sizeof t->message, fmt, ap);
	va_end(ap);

	thread_unlock(t);

	return (true);
}

void
thread_serve(void) {
	mythread_t *t;

	t = thread_getthis();
	if (!t)
		return;

	t->served++;

	thread_unlock(t);
}

/* Let the thread sleep for X msecs, but allow it to be interrupted for exit */
bool
thread_sleep(unsigned int msec) {
	mythread_t	*t;
#ifndef _WIN32
	struct timespec	timeout;
#endif
	int		rc;

	t = thread_getthis();

	/* Nothing we can do, return with failure so that it will abort */
	if (t == NULL) {
		/* mdolog(LOG_ERR, "Couldn't find my thread while trying to sleep!\n"); */
		return (false);
	}

	t->state = thread_state_sleeping;
#ifndef _WIN32
	set_timeout(&timeout, msec);
	rc = pthread_cond_timedwait(&t->cond, &t->mutex, &timeout);
#else
	/* XXX: Add support for conditional breaking (win32) */
	Sleep(msec);
	rc = ETIMEDOUT;
#endif
	t->state = thread_state_running;

	/* Unlock the thread */
	thread_unlock(t);

#ifdef DEBUG
	if (rc != ETIMEDOUT && rc != 0) {
		logline(log_ERR_,
			"cond_timedwait(tr%" PRIu64 ", %u) on "
			"%s returned %u",
			t->thread_num,
			msec,
			t->description ? t->description : "<no description>",
			rc);
	}
#endif
	fassert(rc != EINVAL);

	return (rc == ETIMEDOUT ? true : false);
}

static void
thread_start(mythread_t *t);
static void
thread_start(mythread_t *t) {
	/* Simple identifier (matches LWP on Linux) */
	t->thread_id = getthisthreadid();

	/* Note the time it started */
	t->starttime = gettime();

	logline(log_DEBUG_,
		"Thread %s started%s", t->description,
		t->start_routine ? "" : " (" STR(PROJECT_BUILDTIME) ")");

	/* Add self to the list of threads */
	list_addtail_l(g_threads, &t->node);
}

#ifndef _WIN32
static void *
thread_autoremove(void *arg);
static void *
thread_autoremove(void *arg) {
#else
DWORD WINAPI
thread_autoremove(LPVOID arg);
DWORD WINAPI
thread_autoremove(LPVOID arg) {
#endif
	mythread_t	*t = (mythread_t *)arg;

#ifndef _WIN32
	/* Mask out all signals (main will handle this) */
	sigset_t	mask;
	int		rc;

	sigfillset(&mask);
	rc = pthread_sigmask(SIG_BLOCK, &mask, NULL);
	if (rc != 0)
		logline(log_ERR_, "pthread_sigmask() returned %d", rc);
#endif

	/* Startup */
	thread_start(t);

	/* The actual fun stuff */
	t->start_routine(t->arg);

	/* And the cleanup */
	thread_remove(t);
	thread_destroy(t);

#ifndef _WIN32
	return (NULL);
#else
	return (0);
#endif
}

bool
thread_add(const char *description, void *(*start_routine)(void *), void *arg)
{
	static unsigned int	thread_num = 0;
	mythread_t		*t;

	/* Allocate a new thread structure */
	t = (mythread_t *)mcalloc(sizeof *t, "thread");
	if (!t) {
		logline(log_ERR_,
			"[%s] Couldn't allocate memory for a new thread... "
			"aborting", description);
		return (false);
	}

	node_init(&t->node);
	mutex_init(t->mutex);
	cond_init(t->cond);
	t->thread_num = ++thread_num;
	t->description = mstrdup(description, "thread_description");
	t->start_routine = start_routine;
	t->arg = arg;
	t->state = thread_state_running;

	/* Create the thread if needed (only the 'main' thread should not do this) */
	if (start_routine) {
#ifndef _WIN32
		if (0 != pthread_create(&t->thread, NULL, thread_autoremove, t))
#else
		if ((t->thread = CreateThread(NULL, 0, thread_autoremove,
					      NULL, 0, &t->thread_id)))
#endif
		{
			logline(log_ERR_,
				"[%s] Couldn't create thread... aborting",
				description);

			/* Don't forget to free the thread structure memory */
			mfree(t, "thread", sizeof *t);

			return (false);
		}

#ifndef _WIN32
		/* Detach the thread */
		pthread_detach(t->thread);
#endif
	} else {
		/* The the 'main' thread which is us */
		thread_start(t);
	}

	return (true);
}

void
thread_stopall(bool force) {
	unsigned	int i = 0;
	bool		done = false;
	mythread_t	*t, *tn;
	os_thread_id	tid = getthisthreadid();

	logline(log_DEBUG_, "Signalling thread that they should exit");

	/* Must be initialized */
	fassert(g_threads != NULL);

	/* Set the stop running flag so threads get a hint */
	thread_stop_running();

	list_lock(g_threads);
	list_for(g_threads, t, tn, mythread_t *) {
		if (t->thread_id == tid)
			continue;
#ifndef _WIN32
		pthread_cond_broadcast(&t->cond);
#else
		/* XXX: Signal threads that they should exit (win32) */
#endif
	}
	list_unlock(g_threads);

	/* Make sure that all threads have ended */
	while (i < 20 && !done) {
		done = true;

		/* Sleep a bit if there is something in the list */
		if (!list_isempty(g_threads)) {
			list_lock(g_threads);
			list_for(g_threads, t, tn, mythread_t *) {
				if (t->thread_id == tid)
					continue;

				logline(log_DEBUG_,
					"Still waiting for [tr%" PRIu64 "] "
					"%s [%s]%s to finish...",
					t->thread_num,
					t->description,
					ts_names[t->state],
					t->state != thread_state_running ?
						" .oO(zzZzzZzzz)" : "");

#ifndef _WIN32
				pthread_cond_signal(&t->cond);
#endif
				done = false;
			}
			list_unlock(g_threads);
		}

		if (!done) {
			logline(log_DEBUG_,
				"Threads Exiting - waiting for some threads");
			sleep(5);
		}

		i++;
	}

	/* Force cleanup */
	if (force && !list_isempty(g_threads)) {

		while ((t = (mythread_t *)list_pop(g_threads))) {
			if (t->thread_id != tid) {
				logline(log_DEBUG_,
					" Was still running: [tr%" PRIu64 "] "
					" \"%s\" [%s]",
					t->thread_num,
					t->description,
					ts_names[t->state]);
			}

			if (t->thread_id != tid) {
#ifndef _WIN32
				pthread_cancel(t->thread);
#endif
			}

			/* Destroy it */
			thread_destroy(t);
		}
	}

	logline(log_DEBUG_, "done");
}

void
thread_exit(void) {
	logline(log_DEBUG_, "...");

	fassert(g_threads != NULL);

	/* Stop all running threads */
	thread_stopall(true);

	/* Not inititalized anymore */
	g_threads_initialized = false;

	fassert(list_isempty(g_threads));

	list_destroy(g_threads);
	mfree(g_threads, sizeof *g_threads, "g_threads");
	g_threads = NULL;

	logline(log_DEBUG_, "done");
}

unsigned int
thread_list(thread_list_f cb, void *cbdata) {
	mythread_t	*t, *tn;
	os_thread_id	thread_id = getthisthreadid();
	struct tm	teem;
	uint64_t	now = gettime();
	unsigned int	cnt = 0;
	char		st[64];

	list_lock(g_threads);
	list_for(g_threads, t, tn, mythread_t *) {
		localtime_r(&t->starttime, &teem);

		/* Format the start time */
		snprintf(st, sizeof st, FMT_DATETIME, fmt_datetime(teem));

		/* Callback which might actually show the details */
		/* (lets hope it does not create any threads or so ;) */
		cb(cbdata,
		   t->thread_num,
		   t->thread_id,
		   st,
		   now - t->starttime,
		   t->description,
		   t->thread_id == thread_id,
		   ts_names[t->state],
		   t->message,
		   t->served);

		/* Another thread */
		cnt++;
	}
	list_unlock(g_threads);

	return (cnt);
}

void
thread_stop_running(void) {
	logline(log_DEBUG_, "Stop running...");
	g_keep_running = false;
}

bool
thread_keep_running(void) {
	return (g_keep_running);
}

