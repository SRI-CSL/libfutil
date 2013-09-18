#include <libfutil/misc.h>

/* Debugging */
/* #define DD(x) {} */
#define DD(x) x

/* List of all the threads */
static hlist_t *l_threads = NULL;
#ifndef _WIN32
static mutex_t l_tmutex = PTHREAD_MUTEX_INITIALIZER;
#else
static mutex_t l_tmutex;
#endif
static bool l_keep_running = true;

static const char *ts_names[20] = {
	"dying",
	"running",
	"sleeping",
	"io_read",
	"io_write",
	"select",
	"list_next"
};

static void
thread_lock(mythread_t *t);
static void
thread_lock(mythread_t *t) {
	mutex_lock(t->mutex);
}

static void
thread_unlock(mythread_t *t);
static void
thread_unlock(mythread_t *t) {
	mutex_unlock(t->mutex);
}

#ifndef _WIN32
static void
thread_signal(int i);
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
thread_signal(DWORD UNUSED sig);
static bool
thread_signal(DWORD UNUSED sig) {
	logline(log_ERR_, "Terminating due to CTRL event");
	thread_stop_running();
	return (true);
}
#endif /* _WIN32 */

bool
thread_init(void) {
	fassert(l_threads == NULL);

	l_threads = mcalloc(sizeof *l_threads, "l_threads");
	if (!l_threads) {
		logline(log_ERR_, "Could not add main thread!?");
		return (false);
	}

#ifdef _WIN32
	mutex_init(l_tmutex);
#else
	/* Initialized with static pthread initializer */
#endif

	list_init(l_threads);

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

	return (true);
}

/* Get & Lock current thread handle */
static mythread_t *
thread_getbyid(os_thread_id thread_id);
static mythread_t *
thread_getbyid(os_thread_id thread_id) {
	mythread_t *t, *tn, *tf = NULL;

#ifdef _WIN32
	/* XXX */
	if (l_threads != NULL) {
		return (NULL);
	}
#else
	mutex_lock(l_tmutex);
#endif

	list_lock(l_threads);

	list_for(l_threads, t, tn, mythread_t *) {
		if (t->thread_id != thread_id)
			continue;

		tf = t;
		thread_lock(tf);
		break;
	}

	list_unlock(l_threads);

#ifdef _WIN32
#else
	mutex_unlock(l_tmutex);
#endif

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
static void
thread_remove(mythread_t *t);
static void
thread_remove(mythread_t *t) {

	fassert(t);

	logline(log_DEBUG_, "Thread %s started", t->description);

	list_remove_l(l_threads, &t->node);
}

static void
thread_destroy(mythread_t *t);
static void
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
			t->thread_id,
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
	/* Simple identifier */
	t->thread_id = getthisthreadid();

	/* Note the time it started */
	t->starttime = gettime();

	logline(log_DEBUG_,
		"Thread %s started%s", t->description,
		t->start_routine ? "" : " (" STR(PROJECT_BUILDTIME) ")");

	/* Add self to the list of threads */
	list_addtail_l(l_threads, &t->node);
}

#ifndef _WIN32
static void *
thread_autoremove(void *arg);
static void *
thread_autoremove(void *arg) {
#else
static DWORD WINAPI
thread_autoremove(LPVOID arg);
static DWORD WINAPI
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
	if (start_routine != NULL) {
#ifndef _WIN32
		if (0 != pthread_create(&t->thread, NULL, thread_autoremove, t))
#else
		if ((t->thread = CreateThread(NULL, 0, thread_autoremove,
					      NULL, 0, NULL)))
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
	unsigned	int i = 0, max = 5;
	bool		done = false;
	mythread_t	*t, *tn;
	os_thread_id	tid = getthisthreadid();

	logline(log_DEBUG_, "Signalling thread that they should exit");

	/* Must be initialized */
	fassert(l_threads != NULL);

	/* Set the stop running flag so threads get a hint */
	thread_stop_running();

	list_lock(l_threads);
	list_for(l_threads, t, tn, mythread_t *) {
		if (t->thread_id == tid)
			continue;

		thread_lock(t);
#ifndef _WIN32
		pthread_cond_broadcast(&t->cond);
#else
		/* XXX: Signal threads that they should exit (win32) */
#endif
		thread_unlock(t);
	}
	list_unlock(l_threads);

	/* Make sure that all threads have ended */
	while (i < max && !done) {
		done = true;

		/* Sleep a bit if there is something in the list */
		if (!list_isempty(l_threads)) {
			list_lock(l_threads);
			list_for(l_threads, t, tn, mythread_t *) {
				if (t->thread_id == tid)
					continue;

				thread_lock(t);
				logline(log_DEBUG_,
					"Still waiting for " THREAD_ID
					" \"%s\" [%s]%s to finish...",
					t->thread_id,
					t->description,
					ts_names[t->state],
					t->state != thread_state_running ?
						" .oO(zzZzzZzzz)" : "");
				thread_unlock(t);

#ifndef _WIN32
				pthread_cond_signal(&t->cond);
#endif
				done = false;
			}
			list_unlock(l_threads);
		}

		if (!done) {
			logline(log_DEBUG_,
				"Threads Exiting - "
				"waiting for some threads (try %u/%u)",
				i+1, max);
			sleep(5);
		}

		i++;
	}

	/* Force cleanup */
	if (force && !list_isempty(l_threads)) {
		logline(log_DEBUG_, "Forcing Thread Exit");

		while ((t = (mythread_t *)list_pop(l_threads))) {
			if (t->thread_id != tid) {
				thread_lock(t);
				logline(log_DEBUG_,
					" Was still running: " THREAD_ID
					" \"%s\" [%s]",
					t->thread_id,
					t->description,
					ts_names[t->state]);
				thread_unlock(t);
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

	fassert(l_threads != NULL);

	/* Stop all running threads */
	thread_stopall(true);

	fassert(list_isempty(l_threads));

	list_destroy(l_threads);
	mfree(l_threads, sizeof *l_threads, "l_threads");
	l_threads = NULL;

	logline(log_DEBUG_, "done");

	mutex_destroy(l_tmutex);
}

unsigned int
thread_list(thread_list_f cb, void *cbdata) {
	mythread_t	*t, *tn, *tc;
	os_thread_id	thread_id = getthisthreadid();
	struct tm	teem;
	uint64_t	now = gettime();
	unsigned int	cnt = 0;
	char		st[64];
	hlist_t		tl;

	list_init(&tl);

	list_lock(l_threads);
	list_for(l_threads, t, tn, mythread_t *) {
		tc = mcalloc(sizeof *t, "tmpthread");
		if (tc == NULL)
			break;

		/* Clone it */
		thread_lock(t);
		memcpy(tc, t, sizeof *tc);
		thread_unlock(t);

		/* Empty the node, it is a clone */
		node_init(&tc->node);

		list_addtail(&tl, &tc->node);

		/* Another thread */
		cnt++;
	}
	list_unlock(l_threads);

	/* Now, lockless, do the call backs */
	list_for(&tl, t, tn, mythread_t *) {
		/* Format the start time */
		localtime_r(&t->starttime, &teem);
		snprintf(st, sizeof st, FMT_DATETIME, fmt_datetime(teem));

		/* Callback which might actually show the details */
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

		mfree(t, sizeof *t, "tmpthread");
	}

	return (cnt);
}

void
thread_stop_running(void) {
	logline(log_DEBUG_, "Stop running...");

	mutex_lock(l_tmutex);
	l_keep_running = false;
	mutex_unlock(l_tmutex);
}

bool
thread_keep_running(void) {
	bool	r;

	mutex_lock(l_tmutex);
	r = l_keep_running;
	mutex_unlock(l_tmutex);

	return (r);
}

