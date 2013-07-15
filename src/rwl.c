#include <libfutil/misc.h>

void rwl_init(rwl_t *l) {
	assert(l);
	memzero(l, sizeof *l);
	mutex_init(l->mutex);
	mutex_init(l->mutexW);
	l->readers = 0;
	l->writers = 0;
}

void rwl_destroy(rwl_t *l) {
	assert(l);
	assert(l->readers == 0);
	assert(l->writers == 0);

	mutex_destroy(l->mutex);
	mutex_destroy(l->mutexW);
}

void rwl_lockR(rwl_t *l) {
	assert(l);

	mutex_lock(l->mutex);

	/* Let me read! */
	l->readers++;

	/* Release the readers/writers lock */
	mutex_unlock(l->mutex);

	/* Any waiting writers? Then wait for them to finish */
	if (l->writers > 0) {
		/* Try to get the Write Lock */
		mutex_lock(l->mutexW);

		/* Release it, because readers > 0 it won't be grabbed fully by a writer */
		mutex_unlock(l->mutexW);
	}
}

void rwl_unlockR(rwl_t *l) {
	assert(l);
	assert(l->readers > 0);

	/* One less reader */
	mutex_lock(l->mutex);

	l->readers--;

	mutex_unlock(l->mutex);
}

void rwl_lockW(rwl_t *l) {
	bool		w = false;

	assert(l);

	mutex_lock(l->mutex);

	/* Let me write! */
	l->writers++;

	/* Try to get the write lock */
	if (mutex_trylock(l->mutexW) == 0)
		w = true;

	/* Is something reading? */
	while (l->readers > 0 || !w) {
		/* Give it back */
		mutex_unlock(l->mutex);

		/* Release it for a bit */
		if (w) {
			mutex_unlock(l->mutexW);
			w = false;
		}

		/* Force a context switch */
#ifndef _WIN32
		sched_yield();
#else
		Sleep(0);
#endif

		/* Grab it again */
		mutex_lock(l->mutex);

		/* Try to get the write lock */
		if (mutex_trylock(l->mutexW) == 0)
			w = true;
	}

	mutex_unlock(l->mutex);
}

void rwl_unlockW(rwl_t *l) {
	assert(l);
	assert(l->writers > 0);

	/* Acquire the readers/writers lock */
	mutex_lock(l->mutex);

	/* One less writer */
	l->writers--;

	/* Unlock the write lock*/
	mutex_unlock(l->mutexW);

	/* Release */
	mutex_unlock(l->mutex);
}

