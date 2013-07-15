#ifndef RWL_H
#define RWL_H 1

#include "misc.h"

typedef struct {
	mutex_t		mutex;			/* Lock for changing readers/writers */
	mutex_t		mutexW;			/* Lock held when something is writing */
	unsigned int	readers;		/* How many readers are in */
	unsigned int	writers;		/* How many writers are waiting */
} rwl_t;

void rwl_init(rwl_t *rwl);
void rwl_destroy(rwl_t *rwl);
void rwl_lockR(rwl_t *rwl);
void rwl_unlockR(rwl_t *rwl);
void rwl_lockW(rwl_t *rwl);
void rwl_unlockW(rwl_t *rwl);

#endif /* RWL_H */

