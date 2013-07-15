#ifndef BUF_H
#define BUF_H 1

#include "misc.h"

struct buf {
	mutex_t		mutex;			/* Mutex */
	char		*buf;			/* Buffer */
	uint64_t	size;			/* Size of the buffer */
	uint64_t	offset;			/* Length of data in buffer */
};

typedef struct buf buf_t;

bool buf_init(buf_t *buf);
void buf_destroy(buf_t *buf);

void buf_empty(buf_t *buf);
void buf_shift(buf_t *buf, unsigned int length);

void buf_added(buf_t *buf, unsigned int length);

bool buf_putl(buf_t *buf, const char *txt, unsigned int len);
bool buf_put(buf_t *buf, const char *txt);

bool buf_vprintf(buf_t *buf, const char *fmt, va_list ap)
	ATTR_FORMAT(printf, 2, 0);
bool buf_printf(buf_t *buf, const char *fmt, ...)
	ATTR_FORMAT(printf, 2, 3);

bool buf_minsize(buf_t *buf, unsigned int len);

#define buf_buffer(buff) ((buff)->buf)
#define buf_bufend(buff) (&((buff)->buf)[(buff)->offset])
#define buf_max(buff) ((buff)->size)
#define buf_cur(buff) ((buff)->offset)
#define buf_left(buff) (buf_max(buff) - buf_cur(buff) - 1)

#endif /* BUF_H */
