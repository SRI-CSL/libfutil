#include <libfutil/buf.h>

bool
buf_init(buf_t *buf) {
	logline(log_DEBUG_, "(%p)", (void *)buf);

	/* Empty it out */
	memzero(buf, sizeof *buf);

	/* Init the per-buf mutex (XXX: check success) */
	mutex_init(buf->mutex);

	/* Start with an initial size of 4 KiB */
	buf->size = (4 * 1024);
	buf->buf = (void *)calloc(1, buf->size);
	if (buf->buf == NULL) {
		logline(log_DEBUG_, "(%p)", (void *)buf);
		return (false);
	}

	/* Clean the buffer */
	buf_empty(buf);

	/* XXX Check that callers check return */
	return (true);
}

/* Destroy the mutex, final cleanup */
void
buf_destroy(buf_t *buf) {
	logline(log_DEBUG_, "(%p)", (void *)buf);

	if (buf->buf)
		free(buf->buf);

	buf->buf = NULL;
	buf->size = 0;

	mutex_destroy(buf->mutex);
}

/* Empty the buffer, making it ready for re-use */
void 
buf_empty(buf_t *buf) {
	mutex_lock(buf->mutex);
	if (buf->buf)
		memzero(buf->buf, buf->offset);
	buf->offset = 0;
	mutex_unlock(buf->mutex);
}

void
buf_shift(buf_t *buf, unsigned int length) {
	mutex_lock(buf->mutex);

	/* Should never try to shift out more than what is left */
	fassert(length <= buf->offset);

	/* All of it? Then we are quickly done */
	if (length == buf->offset) {
		buf->offset = 0;
	} else {
		unsigned int left = buf->offset - length;

		memmove(buf->buf, &buf->buf[length], left);

		buf->offset = left;
		buf->buf[left] = '\0';
	}

	mutex_unlock(buf->mutex);
}

void
buf_added(buf_t *buf, unsigned int length) {
	fassert((buf->offset + length) < buf->size);
	buf->offset += length;
}

/* Mutex locked by caller */
bool buf_willfit(buf_t *buf, unsigned int len);
bool buf_willfit(buf_t *buf, unsigned int len) {
	uint64_t	ns;
	char		*b;

	ns = len + buf->offset;

	/* Does it already fit? */
	if (ns < buf->size)
		return (true);

	/* Need more, increase per 8 KiB */
	ns = (((((ns + (8*1024)) / (8*1024))) * (8*1024)) + (8*1024));

	/* Limit to 100 MiB, something wrong if it gets bigger */
	if (ns > (100 * 1024 * 1024)) {
		logline(log_ERR_,
			"Wanted more than 100 MiB (%" PRIu64 ")", ns);
		fassert(false);
		return (false);
	}

	/* Get more memory */
	b = realloc(buf->buf, ns);
	if (!b) {
		logline(log_ERR_, "Out of memory (%" PRIu64 ")", ns);
		fassert(false);
		return (false);
	}

	/* The new buffer */
	buf->buf = b;
	buf->size = ns;

	return (true);
}

bool
buf_minsize(buf_t *buf, unsigned int len) {
	return (buf_willfit(buf, len));
}

bool
buf_putl(buf_t *buf, const char *txt, unsigned int len) {
	bool ret = true;

	mutex_lock(buf->mutex);

	if (!buf_willfit(buf, len)) {
		ret = false;
	} else {
		/* Append it */
		memcpy(&buf->buf[buf->offset], txt, len);

		/* The length that was added */
		buf->offset += len;
	}

	mutex_unlock(buf->mutex);

	return (ret);
}

bool
buf_put(buf_t *buf, const char *txt) {
	return (buf_putl(buf, txt, strlen(txt)));
}

bool
buf_vprintf(buf_t *buf, const char *fmt, va_list ap) {
	int		len;
	bool		ret = true;
	uint64_t	left;
	va_list		aq;

	mutex_lock(buf->mutex);

	while (ret) {
		left = buf->size - buf->offset;

		/* Try to fit it in */
		va_copy(aq, ap);
		len = vsnprintf(&buf->buf[buf->offset],
				left,
				fmt,
				aq);
		va_end(aq);

		if (snprintfok(len, left)) {
			/* The real length that was added */
			buf->offset += len;
			break;
		}

		/* Resize the buffer a bit if we can to fit it */
		if (buf_willfit(buf, len + buf->offset)) {
			/* Try again */
			continue;
		}

		logline(log_CRIT_,
			"Could not add more, buffer too full "
			"(%u > %" PRIu64 " + %" PRIu64 ")",
			len, left, buf->offset);
		fassert(false);

		ret = false;
		break;
	}

	mutex_unlock(buf->mutex);

	return (ret);
}

/* Not locking mutex as buf_vprintf() does that */
bool
buf_printf(buf_t *buf, const char *fmt, ...) {
        va_list	ap;
	bool	ret;

        va_start(ap, fmt);
	ret = buf_vprintf(buf, fmt, ap);
	va_end(ap);

	return (ret);
}

/* Simple char searcher that optionally breaks at ASCII-NUL '\0' */
char *
buf_find(buf_t *buf, uint64_t offset, char chr, bool findnul) {
	uint64_t i, len = buf_cur(buf);

	for (i = offset; i < len; i++) {
		if (buf->buf[i] == chr ||
		    (findnul && buf->buf[i] == '\0')) {
			return &buf->buf[i];
		}
	}

	/* Not found */
	return NULL;
}


