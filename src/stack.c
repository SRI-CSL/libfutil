#if defined(DEBUG)
#include <libfutil/misc.h>

#if defined(_LINUX) || defined(_DARWIN)
#include <execinfo.h>

void
dump_stacktrace(void **trace, uint64_t *trace_size, unsigned int skip) {
	int size = backtrace(trace, *trace_size);

	/* Always skip myself */
	skip++;

	if (size <= 0) {
		*trace_size = 0;
		return;
	}

	if ((unsigned int)size < skip) {
		*trace_size = 0;
		return;
	}

	memmove(trace,
		((char *)trace) + (sizeof(*trace) * skip),
		sizeof(*trace) * (size - skip));

	*trace_size = (size - skip);
}

void
format_stacktrace( char *buf, unsigned int length, void **trace,
			unsigned int trace_size)
{
	char		**messages = NULL;
	uint64_t	tid = getthisthreadid();
	unsigned int	i = 0, o = 0, k;

	memzero(buf, length);

	messages = backtrace_symbols(trace, trace_size);
	if (messages == NULL) {
		snprintf(buf, length,
			THREAD_ID " %02u - "
			"Got trace, but could not generate messages\n",
			tid, i);
		return;
	}

	for (i=0; i < trace_size; i++) {
		k = snprintf(&buf[o], length-o,
		            THREAD_ID " %02u %s\n",
			    tid, i, messages[i]);
		if (k > 0)
			o += k;
		else
			break;
	}

	free(messages);
}

void
output_stacktrace(void) {
	void		*trace[16];
	char		buf[4096];
	uint64_t	trace_size = lengthof(trace);

	dump_stacktrace(trace, &trace_size, 1);
	format_stacktrace(buf, sizeof(buf), trace, trace_size);

	fprintf(stderr,
		"8<---------------------- stack:\n"
		"%s"
		"-------------------->8\n",
		buf);

	fflush(stderr);
}

#else /* _LINUX || _DARWIN */

void
dump_stacktrace(void UNUSED **trace, uint64_t UNUSED *trace_size,
		unsigned int UNUSED skip)
{
}

void
format_stacktrace(char UNUSED *buf, unsigned int UNUSED length,
		  void UNUSED **trace, unsigned int UNUSED trace_size)
{
}

void
output_stacktrace(void) {
}

#endif /* _LINUX || _DARWIN */
#endif

