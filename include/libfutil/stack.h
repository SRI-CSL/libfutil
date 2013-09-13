#ifndef STACK_H
#define STACK_H 1


void dump_stacktrace(void **trace, uint64_t *trace_size, unsigned int skip);
void format_stacktrace(char *buf, unsigned int length, void **trace, unsigned int trace_size);
void output_stacktrace(void);

#ifdef DEBUG_STACKDUMPS
#define fassert(x) { if (!(x)) { output_stacktrace(); abort(); } }
#else
#ifndef NDEBUG
#define fassert(x) assert(x)
#else
#define fassert(x) {}
#endif /* NDEBUG */
#endif /* DEBUG_STACKDUMPS */

#endif /* STACK_H */
