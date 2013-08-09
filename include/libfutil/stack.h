#ifndef STACK_H
#define STACK_H 1

#ifdef DEBUG

void dump_stacktrace(void **trace, uint64_t *trace_size, unsigned int skip);
void format_stacktrace(char *buf, unsigned int length, void **trace, unsigned int trace_size);
void output_stacktrace(void);

#define fassert(x) { if (!(x)) { output_stacktrace(); abort(); } }

#else

#define fassert(x) assert(x)

#define dump_stacktrace(a,b,c) { }
#define format_stacktrace(a,b,c,d) { }
#define output_stacktrace() { }

#endif /* DEBUG */

#endif /* STACK_H */
