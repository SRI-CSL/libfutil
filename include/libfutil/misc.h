#ifndef MISC_H
#define MISC_H 1

#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <sys/time.h>
#include <string.h>

#ifndef _WIN32
/* Not Windows */
#include <netinet/in.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/syscall.h>
#include <pwd.h>
#ifdef _LINUX
#include <sys/sendfile.h>
#endif

#define INVALID_SOCKET		-1
typedef int64_t			socket_t;

/* Windows calls this {close|ioctl}socket() which is clearer thus use it */
#define closesocket(s)		close(s)
#define ioctlsocket(s, n, i)	ioctl(s, n, i)

/* OS Thread & Mutex Abstraction */
typedef pthread_t		os_thread_t;
typedef uint64_t		os_thread_id;
typedef pthread_mutex_t		mutex_t;
typedef pthread_cond_t		cond_t;
#define getthisthread		pthread_self
#ifdef __NR_gettid
#define getthisthreadid()	((os_thread_id)syscall(__NR_gettid))
#else
#ifdef _DARWIN
#define getthisthreadid()	((os_thread_id)syscall(SYS_thread_selfid))
#else
#define getthisthreadid()	(((os_thread_id)pthread_self())
#endif
#endif /* __NR_gettid */
#define mutex_init(m) {							\
				pthread_mutexattr_t attr;		\
				pthread_mutexattr_init(&attr);		\
				pthread_mutexattr_settype(&attr,	\
					PTHREAD_MUTEX_RECURSIVE);	\
				pthread_mutex_init(&m, &attr);		\
				pthread_mutexattr_destroy(&attr);	\
				}
#define mutex_destroy(m)	pthread_mutex_destroy(&(m))
#define mutex_lock(m)		pthread_mutex_lock(&(m))
#define mutex_trylock(m)	(pthread_mutex_trylock(&(m)) == 0 ? true : false)
#define mutex_unlock(m)		pthread_mutex_unlock(&(m))
#define cond_init(c)		pthread_cond_init(&(c), NULL)
#define cond_destroy(c)		pthread_cond_destroy(&(c))
#define cond_trigger(c)		pthread_cond_broadcast(&(c))
#define cond_wait(c,m,msec)	cond_wait_(&c, &m, msec)

#else
/* Windows */

/* No syslog on Windows, but we just want the levels */
#define LOG_EMERG	0
#define LOG_ALERT	1
#define LOG_CRIT	2
#define LOG_ERR		3
#define LOG_WARNING	4
#define LOG_NOTICE	5
#define LOG_INFO	6
#define LOG_DEBUG	7

#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <basetyps.h>
#include <shellapi.h>
#include <winbase.h>
#include <wincrypt.h>

typedef SOCKET			socket_t;
typedef HANDLE			os_thread_t;
typedef uint64_t		os_thread_id;
typedef HANDLE			mutex_t;
typedef HANDLE			cond_t;
#define getthisthread		GetCurrentThread
#define getthisthreadid		GetCurrentThreadId
#define mutex_init(m)		CreateMutex(NULL, false, NULL)
#define mutex_destroy(m)	CloseHandle(m)
#define mutex_lock(m)		WaitForSingleObject(m, INFINITE)
#define mutex_trylock(m)	(WaitForSingleObject(m, 0) != WAIT_ABANDONED)
#define mutex_unlock(m)		ReleaseMutex(m)
#define cond_init(c)		{ NOT IMPLEMENTED }
#define cond_destroy(c)		{ NOT IMPLEMENTED }
#define cond_trigger(c)		{ NOT IMPLEMENTED }
#define cond_wait(c,m,msec)	cond_wait_(&c, &m, msec)

#define FIOBIO			FIONBIO
#define SHUT_RD			SD_RECEIVE
#define SHUT_WR			SD_SEND
#define SHUT_RDWR		SD_BOTH

#define ENOMSG			WSAEINVAL
#define EMSGSIZE		WSAEMSGSIZE
#define ETIMEDOUT		WSAETIMEDOUT
#define EINPROGRESS		WSAEINPROGRESS

#define sleep(n)		Sleep(n * 1000)

/* MINGW headers don't have these on i586 */
/* Value taken from i686 headers */
#ifndef AI_ADDRCONFIG
#define AI_ADDRCONFIG		0x0400
#endif

#endif /* _WIN32 */

bool cond_wait_(cond_t *c, mutex_t *m, unsigned int msec);

#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#ifdef _DARWIN

#include <netinet/in_systm.h>
#include <sys/uio.h>


#ifndef ENODATA
#define ENODATA EFTYPE
#endif

/* OSX is fully 64bit */
#define O_LARGEFILE 0

/* < 10.6 does not have this */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#endif /* _DARWIN */

#define snprintfok(ret, bufsize) (((ret) >= 0) && \
				  (((unsigned int)(ret)) < bufsize))

#define lengthof(x) (sizeof (x) / sizeof (x)[0])

/* We don't use 'name', but we can easily replace this with a logging one */
#define mcalloc(size, name)	calloc(1, (size))
#define mfree(ptr, name, size)	do { free((void *)ptr); ptr = NULL; } while(0)
#define memzero(obj, len)	memset((obj), 0, (len))
#define mstrdup(s, name)	strdup(s)

#define mfreestrdup(s, name)			\
do {						\
	if (s == NULL)				\
		break;				\
	mfree(s, name, strlen(s));		\
} while(0)

#ifdef __GNUC__
#define PACKED __attribute__((packed))
#define ALIGNED __attribute__((aligned))
#define UNUSED __attribute__ ((__unused__))
#else
#define PACKED
#define ALIGNED
#define UNUSED
#endif

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#ifndef ATTR_FORMAT
#if defined(__GNUC__)
#define ATTR_RESTRICT __restrict
#define ATTR_FORMAT(type, x, y) __attribute__ ((format(type, x, y)))
#else
#define ATTR_FORMAT(type, x, y)	/* nothing */
#define ATTR_RESTRICT		/* nothing */
#endif
#endif

#ifndef ntohll
#define ntohll(x) htonll(x)
#endif

#ifndef htonll
#if BYTE_ORDER == LITTLE_ENDIAN
#define htonll(x) ((htonl((x >> 32) & 0xffffffff) + \
		    ((uint64_t) (htonl(x & 0xffffffff)) << 32)))
#else
#define htonll(x) (x)
#endif
#endif

union ipaddress {
	struct in6_addr ip6;
	uint64_t	a64[2];
	uint32_t	a32[4];
	uint16_t	a16[8];
	uint8_t		a8[20];	/* 4 bytes extra, byte 17 == prefixlength */
};

typedef union ipaddress ipaddress_t;

/* default socket backlog number. SOMAXCONN is a system default value */
#define DEF_SOCKET_BACKLOG	SOMAXCONN
#define DEF_POLLSET_NUM		32
#define DEF_POLL_TIMEOUT	1000
#define BUFSIZE			4096

/**
 ** Logging infrastructure
 **/

void logline(unsigned int level, const char *caller, const char *format, ...)
	     ATTR_FORMAT(printf, 3, 4);

#define LOG_ARG __func__

/* We completely compile out DEBUG statements */
#ifdef DEBUG
#define log_dbg(...) logline(LOG_DEBUG,   LOG_ARG, __VA_ARGS__)
#else
#define log_dbg(...) {}
#endif

#define log_emg(...) logline(LOG_EMERG,   LOG_ARG, __VA_ARGS__)
#define log_alt(...) logline(LOG_ALERT,   LOG_ARG, __VA_ARGS__)
#define log_crt(...) logline(LOG_CRIT,    LOG_ARG, __VA_ARGS__)
#define log_err(...) logline(LOG_ERR,     LOG_ARG, __VA_ARGS__)
#define log_wrn(...) logline(LOG_WARNING, LOG_ARG, __VA_ARGS__)
#define log_ntc(...) logline(LOG_NOTICE,  LOG_ARG, __VA_ARGS__)
#define log_inf(...) logline(LOG_INFO,    LOG_ARG, __VA_ARGS__)

typedef void (*logfunc_f)(unsigned int level, const char *caller,
			  const char *format, va_list ap)
			  ATTR_FORMAT(printf, 3, 0);

bool log_set(const char *filename);
void log_chown(uid_t uid, gid_t gid);
void log_setup(const char *name, FILE *f);
void log_setlevel(unsigned int level);
void log_setfunc(logfunc_f func);

/**
 ** inet infrastructure
 **/
#define inet_bits(ip) ((ip)->a8[17])
#define inet_clearbits(ip) ((ip)->a8[17]) = 128

bool isipv4(const ipaddress_t *a);
int inet_ptonA(const char *src, ipaddress_t *dst);
const char *inet_ntopA(const ipaddress_t *addr, char *dst, socklen_t cnt);

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 26
#endif

#define PRIsizet "zd"

/* Default Listen Queue */
#define LISTEN_QUEUE 128

/* Date Time format string */
#define FMT_DATETIME "%4u-%02u-%02u %02u:%02u:%02u"

#define fmt_datetime(teem)					\
		teem.tm_year+1900, teem.tm_mon+1, teem.tm_mday,	\
		teem.tm_hour, teem.tm_min, teem.tm_sec

#include "list.h"
#include "thread.h"
#include "rwl.h"
#include "stack.h"

#define gettime() gettimes(NULL)
uint64_t gettimes(uint64_t *msec);

#ifndef _WIN32
void set_timeout(struct timespec *timeout, unsigned int nsec);
#endif

/* For quick mapping of "header: value" strings */
typedef struct {
	const char	*label;
	unsigned int	offset;
	unsigned int	len;
} misc_map_t;

bool misc_map(const char *str, const misc_map_t *map, char *data);

const char *getprioname(unsigned int level);
unsigned int getpriolevel(const char *name);

void generate_random_bytes(uint8_t *rnd, uint64_t size);
uint64_t generate_random_number(void);


/* Base64 Standard */
unsigned int base64_encode_len(unsigned int len);
unsigned int base64_encode_binary(char *encoded,
				 const unsigned char *str,
				 unsigned int len);

unsigned int base64_decode_len(const char *bufcoded);
unsigned int base64_decode(char *bufplain, const char *bufcoded);

/* Base64 URL */
unsigned int base64url_encode_len(unsigned int len);
unsigned int base64url_encode_binary(char *encoded,
				     const unsigned char *str,
				     unsigned int len);
unsigned int base64url_decode_len(const char *bufcoded);
unsigned int base64url_decode(char *bufplain, const char *bufcoded);

void inet_rtop(struct addrinfo *res, char *buf, unsigned int buflen);

#ifdef _WIN32
const char *inet_ntop(int af, const void *src, char *dst, socklen_t cnt);
int inet_pton(int af, const char *src, void *dst);
struct tm *localtime_r(const time_t *timep, struct tm *result);
int strerror_r(int errnum, char *strerrbuf, size_t buflen);
#endif

const char *aprintf(const char *format, ...) ATTR_FORMAT(printf, 1, 2);
void aprintf_free(const char *buf);

void dumppacket(int level, const uint8_t *packet, uint64_t len);

int parse_iso8601_time(const char *t, uint64_t *when);

int parse_iso8601_interval(const char *interval,
			   uint64_t *start, uint64_t *end);

bool steg_encode(const char *src, unsigned int srclen,
		char **dst, unsigned int *dstlen,
		char **mime, unsigned int *mimelen);

bool steg_decode(const char *src, unsigned int srclen,
		 char **dst, unsigned int *dstlen);

#define yesno(q) (q ? "yes" : "no")

bool human_size(uint64_t n, char *buf, unsigned int buflen);

#endif /* MISC_H */
