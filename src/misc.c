/* We want the syslog prioritynames to be included here */
#define SYSLOG_NAMES

#include <libfutil/misc.h>

#if 1
#define SAFDEF_LOG_LONG 1
#endif

static const char project_ver[] = "Project Version: " STR(PROJECT_VERSION);
static const char project_git[] = "Project GIThash: " STR(PROJECT_GIT);
static const char project_bld[]	= "Project Build: " STR(PROJECT_BUILDTIME);

/* Where logs go to */
static const char	*l_log_filename = NULL;
static FILE		*l_log_output = NULL;
static unsigned int	l_log_level = LOG_INFO;
static const char	*l_log_name = NULL;
static logfunc_f	l_log_func = NULL;
static mutex_t		l_mutex;

void
log_setup(const char *name, FILE *f) {
	mutex_init(l_mutex);

	l_log_name = name;
	l_log_output = f;
}

bool
log_set(const char *filename) {
	FILE	*f;
	bool	ret;

	mutex_lock(l_mutex);

	f = fopen(filename, "w+");
	if (f) {
		l_log_filename = filename;
		l_log_output = f;
		ret = true;
	} else {
		logline(log_ERR_, "Could not open logfile %s", filename);
		ret = false;
	}

	mutex_unlock(l_mutex);

	return (ret);
}

void
log_setlevel(unsigned int level) {
	mutex_lock(l_mutex);
	l_log_level = level;
	mutex_unlock(l_mutex);
}

void
log_setfunc(logfunc_f func) {
	mutex_lock(l_mutex);
	l_log_func = func;
	mutex_unlock(l_mutex);
}

static void
logitVA(unsigned int level, const char *file, unsigned int line, const char *caller,
	const char *format, va_list ap) ATTR_FORMAT(printf, 5, 0);
static void
logitVA(unsigned int level, const char UNUSED *file,
	unsigned int UNUSED line, const char *caller,
	const char *format, va_list ap)
{
	static uint64_t	id_p = 0;
	static unsigned int level_p = -1;
	uint64_t	id = getthisthreadid(), msec;
	int64_t		maxlogsize = (100 * 1024 * 1024);
	struct stat	st;
	time_t		tm;
	struct tm	teem;

	/* Lock her up */
	mutex_lock(l_mutex);

	/* If we maintain our own log file */
	/* Check the filesize to not exceed our threshold */
	if (	l_log_filename &&
		l_log_output &&
		(fstat(fileno(l_log_output), &st) != 0 ||
		 st.st_size > maxlogsize)) {

		/* Error or over our limit */
		rewind(l_log_output);
		if (ftruncate(fileno(l_log_output), 0)) {}
	}

	/* Not open yet? */
	if (!l_log_output && l_log_filename) {
		l_log_output = fopen(l_log_filename, "w+");
	}

	/* No log output */
	if (!l_log_output) {
#ifndef _WIN32
		/* Use syslog as we have nothing better */
		vsyslog(level, format, ap);
#else
		vfprintf(stderr, format, ap);
#endif
	} else {
		char t[32], ln[9];
		unsigned int i;

		/* Skip repeated levels */
		if (level == level_p) {
			i = sizeof ln;
			memset(ln, ' ', i);
			ln[i - 1] = '\0';
		} else {
			level_p = level;
			snprintf(ln, sizeof ln, "%s",
				 getprioname(level));
		}

		/* Skip repeated thread id's */
		snprintf(t, sizeof t, THREAD_ID, id);

		if (id == id_p) {
			i = strlen(t);
			memset(t, ' ', i);
			t[i] = '\0';
		} else {
			id_p = id;
		}

		/* Include the time in the log */
		tm = gettimes(&msec);
		localtime_r(&tm, &teem);

		fprintf(l_log_output,
#ifdef SAFDEF_LOG_LONG
			"%4u-%02u-%02u %02u:%02u:%02u.%03" PRIu64 " "
#else
			"%" PRIu64 " "
#endif
			"%-8s %s %s() ",
#ifdef SAFDEF_LOG_LONG
			teem.tm_year+1900, teem.tm_mon+1, teem.tm_mday,
			teem.tm_hour, teem.tm_min, teem.tm_sec, msec,
#else
			tm,
#endif
			ln, t, caller);
		vfprintf(l_log_output, format, ap);
		fprintf(l_log_output, "\n");
		fflush(l_log_output);
	}

	/* Release her */
	mutex_unlock(l_mutex);
}

static bool
log_levelcheck(unsigned int level);
static bool
log_levelcheck(unsigned int level) {
	static bool	checked_env = false;
	const char 	*e;

	/* Log level setting from environment
	 * Cache it as it can't change (easily at least) anyway
	 */
	if (!checked_env) {
		checked_env = true;

		e = getenv("SAFDEF_LOG_LEVEL");
		if (e) {
			l_log_level = getpriolevel(e);
		}
	}

	/* Ignore it ? */
	return (level > l_log_level ? false : true);
}

/** Log line with details
 *  format SHOULD NOT include "\n"
 */
void
logline(unsigned int level, const char *file, unsigned int line, const char *caller,
	const char *format, ...)
{
	static bool		log_break_checked = false;
	static unsigned int	log_break_level = LOG_CRIT;
	va_list			ap;

	/* Check if we want this logged or not */
	if (!log_levelcheck(level)) {
		return;
	}

	/* Actually log it */
	va_start(ap, format);

	if (l_log_func)
		l_log_func(level, file, line, caller, format, ap);
	else
		logitVA(level, file, line, caller, format, ap);

	va_end(ap);

	/*
	 * During debugging we like this to bail out
	 * so that we don't scroll by the error
	 */
	if (!log_break_checked) {
		const char *e;

		log_break_checked = true;
		e = getenv("SAFDEF_LOG_BREAK");
		if (e) {
			log_break_level = getpriolevel(e);
		}
	}

	if (level <= log_break_level) {
		va_start(ap, format);
		logitVA(level, file, line, caller,
			"Hit Log Break", ap);
		va_end(ap);

		/* Crash and Burn */
		fassert(false);
	}
}

const uint8_t ipv4_mapped_ipv6_prefix[12] = {	0, 0, 0, 0,
						0, 0, 0, 0,
						0, 0, 0xff, 0xff
					    };

/*
 * 0          1
 * 01234567 89012345
 * +----------------
 *            ffabcd    ::ffff:aa.bb.cc.dd = IPv4 mapped
 */
bool
isipv4(const ipaddress_t *a) {
	const uint64_t *a64 = (const uint64_t *)a->a64;
	const uint16_t *a16 = (const uint16_t *)a->a16;

	/* Quick test, bits 80-96 must be 1 (11+12 == 0xffff)
	 * for it to be IPv4
	 */
	if (a->a8[10] != 0xff || a->a8[11] != 0xff)
		return (false);

	/* Check the first 80 bits to be 0, otherwise it is IPv6 anyway */
	/* First 64 bits + bits 64-80 */
	if (a64[0] != 0 || a16[4] != 0)
		return (false);

	/* Passed all tests, must be IPv4 (-Mapped IPv6 Address). */
	return (true);
}

int
inet_ptonA(const char *src, ipaddress_t *dst) {
	char		tmp[1024];
	unsigned int	af, ret, i;
	unsigned int	l = 128;
	char		*s;

	/* Clear it out. */
	memzero(dst, sizeof *dst);

	/* When it includes a ':' it is an IPv6 address. */
	af = strstr(src, ":") ? AF_INET6 : AF_INET;

	/* Copy the address till the end or '/'. */
	memzero(tmp, sizeof tmp);
	for (i = 0; i < sizeof tmp && src[i] != '\0' && src[i] != '/'; i++)
		tmp[i] = src[i];
	if (i >= sizeof tmp) {
		errno = ENOSPC;
		return (-1);
	}

	/* Parse the address */
	ret = inet_pton(af, tmp, dst->a8);
	if (ret <= 0)
		return (ret);

	/* Move IPv4 address to the back and set the ::ffff in front of it. */
	if (af == AF_INET) {
		memcpy(&dst->a8[12], &dst->a8[0], 4);
		memcpy(&dst->a8[0], ipv4_mapped_ipv6_prefix,
		       sizeof ipv4_mapped_ipv6_prefix);
	}

	/* Prefix length given? */
	s = strchr(src, '/');

	/* No prefixlength given. */
	if (s) {
		/* Don't allow negativity. */
		if (s[1] == '-') {
			errno = ENOMSG;
			return (-1);
		}

		/* Get the length from behind the number. */
		if (sscanf(&s[1], "%u", &l) != 1) {
			errno = EDOM;
			return (-1);
		}

		/* Add 96 bits as that is where IPv4 starts inside IPv6.
		 * Users specify a /24, but then it is a /120 to us.
		 * Only do this when it is IPv4.
		 */
		if (af == AF_INET)
			l += 96;
	}

	/* Verify that the prefix length is valid. */
	if (l > 128) {
		errno = EMSGSIZE;
		return (-1);
	}

	/* Store it. */
	dst->a8[17] = l;

	return (ret);
}

/* Version aware version of inet_ntop(). */
const char *
inet_ntopA(const ipaddress_t *addr, char *dst, socklen_t cnt) {
	bool		isv4 = isipv4(addr);
	const char	*ret;

	/* Wipe it clean. */
	memzero(dst, cnt);

	ret = isv4 ? inet_ntop(AF_INET, (char *)&addr->a8[12], dst, cnt)
		   : inet_ntop(AF_INET6, (char *)addr, dst, cnt);

	if (ret == dst) {
		/* Does it have a prefix length? */
		if (addr->a8[17] != 128) {
			socklen_t l = strlen(dst);
			if (l >= cnt)
				return (ret);
			snprintf(&dst[l], cnt - l, "/%u",
				 addr->a8[17] - (isv4 ? 96 : 0));
		}
	}

	return (ret);
}

uint64_t
gettimes(uint64_t *msec) {
#ifdef __MACH__
	/* OS X does not have clock_gettime, use clock_get_time */
	clock_serv_t	cclock;
	mach_timespec_t	mts;

	host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
	clock_get_time(cclock, &mts);
	mach_port_deallocate(mach_task_self(), cclock);

	if (msec != NULL) {
		/* nsec -> msec */
		*msec = mts.tv_nsec / (1000*1000);
	}

	return (mts.tv_sec);
#else
#ifndef _WIN32
	struct timespec	ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	if (msec != NULL) {
		/* nsec -> msec */
		*msec = ts.tv_nsec / (1000*1000);
	}
	return (ts.tv_sec);
#else /* _WIN32 */
	/* Note: Windows stores time in 'intervals of 100 nanoseconds' */
	LARGE_INTEGER	t;
	FILETIME	f;
	uint64_t	ret, m;

	GetSystemTimeAsFileTime(&f);
	t.LowPart = f.dwLowDateTime;
	t.HighPart = f.dwHighDateTime;
	ret = t.QuadPart;

	/* Convert from file time to UNIX epoch time. */
	ret -= 116444736000000000LL;

	/* Keep this around for a bit */
	m = ret;

	ret /= (10*1000*1000); /* From 100 nano seconds (10^-7) to seconds */

	/* Fill in the microseconds if wanted */
	if (msec != NULL) {
		/* Remove the seconds */
		m -= (ret * 10*1000*1000);

		/* 100 nsec -> msec */
		*msec = m / (10*1000);
	}

	return (ret);
#endif /* _WIN32 */
#endif /* __MACH__ */
}

/*
 *             1 sec          ( sec) =
 *         1.000 milliseconds (msec) =
 *     1.000.000 microseconds (usec) =
 * 1.000.000.000 nanoseconds  (nsec)
 *
 * win32 Sleep() uses milliseconds
 */
#ifndef _WIN32
void
set_timeout(struct timespec *timeout, unsigned int msec) {
#ifdef _LINUX
	/* get current time */
	memzero(timeout, sizeof *timeout);
	clock_gettime(CLOCK_REALTIME, timeout);
	timeout->tv_nsec += msec * (1000 * 1000);
#else
	struct timeval now;

	gettimeofday(&now, NULL);
	memzero(timeout, sizeof *timeout);
	timeout->tv_sec = now.tv_sec + msec / 1000;
	timeout->tv_nsec = (now.tv_usec * 1000) + (msec % 1000) * (1000*1000);
#endif
	fassert(timeout->tv_nsec >= 0);

	while (timeout->tv_nsec > (1000*1000*1000)) {
		timeout->tv_sec++;
		timeout->tv_nsec -= (1000*1000*1000);
	}
}
#endif

bool
misc_map(const char *str, const misc_map_t *map, char *data) {
	unsigned int	i = 0, l, len;
	const char	*s;

	/* How long is the string? */
	len = strlen(str);

	/* How long is the header name? */
	s = strchr(str, ':');

	/* Should never happen as we feed it but you never know */
	if (s == NULL) {
		return (false);
	}

	/* Length of this header */
	l = s - str;

	/* Empty header? */
	if ((l+2) >= len) {
		return (false);
	}

	/* Length of the value */
	len -= (l+2);

	for (i = 0; map[i].label; i++) {
		/* Not it then next */
		if (strncasecmp(map[i].label, str, l) != 0) {
			continue;
		}

		/* Be sure that was the full header name */
		if (str[l] != ':' && str[l+1] != ' ') {
			continue;
		}

		/* Will it fit? */
		if (len > map[i].len) {
			/* During debugging we want to catch this */
			logline(log_DEBUG_, "Won't fit! %u vs %u\n",
				len, map[i].len);
			fassert(false);
			l = map[i].len;
		}

		/* Skip the ": " */
		l += 2;

		/* Found it, fill it in */
		memcpy(&data[map[i].offset], &str[l], len);

		/* Make sure the string is terminated */
		data[map[i].offset + len] = '\0';

		return (true);
	}

	return (false);
}

static const struct {
	const char	*c_name;
	int		c_level;
} priority_names[] = {
	{ "emerg",	LOG_EMERG },
	{ "alert",	LOG_ALERT },
	{ "crit",	LOG_CRIT },
	{ "error",	LOG_ERR },
	{ "warning",	LOG_WARNING },
	{ "notice",	LOG_NOTICE },
	{ "info",	LOG_INFO },
	{ "debug",	LOG_DEBUG },

	/* Aliases (lookup only) */
	{ "emergency",	LOG_EMERG },
	{ "err",	LOG_ERR },
	{ "warn",	LOG_WARNING }
};

const char *
getprioname(unsigned int level) {
	return (level < lengthof(priority_names) ?
		priority_names[level].c_name : "unknown");
}

unsigned int
getpriolevel(const char *name) {
	unsigned int i;

	/* It is already a number */
	if (sscanf(name, "%u", &i) == 1) {
		return i;
	}

	for (i = 0; i < lengthof(priority_names); i++) {
		if (strcasecmp(priority_names[i].c_name, name) == 0)
			return (priority_names[i].c_level);
	}

	/* Not found */
	logline(log_CRIT_,
		"Priority level '%s' does not exist",
		name);

	return (0);
}

/* If random reading fails the 'random' will be the input buffer */
void
generate_random_bytes(uint8_t *rnd, uint64_t size) {
#ifndef _WIN32
	FILE		*f;
	size_t		n;
	const char	dev[] = "/dev/urandom";

	/* Open it */
	f = fopen(dev, "r");
	if (!f) {
		logline(log_CRIT_, "Could not open %s", dev);
		return;
	}

	n = fread(rnd, 1, size, f);
	if (n != size) {
		logline(log_CRIT_,
			"Random read failed, got %" PRIu64 " of %" PRIu64,
			(uint64_t)n, size);
	}

	/* Close her up */
	fclose(f);

	/* Just in case */
	fassert(n == size);
#else
	HCRYPTPROV	hProvider = 0;

	if (!CryptAcquireContextA(&hProvider, 0, 0, PROV_RSA_FULL,
				   CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		return;
	}

	if (!CryptGenRandom(hProvider, size, rnd)) {
		logline(log_CRIT_, "CryptGenRandom() failed");
	}

	CryptReleaseContext(hProvider, 0);
#endif
}

uint64_t
generate_random_number(void) {
	unsigned char	rnd[8];
	uint64_t	i, r;

	/* Generate some randomness */
	generate_random_bytes(rnd, sizeof rnd);

	/* Add them up so that we have a random number from 64 bits */
	for (r=0, i=0; i < sizeof rnd; i++) {
		r += rnd[i];
	}

	/* Clean out our random sauce */
	memzero(rnd, sizeof rnd);

	return (r);
}

/* As per the Apache APR base64 functions but with variable alphabet */

unsigned int
base64_encode_len(unsigned int len) {
	return ((len + 2) / 3 * 4) + 1;
}

unsigned int
base64url_encode_len(unsigned int len) {
	return (base64_encode_len(len));
}

unsigned int
base64_encode_binary_alpha(char *encoded,
			   const unsigned char *str,
			   unsigned int len,
			   const char *alphabet,
			   const char pad);
unsigned int
base64_encode_binary_alpha(char *encoded,
			   const unsigned char *str,
			   unsigned int len,
			   const char *alphabet,
			   const char pad) {
	unsigned int	i;
	char		*p;

	p = encoded;
	for (i = 0; i < len - 2; i += 3) {
		*p++ = alphabet[(str[i] >> 2) & 0x3F];
		*p++ = alphabet[((str[i] & 0x3) << 4) |
			((int) (str[i + 1] & 0xF0) >> 4)];
		*p++ = alphabet[((str[i + 1] & 0xF) << 2) |
			((int) (str[i + 2] & 0xC0) >> 6)];
		*p++ = alphabet[str[i + 2] & 0x3F];
	}

	if (i < len) {
		*p++ = alphabet[(str[i] >> 2) & 0x3F];

		if (i == (len - 1)) {
			*p++ = alphabet[((str[i] & 0x3) << 4)];
			*p++ = '=';
		} else {
			*p++ = alphabet[((str[i] & 0x3) << 4) |
				((int) (str[i + 1] & 0xF0) >> 4)];
			*p++ = alphabet[((str[i + 1] & 0xF) << 2)];
		}

		*p++ = pad;
	}

	*p++ = '\0';

	return (p - encoded);
}

unsigned int
base64_encode_binary(char *encoded, const unsigned char *str, unsigned int len) {
	static const char basis_64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	return (base64_encode_binary_alpha(encoded, str, len, basis_64, '='));
}

/* As per http://tools.ietf.org/html/rfc4648 */
unsigned int
base64url_encode_binary(char *encoded, const unsigned char *str, unsigned int len) {
	static const char basis_64url[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

	return (base64_encode_binary_alpha(encoded, str, len, basis_64url, '='));
}

static const unsigned char pr2six[256] =
{
	/* ASCII table */
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static const unsigned char pr2six_url[256] =
{
	/* ASCII table */
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};


static unsigned int
base64_decode_len_alpha(const char *bufcoded, const char unsigned *alpha);
static unsigned int
base64_decode_len_alpha(const char *bufcoded, const char unsigned *alpha) {
	int				nbytesdecoded;
	register const unsigned char	*bufin;
	register unsigned int		nprbytes;

	bufin = (const unsigned char *)bufcoded;
	while (alpha[*(bufin++)] <= 63);

	nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
	nbytesdecoded = (((int)nprbytes + 3) / 4) * 3;

	return (nbytesdecoded + 1);
}

unsigned int
base64_decode_len(const char *bufcoded) {
	return (base64_decode_len_alpha(bufcoded, pr2six));
}

unsigned int
base64url_decode_len(const char *bufcoded) {
	return (base64_decode_len_alpha(bufcoded, pr2six_url));
}

/* This is the same as apr_base64_decode() except on EBCDIC machines, where
 * the conversion of the output to ebcdic is left out.
 */
static unsigned int
base64_decode_binary(unsigned char *bufplain,
		     const char *bufcoded,
		     const unsigned char *alpha);
static unsigned int
base64_decode_binary(unsigned char *bufplain,
		     const char *bufcoded,
		     const unsigned char *alpha)
{
	unsigned int			nbytesdecoded;
	register const unsigned char	*bufin;
	register unsigned char		*bufout;
	register unsigned int		nprbytes;

	bufin = (const unsigned char *)bufcoded;

	while (alpha[*(bufin++)] <= 63);

	nprbytes = (bufin - (const unsigned char *)bufcoded) - 1;
	nbytesdecoded = (((int)nprbytes + 3) / 4) * 3;

	bufout = (unsigned char *)bufplain;
	bufin = (const unsigned char *)bufcoded;

	while (nprbytes > 4) {
		*(bufout++) =
			(unsigned char)(alpha[*bufin] << 2 |
					alpha[bufin[1]] >> 4);
		*(bufout++) =
			(unsigned char)(alpha[bufin[1]] << 4 |
					alpha[bufin[2]] >> 2);
		*(bufout++) =
			(unsigned char)(alpha[bufin[2]] << 6 |
					alpha[bufin[3]]);
		bufin += 4;
		nprbytes -= 4;
	}

	/* Note: (nprbytes == 1) would be an error, so just ignore that case */
	if (nprbytes > 1) {
		*(bufout++) =
			(unsigned char)(alpha[*bufin] << 2 |
					alpha[bufin[1]] >> 4);
	}

	if (nprbytes > 2) {
		*(bufout++) =
			(unsigned char)(alpha[bufin[1]] << 4 |
					alpha[bufin[2]] >> 2);
	}

	if (nprbytes > 3) {
		*(bufout++) =
			(unsigned char)(alpha[bufin[2]] << 6 |
					alpha[bufin[3]]);
	}

	nbytesdecoded -= (4 - nprbytes) & 3;

	return (nbytesdecoded);
}


unsigned int
base64_decode(char *bufplain, const char *bufcoded) {
	unsigned int len;

	len = base64_decode_binary(
		(unsigned char *)bufplain,
		bufcoded,
		pr2six);

	bufplain[len] = '\0';

	return (len);
}

unsigned int
base64url_decode(char *bufplain, const char *bufcoded) {
	unsigned int len;

	len = base64_decode_binary(
		(unsigned char *)bufplain,
		bufcoded,
		pr2six_url);
	bufplain[len] = '\0';

	return (len);
}

#define family_name(fm)					\
	(fm == AF_INET		?	"IPv4" :	\
	(fm == AF_INET6		?	"IPv6" :	\
					"unknown"))

#define protocol_name(pr)				\
	(pr == IPPROTO_UDP	?	"udp" :		\
	(pr == IPPROTO_TCP	?	"tcp" :		\
	(pr == IPPROTO_SCTP	?	"sctp" :	\
					"unknown")))

#define socktype_name(st)				\
	(st == SOCK_STREAM	?	"stream" :	\
	(st == SOCK_DGRAM	?	"datagram" :	\
	(st == SOCK_SEQPACKET	?	"seqpacket" :	\
					"unknown")))

/* Convert a addrinfo structure into a readable string */
void
inet_rtop(struct addrinfo *res, char *buf, unsigned int buflen) {
	struct sockaddr_in	res4;
	struct sockaddr_in6	res6;
	char			hst[42];

	if (res->ai_family == AF_INET)
		memcpy(&res4, res->ai_addr, sizeof res4);
	else
		memcpy(&res6, res->ai_addr, sizeof res6);

	inet_ntop(res->ai_family,
		  res->ai_family == AF_INET6 ?
		  	(void *)&res6.sin6_addr :
		  	(void *)&res4.sin_addr,
		  hst, sizeof hst);

	snprintf(buf, buflen, "%s://%s%s%s:%u (%s %s/%u)",
		 protocol_name(res->ai_protocol),
		 res->ai_family == AF_INET6 ? "[" : "",
		 hst,
		 res->ai_family == AF_INET6 ? "]" : "",
		 htons(res->ai_family == AF_INET6 ?
			res6.sin6_port : res4.sin_port),
		 family_name(res->ai_family),
		 socktype_name(res->ai_socktype), res->ai_socktype);
}

#ifdef _WIN32
const char *
inet_ntop(int af, const void *src, char *dst, socklen_t cnt) {
	if (af == AF_INET) {
		struct sockaddr_in in;

		memzero(&in, sizeof in);
		in.sin_family = AF_INET;
		memcpy(&in.sin_addr, src, sizeof in.sin_addr);
		getnameinfo((struct sockaddr *)&in,
			    sizeof in,
			    dst, cnt, NULL, 0, NI_NUMERICHOST);
		return (dst);
	} else if (af == AF_INET6) {
		struct sockaddr_in6 in;

		memzero(&in, sizeof in);
		in.sin6_family = AF_INET6;
		memcpy(&in.sin6_addr, src, sizeof in.sin6_addr);
		getnameinfo((struct sockaddr *)&in,
			    sizeof in,
			    dst, cnt, NULL, 0, NI_NUMERICHOST);
		return (dst);
	}

	return (NULL);
}

int
inet_pton(int af, const char *src, void *dst) {
	struct addrinfo hints, *res, *ressave;

	memzero(&hints, sizeof hints);
	hints.ai_family = af;

	if (getaddrinfo(src, NULL, &hints, &res) != 0) {
		logline(log_ERR_, "Couldn't resolve host %s", src);
		return (-1);
	}

	ressave = res;

	while (res) {
		/* Check if AF is correct */
		if (res->ai_family != af) {
			res = res->ai_next;
			continue;
		}

		/* This is the one we want */
		memcpy(dst, res->ai_addr,
		       af == AF_INET6 ?
				sizeof(struct in_addr6):
				sizeof(struct in_addr));

		/* We only need one */
		break;
	}

	if (ressave)
		freeaddrinfo(ressave);

	return (0);
}

struct tm *
localtime_r(const time_t *timep, struct tm *result) {
	result = localtime(timep);
	return (result);
}

int
strerror_r(int errnum, char *strerrbuf, size_t buflen) {
	char *result;

	result = strerror(errnum);
	strncpy(strerrbuf, result, buflen);

	return (result ? 0 : EINVAL);
}

#endif /* _WIN32 */

#define DUMPPACKET_PERLINE	16
#define DUMPPACKET_LINES	8
#define DUMPPACKET_MAX		(DUMPPACKET_PERLINE * DUMPPACKET_LINES)
void
dumppacket(int level, const uint8_t *packet, uint64_t len) {
	unsigned int	i, j, k;
	uint8_t		c;
	uint64_t	plen = len;

	/* Silently ignore as we have nowhere to log
	 * Users debugging and needing these details will notice
	 * as all other log messages are not there either
	 */
	if (!l_log_output) {
		return;
	}

	/* Check if we want this logged or not */
	if (!log_levelcheck(level)) {
		return;
	}

	mutex_lock(l_mutex);

	/* Limit the length? */
	if (plen > DUMPPACKET_MAX) {
		plen = DUMPPACKET_MAX;
	}

	for (i = 0; i < plen; i++) {
		/* Show the position? */
		if (i % DUMPPACKET_PERLINE == 0) {
			fprintf(l_log_output, "%08x ", i);
		}

		/* Print the char */
		fprintf(l_log_output, "%02x ", packet[i]);

		/* Show the ASCII portion at the end? */
		j = i % DUMPPACKET_PERLINE;
		if (j == (DUMPPACKET_PERLINE - 1) || i == (plen - 1)) {
			/* Add spaces for bytes that we do not show */
			for (k = j; k < DUMPPACKET_PERLINE-1; k++) {
				fprintf(l_log_output, "   ");
			}

			/* Go back to the beginning of the line */
			i -= j;

			/* Show the bytes in ASCII */
			for (k = 0; k <= j; k++) {
				c = packet[i+k];
				fprintf(l_log_output,
					"%c", c >= ' ' && c <= '~' ? c : '.');
			}

			/* At the end again */
			i += j;

			/* Finish the line */
			fprintf(l_log_output, "\n");
		}
	}

	if (plen != len) {
		fprintf(l_log_output,
			"-------- Only showed first %" PRIu64 " of %" PRIu64 "\n",
			plen, len);
	}

	mutex_unlock(l_mutex);
}

/* Verbose error messages for parse_iso8601_time() */
#if 0
#define PI8601D(x) { fprintf(stderr, "%s\n", x); }
#define PI8601DD(x,e) { fprintf(stderr, "%s (%d)\n", x, e); }
#else
#define PI8601D(x) { }
#define PI8601DD(x,e) { }
#endif

/*
 * Parse a time in the format:
 *  1996-12-19T16:39:57-08:00
 *  1990-12-31T23:59:60Z
 *
 * Manual parse as strptime() is not available on all platforms
 * and %z is not standard even then, can't use sscanf as then
 * we would not know where the end is, or have to specify all
 * possible combinations.
 *
 * XXX: Might have issues with DST, should test that
 *
 * Returns <x for the char where parsing failed or >0 when okay
 */
int
parse_iso8601_time(const char *t, uint64_t *when) {
	struct tm	tm;
	unsigned int	n = 0, m = strlen(t);
	int		tzpos = 0, tz = 0;

	memzero(&tm, sizeof tm);
	*when = 0;

	PI8601D("parse_iso8601_time()---------------");
	PI8601D(t);
	PI8601D("parse_iso8601_time()---------------");

	/* Year */
	for (; n < m; n++) {
		if (t[n] >= '0' && t[n] <= '9') {
			tm.tm_year *= 10;
			tm.tm_year += t[n] - '0';
		}
		else if (t[n] == '-') {
			n++;
			break;
		} else {
			/* Year broken */
			PI8601D("year broken");
			return (-n);
		}
	}

	/* Years are -1900 */
	if (tm.tm_year < 1900) {
		PI8601DD("year < 1900", tm.tm_year);
		return (-n);
	}
	PI8601DD("year", tm.tm_year);

	/* Month */
	for (; n < m; n++) {
		if (t[n] >= '0' && t[n] <= '9') {
			tm.tm_mon *= 10;
			tm.tm_mon += t[n] - '0';
		}
		else if (t[n] == '-') {
			n++;
			break;
		} else {
			/* Month broken */
			PI8601D("month broken");
			return (-n);
		}
	}

	/* Month ranges from 0-11 */
	if (tm.tm_mon == 0 || tm.tm_mon > 12) {
		PI8601DD("month == 0 || month >12", tm.tm_mon);
		return (-n);
	}
	PI8601DD("month", tm.tm_mon);

	tm.tm_mon--;

	/* Day */
	for (; n < m; n++) {
		if (t[n] >= '0' && t[n] <= '9') {
			tm.tm_mday *= 10;
			tm.tm_mday += t[n] - '0';
		}
		else if (t[n] == 'T') {
			n++;
			break;
		} else {
			/* Day broken */
			PI8601D("day broken");
			return (-n);
		}
	}

	if (tm.tm_mday == 0 || tm.tm_mday > 31) {
		PI8601DD("day == 0 || day > 31", tm.tm_mday);
		return (-n);
	}
	PI8601DD("day", tm.tm_mday);

	/* Hour */
	for (; n < m; n++) {
		if (t[n] >= '0' && t[n] <= '9') {
			tm.tm_hour *= 10;
			tm.tm_hour += t[n] - '0';
		}
		else if (t[n] == ':') {
			n++;
			break;
		} else {
			/* Hour broken */
			PI8601D("hour broken");
			return (-n);
		}
	}

	if (tm.tm_hour == 0 || tm.tm_hour > 24) {
		PI8601DD("hour == 0 || hour > 31", tm.tm_hour);
		return (-n);
	}
	PI8601DD("hour", tm.tm_hour);

	/* Minutes */
	for (; n < m; n++) {
		if (t[n] >= '0' && t[n] <= '9') {
			tm.tm_min *= 10;
			tm.tm_min += t[n] - '0';
		}
		else if (t[n] == ':') {
			n++;
			break;
		} else if (t[n] == '-' || t[n] == '+' || t[n] == 'Z') {
			/* Don't skip as we need it next for TZ */
			break;
		} else {
			/* Minutes broken */
			PI8601D("minutes broken");
			return (-n);
		}
	}

	if (tm.tm_min > 59) {
		PI8601DD("min > 59", tm.tm_min);
		return (-n);
	}
	PI8601DD("min", tm.tm_min);

	/* Seconds */
	for (; n < m; n++) {
		if (t[n] >= '0' && t[n] <= '9') {
			tm.tm_sec *= 10;
			tm.tm_sec += t[n] - '0';
		}
		else if (t[n] == '.') {
			/* Skip over subseconds */
			for (n++; n < m && t[n] >= '0' && t[n] <= '9'; n++);
		} else if (t[n] == '-' || t[n] == '+' || t[n] == 'Z') {
			/* Don't skip as we need it next for TZ */
			break;
		} else {
			/* Seconds broken */
			PI8601D("seconds broken");
			return (-n);
		}
	}

	/* Note valid range is 00 - 60 due to leap seconds */
	if (tm.tm_sec > 60) {
		PI8601DD("sec > 60", tm.tm_sec);
		return (-n);
	}
	PI8601DD("sec", tm.tm_sec);

	/* TZ included? */
	if (n < m) {
		if (t[n] == 'Z') {
			/* Zulu and thus UTC based */
			tz = 0;
			n++;
		} else if (t[n] == '-' || t[n] == '+') {

			/* Negative or positive offset? */
			if (t[n] == '-') {
				tzpos = -1;
			} else {
				tzpos = 1;
			}

			/* Skip over offset */
			n++;

			/* Parse the TZ offset */
			for (;n < m; n++) {
				if (t[n] >= '0' && t[n] <= '9') {
					tz *= 10;
					tz += t[n] - '0';
				}
				else if (t[n] == ':') {
					n++;
					break;
				} else {
					/* Timezone broken */
					PI8601D("timezone broken");
					return (-n);
				}
			}

			/* No minutes specified? */
			if (tz < 100)
				tz *= 100;

			/* Apply negative/positive */
			tz *= tzpos;
		}

		PI8601DD("timezone", tz);

#ifndef _WIN32
		/* Seconds east of UTC (glibc, introduced in 4.3BSD-Reno) */
		tm.tm_gmtoff = tz*100;
#endif
	}

	/* Return a epoch time */
	*when = mktime(&tm);

	return (n);
}

/*
 * Parse an interval of two ISO8601 times, separated by a forward slash ('/')
 *
 * returns negative value for the location of the problem
 * or positive where the parse stopped
 */
int
parse_iso8601_interval(const char *interval, uint64_t *start, uint64_t *end) {
	int n, m;

	/* Parse them */
	n = parse_iso8601_time(&interval[0], start);
	if (n <= 0) {
		PI8601DD("first time parse failed", n);
		return (n);
	}

	/* Should be a forward slash here */
	if (interval[n] != '/') {
		PI8601DD("no forward slash", n);
		return (-n);
	}

	m = parse_iso8601_time(&interval[n+1], end);
	if (m <= 0) {
		PI8601DD("second time parse failed", m);
		return ((-1 * (n+1)) + m);
	}

	/* End before start? */
	if (*end < *start) {
		PI8601D("end before start");
		return (-(n+m));
	}

	/* All okay */
	return (n+m);
}

bool
steg_encode(const char *src, unsigned int srclen,
	    char **dst, unsigned int *dstlen,
	    char **mime, unsigned int *mimelen)
{
	const char	mimetype[] = "application/octet-stream";
	char		*d, *m;
	unsigned int	i, j, m_len = strlen(mimetype)+1;

	/* XXX: we do a silly transform till we have StegoTorus stegs */

	d = mcalloc(srclen, "steg_data");
	m = mcalloc(m_len, "steg_mime");

	/* Our semi-fixed mimetype */
	memcpy(m, mimetype, m_len);

	/* Do the transform */
	for (i = 0; i < srclen; i++) {
		j = src[i];
		j += (42 + i);
		j &= 0xff;
		d[i] = j;
	}

	/* The result */
	*dst = d;
	*dstlen = srclen;
	*mime = m;
	*mimelen = m_len;

	return (true);
}

bool
steg_decode(const char *src, unsigned int srclen,
	    char **dst, unsigned int *dstlen)
{
	unsigned int	i, j;
	char		*d;

	/* XXX: reverse the silly thing till we have StegoTorus stegs */

	d = mcalloc(srclen, "steg");

	for (i = 0; i < srclen; i++) {
		j = src[i];
		j += 256;
		j -= (42 + i);
		j &= 0xff;
		d[i] = j;
	}

	/* The result */
	*dst = d;
	*dstlen = srclen;

	return (true);
}

bool
human_size(uint64_t n, char *buf, unsigned int buflen) {
	static const char	sizes[] = " KMGTPEZY";
	unsigned int		s;
	int			r;

	for (s = 0; s < lengthof(sizes) && n >= (100 * 1024); s++) {
		n /= 1024;
	}

	if (s == 0) {
		r = snprintf(buf, buflen,
			 "%" PRIu64 " B",
			 n);
	} else {
		r = snprintf(buf, buflen,
			 "%" PRIu64 " %ciB",
			 n, sizes[s]);
	}

	return (snprintfok(r, buflen));
}

