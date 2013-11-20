#include <libfutil/misc.h>
#include "test_misc.h"

unsigned int
test_isipv4(void);
unsigned int
test_isipv4(void) {
	ipaddress_t	addr;
	unsigned int	fails = 0;
	const char	*testfunc = "isipv4";
	const char	*parm;

	/*******************************************************/
	parm = "2001:db8::1";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAILA("inet_ptonA", parm);
		fails++;
	}

	if (isipv4(&addr)) {
		TEST_FAIL(parm);
		fails++;
	}

	/*******************************************************/
	parm = "192.0.2.1";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAILA("inet_ptonA", parm);
		fails++;
	}

	if (!isipv4(&addr)) {
		TEST_FAIL(parm);
		fails++;
	}

	return (fails);
}

unsigned int
test_inet_ptonA(void);
unsigned int
test_inet_ptonA(void) {
	ipaddress_t	addr;
	unsigned int	fails = 0;
	const char	*testfunc = "inet_ptonA";
	const char	*parm;

	/*******************************************************/
	parm = "2001:db8::1";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAIL(parm);
		fails++;
	}

	/*******************************************************/
	parm = "NOT.AN.IP.ADDR";
	if (inet_ptonA(parm, &addr) != 0) {
		TEST_FAIL(parm);
		fails++;
	}

	/*******************************************************/
	parm = "2001:db8::/32";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAIL(parm);
		fails++;
	}

	/*******************************************************/
	parm = "2001:db8::/128";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAIL(parm);
		fails++;
	}

	/*******************************************************/
	parm = "2001:db8::/-1";
	if (inet_ptonA(parm, &addr) == 1) {
		TEST_FAIL(parm);
		fails++;
	}

	/*******************************************************/
	parm = "2001:db8::/BLA";
	if (inet_ptonA(parm, &addr) == 1) {
		TEST_FAIL(parm);
		fails++;
	}

	/*******************************************************/
	parm = "192.0.2.1";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAIL(parm);
		fails++;
	}

	/*******************************************************/
	parm = "192.0.2.1/24";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAIL(parm);
		fails++;
	}

	if (inet_bits(&addr) != (128-(32-24))) {
		TEST_FAILA("netmask", parm);
		fails++;
	}

	/*******************************************************/
	parm = "192.0.2.1/0";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAIL(parm);
		fails++;
	}

	if (inet_bits(&addr) != (128-32)) {
		TEST_FAILA("netmask", parm);
		fails++;
	}

	return (fails);
}

unsigned int
test_inet_ntopA(void);
unsigned int
test_inet_ntopA(void) {
	ipaddress_t	addr;
	unsigned int	fails = 0;
	char		str[128];
	const char	*testfunc = "inet_ntopA";
	const char	*parm;

	/*******************************************************/
	parm = "2001:db8::1";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAILA("inet_ptonA", parm);
		fails++;
	}

	if (inet_ntopA(&addr, str, sizeof(str)) != str) {
		TEST_FAIL(parm);
		fails++;
	}

	/*******************************************************/
	parm = "192.0.2.1";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAILA("inet_ptonA", parm);
		fails++;
	}

	if (inet_ntopA(&addr, str, sizeof(str)) != str) {
		TEST_FAIL(parm);
		fails++;
	}

	if (strcasecmp(str, parm) != 0) {
		TEST_FAILA("string", parm);
		fails++;
	}

	/*******************************************************/
	parm = "192.0.2.1/24";
	if (inet_ptonA(parm, &addr) != 1) {
		TEST_FAILA("inet_ptonA", parm);
		fails++;
	}

	if (inet_ntopA(&addr, str, sizeof(str)) != str) {
		TEST_FAIL(parm);
		fails++;
	}

	if (strcasecmp(str, parm) != 0) {
		TEST_FAILA("string", parm);
		fails++;
	}


	return (fails);
}

unsigned int
test_iso8601_time(void);
unsigned int
test_iso8601_time(void) {
	unsigned int	fails = 0;
	const char	*testfunc = "parse_iso8601_time";
	const char	*parm;
	uint64_t	when;
	int		n;

	/*******************************************************/
	parm = "1996-12-19T16:39:57-08";
	n = parse_iso8601_time(parm, &when);
	if (n <= 0) {
		TEST_FAILAR(testfunc, parm, n, strlen(parm));
		fails++;
	}

	/*******************************************************/
	parm = "1996-12-19T16:39:57-08:00";
	n = parse_iso8601_time(parm, &when);
	if (n <= 0) {
		TEST_FAILAR(testfunc, parm, n, strlen(parm));
		fails++;
	}

	/*******************************************************/
	parm = "1996-12-19T16:39:57+12:00";
	n = parse_iso8601_time(parm, &when);
	if (n <= 0) {
		TEST_FAILAR(testfunc, parm, n, strlen(parm));
		fails++;
	}

	/*******************************************************/
	parm = "1990-12-31T23:59:60Z";
	n = parse_iso8601_time(parm, &when);
	if (n <= 0) {
		TEST_FAILAR(testfunc, parm, n, strlen(parm));
		fails++;
	}

	/*******************************************************/
	parm = "ABCDEFG";
	n = parse_iso8601_time(parm, &when);
	if (n > 0) {
		TEST_FAILAR(testfunc, parm, n, strlen(parm));
		fails++;
	}

	return (fails);
}

unsigned int
test_iso8601_interval(void);
unsigned int
test_iso8601_interval(void) {
	unsigned int	fails = 0;
	const char	*testfunc = "parse_iso8601_interval";
	const char	*parm;
	uint64_t	start, end;
	int		n;

	parm = "2013-01-01T18:00Z/2013-02-01T18:00:00-08:00";
	n = parse_iso8601_interval(parm, &start, &end);
	if (n < 0) {
		TEST_FAILAR(testfunc, parm, n, strlen(parm));
		fails++;
	}

	return (fails);
}

unsigned int
test_human_size(void);
unsigned int
test_human_size(void) {
	unsigned int	fails = 0, i;
	const char	*testfunc = "human_size";
	const char	*exp;
	uint64_t	parm;
	char		buf[1024];
	bool		ok;
	const uint64_t	parms[] = {
				1,
				100,
				1024,
				(1024*100)-1,
				(1024*100),
				(1024L*1024),
				(1024L*1024*10),
				(1024L*1024*1024),
#ifdef _64BIT
				(1024L*1024*1024*10) + 123,
				(1024L*1024*1024*100),
				(1024L*1024*1024*1024*1024),
				(1234567890123456789L),
#endif
			};
	const char	*exps[] = {
				"1 B",
				"100 B",
				"1024 B",
				"102399 B",
				"100 KiB",
				"1024 KiB",
				"10240 KiB",
				"1024 MiB",
#ifdef _64BIT
				"10240 MiB",
				"100 GiB",
				"1024 TiB",
				"1096 PiB",
#endif
			};

	assert(lengthof(parms) == lengthof(exps));

	for (i=0; i < lengthof(parms); i++) {
		parm = parms[i];
		exp = exps[i];
		ok = human_size(parm, buf, sizeof buf);
		if (ok == false) {
			TEST_FAILN(parm, ok, true);
			fails++;
		} else if (strcmp(buf, exp) != 0) {
			TEST_FAILNS(parm, buf, exp);
		}
	}

	return (fails);
}


unsigned int
test_misc(void) {
	unsigned int fails = 0;

	fails += test_isipv4();

	fails += test_inet_ptonA();
	fails += test_inet_ntopA();

	fails += test_iso8601_time();
	fails += test_iso8601_interval();

	fails += test_human_size();

	return (fails);
}

