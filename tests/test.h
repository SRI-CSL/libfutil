#ifndef TESTS_TEST_H
#define TESTS_TEST_H 1

/* a = sub-test-name, p = param, v = got value, e = expected value */
#define TEST_FAILA(a,p)		{ fprintf(stderr, "FAIL: %s -%s- %s\n", testfunc, a, p); }
#define TEST_FAILAR(a,p,v,e)	{ fprintf(stderr, "FAIL: %s -%s- %s (%d/%d)\n", testfunc, a, p, v, (int)e); }
#define TEST_FAILN(p,v,e)	{ fprintf(stderr, "FAIL: %s %" PRIu64 "- (%s/%s)\n", testfunc, p, yesno(v), yesno(e)); }
#define TEST_FAILNS(p,v,e)	{ fprintf(stderr, "FAIL: %s %" PRIu64 "- (\"%s\" != \"%s\")\n", testfunc, p, v, e); }
#define TEST_FAIL(parm)		{ TEST_FAILA("", parm); }

unsigned int test(void);

#endif /* TESTS_TEST_H */

