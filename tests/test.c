#include <stdio.h>

#include <libfutil/misc.h>
#include "test.h"
#include "test_buf.h"
#include "test_misc.h"

int
main(int UNUSED argc, const char UNUSED *argv[]) {
	unsigned int fails = 0;

	fails += test_buf();
	fails += test_misc();

	fprintf(stdout, "- libfutil tests result: %u errors\n", fails);

	return (fails);
}

