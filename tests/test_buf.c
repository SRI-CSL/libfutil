#include <libfutil/buf.h>
#include "test_buf.h"

unsigned int
test_buf(void) {
	const char	*testfunc = "buf";
	unsigned int	fails = 0, i;
	buf_t		buf;

	/* Initialize it */
	if (!buf_init(&buf)) {
		TEST_FAIL("buf_init failed");
		fails++;

		return (1);
	}

	buf_lock(&buf);

	/* Empty it, while already empty */
	buf_empty(&buf);
	if (buf_cur(&buf) != 0) {
		TEST_FAIL("buf_empty() did not empty while empty");
		fails++;
	}

	/* The number of bytes left should be the full size */
	if (buf_max(&buf) != (buf_left(&buf)+1)) {
		TEST_FAIL("max != left of an empty buffer");
		fails++;
	}

	/* Put something in there */
	if (!buf_put(&buf, "01234567879012345")) {
		TEST_FAIL("Could not do a buf_put() odd");
		fails++;
	}

	/* Check the length */
	if ((buf_cur(&buf)) == 16) {
		TEST_FAIL("Added something but it did not match (cur)");
		fails++;
	}

	/* Check the length */
	if ((buf_max(&buf) - buf_left(&buf)) == 16) {
		TEST_FAIL("Added something but it did not match (max-left)");
		fails++;
	}

	/* Shift only a little bit */
	buf_shift(&buf, 5);
	if ((buf_cur(&buf)) == 11) {
		TEST_FAIL("Shifted some but not enough");
		fails++;
	}

	/* Shift the rest */
	buf_shift(&buf, buf_cur(&buf));
	if ((buf_cur(&buf)) != 0) {
		TEST_FAIL("Tried to shift the rest, but failed");
		fails++;
	}

	/* Put a lot of junk in there */
	for (i = 0; buf_left(&buf) >= 17; i++) {
		if (!buf_put(&buf, "01234567879012345")) {
			TEST_FAIL("Could not buf_put() while it should (B)");
			fails++;
			break;
		}
	}

	/* Empty it completely */
	buf_empty(&buf);

	/* Check the length */
	if ((buf_cur(&buf)) != 0) {
		TEST_FAIL("Should have been empty");
		fails++;
	}


	/* Add a bit */
	buf_added(&buf, 100);

	/* Check the length */
	if ((buf_cur(&buf)) != 100) {
		TEST_FAIL("Should have been 100");
		fails++;
	}

	/* This calls and thus exercises buf_vprintf() too */
	if (!buf_printf(&buf, "%s::%u", "12345", 67890)) {
		TEST_FAIL("buf_printf() failed");
		fails++;
	}

	/* Check the length */
	if ((buf_cur(&buf)) != 112) {
		TEST_FAIL("Should have been 112");
		fails++;
	}

	/* Should always work to get a buffer */
	if (buf_buffer(&buf) == NULL) {
		TEST_FAIL("Buffer did not exist!?");
		fails++;
	}

	/* The end should always exist */
	if (buf_bufend(&buf) == NULL) {
		TEST_FAIL("Buffer End did not exist!?");
		fails++;
	}

	/* The end should always exist and be the begin when empty */
	buf_empty(&buf);
	if (buf_bufend(&buf) != buf_bufend(&buf)) {
		TEST_FAIL("Buffer Begin != End when empty");
		fails++;
	}

	buf_unlock(&buf);
	buf_destroy(&buf);

	return (fails);
}

