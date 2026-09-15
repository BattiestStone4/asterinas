// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

/*
 * Tests `PR_SET_SECCOMP` and `PR_GET_SECCOMP`, the `prctl(2)` interface to the
 * seccomp modes.
 *
 * They predate `seccomp(2)` and select the same modes, so the strict mode that
 * they enter is the one that `strict.c` covers in depth. The tests below only
 * cover what is specific to the `prctl(2)` spelling: the shape of the
 * arguments, and the mode reported by `PR_GET_SECCOMP`.
 *
 * As in `strict.c`, no test enters the strict mode in the test process itself,
 * for the reasons explained there.
 */

FN_TEST(disabled_mode_is_reported_by_prctl)
{
	SKIP_IF_CONFINED();

	/* A thread that has not entered a seccomp mode reports 0. */
	TEST_RES(prctl(PR_GET_SECCOMP), _ret == 0);
}
END_TEST()

FN_TEST(strict_mode_can_be_entered_by_prctl)
{
	SKIP_IF_CONFINED();

	int ready_pipe[2];
	TEST_SUCC(pipe(ready_pipe));

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);

		/* Unlike `seccomp(2)`, `PR_SET_SECCOMP` takes the mode as its
		 * second argument. */
		long ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
		char report = (ret == 0) ? 'S' : 'F';
		if (write(ready_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		syscall(SYS_exit, EXIT_SUCCESS);
	}

	close(ready_pipe[1]);

	char report = '\0';
	TEST_RES(read(ready_pipe[0], &report, 1), _ret == 1 && report == 'S');

	/* The strict mode must be the one that the child entered. */
	TEST_RES(read_seccomp_mode(child), _ret == 1);

	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(close(ready_pipe[0]));
}
END_TEST()

FN_TEST(invalid_modes_are_rejected_by_prctl)
{
	SKIP_IF_CONFINED();

	/* The disabled mode cannot be entered, and there is no mode 3. */
	TEST_ERRNO(prctl(PR_SET_SECCOMP, 0), EINVAL);
	TEST_ERRNO(prctl(PR_SET_SECCOMP, 3), EINVAL);
	TEST_ERRNO(prctl(PR_SET_SECCOMP, 0xdeadbeef), EINVAL);
}
END_TEST()
