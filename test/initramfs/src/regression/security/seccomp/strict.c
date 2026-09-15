// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

/*
 * Tests the seccomp strict mode, which restricts a thread to `read(2)`,
 * `write(2)`, `_exit(2)` and `sigreturn(2)`.
 *
 * None of the tests below enters the strict mode in the test process itself:
 * a thread in the strict mode may not make any other system call, so it could
 * neither report its own results nor open `/proc/self/status` to have them
 * observed. Instead, a child process enters the strict mode and stays within
 * the system calls that the strict mode allows, while the test process acts as
 * an inspector. This keeps the tests working once the strict mode is enforced.
 */

FN_TEST(invalid_arguments_are_rejected)
{
	SKIP_IF_CONFINED();

	/* The strict mode takes neither flags nor an argument. */
	TEST_ERRNO(syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 1, NULL),
		   EINVAL);
	TEST_ERRNO(syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, (void *)1),
		   EINVAL);

	/* An unknown operation is rejected. */
	TEST_ERRNO(syscall(SYS_seccomp, 0xdeadbeef, 0, NULL), EINVAL);
}
END_TEST()

FN_TEST(strict_mode_is_reported_by_procfs)
{
	SKIP_IF_CONFINED();

	int ready_pipe[2], done_pipe[2];
	TEST_SUCC(pipe(ready_pipe));
	TEST_SUCC(pipe(done_pipe));

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);
		close(done_pipe[1]);

		/* Enter the strict mode, and report whether it succeeded. */
		long ret =
			syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL);
		char report = (ret == 0) ? 'S' : 'F';
		if (write(ready_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		/* Wait to be released by the inspector. */
		char ignored;
		if (read(done_pipe[0], &ignored, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		/* Note that `exit(3)` would issue `exit_group(2)`, which the
		 * strict mode does not allow, so use `exit(2)` directly. */
		syscall(SYS_exit, EXIT_SUCCESS);
	}

	close(ready_pipe[1]);
	close(done_pipe[0]);

	/* Wait for the child to enter the strict mode. */
	char report = '\0';
	TEST_RES(read(ready_pipe[0], &report, 1), _ret == 1 && report == 'S');

	/* The strict mode of the child must be visible from the outside. */
	TEST_RES(read_seccomp_mode(child), _ret == 1);

	/* The child must be able to exit while staying in the strict mode. */
	TEST_RES(write(done_pipe[1], "D", 1), _ret == 1);

	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

FN_TEST(forbidden_syscall_kills_the_thread)
{
	SKIP_IF_CONFINED();

	int ready_pipe[2];
	TEST_SUCC(pipe(ready_pipe));

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);

		long ret =
			syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL);
		if (ret == 0) {
			/* `getpid(2)` is not in the strict mode's allowlist, so
			 * the kernel must terminate the thread right here, without
			 * ever dispatching the system call. */
			(void)syscall(SYS_getpid);
		}

		/* Reaching this point means that either the strict mode was not
		 * entered, or else the forbidden system call was dispatched
		 * instead of being intercepted. */
		char report = (ret == 0) ? 'S' : 'F';
		if (write(ready_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}
		syscall(SYS_exit, EXIT_SUCCESS);
	}

	close(ready_pipe[1]);

	/* The forbidden system call must have killed the thread with a
	 * SIGKILL, rather than having it exit normally. */
	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

	/* The child must not have written anything. The read is done after the
	 * child has been reaped, so that its write end is certainly closed and
	 * the read cannot block. */
	char report = '\0';
	TEST_RES(read(ready_pipe[0], &report, 1), _ret == 0);
	CHECK(close(ready_pipe[0]));
}
END_TEST()

/*
 * The allowlist holds `_exit(2)` but not `exit_group(2)`, even though the two
 * calls look interchangeable. They are not: `exit(3)` issues `exit_group(2)`,
 * so a confined thread that ends with `exit(3)` is terminated rather than
 * exiting. Pin the contrast down in one place, since removing `_exit(2)` from
 * the allowlist and adding `exit_group(2)` to it are both plausible mistakes.
 */
FN_TEST(exit_is_allowed_but_exit_group_is_not)
{
	SKIP_IF_CONFINED();

	int ready_pipe[2];
	TEST_SUCC(pipe(ready_pipe));

	/* `_exit(2)` lets the confined thread terminate normally. */
	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);

		long ret =
			syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL);
		char report = (ret == 0) ? 'S' : 'F';
		if (write(ready_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		syscall(SYS_exit, EXIT_SUCCESS);
	}

	close(ready_pipe[1]);

	char report = '\0';
	TEST_RES(read(ready_pipe[0], &report, 1), _ret == 1 && report == 'S');

	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* `exit_group(2)` terminates the thread instead, without the call ever
	 * being dispatched. */
	int group_pipe[2];
	TEST_SUCC(pipe(group_pipe));

	child = TEST_SUCC(fork());
	if (child == 0) {
		close(group_pipe[0]);

		long ret =
			syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL);
		char report = (ret == 0) ? 'S' : 'F';
		if (write(group_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		/* The kernel must terminate the thread right here. */
		(void)syscall(SYS_exit_group, EXIT_SUCCESS);
		syscall(SYS_exit, EXIT_FAILURE);
	}

	close(group_pipe[1]);

	report = '\0';
	TEST_RES(read(group_pipe[0], &report, 1), _ret == 1 && report == 'S');

	status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

	CHECK(close(group_pipe[0]));
	CHECK(close(ready_pipe[0]));
}
END_TEST()
