// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

/*
 * Tests the seccomp filter mode, in which a thread installs a classic-BPF
 * program that is run against every system call it makes.
 *
 * As in `strict.c`, no test installs a filter in the test process itself. A
 * filter can refuse any system call, including the ones a test needs in order
 * to report its results, and a filter that asks for a kill takes down either the
 * calling thread or the whole thread group. The tests below therefore fork a
 * child that installs the filter and are observed from the outside.
 *
 * The program a filter runs is the one part of seccomp that userspace gets to
 * write, so these tests are as much about what the kernel refuses to run as
 * about what it does with the programs it accepts.
 */

/* What a confined child reports to the test process. */
#define REPORT_INSTALLED 'S'
#define REPORT_NOT_ENFORCED 'N'
#define REPORT_INSTALL_FAILED 'F'

/**
 * Fills `program` with a four-instruction filter that refuses `getpid(2)` with
 * `verdict`, and allows every other system call.
 *
 * `getpid(2)` is the system call the tests use to reach the filter: it takes no
 * arguments and has no effect, so a filter that refuses it can be told apart
 * from one that does not, without anything else in the process changing.
 */
static void build_refuse_getpid(struct sock_filter *program,
				unsigned int verdict)
{
	struct sock_filter body[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, verdict),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	memcpy(program, body, sizeof(body));
}

/**
 * Fills `program` with a filter that allows every system call but one: an
 * `lseek(2)` whose file descriptor is `refused_fd` is refused with `EPERM` and
 * every other `lseek(2)` is allowed.
 *
 * This is the test that the *arguments* of a system call reach the filter,
 * rather than only its number. It is written so that the filter's answer is
 * distinguishable from the kernel's: a descriptor the filter refuses is one the
 * kernel would reject with `EBADF` anyway, so `EPERM` can only have come from
 * the filter.
 */
static void build_refuse_lseek_fd(struct sock_filter *program,
				  unsigned int refused_fd)
{
	/*
	 * The offsets are relative to the following instruction: from the first
	 * jump, four instructions ahead is the final allow; from the second, one
	 * ahead is the refusal.
	 */
	struct sock_filter body[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_lseek, 0, 4),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARGS_OFFSET),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, refused_fd, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	memcpy(program, body, sizeof(body));
}

/* A program that allows every system call. */
static void build_allow_all(struct sock_filter *program)
{
	struct sock_filter body[] = {
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};

	memcpy(program, body, sizeof(body));
}

/* Sets `no_new_privs`, without which a filter may not be installed. */
static int allow_confining_this_thread(void)
{
	return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

/**
 * Whether a verdict asks for a kill, rather than for the system call to fail.
 *
 * The two killing verdicts are the ones that end a thread or a process; the
 * others let the call be dispatched or refuse it with an errno.
 */
static int is_killing_verdict(unsigned int verdict)
{
	return verdict == SECCOMP_RET_KILL_PROCESS ||
	       verdict == SECCOMP_RET_KILL_THREAD;
}

/*
 * A valid program one instruction longer than the largest a filter may be. The
 * extra instruction is what lets the tests hand the kernel a program of either
 * length without the program running off the end of the array: it is the
 * declared length that decides whether a program is too long, and both lengths
 * describe a program whose last instruction is a verdict.
 *
 * The program loads and discards a word over and over before reaching that
 * verdict, so it is a valid program of the length it claims to be, and the only
 * thing that can be wrong with it is how long it is.
 */
static struct sock_filter largest_program[BPF_MAXINSNS + 1];

static void build_largest_program(void)
{
	for (int i = 0; i < BPF_MAXINSNS; i++) {
		largest_program[i] = (struct sock_filter)BPF_STMT(
			BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR_OFFSET);
	}
	largest_program[BPF_MAXINSNS - 1] = (struct sock_filter)BPF_STMT(
		BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
	largest_program[BPF_MAXINSNS] = (struct sock_filter)BPF_STMT(
		BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
}

FN_TEST(installing_a_filter_requires_no_new_privs)
{
	SKIP_IF_CONFINED();

	int ready_pipe[2];
	TEST_SUCC(pipe(ready_pipe));

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);

		struct sock_filter program[1];
		build_allow_all(program);

		/*
		 * Without the promise that the thread will not gain privileges,
		 * confining it is not something it is allowed to decide.
		 */
		char report = 'F';
		if (install_filter(program, 1, 0) != 0 && errno == EACCES) {
			report = allow_confining_this_thread() == 0 &&
						 install_filter(program, 1,
								0) == 0 ?
					 'S' :
					 'A';
		}

		if (write(ready_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		/* The filter allows everything, so `exit(3)` is allowed too. */
		exit(EXIT_SUCCESS);
	}

	close(ready_pipe[1]);

	char report = '\0';
	TEST_RES(read(ready_pipe[0], &report, 1), _ret == 1 && report == 'S');

	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(close(ready_pipe[0]));
}
END_TEST()

FN_TEST(filter_mode_is_reported_by_procfs)
{
	SKIP_IF_CONFINED();

	int ready_pipe[2], done_pipe[2];
	TEST_SUCC(pipe(ready_pipe));
	TEST_SUCC(pipe(done_pipe));

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);
		close(done_pipe[1]);

		struct sock_filter program[1];
		build_allow_all(program);

		char report = 'F';
		if (allow_confining_this_thread() == 0 &&
		    install_filter(program, 1, 0) == 0) {
			report = 'S';
		}
		if (write(ready_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		/* Wait to be released by the inspector. */
		char ignored;
		if (read(done_pipe[0], &ignored, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		exit(EXIT_SUCCESS);
	}

	close(ready_pipe[1]);
	close(done_pipe[0]);

	char report = '\0';
	TEST_RES(read(ready_pipe[0], &report, 1), _ret == 1 && report == 'S');

	/* The strict mode is reported as 1, and the filter mode as 2. */
	TEST_RES(read_seccomp_mode(child), _ret == 2);

	TEST_RES(write(done_pipe[1], "D", 1), _ret == 1);

	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(close(ready_pipe[0]));
	CHECK(close(done_pipe[1]));
}
END_TEST()

FN_TEST(an_errno_verdict_fails_the_syscall_it_names)
{
	SKIP_IF_CONFINED();

	int ready_pipe[2];
	TEST_SUCC(pipe(ready_pipe));

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);

		struct sock_filter program[4];
		build_refuse_getpid(program, SECCOMP_RET_ERRNO | EPERM);

		char report = 'F';
		if (allow_confining_this_thread() == 0 &&
		    install_filter(program, 4, 0) == 0) {
			/*
			 * The errno is the filter's, which is not the errno the
			 * kernel would have produced: `getpid(2)` cannot fail on
			 * its own. Reaching it therefore means the call was
			 * refused rather than dispatched.
			 */
			errno = 0;
			long refused = syscall(SYS_getpid);

			/* A system call the filter does not name is dispatched
			 * as usual. */
			errno = 0;
			long allowed = syscall(SYS_getppid);

			if (refused == -1 && errno == 0 && allowed >= 0) {
				report = 'S';
			} else if (refused != -1) {
				report = 'N';
			}
		}

		if (write(ready_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	close(ready_pipe[1]);

	char report = '\0';
	TEST_RES(read(ready_pipe[0], &report, 1), _ret == 1 && report == 'S');

	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(close(ready_pipe[0]));
}
END_TEST()

FN_TEST(the_filter_sees_the_arguments_of_the_syscall)
{
	SKIP_IF_CONFINED();

	/* A descriptor the filter refuses, and one that does not exist. */
	const unsigned int refused_fd = 12345;
	const unsigned int unknown_fd = 4242;

	int ready_pipe[2];
	TEST_SUCC(pipe(ready_pipe));

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);

		struct sock_filter program[7];
		build_refuse_lseek_fd(program, refused_fd);

		char report = 'F';
		if (allow_confining_this_thread() == 0 &&
		    install_filter(program, 7, 0) == 0) {
			errno = 0;
			(void)syscall(SYS_lseek, (long)refused_fd, 0, SEEK_SET);
			int refused_errno = errno;

			errno = 0;
			(void)syscall(SYS_lseek, (long)unknown_fd, 0, SEEK_SET);
			int unknown_errno = errno;

			/*
			 * The filter refuses one descriptor and not the other,
			 * so it must have read the argument. The descriptor it
			 * lets through reaches the kernel, which rejects it
			 * because it names no open file.
			 */
			if (refused_errno == EPERM && unknown_errno == EBADF) {
				report = 'S';
			}
		}

		if (write(ready_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	close(ready_pipe[1]);

	char report = '\0';
	TEST_RES(read(ready_pipe[0], &report, 1), _ret == 1 && report == 'S');

	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(close(ready_pipe[0]));
}
END_TEST()

/*
 * What one confined thread reports about itself. It is written by that thread
 * and read by the process's first thread once the thread has been joined, which
 * is what orders the two.
 */
struct thread_report {
	int installed;
	int reached_call;
	int survived;
};

static unsigned int confined_thread_verdict;

static void *confined_thread(void *arg)
{
	struct thread_report *report = arg;
	struct sock_filter program[4];
	build_refuse_getpid(program, confined_thread_verdict);

	/* `no_new_privs` is a property of a thread, so this thread has to make
	 * the promise itself before it may be confined. */
	if (allow_confining_this_thread() != 0 ||
	    install_filter(program, 4, 0) != 0) {
		return NULL;
	}
	report->installed = 1;

	report->reached_call = 1;
	(void)syscall(SYS_getpid);

	/* Only reached if the verdict did not end this thread. */
	report->survived = 1;
	return NULL;
}

/*
 * Runs `verdict` against `getpid(2)` in a thread of a child process, and
 * returns what the child's first thread reported, or -1 if the child died
 * before it could report anything.
 *
 * `out_status` is given the status the child was waited for with.
 */
static int run_confined_thread(unsigned int verdict, int *out_status)
{
	int ready_pipe[2];
	CHECK(pipe(ready_pipe));

	pid_t child = CHECK(fork());
	if (child == 0) {
		close(ready_pipe[0]);

		confined_thread_verdict = verdict;

		struct thread_report report = { 0 };
		pthread_t thread;
		if (pthread_create(&thread, NULL, confined_thread, &report) !=
		    0) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		/*
		 * The join returns once the thread is gone, whichever way it
		 * went. The process outliving the thread is the whole point of
		 * the `KILL_THREAD` verdict.
		 */
		(void)pthread_join(thread, NULL);

		char message = report.survived	? REPORT_NOT_ENFORCED :
			       report.installed ? REPORT_INSTALLED :
						  REPORT_INSTALL_FAILED;
		if (write(ready_pipe[1], &message, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	close(ready_pipe[1]);

	char message = '\0';
	ssize_t len = read(ready_pipe[0], &message, 1);
	CHECK(close(ready_pipe[0]));

	int status = 0;
	CHECK(waitpid(child, &status, 0));
	*out_status = status;

	return len == 1 ? (int)message : -1;
}

/*
 * The two killing verdicts differ in how far the kill reaches, which is the
 * only thing that distinguishes them: `KILL_THREAD` ends the thread that made
 * the system call, and `KILL_PROCESS` ends every thread of its process. The two
 * tests below run the same program in the same shape of process and differ only
 * in the verdict, so what they observe is the difference between the verdicts
 * and nothing else.
 *
 * Note that a filter kills with `SIGSYS`, where the strict mode that `strict.c`
 * covers kills with `SIGKILL`. Both are unconditional: a program that installs
 * a handler for the signal is not asked what to do with it.
 */
FN_TEST(killing_a_thread_leaves_the_rest_of_the_process_alone)
{
	SKIP_IF_CONFINED();

	int status = 0;
	int report = run_confined_thread(SECCOMP_RET_KILL_THREAD, &status);

	/*
	 * The process must have run to the end: the thread was ended, and the
	 * thread that installed no filter went on to report and exit normally.
	 */
	TEST_RES(report, report == REPORT_INSTALLED);
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
END_TEST()

FN_TEST(killing_the_process_takes_the_whole_thread_group_with_it)
{
	SKIP_IF_CONFINED();

	int status = 0;
	int report = run_confined_thread(SECCOMP_RET_KILL_PROCESS, &status);

	/* Nothing was reported, because there was no thread left to report. */
	TEST_RES(report, report == -1);

	int status_ok = WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS;
	TEST_RES(status, status_ok);
}
END_TEST()

FN_TEST(the_stricter_verdict_wins_whichever_filter_it_came_from)
{
	SKIP_IF_CONFINED();

	/*
	 * Both filters are asked about `getpid(2)` and disagree. The stricter of
	 * the two has to decide the call, and it has to do so whether it was
	 * installed before or after the other: installing a laxer filter on top
	 * of a stricter one cannot loosen it, which is what walking the whole
	 * chain means rather than stopping at the first verdict that says
	 * something.
	 *
	 * The verdicts are compared as *signed* numbers, which is what puts
	 * `KILL_PROCESS` above an errno: its action is `0x80000000`, so read as
	 * an unsigned number it would be the largest action and would lose.
	 */
	struct {
		unsigned int first;
		unsigned int second;
	} cases[] = {
		{ SECCOMP_RET_ERRNO | EPERM, SECCOMP_RET_KILL_PROCESS },
		{ SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_ERRNO | EPERM },
		{ SECCOMP_RET_ERRNO | EPERM, SECCOMP_RET_KILL_THREAD },
		{ SECCOMP_RET_KILL_THREAD, SECCOMP_RET_ERRNO | EPERM },
		{ SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO | EPERM },
		{ SECCOMP_RET_ERRNO | EPERM, SECCOMP_RET_ALLOW },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		/* Either filter asking for a kill is enough for one: the two
		 * verdicts are weighed against each other, not the newer one
		 * against the older one. */
		int killed = is_killing_verdict(cases[i].first) ||
			     is_killing_verdict(cases[i].second);

		int ready_pipe[2];
		TEST_SUCC(pipe(ready_pipe));

		pid_t child = TEST_SUCC(fork());
		if (child == 0) {
			close(ready_pipe[0]);

			struct sock_filter first[4], second[4];
			build_refuse_getpid(first, cases[i].first);
			build_refuse_getpid(second, cases[i].second);

			int ok = allow_confining_this_thread() == 0 &&
				 install_filter(first, 4, 0) == 0 &&
				 install_filter(second, 4, 0) == 0;

			char report = ok ? 'S' : 'F';
			if (write(ready_pipe[1], &report, 1) != 1) {
				syscall(SYS_exit, EXIT_FAILURE);
			}
			if (!ok) {
				syscall(SYS_exit, EXIT_FAILURE);
			}

			/*
			 * The stricter of the two verdicts kills, so reaching
			 * here means it did not win.
			 */
			errno = 0;
			(void)syscall(SYS_getpid);
			report = (errno == EPERM) ? 'A' : 'B';
			if (write(ready_pipe[1], &report, 1) != 1) {
				syscall(SYS_exit, EXIT_FAILURE);
			}
			exit(EXIT_SUCCESS);
		}

		close(ready_pipe[1]);

		char report = '\0';
		TEST_RES(read(ready_pipe[0], &report, 1),
			 _ret == 1 && report == 'S');

		int status = 0;
		TEST_SUCC(waitpid(child, &status, 0));

		if (killed) {
			TEST_RES(status, WIFSIGNALED(status) &&
						 WTERMSIG(status) == SIGSYS);
		} else {
			TEST_RES(status,
				 WIFEXITED(status) && WEXITSTATUS(status) == 0);

			/* The errno the filter chose, not the kernel's. */
			char second_report = '\0';
			TEST_RES(read(ready_pipe[0], &second_report, 1),
				 _ret == 1 && second_report == 'A');
		}
		CHECK(close(ready_pipe[0]));
	}
}
END_TEST()

FN_TEST(a_tie_between_two_errno_verdicts_is_broken_by_the_newer_filter)
{
	SKIP_IF_CONFINED();

	/*
	 * Both filters refuse `getpid(2)` with an errno, and only the numbers
	 * differ, so the verdicts weigh the same and the walk has to break the
	 * tie. The newer filter is the one that decides it.
	 *
	 * The expectation is not a guess: on Linux, installing `EACCES` and then
	 * `EPERM` makes the refused call return `EPERM`, and installing them the
	 * other way round returns `EACCES`.
	 */
	struct {
		unsigned int first;
		unsigned int second;
		int expected;
	} cases[] = {
		{ SECCOMP_RET_ERRNO | EACCES, SECCOMP_RET_ERRNO | EPERM,
		  EPERM },
		{ SECCOMP_RET_ERRNO | EPERM, SECCOMP_RET_ERRNO | EACCES,
		  EACCES },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int ready_pipe[2];
		TEST_SUCC(pipe(ready_pipe));

		pid_t child = TEST_SUCC(fork());
		if (child == 0) {
			close(ready_pipe[0]);

			struct sock_filter first[4], second[4];
			build_refuse_getpid(first, cases[i].first);
			build_refuse_getpid(second, cases[i].second);

			int ok = allow_confining_this_thread() == 0 &&
				 install_filter(first, 4, 0) == 0 &&
				 install_filter(second, 4, 0) == 0;

			char report = 'F';
			if (ok) {
				errno = 0;
				(void)syscall(SYS_getpid);
				report = (errno == cases[i].expected) ? 'S' :
									'N';
			}

			if (write(ready_pipe[1], &report, 1) != 1) {
				syscall(SYS_exit, EXIT_FAILURE);
			}
			exit(EXIT_SUCCESS);
		}

		close(ready_pipe[1]);

		char report = '\0';
		TEST_RES(read(ready_pipe[0], &report, 1),
			 _ret == 1 && report == 'S');

		int status = 0;
		TEST_SUCC(waitpid(child, &status, 0));
		TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
		CHECK(close(ready_pipe[0]));
	}
}
END_TEST()

FN_TEST(the_modes_cannot_be_swapped)
{
	SKIP_IF_CONFINED();

	/*
	 * A thread that is confined one way may not move to the other way. The
	 * filter half is observable, because the filter allows the `seccomp(2)`
	 * call through and the check is what refuses it.
	 */
	int ready_pipe[2];
	TEST_SUCC(pipe(ready_pipe));

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);

		struct sock_filter program[1];
		build_allow_all(program);

		char report = 'F';
		if (allow_confining_this_thread() == 0 &&
		    install_filter(program, 1, 0) == 0) {
			errno = 0;
			long ret = syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT,
					   0, NULL);
			if (ret == -1 && errno == EINVAL) {
				report = 'S';
			}
		}

		if (write(ready_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	close(ready_pipe[1]);

	char report = '\0';
	TEST_RES(read(ready_pipe[0], &report, 1), _ret == 1 && report == 'S');

	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/*
	 * The other order cannot be observed the same way, and that is worth
	 * pinning down rather than leaving as a gap: a thread in the strict mode
	 * may not call `seccomp(2)` at all, so its attempt to install a filter
	 * kills it before the mode check is ever reached.
	 */
	int strict_pipe[2];
	TEST_SUCC(pipe(strict_pipe));

	child = TEST_SUCC(fork());
	if (child == 0) {
		close(strict_pipe[0]);

		long ret =
			syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL);
		char report = (ret == 0) ? 'S' : 'F';
		if (write(strict_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		struct sock_filter program[1];
		build_allow_all(program);
		(void)install_filter(program, 1, 0);

		/* Reaching this point means the strict mode let `seccomp(2)`
		 * through, which it must not. */
		syscall(SYS_exit, EXIT_FAILURE);
	}

	close(strict_pipe[1]);

	report = '\0';
	TEST_RES(read(strict_pipe[0], &report, 1), _ret == 1 && report == 'S');

	status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

	CHECK(close(ready_pipe[0]));
	CHECK(close(strict_pipe[0]));
}
END_TEST()

FN_TEST(a_program_of_the_wrong_length_is_rejected)
{
	SKIP_IF_CONFINED();

	int ready_pipe[2];
	TEST_SUCC(pipe(ready_pipe));

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);

		build_largest_program();

		int ok = 0;

		/*
		 * An empty program is refused. The length is checked before
		 * anything else about the caller is, so this is `EINVAL` even
		 * though the thread has not promised `no_new_privs`: a program
		 * of no instructions is not one that could have been installed.
		 */
		errno = 0;
		if (install_filter(largest_program, 0, 0) == -1 &&
		    errno == EINVAL) {
			ok++;
		}

		if (allow_confining_this_thread() == 0) {
			/* One instruction longer than the largest allowed
			 * program is refused. */
			errno = 0;
			if (install_filter(largest_program, BPF_MAXINSNS + 1,
					   0) == -1 &&
			    errno == EINVAL) {
				ok++;
			}

			/* A flag that the operation does not define is refused
			 * as well. */
			errno = 0;
			if (install_filter(largest_program, 1, 1u << 20) ==
				    -1 &&
			    errno == EINVAL) {
				ok++;
			}

			/* Neither refusal confined the thread, which is what
			 * separates a rejected installation from one that
			 * half-happened. */
			if (read_seccomp_mode(getpid()) == 0) {
				ok++;
			}

			/* The largest length a program may have is not too
			 * long. It is exactly the boundary, so it is the case
			 * the check is most likely to get wrong by one. */
			errno = 0;
			if (install_filter(largest_program, BPF_MAXINSNS, 0) ==
			    0) {
				ok++;
			}

			/* And that installation did confine the thread. */
			if (read_seccomp_mode(getpid()) == 2) {
				ok++;
			}
		}

		char report = (ok == 6) ? 'S' : 'F';
		if (write(ready_pipe[1], &report, 1) != 1) {
			syscall(SYS_exit, EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	close(ready_pipe[1]);

	char report = '\0';
	TEST_RES(read(ready_pipe[0], &report, 1), _ret == 1 && report == 'S');

	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(close(ready_pipe[0]));
}
END_TEST()

FN_TEST(too_many_filters_in_a_chain_are_refused)
{
	SKIP_IF_CONFINED();

	int ready_pipe[2];
	TEST_SUCC(pipe(ready_pipe));

	pid_t child = TEST_SUCC(fork());
	if (child == 0) {
		close(ready_pipe[0]);

		if (allow_confining_this_thread() != 0) {
			syscall(SYS_exit, EXIT_FAILURE);
		}

		build_largest_program();

		int installed = 0;
		int failure_errno = 0;
		for (int i = 0; i < 32; i++) {
			if (install_filter(largest_program, BPF_MAXINSNS, 0) ==
			    0) {
				installed++;
			} else {
				failure_errno = errno;
				break;
			}
		}

		char report[2] = { (char)installed, (char)failure_errno };
		if (write(ready_pipe[1], report, 2) != 2) {
			syscall(SYS_exit, EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}

	close(ready_pipe[1]);

	char report[2] = { 0, 0 };
	TEST_RES(read(ready_pipe[0], report, 2), _ret == 2);

	/*
	 * Some filters must have been installed, or else the limit was never
	 * reached and the test would pass for the wrong reason. Running out of
	 * room is `ENOMEM` rather than `EINVAL`: the program is a valid one, and
	 * it is the thread's total that is exhausted. How many filters fit
	 * depends on how they are counted internally, so only the kind of
	 * failure is pinned down here.
	 */
	TEST_RES(report[0], report[0] >= 1);
	TEST_RES(report[1], report[1] == ENOMEM);

	int status = 0;
	TEST_SUCC(waitpid(child, &status, 0));
	TEST_RES(status, WIFEXITED(status) && WEXITSTATUS(status) == 0);
	CHECK(close(ready_pipe[0]));
}
END_TEST()

FN_TEST(the_core_actions_are_reported_as_available)
{
	SKIP_IF_CONFINED();

	unsigned int available[] = {
		SECCOMP_RET_KILL_PROCESS,
		SECCOMP_RET_KILL_THREAD,
		SECCOMP_RET_ERRNO,
		SECCOMP_RET_ALLOW,
	};

	for (size_t i = 0; i < sizeof(available) / sizeof(available[0]); i++) {
		unsigned int action = available[i];
		TEST_SUCC(syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
				  &action));
	}

	/* An action that names nothing, with or without data in its low half. */
	unsigned int unknown = 0xdead0000;
	TEST_ERRNO(syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &unknown),
		   EOPNOTSUPP);

	unknown = 0xdeadbeef;
	TEST_ERRNO(syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0, &unknown),
		   EOPNOTSUPP);
}
END_TEST()
