// SPDX-License-Identifier: MPL-2.0

/*
 * The `SECCOMP_RET_TRAP` verdict.
 *
 * A trap is the verdict that hands a system call to the program instead of
 * deciding for it: the call is not made, and a `SIGSYS` is raised in its place
 * carrying enough about the call for a handler to answer it. The handler then
 * chooses what the call reports, which is how a supervisor emulates a call it
 * trapped rather than merely refusing it.
 *
 * A trapped call is not a call that failed. Nothing writes its return value, so
 * the caller sees whatever its return register already held when the call was
 * made; the handler below always writes one of its own, which is the case a
 * program can rely on and the reason `SECCOMP_RET_TRAP` is of any use.
 *
 * The signal is raised in place of the call, so it arrives before the
 * instruction that follows the call does. The tests here fork, because a filter
 * cannot be taken off a thread once it is on: whichever process installs one is
 * confined for the rest of its life.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <ucontext.h>

#include "common.h"

/* What the handler of a trapped call makes the call report. `close(2)` returns
 * either 0 or -1, so a value that is neither can only have come from here. */
#define TRAPPED_RETURN 0x5eedL

/* What the filter puts in the data half of the verdict, which the trap reports
 * as `si_errno`. */
#define TRAP_DATA 0x1234U

/* The system call the filters below trap. */
#define TRAPPED_SYSCALL SYS_close

/* The three ways a `SIGSYS` can fail to reach a handler. */
#define SET_DEFAULT 0
#define SET_IGNORE 1
#define SET_BLOCKED 2

/*
 * Builds a filter that traps one system call and lets the rest through.
 *
 * The architecture is checked first, as every filter that libseccomp generates
 * does, since the same system call number names different calls on different
 * machines. Note that a trap is where that matters most: the handler is told
 * which architecture the call was made on, and on that answer rests whether
 * the number it was given means anything.
 */
static void build_trap_syscall(struct sock_filter *program, int syscall_number,
			       unsigned int data)
{
	program[0] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
						  SECCOMP_DATA_ARCH_OFFSET);
	program[1] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
						  AUDIT_ARCH_NATIVE, 1, 0);
	program[2] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						  SECCOMP_RET_KILL_PROCESS);
	program[3] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
						  SECCOMP_DATA_NR_OFFSET);
	program[4] = (struct sock_filter)BPF_JUMP(
		BPF_JMP | BPF_JEQ | BPF_K, (unsigned int)syscall_number, 0, 1);
	program[5] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						  SECCOMP_RET_TRAP | data);
	program[6] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
						  SECCOMP_RET_ALLOW);
}

/* What the handler of a trapped call saw, and what became of the call. */
struct trap_report {
	int trapped;
	int signo;
	int code;
	int errno_field;
	int syscall_field;
	unsigned long arch_field;
	long call_return;
	int fd_still_open;
};

/*
 * Writes the value the trapped call will report.
 *
 * A system call returns in `rax` on x86-64, and in the first of the
 * general-purpose registers on the machines that pass both the first argument
 * and the result in `x0`. The saved registers live in different shapes of
 * context on the two, so this is where the test stops being one program.
 */
static void set_call_return(ucontext_t *uc, long value)
{
#if defined(__x86_64__)
	uc->uc_mcontext.gregs[REG_RAX] = (greg_t)value;
#elif defined(__aarch64__)
	uc->uc_mcontext.regs[0] = (unsigned long)value;
#else
#error "no system call return register for this machine"
#endif
}

static struct trap_report seen;
static int trap_count;

static void sigsys_handler(int sig, siginfo_t *info, void *ctx)
{
	ucontext_t *uc = ctx;

	trap_count++;
	seen.signo = sig;
	seen.code = info->si_code;
	seen.errno_field = info->si_errno;
	seen.syscall_field = info->si_syscall;
	seen.arch_field = (unsigned long)info->si_arch;

	/*
	 * Choose what the trapped call reports. The register the call would
	 * have returned in is saved in the context the handler is handed, and
	 * `sigreturn(2)` puts it back when the handler returns, so writing it
	 * here is what decides the answer.
	 */
	set_call_return(uc, TRAPPED_RETURN);
}

/*
 * Answers a trapped call by resuming the program where the call would have
 * returned to, which is what `si_call_addr` names.
 *
 * `si_call_addr` is the address the trapped instruction would have returned to,
 * not the address of the instruction itself: a handler that resumes there is
 * done with the call, and one that does not resume there watches the call be
 * made again. This is the whole of how a supervisor emulates a call rather than
 * refusing it, and it is the reason the field is worth a test of its own.
 */
static void resume_after_call(ucontext_t *uc, unsigned long call_addr,
			      long value)
{
#if defined(__x86_64__)
	uc->uc_mcontext.gregs[REG_RIP] = (greg_t)call_addr;
	uc->uc_mcontext.gregs[REG_RAX] = (greg_t)value;
#elif defined(__aarch64__)
	uc->uc_mcontext.pc = call_addr;
	uc->uc_mcontext.regs[0] = (unsigned long)value;
#else
#error "no system call return register for this machine"
#endif
}

static void answering_handler(int sig, siginfo_t *info, void *ctx)
{
	ucontext_t *uc = ctx;

	(void)sig;

	trap_count++;

	if (trap_count > 1) {
		/*
		 * Resuming at `si_call_addr` did not get past the call, so the
		 * call was made a second time. Report that as a status instead
		 * of answering again, which would trap forever.
		 */
		syscall(SYS_exit_group, 3);
	}

	resume_after_call(uc, (unsigned long)info->si_call_addr,
			  TRAPPED_RETURN);
}

static void take_sigsys(void (*handler)(int, siginfo_t *, void *))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);

	CHECK(sigaction(SIGSYS, &sa, NULL));
}

/*
 * Runs a trapped `close(2)` in a child process, and returns the status the
 * child was waited for with, or -1 if it died before it could report.
 *
 * The child closes the read end of the pipe the report travels on, and then
 * asks for that descriptor again. A close that had gone through would leave
 * nothing to ask about, so the answer says whether the call was made or
 * replaced.
 *
 * When `answer` is set the child's handler resumes the call instead of letting
 * it return to where it trapped, which is the other way a handler ends a trap.
 */
static int run_trapped_close(struct trap_report *report, int answer)
{
	int ready_pipe[2];
	CHECK(pipe(ready_pipe));

	pid_t child = CHECK(fork());
	if (child == 0) {
		/*
		 * The child must not use the framework from here on: the
		 * `close(2)` calls it makes are exactly what is about to stop
		 * working, and `CHECK` would take a trapped close for a
		 * failure.
		 */
		struct sock_filter program[7];
		build_trap_syscall(program, TRAPPED_SYSCALL, TRAP_DATA);

		take_sigsys(answer ? answering_handler : sigsys_handler);
		if (allow_confining_this_thread() != 0 ||
		    install_filter(program, 7, 0) != 0) {
			syscall(SYS_exit, 1);
		}

		int fd = ready_pipe[0];
		seen.call_return = close(fd);
		seen.fd_still_open = fcntl(fd, F_GETFD) >= 0;
		seen.trapped = trap_count;

		(void)!write(ready_pipe[1], &seen, sizeof(seen));
		syscall(SYS_exit, 0);
	}

	CHECK(close(ready_pipe[1]));

	ssize_t len = read(ready_pipe[0], report, sizeof(*report));
	CHECK(close(ready_pipe[0]));

	int status = 0;
	CHECK(waitpid(child, &status, 0));

	return len == (ssize_t)sizeof(*report) ? status : -1;
}

FN_TEST(a_trap_raises_a_sigsys_instead_of_making_the_call)
{
	SKIP_IF_CONFINED();

	struct trap_report report = { 0 };
	int status = run_trapped_close(&report, 0);

	TEST_RES(status,
		 status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* The handler ran, and ran once. */
	TEST_RES(report.trapped, report.trapped == 1);

	/* The call reported what the handler chose, not what `close(2)`
	 * returns. */
	TEST_RES(report.call_return, report.call_return == TRAPPED_RETURN);

	/* And the descriptor it named is still open, so the call was never
	 * made. */
	TEST_RES(report.fd_still_open, report.fd_still_open == 1);
}
END_TEST()

FN_TEST(a_trap_reports_the_call_it_replaced)
{
	SKIP_IF_CONFINED();

	struct trap_report report = { 0 };
	int status = run_trapped_close(&report, 0);

	TEST_RES(status,
		 status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0);

	TEST_RES(report.signo, report.signo == SIGSYS);
	TEST_RES(report.code, report.code == SYS_SECCOMP);

	/* The data half of the verdict is what the trap reports as the error
	 * number, which is how a filter passes a reason to the handler. */
	TEST_RES(report.errno_field, report.errno_field == (int)TRAP_DATA);

	/* The call that was replaced, and the machine it was made on. Without
	 * the latter the former is not a system call number at all. */
	TEST_RES(report.syscall_field, report.syscall_field == TRAPPED_SYSCALL);
	TEST_RES(report.arch_field, report.arch_field == AUDIT_ARCH_NATIVE);
}
END_TEST()

FN_TEST(a_handler_can_answer_a_trap_by_resuming_the_call)
{
	SKIP_IF_CONFINED();

	struct trap_report report = { 0 };
	int status = run_trapped_close(&report, 1);

	/*
	 * The handler resumes the call at `si_call_addr` rather than letting it
	 * return where it trapped, so this is also what says the address is the
	 * one after the call: resumed at the call itself, the call would be
	 * made again and the handler would have to refuse it, which the child
	 * reports as status 3 rather than by trapping forever.
	 */
	TEST_RES(status,
		 status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* The call was answered once, not twice. */
	TEST_RES(report.trapped, report.trapped == 1);

	/* It reported what the handler chose, and left the descriptor alone. */
	TEST_RES(report.call_return, report.call_return == TRAPPED_RETURN);
	TEST_RES(report.fd_still_open, report.fd_still_open == 1);
}
END_TEST()

/*
 * A trap whose signal cannot reach a handler is not left pending and is not
 * quietly dropped: the process is ended on the spot, as it is when the signal
 * is left at its default. All three arrangements below end the same way, and
 * the third is the one worth stating, since a blocked signal that is never
 * handled would otherwise sit in the queue forever while the trapped call
 * neither happened nor reported.
 *
 * This was measured against Linux 6.8 rather than read off a manual page: in
 * all three cases the process dies of `SIGSYS` at the system call, before the
 * instruction after it runs.
 */
static int run_unanswerable_trap(int how)
{
	int ready_pipe[2];
	CHECK(pipe(ready_pipe));

	pid_t child = CHECK(fork());
	if (child == 0) {
		struct sock_filter program[7];
		build_trap_syscall(program, TRAPPED_SYSCALL, TRAP_DATA);

		if (how == SET_DEFAULT) {
			/* Nothing to do: `SIGSYS` starts out at its
			 * default. */
		} else if (how == SET_IGNORE) {
			signal(SIGSYS, SIG_IGN);
		} else {
			sigset_t blocked;
			sigemptyset(&blocked);
			sigaddset(&blocked, SIGSYS);
			sigprocmask(SIG_BLOCK, &blocked, NULL);
		}

		if (allow_confining_this_thread() != 0 ||
		    install_filter(program, 7, 0) != 0) {
			syscall(SYS_exit, 1);
		}

		/* Only reached if the trap did not end the process. A raw
		 * `close(2)` is used so that nothing else is asked of the
		 * confined process first. */
		(void)syscall(SYS_close, ready_pipe[0]);

		(void)!write(ready_pipe[1], "x", 1);
		syscall(SYS_exit, 0);
	}

	CHECK(close(ready_pipe[1]));

	char message = '\0';
	ssize_t len = read(ready_pipe[0], &message, 1);
	CHECK(close(ready_pipe[0]));

	int status = 0;
	CHECK(waitpid(child, &status, 0));

	/* Nothing was reported, so that particular arrangement of the signal
	 * did not keep the process alive. */
	return len == 1 ? -1 : status;
}

FN_TEST(a_trap_that_no_handler_can_take_kills_the_process)
{
	SKIP_IF_CONFINED();

	int arrangements[] = { SET_DEFAULT, SET_IGNORE, SET_BLOCKED };
	const char *names[] = { "default", "ignored", "blocked" };

	for (size_t i = 0; i < sizeof(arrangements) / sizeof(arrangements[0]);
	     i++) {
		int status = run_unanswerable_trap(arrangements[i]);

		TEST_RES(status, status != -1 && WIFSIGNALED(status) &&
					 WTERMSIG(status) == SIGSYS);
		if (!(status != -1 && WIFSIGNALED(status) &&
		      WTERMSIG(status) == SIGSYS)) {
			fprintf(stderr, "  (the signal was %s)\n", names[i]);
		}
	}
}
END_TEST()
