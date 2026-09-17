// SPDX-License-Identifier: MPL-2.0

/*
 * Helpers shared by the seccomp tests.
 */

#ifndef SECCOMP_TEST_COMMON_H
#define SECCOMP_TEST_COMMON_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../../common/test.h"

/* Restricts the calling thread to `read(2)`, `write(2)`, `_exit(2)` and
 * `sigreturn(2)`. */
#define SECCOMP_SET_MODE_STRICT 0

/* Installs a classic-BPF program that filters the system calls of the thread. */
#define SECCOMP_SET_MODE_FILTER 1

/* Asks whether an action is available. Its argument is a pointer to the action
 * to ask about. */
#define SECCOMP_GET_ACTION_AVAIL 2

/* What the second argument of `PR_SET_SECCOMP` selects. This is a different set
 * of numbers from the operations above, because the older call predates their
 * naming, and the two are easy to confuse: the strict mode is 0 as an operation
 * and 1 as a mode. */
#define SECCOMP_MODE_STRICT 1
#define SECCOMP_MODE_FILTER 2

/* Confines every thread of the calling thread's group with the filter, rather
 * than only the thread that installs it. */
#define SECCOMP_FILTER_FLAG_TSYNC (1U << 0)

/* Asks for the speculation barrier that the system call behind the filter would
 * otherwise run behind to be left out. It is a hint about performance rather
 * than about what the filter does: a filter installed with it refuses exactly
 * the same calls as one installed without it. */
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW (1U << 2)

/* Reports a thread that a `TSYNC` could not confine as `ESRCH` rather than as
 * the thread's id. It means nothing on its own, and the two flags go together:
 * it is the id that is useful, and this is for a caller that would rather not
 * have a positive value to tell apart from the zero of success. */
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH (1U << 4)

/* Older versions of `<sys/syscall.h>` may not define this. */
#ifndef SYS_seccomp
#define SYS_seccomp 317
#endif

/*
 * The seccomp ABI, restated.
 *
 * `<linux/filter.h>` and `<linux/seccomp.h>` are not available in every build
 * environment, so the few definitions that the tests need are repeated here.
 * They are part of the interface with the kernel, and a change to any of them
 * is a change to the ABI rather than to these tests.
 */

/* What a filter asks to happen to a system call. The high half of a verdict
 * names the action and the low half carries data for it. */
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#define SECCOMP_RET_KILL_THREAD 0x00000000U
#define SECCOMP_RET_TRAP 0x00030000U
#define SECCOMP_RET_ERRNO 0x00050000U
#define SECCOMP_RET_ALLOW 0x7fff0000U
#define SECCOMP_RET_DATA 0x0000ffffU

/* The `si_code` of the `SIGSYS` that a `SECCOMP_RET_TRAP` verdict raises, for
 * which the data half of the verdict is reported as `si_errno`. */
#define SYS_SECCOMP 1

/* The largest program a filter may be, in instructions. */
#define BPF_MAXINSNS 4096

/* The offsets of the fields of `struct seccomp_data`, which is what a filter is
 * given to inspect. The system call number comes first, then the architecture,
 * then the instruction pointer, and the six arguments last. */
#define SECCOMP_DATA_NR_OFFSET 0
#define SECCOMP_DATA_ARCH_OFFSET 4
#define SECCOMP_DATA_ARGS_OFFSET 16

/* The value the `arch` field holds: the machine's `EM_*` number combined with
 * the flags saying it is 64-bit and little-endian, which is one value per
 * architecture.
 *
 * A filter has to check this before it trusts a system call number, since the
 * same number names different calls on different architectures. Every filter
 * libseccomp generates opens with that check for this reason. The values below
 * are written out rather than computed, because the machine numbers are not
 * available to a program that only includes the C library, and the `#else` is
 * there so that a machine without an entry fails the build rather than quietly
 * checking for the wrong one. */
#if defined(__x86_64__)
#define AUDIT_ARCH_NATIVE 0xc000003eU
#elif defined(__aarch64__)
#define AUDIT_ARCH_NATIVE 0xc00000b7U
#elif defined(__riscv) && __riscv_xlen == 64
#define AUDIT_ARCH_NATIVE 0xc00000f3U
#elif defined(__loongarch__) && __loongarch_grlen == 64
#define AUDIT_ARCH_NATIVE 0xc0000102U
#else
#error "no seccomp architecture for this machine"
#endif

/* One classic-BPF instruction, and a program as userspace describes it. */
struct sock_filter {
	unsigned short code;
	unsigned char jt;
	unsigned char jf;
	unsigned int k;
};

struct sock_fprog {
	unsigned short len;
	struct sock_filter *filter;
};

/* The instruction encodings used by the tests. A full classic-BPF opcode is a
 * class, a size, a mode and an operation, so they are spelled out rather than
 * written as literals. */
#define BPF_LD 0x00
#define BPF_W 0x00
#define BPF_ABS 0x20
#define BPF_JMP 0x05
#define BPF_JEQ 0x10
#define BPF_K 0x00
#define BPF_RET 0x06

#define BPF_STMT(code, k)                                       \
	{                                                       \
		(unsigned short)(code), 0, 0, (unsigned int)(k) \
	}
#define BPF_JUMP(code, k, jt, jf)                                     \
	{                                                             \
		(unsigned short)(code), (jt), (jf), (unsigned int)(k) \
	}

/**
 * Installs `program` as a filter on the calling thread.
 *
 * Returns 0 on success and -1 with `errno` set otherwise, as `seccomp(2)` does.
 * The caller must have set `no_new_privs` first, or the installation will be
 * refused with `EACCES`.
 */
static inline long install_filter(struct sock_filter *program,
				  unsigned short len, unsigned int flags)
{
	struct sock_fprog fprog = { .len = len, .filter = program };

	return syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &fprog);
}

/**
 * Installs `program` as a filter on the calling thread through
 * `PR_SET_SECCOMP`, the older spelling, which takes no flags.
 *
 * Note what this call is given: a pointer to a `struct sock_fprog`, exactly as
 * `seccomp(2)` is. The two spellings differ in the flags they accept, not in
 * what they describe the program with. Handing this one the program itself
 * instead is refused with `EFAULT`, because the kernel reads a structure of its
 * own shape out of the pointer it is given.
 */
static inline long install_filter_by_prctl(struct sock_filter *program,
					   unsigned short len)
{
	struct sock_fprog fprog = { .len = len, .filter = program };

	return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog);
}

/**
 * Makes the promise that the calling thread will not gain any privileges,
 * without which a filter may not be installed.
 *
 * The promise is a property of a thread, so a thread that wants to install one
 * has to make it itself, even if another thread already has.
 */
static inline int allow_confining_this_thread(void)
{
	return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
}

/**
 * Skips the current test if the test process is already confined by a seccomp
 * filter.
 *
 * A thread that is already in the filter mode cannot enter the strict mode,
 * and the filter may well reject the `seccomp(2)` calls that the tests make.
 * This is the case when the tests run on Linux under a container runtime that
 * applies a seccomp profile.
 */
#define SKIP_IF_CONFINED() SKIP_TEST_IF(read_seccomp_mode(getpid()) != 0)

/**
 * Returns the value of the `Seccomp` field in `/proc/<pid>/status`.
 *
 * The field is the seccomp mode of the thread, i.e., 0 for the disabled mode
 * and 1 for the strict mode.
 */
static inline int read_seccomp_mode(pid_t pid)
{
	char path[32];
	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);

	int fd = CHECK(open(path, O_RDONLY));
	char buf[8192] = { 0 };
	ssize_t total = 0;
	while (total < (ssize_t)sizeof(buf) - 1) {
		ssize_t len =
			CHECK(read(fd, buf + total, sizeof(buf) - 1 - total));
		if (len == 0) {
			break;
		}
		total += len;
	}
	CHECK(close(fd));

	char *field = strstr(buf, "Seccomp:");
	if (field == NULL) {
		fprintf(stderr, "fatal error: no Seccomp field in %s\n", path);
		exit(EXIT_FAILURE);
	}

	return atoi(field + strlen("Seccomp:"));
}

#endif /* SECCOMP_TEST_COMMON_H */
