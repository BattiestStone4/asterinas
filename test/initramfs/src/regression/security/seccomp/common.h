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
#include <sys/syscall.h>
#include <unistd.h>

#include "../../common/test.h"

/* Restricts the calling thread to `read(2)`, `write(2)`, `_exit(2)` and
 * `sigreturn(2)`. */
#define SECCOMP_SET_MODE_STRICT 0

/* Older versions of `<sys/syscall.h>` may not define this. */
#ifndef SYS_seccomp
#define SYS_seccomp 317
#endif

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
