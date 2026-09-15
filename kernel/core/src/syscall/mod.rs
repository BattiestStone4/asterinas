// SPDX-License-Identifier: MPL-2.0

//! System call handlers.

#![cfg_attr(
    any(
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "aarch64"
    ),
    expect(dead_code)
)]

pub(crate) use clock_gettime::ClockId;
use ostd::arch::cpu::context::UserContext;
pub(crate) use timer_create::create_timer_for_clock;

use crate::{
    cpu::LinuxAbi,
    prelude::*,
    process::{
        TermStatus,
        posix_thread::{SeccompMode, do_exit},
        signal::constants::SIGKILL,
    },
};

#[cfg_attr(target_arch = "x86_64", path = "arch/x86.rs")]
#[cfg_attr(target_arch = "riscv64", path = "arch/riscv.rs")]
#[cfg_attr(target_arch = "loongarch64", path = "arch/loongarch.rs")]
#[cfg_attr(target_arch = "aarch64", path = "arch/arm.rs")]
mod arch;

mod accept;
mod access;
mod alarm;
#[cfg(target_arch = "x86_64")]
mod arch_prctl;
mod bind;
mod brk;
mod capget;
mod capset;
mod chdir;
mod chmod;
mod chown;
mod chroot;
mod clock_gettime;
mod clone;
mod close;
mod connect;
mod constants;
mod dup;
mod epoll;
mod eventfd;
mod execve;
mod exit;
mod exit_group;
mod fadvise64;
mod fallocate;
mod fcntl;
mod flock;
mod fork;
mod fsconfig;
mod fsmount;
mod fsopen;
mod fsync;
mod futex;
mod get_ioprio;
mod get_priority;
mod getcpu;
mod getcwd;
mod getdents64;
mod getegid;
mod geteuid;
mod getgid;
mod getgroups;
mod getpeername;
mod getpgid;
mod getpgrp;
mod getpid;
mod getppid;
mod getrandom;
mod getresgid;
mod getresuid;
mod getrusage;
mod getsid;
mod getsockname;
mod getsockopt;
mod gettid;
mod gettimeofday;
mod getuid;
mod getxattr;
mod inotify;
mod ioctl;
mod kill;
mod link;
mod listen;
mod listmount;
mod listxattr;
mod lseek;
mod madvise;
mod memfd_create;
mod mkdir;
mod mknod;
mod mmap;
mod mount;
mod move_mount;
mod mprotect;
mod mremap;
mod msync;
mod munmap;
mod nanosleep;
mod open;
mod pause;
mod personality;
mod pidfd_getfd;
mod pidfd_open;
mod pidfd_send_signal;
mod pipe;
mod pivot_root;
mod poll;
mod ppoll;
mod prctl;
mod pread64;
mod preadv;
mod prlimit64;
mod pselect6;
mod ptrace;
mod pwrite64;
mod pwritev;
mod read;
mod readlink;
mod reboot;
mod recvfrom;
mod recvmsg;
mod removexattr;
mod rename;
mod rmdir;
mod rt_sigaction;
mod rt_sigpending;
mod rt_sigprocmask;
mod rt_sigreturn;
mod rt_sigsuspend;
mod rt_sigtimedwait;
mod sched_affinity;
mod sched_get_priority_max;
mod sched_get_priority_min;
mod sched_getattr;
mod sched_getparam;
mod sched_getscheduler;
mod sched_setattr;
mod sched_setparam;
mod sched_setscheduler;
mod sched_yield;
mod seccomp;
mod select;
mod semctl;
mod semget;
mod semop;
mod sendfile;
mod sendmmsg;
mod sendmsg;
mod sendto;
mod set_ioprio;
mod set_priority;
mod set_robust_list;
mod set_tid_address;
mod setdomainname;
mod setfsgid;
mod setfsuid;
mod setgid;
mod setgroups;
mod sethostname;
mod setitimer;
mod setns;
mod setpgid;
mod setregid;
mod setresgid;
mod setresuid;
mod setreuid;
mod setsid;
mod setsockopt;
mod setuid;
mod setxattr;
mod shutdown;
mod sigaltstack;
mod signalfd;
mod socket;
mod socketpair;
mod stat;
mod statfs;
mod statx;
mod symlink;
mod sync;
mod sysinfo;
mod tgkill;
mod time;
mod timer_create;
mod timer_settime;
mod timerfd_create;
mod timerfd_gettime;
mod timerfd_settime;
mod truncate;
mod umask;
mod umount;
mod uname;
mod unlink;
mod unshare;
mod utimens;
mod wait4;
mod waitid;
mod write;

/// This macro is used to define syscall handler.
/// The first param is the number of parameters,
/// The second param is the function name of syscall handler,
/// The third is optional, means the args(if parameter number > 0),
/// The fourth is optional, means if cpu ctx is required.
macro_rules! syscall_handler {
    (0, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name($ctx)
    };
    (0, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name($ctx, $user_ctx)
    };

    (1, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name($args[0] as _, $ctx)
    };
    (1, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name($args[0] as _, $ctx, $user_ctx)
    };

    (2, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name($args[0] as _, $args[1] as _, $ctx)
    };
    (2, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name($args[0] as _, $args[1] as _, $ctx, $user_ctx)
    };

    (3, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name($args[0] as _, $args[1] as _, $args[2] as _, $ctx)
    };
    (3, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name($args[0] as _, $args[1] as _, $args[2] as _, $ctx, $user_ctx)
    };

    (4, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $ctx,
        )
    };
    (4, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $ctx,
            $user_ctx,
        )
    };

    (5, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $args[4] as _,
            $ctx,
        )
    };
    (5, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $args[4] as _,
            $ctx,
            $user_ctx,
        )
    };

    (6, $fn_name: ident, $args: ident, $ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $args[4] as _,
            $args[5] as _,
            $ctx,
        )
    };
    (6, $fn_name: ident, $args: ident, $ctx: expr, $user_ctx: expr) => {
        $fn_name(
            $args[0] as _,
            $args[1] as _,
            $args[2] as _,
            $args[3] as _,
            $args[4] as _,
            $args[5] as _,
            $ctx,
            $user_ctx,
        )
    };
}

macro_rules! dispatch_fn_inner {
    ( $args: ident, $ctx: ident, $user_ctx: ident, $handler: ident ( args[ .. $cnt: tt ] ) ) => {
        $crate::syscall::syscall_handler!($cnt, $handler, $args, $ctx)
    };
    ( $args: ident, $ctx: ident, $user_ctx: ident, $handler: ident ( args[ .. $cnt: tt ] , &user_ctx ) ) => {
        $crate::syscall::syscall_handler!($cnt, $handler, $args, $ctx, &$user_ctx)
    };
    ( $args: ident, $ctx: ident, $user_ctx: ident, $handler: ident ( args[ .. $cnt: tt ] , &mut user_ctx ) ) => {
        // `$user_ctx` is already of type `&mut ostd::cpu::UserContext`,
        // so no need to take `&mut` again
        $crate::syscall::syscall_handler!($cnt, $handler, $args, $ctx, $user_ctx)
    };
}

macro_rules! impl_syscall_nums_and_dispatch_fn {
    // $args, $user_ctx, and $dispatcher_name are needed since Rust macro is hygienic
    ( $( $name: ident = $num: literal => $handler: ident $args: tt );* $(;)? ) => {
        // First, define the syscall numbers
        $(
            pub(crate) const $name: u64 = $num;
        )*

        // Then, define the dispatcher function
        pub(crate) fn syscall_dispatch(
            syscall_number: u64,
            args: [u64; 6],
            ctx: &crate::context::Context,
            user_ctx: &mut ostd::arch::cpu::context::UserContext,
        ) -> $crate::prelude::Result<$crate::syscall::SyscallReturn> {
            match syscall_number {
                $(
                    $num => {
                        $crate::syscall::log_syscall_entry!($name);
                        $crate::syscall::dispatch_fn_inner!(args, ctx, user_ctx, $handler $args)
                    }
                )*
                _ => {
                    ostd::warn!("Unimplemented syscall number: {}", syscall_number);
                    $crate::error::return_errno_with_message!(
                        $crate::error::Errno::ENOSYS,
                        "Syscall was unimplemented"
                    );
                }
            }
        }
    }
}

// Export macros to sub-modules
use dispatch_fn_inner;
use impl_syscall_nums_and_dispatch_fn;
use syscall_handler;

struct SyscallArgument {
    syscall_number: u64,
    args: [u64; 6],
}

/// Syscall return
#[derive(Clone, Copy, Debug)]
enum SyscallReturn {
    /// return isize, this value will be used to set rax
    Return(isize),
    /// does not need to set rax
    NoReturn,
}

impl SyscallArgument {
    fn new_from_context(user_ctx: &UserContext) -> Self {
        let syscall_number = user_ctx.syscall_num() as u64;
        let args = user_ctx.syscall_args().map(|x| x as u64);
        Self {
            syscall_number,
            args,
        }
    }
}

pub(crate) fn handle_syscall(ctx: &Context, user_ctx: &mut UserContext) {
    let syscall_frame = SyscallArgument::new_from_context(user_ctx);

    if ctx.posix_thread.seccomp().mode() == SeccompMode::Strict
        && !is_allowed_in_strict_mode(syscall_frame.syscall_number)
    {
        debug!(
            "seccomp: the strict mode forbids the syscall {}",
            syscall_frame.syscall_number
        );

        // The thread is terminated on the spot, as Linux does with
        // `do_exit(SIGKILL)`. Note that, unlike Linux's, our `do_exit` returns,
        // so the forbidden system call must not be dispatched afterwards.
        do_exit(TermStatus::Killed(SIGKILL), ctx, user_ctx);
        return;
    }

    let syscall_return = arch::syscall_dispatch(
        syscall_frame.syscall_number,
        syscall_frame.args,
        ctx,
        user_ctx,
    );

    match syscall_return {
        Ok(return_value) => {
            if let SyscallReturn::Return(return_value) = return_value {
                user_ctx.set_syscall_ret(return_value as usize);
            }
        }
        Err(err) => {
            debug!("syscall return error: {:?}", err);
            let errno = err.error() as i32;
            user_ctx.set_syscall_ret((-errno) as usize)
        }
    }
}

/// Returns whether `syscall_number` may be made while the seccomp strict mode is
/// in effect.
///
/// Following the seccomp(2) manual page, the strict mode allows only `read(2)`,
/// `write(2)`, `_exit(2)` and `sigreturn(2)`. Their numbers are taken from the
/// architecture's syscall table instead of being hard-coded, because the system
/// call that returns from a signal handler differs between architectures: it is
/// `rt_sigreturn(2)` on every architecture that Asterinas supports, and only on
/// 32-bit x86 is it `sigreturn(2)` proper. Linux keeps the set behind the
/// `__NR_seccomp_*` macros for the same reason.
///
/// Note that the strict mode is an allowlist of system call numbers only; it
/// does not inspect the arguments of the calls that it lets through.
fn is_allowed_in_strict_mode(syscall_number: u64) -> bool {
    matches!(
        syscall_number,
        arch::SYS_READ | arch::SYS_WRITE | arch::SYS_EXIT | arch::SYS_RT_SIGRETURN
    )
}

macro_rules! log_syscall_entry {
    ($syscall_name: tt) => {
        if ostd::log_enabled!(ostd::log::Level::Info) {
            let syscall_name_str = stringify!($syscall_name);
            let pid = $crate::context::current!().pid();
            let tid = {
                use $crate::process::posix_thread::AsPosixThread;
                $crate::context::current_thread!()
                    .as_posix_thread()
                    .unwrap()
                    .tid()
            };
            ostd::info!(
                "[pid={}][tid={}][id={}][{}]",
                pid,
                tid,
                $syscall_name,
                syscall_name_str
            );
        }
    };
}

use log_syscall_entry;
