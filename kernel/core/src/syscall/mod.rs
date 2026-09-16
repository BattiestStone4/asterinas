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
use ostd::{arch::cpu::context::UserContext, user::UserContextApi};
pub(crate) use timer_create::create_timer_for_clock;

use crate::{
    arch::cpu::AUDIT_ARCH,
    cpu::LinuxAbi,
    prelude::*,
    process::{
        TermStatus,
        posix_thread::{do_exit, do_exit_group},
        signal::{
            constants::{SIGKILL, SIGSYS},
            get_sig_action,
            sig_action::SigAction,
            signals::sigsys::SigsysSignal,
        },
    },
    seccomp::{SeccompAction, SeccompData, SeccompMode},
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

    if !seccomp_allows(ctx, user_ctx, &syscall_frame) {
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

/// Applies the seccomp restrictions of the calling thread to the system call it
/// is making, and returns whether the system call may go ahead.
///
/// By the time this returns `false`, the restriction has already been carried
/// out: an `errno` has been placed in the system call's return value, a `SIGSYS`
/// has been raised, or a kill has terminated either the thread or its whole
/// process. The kills, like [`do_exit`], return, so the caller must not dispatch
/// the system call afterwards — which is exactly what the return value says.
fn seccomp_allows(
    ctx: &Context,
    user_ctx: &mut UserContext,
    syscall_frame: &SyscallArgument,
) -> bool {
    match ctx.posix_thread.seccomp().mode() {
        SeccompMode::Disabled => true,

        SeccompMode::Strict => {
            if is_allowed_in_strict_mode(syscall_frame.syscall_number) {
                return true;
            }

            debug!(
                "seccomp: the strict mode forbids the syscall {}",
                syscall_frame.syscall_number
            );

            // The thread is terminated on the spot, as Linux does with
            // `do_exit(SIGKILL)`. Note that, unlike Linux's, our `do_exit`
            // returns, so the forbidden system call must not be dispatched
            // afterwards.
            do_exit(TermStatus::Killed(SIGKILL), ctx, user_ctx);
            false
        }

        SeccompMode::Filter => {
            // The address the system call would return to. A filter is shown it
            // and a trap reports it, so it is read once and used for both.
            let instruction_pointer = user_ctx.instruction_pointer() as u64;

            // This is everything a filter is allowed to see of the system call,
            // which is what keeps one from reaching into the kernel: it is given
            // numbers, never objects.
            let data = SeccompData {
                nr: syscall_frame.syscall_number as i32,
                arch: AUDIT_ARCH,
                instruction_pointer,
                args: syscall_frame.args,
            };

            let verdict = ctx.posix_thread.seccomp().run_filters(&data);

            match SeccompAction::from_verdict(verdict) {
                SeccompAction::Allow => true,

                SeccompAction::Errno(errno) => {
                    debug!(
                        "seccomp: the filter refuses the syscall {} with errno {}",
                        syscall_frame.syscall_number, errno
                    );

                    // The system call is not dispatched at all. The error number
                    // the filter chose is returned in its place, as a negative
                    // number, which is how a system call reports failure.
                    user_ctx.set_syscall_ret(-(errno as isize) as usize);
                    false
                }

                SeccompAction::Trap(data) => {
                    debug!(
                        "seccomp: the filter traps the syscall {}",
                        syscall_frame.syscall_number
                    );

                    // Note what is *not* done here: the return value is left
                    // alone. A trapped system call is not one that failed, it is
                    // one that is never made, so the caller sees whichever value
                    // its return register already held. Leaving the register be
                    // is what produces that, and it is also what lets the signal
                    // handler choose the value instead, by writing it into the
                    // context it is handed.
                    //
                    // Leaving it be has one consequence that is worth naming,
                    // because it looks like a mistake. On the machines whose
                    // return register is also the one that carried the first
                    // argument (aarch64, riscv64 and loongarch64), a trapped call
                    // that was passed `-ERESTARTSYS` leaves exactly the value the
                    // restart logic looks for in the place where it looks, and a
                    // handler with `SA_RESTART` therefore watches the call be
                    // made again. Linux answers the same way for the same reason,
                    // as measured on aarch64: the register is not written there
                    // either, so neither machine can tell this call from one that
                    // was interrupted. x86-64 is out of reach of the question
                    // altogether, since its return register holds the system call
                    // number for as long as the trap is being raised.
                    let signal = SigsysSignal::new(
                        data,
                        syscall_frame.syscall_number as i32,
                        AUDIT_ARCH,
                        instruction_pointer as Vaddr,
                    );

                    // Raising the signal is only worth doing if it can reach a
                    // handler. One that the thread has blocked cannot, and one
                    // that is ignored is not wanted; Linux kills the process in
                    // both cases rather than let the call through or let the
                    // signal sit pending forever. A `SIGSYS` left at its default
                    // needs nothing special, since its default action is to
                    // terminate and the delivery below will do that.
                    let reaches_a_handler = !ctx.posix_thread.sig_mask().contains(SIGSYS)
                        && !matches!(get_sig_action(ctx, SIGSYS), SigAction::Ign);

                    if reaches_a_handler {
                        ctx.posix_thread.enqueue_signal(Box::new(signal));
                    } else {
                        do_exit_group(TermStatus::Killed(SIGSYS), ctx, user_ctx);
                    }
                    false
                }

                SeccompAction::KillThread => {
                    debug!(
                        "seccomp: the filter kills the thread over the syscall {}",
                        syscall_frame.syscall_number
                    );

                    // Note the signal: a filter kills with `SIGSYS`, where the
                    // strict mode above kills with `SIGKILL`. Linux makes the
                    // same distinction. Neither kill is catchable, whichever
                    // verdict asked for it; a filter that wants a `SIGSYS` a
                    // handler can take has to ask for `SECCOMP_RET_TRAP`.
                    do_exit(TermStatus::Killed(SIGSYS), ctx, user_ctx);
                    false
                }

                SeccompAction::KillProcess => {
                    debug!(
                        "seccomp: the filter kills the process over the syscall {}",
                        syscall_frame.syscall_number
                    );

                    do_exit_group(TermStatus::Killed(SIGSYS), ctx, user_ctx);
                    false
                }
            }
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
