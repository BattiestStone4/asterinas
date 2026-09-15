// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{
    prelude::*,
    seccomp::{
        BPF_MAXINSNS, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
        SECCOMP_RET_KILL_THREAD, SeccompMode, SockFilter, SockFprog, verify,
    },
};

/// Restricts the thread to `read(2)`, `write(2)`, `_exit(2)` and `sigreturn(2)`.
const SECCOMP_SET_MODE_STRICT: u32 = 0;
/// Installs a BPF program that filters the system calls of the thread.
const SECCOMP_SET_MODE_FILTER: u32 = 1;
/// Queries whether a seccomp action is available.
const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
/// Queries the sizes of the seccomp notification structures.
const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

/// The filter flags whose behaviour is implemented, which is none of them.
///
/// A flag that a caller passes and that installation ignores would leave it
/// believing the filter does more than it does, so every flag is refused
/// instead. [`SECCOMP_FILTER_FLAG_TSYNC`] is the one that matters most.
const SUPPORTED_FILTER_FLAGS: u32 = 0;

/// Syncs the filter to every thread of the thread group, rather than confining
/// only the thread that installs it.
///
/// This is not implemented, and it is named here on purpose: it is what a
/// sandbox runtime passes when it sets up a container, and it is the difference
/// between a process being confined and only one of its threads being confined.
/// Refusing the flag leaves a caller that asks for it in no doubt about what it
/// got, and this constant is the one place that has to change to support it.
const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;

/// The actions that `SECCOMP_GET_ACTION_AVAIL` reports as available.
///
/// These are the actions this kernel implements, so the answer is a real one.
/// Linux answers for a longer list, which includes the actions the later stages
/// of the seccomp work will add; reporting one of those as available now would
/// be a lie to the program that asked.
const AVAILABLE_ACTIONS: [u32; 4] = [
    SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_KILL_THREAD,
    SECCOMP_RET_ERRNO,
    SECCOMP_RET_ALLOW,
];

pub(super) fn sys_seccomp(
    operation: u32,
    flags: u32,
    args: Vaddr,
    ctx: &Context,
) -> Result<SyscallReturn> {
    match operation {
        SECCOMP_SET_MODE_STRICT => {
            if flags != 0 || args != 0 {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "SECCOMP_SET_MODE_STRICT takes neither flags nor arguments"
                );
            }

            enter_strict_mode(ctx)?;
        }
        SECCOMP_SET_MODE_FILTER => {
            install_filter(ctx, flags, args)?;
        }
        SECCOMP_GET_ACTION_AVAIL => {
            if flags != 0 {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "SECCOMP_GET_ACTION_AVAIL takes no flags"
                );
            }

            // The argument is a pointer to the action to ask about, and asking
            // about one that is not implemented is not an error in itself: the
            // answer is simply that it is not available.
            let action = ctx.user_space().read_val::<u32>(args)?;
            if !AVAILABLE_ACTIONS.contains(&action) {
                return_errno_with_message!(
                    Errno::EOPNOTSUPP,
                    "the action is not available"
                );
            }
        }
        SECCOMP_GET_NOTIF_SIZES => {
            if flags != 0 {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "SECCOMP_GET_NOTIF_SIZES takes no flags"
                );
            }

            // The notification structures are part of the user-notification
            // action, which is not implemented, so there are no sizes to report.
            return_errno_with_message!(Errno::ENOSYS, "the operation is not supported yet");
        }
        _ => {
            return_errno_with_message!(Errno::EINVAL, "unknown seccomp operation");
        }
    }

    Ok(SyscallReturn::Return(0))
}

/// Moves the calling thread into the strict mode.
///
/// Note that, unlike installing a filter, entering the strict mode requires
/// neither `no_new_privs` nor any capability: it only ever takes away from what
/// the thread may do. See
/// <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/seccomp.c>.
pub(crate) fn enter_strict_mode(ctx: &Context) -> Result<()> {
    ctx.posix_thread.seccomp().set_mode(SeccompMode::Strict)
}

/// Installs the filter that the program at `fprog_addr` describes, and moves the
/// calling thread into the filter mode.
///
/// This is shared by `seccomp(2)` and by `PR_SET_SECCOMP`, which is the older
/// spelling of the same operation, and it is the single place that installing a
/// filter goes through. Confining a whole thread group, which is what
/// `SECCOMP_FILTER_FLAG_TSYNC` asks for, is a change to this one function.
///
/// The order in which this can fail is the one Linux uses: the flags first, then
/// the program description as it is read out of user memory, then the length of
/// the program, then the requirement of `no_new_privs`, and only then the
/// program itself.
pub(crate) fn install_filter(ctx: &Context, flags: u32, fprog_addr: Vaddr) -> Result<()> {
    if flags & !SUPPORTED_FILTER_FLAGS != 0 {
        // The flag that a sandbox runtime passes and that it is most important
        // to say no to gets an answer of its own, since a caller that asked for
        // it is the one that would otherwise believe the whole thread group is
        // confined.
        if flags & SECCOMP_FILTER_FLAG_TSYNC != 0 {
            return_errno_with_message!(
                Errno::EINVAL,
                "SECCOMP_FILTER_FLAG_TSYNC is not supported"
            );
        }
        return_errno_with_message!(Errno::EINVAL, "the filter flags are not supported");
    }

    let fprog = ctx.user_space().read_val::<SockFprog>(fprog_addr)?;

    // The length is checked before anything else about the caller, since a
    // program of the wrong length is not one that could be installed.
    if fprog.len == 0 || fprog.len as usize > BPF_MAXINSNS {
        return_errno_with_message!(
            Errno::EINVAL,
            "a filter must contain between 1 and BPF_MAXINSNS instructions"
        );
    }

    // Installing a filter confines the calls that children will be able to make,
    // which is not something that a process may decide for one that has more
    // privileges than it has. `no_new_privs` is a promise that the process will
    // not gain any, so a process that has made it may be confined.
    if !ctx.posix_thread.credentials().no_new_privs() {
        return_errno_with_message!(
            Errno::EACCES,
            "installing a filter requires no_new_privs"
        );
    }

    let program = read_program(ctx, fprog.filter, fprog.len as usize)?;
    let program = verify(program)?;

    ctx.posix_thread.seccomp().attach_filter(program)
}

/// Reads the `len` instructions of the filter program at `addr` out of user
/// memory.
fn read_program(ctx: &Context, addr: Vaddr, len: usize) -> Result<Vec<SockFilter>> {
    let mut program = vec![SockFilter::new_zeroed(); len];
    ctx.user_space().read_slice(addr, &mut program)?;
    Ok(program)
}
