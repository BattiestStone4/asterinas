// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmIo;

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::posix_thread::AsPosixThread,
    seccomp::{
        BPF_MAXINSNS, Program, SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS,
        SECCOMP_RET_KILL_THREAD, SECCOMP_RET_TRAP, SeccompMode, SockFilter, SockFprog, verify,
    },
    thread::AsThread,
};

/// Restricts the thread to `read(2)`, `write(2)`, `_exit(2)` and `sigreturn(2)`.
const SECCOMP_SET_MODE_STRICT: u32 = 0;
/// Installs a BPF program that filters the system calls of the thread.
const SECCOMP_SET_MODE_FILTER: u32 = 1;
/// Queries whether a seccomp action is available.
const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
/// Queries the sizes of the seccomp notification structures.
const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

/// The filter flags that installation accepts.
///
/// A caller that passes a flag installation ignores is left believing the
/// filter does more than it does, so a flag is accepted only when ignoring it
/// cannot mislead anyone. `SPEC_ALLOW` is such a flag, and the two `TSYNC` ones
/// are acted on rather than ignored.
const SUPPORTED_FILTER_FLAGS: u32 =
    SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_SPEC_ALLOW | SECCOMP_FILTER_FLAG_TSYNC_ESRCH;

/// Syncs the filter to every thread of the thread group, rather than confining
/// only the thread that installs it.
///
/// This is what a sandbox runtime passes when it sets up a container, and it is
/// the difference between a process being confined and only one of its threads
/// being confined: a system call can be made from any of them, so a filter that
/// one thread holds is not a filter on the process.
///
/// A thread group is not always one that can be confined. The other threads may
/// hold filters of their own, and a thread whose filters the new one is not
/// installed on top of would have one taken away from it by the sync, which
/// seccomp never does. When that is the case nothing is installed on any
/// thread, and the system call reports the id of a thread that stood in the
/// way: a failure is not an error number here, since what the caller needs to
/// know is *which* thread it was, and `-1` cannot say.
const SECCOMP_FILTER_FLAG_TSYNC: u32 = 1 << 0;

/// Reports a thread that had to be left out of a sync as `ESRCH` rather than as
/// its id.
///
/// The id is more useful, but it is also a positive value that a caller may
/// mistake for the zero of success, so this flag is there for a caller that
/// wants a failure to be one that cannot be missed. It means nothing on its
/// own, and Linux accepts it on its own all the same.
const SECCOMP_FILTER_FLAG_TSYNC_ESRCH: u32 = 1 << 4;

/// Asks for the speculation barrier that a filter would otherwise run behind to
/// be left out.
///
/// The flag is accepted and acted on by doing nothing, which is what Linux does
/// on a machine that has no such barrier to install. Linux reads it in exactly
/// one place, `seccomp_assign_mode`, and only to decide whether to call
/// `arch_seccomp_spec_mitigate()`; that function's own definition is empty and
/// an architecture overrides it only if it has a barrier to turn on. Asterinas'
/// interpreter runs the program directly and has none, so the flag has nothing
/// to switch off and refusing it would report a difference where there is none.
/// See <https://elixir.bootlin.com/linux/v6.18/source/kernel/seccomp.c>.
const SECCOMP_FILTER_FLAG_SPEC_ALLOW: u32 = 1 << 2;

/// The actions that `SECCOMP_GET_ACTION_AVAIL` reports as available.
///
/// These are the actions this kernel implements, so the answer is a real one.
/// Linux answers for a longer list, which includes the actions the later stages
/// of the seccomp work will add; reporting one of those as available now would
/// be a lie to the program that asked.
const AVAILABLE_ACTIONS: [u32; 5] = [
    SECCOMP_RET_KILL_PROCESS,
    SECCOMP_RET_KILL_THREAD,
    SECCOMP_RET_TRAP,
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
            return Ok(SyscallReturn::Return(install_filter(ctx, flags, args)?));
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
                return_errno_with_message!(Errno::EOPNOTSUPP, "the action is not available");
            }
        }
        SECCOMP_GET_NOTIF_SIZES => {
            if flags != 0 {
                return_errno_with_message!(Errno::EINVAL, "SECCOMP_GET_NOTIF_SIZES takes no flags");
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
    // Every seccomp operation of the process takes this lock, so that one of
    // them cannot be overtaken by another. Entering the strict mode is an
    // operation a sync has to be able to rule out: a thread that did it between
    // the sync asking whether the thread can take a filter and the sync giving
    // it one is a thread the filter cannot be added to. The lock is what keeps
    // the answer to that question good; see `confine_thread_group`.
    let _tasks = ctx.process.tasks().lock();

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
/// the program, then the permission to install one, then the program itself, and
/// last the threads that would have to adopt it.
///
/// Returns what the system call reports, which is `0` when all went well, and
/// otherwise the id of a thread that could not be confined: see
/// [`SECCOMP_FILTER_FLAG_TSYNC`].
pub(crate) fn install_filter(ctx: &Context, flags: u32, fprog_addr: Vaddr) -> Result<isize> {
    if flags & !SUPPORTED_FILTER_FLAGS != 0 {
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
    // privileges than it has. There are two ways to be allowed to do it: by
    // making `no_new_privs`, a promise that the process will not gain any
    // privileges, or by holding `CAP_SYS_ADMIN`, which is the privilege to
    // decide this for other processes in the first place.
    if !ctx.posix_thread.credentials().no_new_privs() && !holds_sys_admin(ctx) {
        return_errno_with_message!(
            Errno::EACCES,
            "installing a filter requires no_new_privs or CAP_SYS_ADMIN"
        );
    }

    let program = read_program(ctx, fprog.filter, fprog.len as usize)?;
    let program = verify(program)?;

    if flags & SECCOMP_FILTER_FLAG_TSYNC == 0 {
        // Held for the reason given in `enter_strict_mode`, and for one more:
        // the filter is built and installed under the same lock, so a sync that
        // runs in between cannot have a filter built against a chain the caller
        // then replaces with one that does not reach back to it. See
        // `SeccompState::prepare_attach`.
        let _tasks = ctx.process.tasks().lock();

        ctx.posix_thread.seccomp().attach_filter(program)?;
        return Ok(0);
    }

    confine_thread_group(ctx, program, flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH != 0)
}

/// Confines every thread of the calling thread's group with `program`, which is
/// what `SECCOMP_FILTER_FLAG_TSYNC` asks for, and returns what the system call
/// reports.
fn confine_thread_group(ctx: &Context, program: Program, report_esrch: bool) -> Result<isize> {
    let seccomp = ctx.posix_thread.seccomp();

    // The lock is held from here to the end of the sync, and every seccomp
    // operation of the process takes it, so no thread can change its own
    // seccomp state while the group is being examined: the two passes below,
    // which ask whether each thread can be moved and then move it, are one
    // change to the group rather than two. Linux holds `sighand->siglock` for
    // the same span and for the same reason.
    //
    // A thread that is being cloned while this runs is the one thread that is
    // not covered. `clone_child_task` takes the child's seccomp state and
    // starts the child before it registers it here, so a child of a thread
    // that this sync confines can come into being with the state its parent had
    // when the clone began, and nothing adds the filter to it afterwards.
    let tasks = ctx.process.tasks().lock();

    // The filter is built before any thread is looked at. The checks it makes
    // can turn the whole operation down on their own, and Linux makes them
    // before it looks at a thread as well, so that a request that is over the
    // instruction limit is refused for that reason rather than for whichever
    // thread happens to be first in the list.
    //
    // Nothing has been installed on any thread at this point.
    let filter = seccomp.prepare_attach(program)?;

    // Every thread has to be one that can be moved onto the new chain, or none
    // of them is moved: a group that is half confined is one in which the
    // caller's filter can be stepped around by making the system call from
    // another thread, which is the state the caller asked to avoid.
    for task in tasks.as_slice() {
        let Some(thread) = task.as_posix_thread() else {
            continue;
        };

        // The calling thread is the one the others are measured against, so it
        // is not one of the threads to be measured, and it is confined below.
        if core::ptr::eq(thread, ctx.posix_thread) {
            continue;
        }

        // A thread that has exited is left out. It is not one that can be made
        // to bypass anything, and its filters are on their way out with it.
        if task.as_thread().is_some_and(|thread| thread.is_exited()) {
            continue;
        }

        if thread.seccomp().can_adopt(&filter) {
            continue;
        }

        // The thread that stood in the way is what the caller is told about,
        // since which thread it was is what tells the caller what to do about
        // it.
        if report_esrch {
            return_errno_with_message!(Errno::ESRCH, "a thread cannot be confined");
        }
        return Ok(thread.tid() as isize);
    }

    // Nothing has failed, so the filter is installed on the calling thread
    // first and on the rest of the group after it, which is the order Linux
    // uses.
    seccomp.commit_attach(&filter)?;

    // Whether the promise is copied is decided once, from the thread that made
    // it, since installing a filter may only be done by a thread that has made
    // it or that holds `CAP_SYS_ADMIN`, and a group is confined as one.
    let copy_no_new_privs = ctx.posix_thread.credentials().no_new_privs();

    for task in tasks.as_slice() {
        let Some(thread) = task.as_posix_thread() else {
            continue;
        };
        if core::ptr::eq(thread, ctx.posix_thread)
            || task.as_thread().is_some_and(|thread| thread.is_exited())
        {
            continue;
        }

        // The lock has been held across both passes, so a thread that
        // `can_adopt` approved above is still one that can be moved here, and
        // the filter is not one that has to be taken back.
        let moved = thread.seccomp().adopt_filter(&filter);
        debug_assert!(
            moved,
            "a thread that `can_adopt` approved could not be moved"
        );

        // A thread that holds a filter without having made the promise could
        // exec a program that gains privileges, which is what the promise is
        // there to prevent, so the promise is copied along with the filter.
        if copy_no_new_privs {
            thread.set_no_new_privs();
        }
    }

    Ok(0)
}

/// Returns whether the calling thread holds `CAP_SYS_ADMIN` over its user
/// namespace.
///
/// The question is put to the LSM hooks rather than to the credential set
/// directly, so that a security module gets its say. A denial is reported as a
/// plain "no" rather than as the module's error, because the caller has an
/// answer of its own to give for it (`EACCES`, as on Linux) and does not care
/// which check turned it down.
fn holds_sys_admin(ctx: &Context) -> bool {
    use crate::{process::credentials::capabilities::CapSet, security::lsm::hooks as lsm_hooks};

    lsm_hooks::on_capable(lsm_hooks::CapableContext::new(
        ctx.thread_local.borrow_user_ns().as_ref(),
        ctx.posix_thread,
        CapSet::SYS_ADMIN,
    ))
    .is_ok()
}

/// Reads the `len` instructions of the filter program at `addr` out of user
/// memory.
fn read_program(ctx: &Context, addr: Vaddr, len: usize) -> Result<Vec<SockFilter>> {
    let mut program = vec![SockFilter::new_zeroed(); len];
    ctx.user_space().read_slice(addr, &mut program)?;
    Ok(program)
}
