// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{prelude::*, process::posix_thread::SeccompMode};

/// Restricts the thread to `read(2)`, `write(2)`, `_exit(2)` and `sigreturn(2)`.
const SECCOMP_SET_MODE_STRICT: u32 = 0;
/// Installs a BPF program that filters the system calls of the thread.
const SECCOMP_SET_MODE_FILTER: u32 = 1;
/// Queries whether a seccomp action is available.
const SECCOMP_GET_ACTION_AVAIL: u32 = 2;
/// Queries the sizes of the seccomp notification structures.
const SECCOMP_GET_NOTIF_SIZES: u32 = 3;

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

            set_mode(SeccompMode::Strict, ctx)?;
        }
        SECCOMP_SET_MODE_FILTER => {
            set_mode(SeccompMode::Filter, ctx)?;
        }
        SECCOMP_GET_ACTION_AVAIL | SECCOMP_GET_NOTIF_SIZES => {
            return_errno_with_message!(Errno::ENOSYS, "the operation is not supported yet");
        }
        _ => {
            return_errno_with_message!(Errno::EINVAL, "unknown seccomp operation");
        }
    }

    Ok(SyscallReturn::Return(0))
}

/// Moves the calling thread into `mode`.
///
/// This is shared by `seccomp(2)` and by `PR_SET_SECCOMP`, which is the older
/// spelling of the same operation.
///
/// Note that, unlike installing a filter, entering the strict mode requires
/// neither `no_new_privs` nor any capability. See
/// <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/seccomp.c>.
pub(crate) fn set_mode(mode: SeccompMode, ctx: &Context) -> Result<()> {
    if mode == SeccompMode::Filter {
        return_errno_with_message!(Errno::ENOSYS, "the filter mode is not supported yet");
    }

    ctx.posix_thread.seccomp().set_mode(mode)
}
