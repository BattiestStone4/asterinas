// SPDX-License-Identifier: MPL-2.0

use super::Signal;
use crate::{
    prelude::*,
    process::signal::{
        c_types::siginfo_t,
        constants::{SIGSYS, SYS_SECCOMP},
        sig_num::SigNum,
    },
};

/// The `SIGSYS` that a filter raises with `SECCOMP_RET_TRAP`.
///
/// A trapped system call is not a system call that failed: it is one that is
/// never made, and this signal is delivered in its place. The caller therefore
/// does not see an error number the kernel chose. Nothing writes the return
/// register, so the value the caller sees is the one that was already there when
/// the call was made — unless the handler writes a value of its own into the
/// context it is handed, which is how a supervisor emulates the call it trapped.
///
/// See `SECCOMP_RET_TRAP` in `seccomp(2)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SigsysSignal {
    /// The data half of the verdict, which Linux reports as `si_errno`.
    ///
    /// The name is not a slip: `si_errno` in an `si_code`-specific part of a
    /// `siginfo_t` is a small integer belonging to that signal, and the one
    /// belonging to `SYS_SECCOMP` is the filter's data.
    data: u16,
    syscall: i32,
    arch: u32,
    call_addr: Vaddr,
}

impl SigsysSignal {
    pub(crate) fn new(data: u16, syscall: i32, arch: u32, call_addr: Vaddr) -> Self {
        Self {
            data,
            syscall,
            arch,
            call_addr,
        }
    }
}

impl Signal for SigsysSignal {
    fn num(&self) -> SigNum {
        SIGSYS
    }

    fn to_info(&self) -> siginfo_t {
        let mut info = siginfo_t::new(SIGSYS, SYS_SECCOMP);
        info.set_si_errno(self.data as i32);
        info.set_sigsys(self.call_addr, self.syscall, self.arch);
        info
    }
}
