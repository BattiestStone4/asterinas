// SPDX-License-Identifier: MPL-2.0

//! The seccomp (secure computing) state of a thread.
//!
//! Seccomp restricts the system calls that a thread is allowed to make. Every
//! thread starts with seccomp disabled, and a thread that has entered a seccomp
//! mode can neither leave it nor switch to a different one.
//!
//! Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/seccomp.c>.

use core::sync::atomic::{AtomicU8, Ordering};

use super::PosixThread;
use crate::prelude::*;

/// The seccomp mode of a thread.
///
/// The numeric values are the ones reported in the `Seccomp` field of
/// `/proc/[pid]/status`, and therefore match the ones used by Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum SeccompMode {
    /// Seccomp is disabled. This is the mode that every thread starts in.
    Disabled = 0,
    /// Only `read(2)`, `write(2)`, `_exit(2)` and `sigreturn(2)` are allowed.
    /// Any other system call terminates the thread.
    Strict = 1,
    /// The system calls are filtered by a BPF program installed by the thread.
    Filter = 2,
}

impl SeccompMode {
    /// Converts a raw mode value into a [`SeccompMode`].
    fn from_raw(raw: u8) -> Self {
        match raw {
            raw if raw == Self::Strict as u8 => Self::Strict,
            raw if raw == Self::Filter as u8 => Self::Filter,
            // `SeccompState` is the only writer of the raw value, and it only
            // ever writes a value that comes from `SeccompMode`, so this arm is
            // unreachable in practice.
            _ => Self::Disabled,
        }
    }
}

/// The seccomp state of a thread.
pub(crate) struct SeccompState {
    /// The current [`SeccompMode`], stored as its raw value.
    mode: AtomicU8,
}

impl SeccompState {
    /// Creates a [`SeccompState`] with seccomp disabled.
    pub(crate) fn new() -> Self {
        Self {
            mode: AtomicU8::new(SeccompMode::Disabled as u8),
        }
    }

    /// Creates a [`SeccompState`] that starts out in the mode of `parent`.
    ///
    /// A thread created by `clone(2)` inherits the seccomp mode of the thread
    /// that created it. The inheritance is a snapshot: afterwards the two
    /// threads hold independent states, so one of them entering a seccomp mode
    /// does not move the other into it.
    pub(crate) fn new_from(parent: &SeccompState) -> Self {
        Self {
            mode: AtomicU8::new(parent.mode.load(Ordering::Relaxed)),
        }
    }

    /// Returns the current seccomp mode.
    pub(crate) fn mode(&self) -> SeccompMode {
        SeccompMode::from_raw(self.mode.load(Ordering::Relaxed))
    }

    /// Tries to move this thread into `mode`.
    ///
    /// Entering the current mode again is a no-op that succeeds, but a thread
    /// that is already in a different seccomp mode cannot switch to `mode`.
    ///
    /// Returns `EINVAL` if the thread is already in a different seccomp mode.
    pub(crate) fn set_mode(&self, mode: SeccompMode) -> Result<()> {
        // Checking the current mode and writing the new one must be atomic
        // together, since seccomp allows a mode to be set only once.
        let mut current = self.mode.load(Ordering::Relaxed);
        loop {
            if current == mode as u8 {
                return Ok(());
            }
            if current != SeccompMode::Disabled as u8 {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "the thread is already in a different seccomp mode"
                );
            }

            match self.mode.compare_exchange_weak(
                current,
                mode as u8,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }
}

impl PosixThread {
    /// Returns the seccomp state of this thread.
    pub(crate) fn seccomp(&self) -> &SeccompState {
        &self.seccomp
    }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::*;

    use super::*;

    #[ktest]
    fn seccomp_mode_starts_disabled() {
        let state = SeccompState::new();
        assert_eq!(state.mode(), SeccompMode::Disabled);
    }

    #[ktest]
    fn seccomp_strict_mode_can_be_entered_from_the_disabled_mode() {
        let state = SeccompState::new();

        assert!(state.set_mode(SeccompMode::Strict).is_ok());
        assert_eq!(state.mode(), SeccompMode::Strict);

        // Entering the mode that is already in effect is a no-op that succeeds.
        assert!(state.set_mode(SeccompMode::Strict).is_ok());
        assert_eq!(state.mode(), SeccompMode::Strict);
    }

    #[ktest]
    fn seccomp_mode_cannot_be_switched() {
        // A thread in the strict mode cannot install a filter.
        let state = SeccompState::new();
        assert!(state.set_mode(SeccompMode::Strict).is_ok());

        assert_eq!(
            state.set_mode(SeccompMode::Filter).unwrap_err().error(),
            Errno::EINVAL
        );
        assert_eq!(state.mode(), SeccompMode::Strict);
    }

    #[ktest]
    fn seccomp_state_is_inherited_by_the_cloned_thread() {
        let parent = SeccompState::new();
        assert!(parent.set_mode(SeccompMode::Strict).is_ok());

        // A thread created by `clone(2)` starts out in its parent's mode.
        let child = SeccompState::new_from(&parent);
        assert_eq!(child.mode(), SeccompMode::Strict);
    }

    #[ktest]
    fn inherited_seccomp_state_is_independent_of_the_parent() {
        // A thread that is cloned before its parent enters a seccomp mode does
        // not follow the parent into it.
        let parent = SeccompState::new();
        let child = SeccompState::new_from(&parent);

        assert!(parent.set_mode(SeccompMode::Strict).is_ok());
        assert_eq!(child.mode(), SeccompMode::Disabled);
    }
}
