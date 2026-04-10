// SPDX-License-Identifier: MPL-2.0

//! Filesystem notification mode flags.
//!
//! These flags control which fsnotify events are suppressed for an
//! opened file descriptor. They correspond to the `FMODE_NONOTIFY`
//! and `FMODE_NONOTIFY_PERM` flags in Linux's `f_mode` field.

use bitflags::bitflags;

bitflags! {
    /// Controls which filesystem notification events are suppressed for a file.
    pub struct FsNotifyMode: u8 {
        /// Suppresses all fsnotify events for this file descriptor.
        ///
        /// Set on `O_PATH` file descriptors and fanotify-internal fds
        /// to prevent recursive notification loops.
        const NONOTIFY      = 1 << 0;
        /// Suppresses permission-class fsnotify events only.
        ///
        /// Reserved for future fanotify support. When set without
        /// `NONOTIFY`, only permission events (`FAN_ACCESS_PERM`,
        /// `FAN_OPEN_PERM`) are suppressed.
        const NONOTIFY_PERM = 1 << 1;
    }
}
