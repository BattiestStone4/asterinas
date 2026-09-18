// SPDX-License-Identifier: MPL-2.0

//! Seccomp (secure computing).
//!
//! Seccomp restricts the system calls that a thread is allowed to make. A thread
//! that has entered a seccomp mode can neither leave it nor switch to a
//! different one, so the restrictions only ever accumulate.
//!
//! There are two modes. The strict mode is an allowlist of system call numbers
//! built into the kernel. The filter mode lets the thread install a classic-BPF
//! program that inspects the system call and decides what happens to it.
//!
//! Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/seccomp.c>.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::prelude::*;

mod bpf;
mod interpreter;
mod verifier;

// The parts of a filter that the system call layer has to name: the description
// it reads out of user memory, the instructions it is made of, the length they
// may not exceed, and the check they have to pass before the filter may run.
pub(crate) use bpf::{BPF_MAXINSNS, SockFilter, SockFprog};
pub(crate) use interpreter::Program;
pub(crate) use verifier::verify;

/// The verdicts a filter may reach, as the seccomp ABI encodes them.
///
/// A verdict carries an action in its high half and up to sixteen bits of data
/// for that action in its low half. A filter that returns a value that is not
/// one of these is taken to mean [`SECCOMP_RET_KILL_PROCESS`], which is the
/// safest reading of a verdict nobody recognises.
pub(crate) const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub(crate) const SECCOMP_RET_KILL_THREAD: u32 = 0x0000_0000;
pub(crate) const SECCOMP_RET_TRAP: u32 = 0x0003_0000;
pub(crate) const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub(crate) const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// The part of a verdict that names the action, without its data.
const SECCOMP_RET_ACTION_FULL: u32 = 0xffff_0000;

/// The part of a verdict that carries data for the action.
const SECCOMP_RET_DATA: u32 = 0x0000_ffff;

/// The part of a verdict that decides what happens to the system call, as the
/// signed number that the verdicts are weighed by.
///
/// The sign is not incidental. `SECCOMP_RET_KILL_PROCESS` has `0x8000_0000` as
/// its action, which is negative read this way, so it compares below every
/// other action; that is what makes killing the process outrank an `errno`
/// from another filter. Read as an unsigned number it would be the largest
/// action instead, and the two verdicts would be weighed the wrong way round.
fn action_only(verdict: u32) -> i32 {
    (verdict & SECCOMP_RET_ACTION_FULL) as i32
}

/// The largest error number a filter may ask a system call to fail with. The
/// data half of a verdict has room for more than this, and Linux caps it here.
const MAX_ERRNO: u16 = 4095;

/// What a filter asked to happen to the system call it inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SeccompAction {
    /// Run the system call as usual.
    Allow,
    /// Fail the system call with this error number.
    Errno(u16),
    /// Do not make the system call, and raise a `SIGSYS` instead. The data is
    /// the verdict's, and is reported to the handler as `si_errno`.
    Trap(u16),
    /// Terminate the thread that made the system call.
    KillThread,
    /// Terminate every thread in the process that made the system call.
    KillProcess,
}

impl SeccompAction {
    /// Reads the action out of the verdict a filter reached.
    ///
    /// A verdict that names an action this kernel does not implement is read as
    /// [`SeccompAction::KillProcess`], which is what Linux does with one: a
    /// verdict nobody recognises must not be taken for permission. That also
    /// covers the kills themselves, since [`SECCOMP_RET_KILL_PROCESS`] is the
    /// one arm left over.
    pub(crate) fn from_verdict(verdict: u32) -> Self {
        match verdict & SECCOMP_RET_ACTION_FULL {
            SECCOMP_RET_ALLOW => Self::Allow,
            // The error number is capped here rather than where it is used, so
            // that an `Errno` always carries the number the system call will
            // fail with. The data of a trap is not an error number, so it is
            // passed through as it is.
            SECCOMP_RET_ERRNO => Self::Errno(((verdict & SECCOMP_RET_DATA) as u16).min(MAX_ERRNO)),
            SECCOMP_RET_TRAP => Self::Trap((verdict & SECCOMP_RET_DATA) as u16),
            SECCOMP_RET_KILL_THREAD => Self::KillThread,
            _ => Self::KillProcess,
        }
    }
}

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

/// The system call, as a seccomp filter sees it.
///
/// A filter may only inspect this structure, which is what keeps seccomp
/// filters from reaching into the kernel: they see numbers, never objects.
///
/// The layout is part of the ABI. A filter is compiled against one particular
/// layout, so the offsets must be the same on every kernel, and the size must
/// match what `BPF_LEN` evaluates to. Both are asserted below.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(crate) struct SeccompData {
    /// The system call number, as passed in the system call instruction.
    pub nr: i32,
    /// The architecture, as an `AUDIT_ARCH_*` value.
    pub arch: u32,
    /// The user instruction pointer at the time of the call.
    pub instruction_pointer: u64,
    /// The six system call arguments.
    pub args: [u64; 6],
}

impl SeccompData {
    /// Reads the four bytes at `offset` as a word.
    ///
    /// `offset` has to be word-aligned and leave room for a whole word, which
    /// is what [`verifier::verify`] makes sure of for every load it allows. The
    /// bytes are assembled in this machine's own order, so a filter sees the
    /// structure laid out the way the ABI describes it here.
    pub(super) fn word_at(&self, offset: u32) -> u32 {
        let offset = offset as usize;
        let bytes = self.as_bytes();

        u32::from_ne_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }
}

/// The size of [`SeccompData`], which is what a filter sees for `BPF_LEN` and
/// the bound on how far a filter may read into it.
pub(super) const SECCOMP_DATA_SIZE: u32 = 64;

// The seccomp ABI fixes both of these, so they cannot be left to drift with the
// definition above.
const _: () = assert!(size_of::<SeccompData>() == SECCOMP_DATA_SIZE as usize);

/// The largest number of instructions that the filters of one thread may amount
/// to altogether. Linux writes this as a quarter of a megabyte of instructions.
const MAX_INSNS_PER_PATH: usize = (1 << 18) / size_of::<SockFilter>();

/// What each filter in a chain costs on top of its own instructions, in
/// instructions. Linux charges this because the program it runs is a converted
/// one with a header of its own.
const INSN_PENALTY_PER_FILTER: usize = 4;

/// One filter in the chain of them that a thread has installed.
///
/// Installing a filter puts a new node in front of the ones that are already
/// there, so a chain only ever grows and a node that has been installed never
/// changes. That is what lets a forked child share its parent's filters: the
/// programs are read-only, so neither thread can disturb the other through
/// them, while the two modes stay independent.
pub(crate) struct SeccompFilter {
    /// The verified program to run against a system call.
    program: Program,
    /// The filter installed before this one, if there was one.
    prev: Option<Arc<SeccompFilter>>,
}

impl Drop for SeccompFilter {
    fn drop(&mut self) {
        // The chain is taken apart a node at a time rather than by letting the
        // node in front free the one behind it, which would need a stack frame
        // per filter: a chain can hold thousands of them, and the frames alone
        // would be more than a kernel stack has room for. Linux frees a chain
        // iteratively for the same reason.
        let mut next = self.prev.take();
        while let Some(filter) = next {
            // A node that another thread still holds is left where it is, and
            // the chain behind it with it: the count is what says whether this
            // is the thread that frees it.
            match Arc::try_unwrap(filter) {
                // Taking the chain out first leaves the node with nothing to
                // free when it goes out of scope here, so this stays a loop
                // rather than becoming a recursion again.
                Ok(mut filter) => next = filter.prev.take(),
                Err(_) => break,
            }
        }
    }
}

/// Returns whether `parent` is one of the filters on the chain that `child`
/// names.
///
/// A chain is a path through the filters of a thread, from the newest to the
/// oldest, and two threads that forked from one another share the nodes of the
/// part they have in common. So asking whether one chain reaches back to a
/// filter that another chain holds is asking whether the second chain is an
/// extension of the first, which is what makes it safe for the second thread to
/// hand its chain to the first.
///
/// A chain with no filters is below every other chain, so `None` is the
/// ancestor of everything.
fn is_ancestor(parent: Option<&Arc<SeccompFilter>>, child: Option<&Arc<SeccompFilter>>) -> bool {
    let Some(parent) = parent else {
        return true;
    };

    let mut node = child;
    while let Some(filter) = node {
        if Arc::ptr_eq(filter, parent) {
            return true;
        }
        node = filter.prev.as_ref();
    }
    false
}

/// The seccomp state of a thread.
pub(crate) struct SeccompState {
    /// The current [`SeccompMode`], stored as its raw value.
    ///
    /// Keeping the mode in an atomic lets the common case — a thread that is not
    /// confined at all — be answered without taking a lock, since the system
    /// call entry path reads this on every system call.
    mode: AtomicU8,
    /// The installed filters, the most recently installed one first.
    ///
    /// Only reached once the mode says there is something to run, which is why
    /// the lock costs nothing to a thread that is not confined.
    ///
    /// Invariant: this is populated whenever the mode is
    /// [`SeccompMode::Filter`]. [`SeccompState::attach_filter`] establishes it,
    /// by filling in the chain before it publishes the mode.
    filters: Mutex<Option<Arc<SeccompFilter>>>,
}

impl SeccompState {
    /// Creates a [`SeccompState`] with seccomp disabled.
    pub(crate) fn new() -> Self {
        Self {
            mode: AtomicU8::new(SeccompMode::Disabled as u8),
            filters: Mutex::new(None),
        }
    }

    /// Creates a [`SeccompState`] that starts out in the mode of `parent`, with
    /// the filters of `parent`.
    ///
    /// A thread created by `clone(2)` inherits the seccomp mode of the thread
    /// that created it. The inheritance is a snapshot: afterwards the two
    /// threads hold independent states, so one of them entering a seccomp mode
    /// does not move the other into it. The filters are shared rather than
    /// copied, which is sound because installing one never changes the ones
    /// already installed.
    pub(crate) fn new_from(parent: &SeccompState) -> Self {
        Self {
            mode: AtomicU8::new(parent.mode.load(Ordering::Relaxed)),
            filters: Mutex::new(parent.filters.lock().clone()),
        }
    }

    /// Adds `program` to the thread's chain of filters, and moves the thread
    /// into the filter mode.
    ///
    /// Returns `EINVAL` if the thread is in the strict mode, which no filter can
    /// be added to.
    pub(crate) fn attach_filter(&self, program: Program) -> Result<()> {
        let filter = self.prepare_attach(program)?;

        self.commit_attach(&filter)
    }

    /// Builds the node that installing `program` would put in front of the
    /// thread's filters, without installing it.
    ///
    /// Everything that can turn an installation down is checked here and
    /// nowhere else, so that a caller which has to know the outcome before it
    /// changes anything can ask first. `SECCOMP_FILTER_FLAG_TSYNC` is such a
    /// caller: it may only confine the other threads of a group once it knows
    /// that all of them can be confined, and a thread it cannot confine has to
    /// leave the group as it found it.
    pub(crate) fn prepare_attach(&self, program: Program) -> Result<Arc<SeccompFilter>> {
        // The mode has to be checked before anything is attached. Attaching
        // first and letting `set_mode` fail would leave the chain holding a
        // filter that nothing will ever run.
        if self.mode() == SeccompMode::Strict {
            return_errno_with_message!(
                Errno::EINVAL,
                "the thread is already in the strict seccomp mode"
            );
        }

        let prev = self.filters.lock().clone();

        // A thread may hold any number of filters, but only up to a limit on
        // how much running them can cost, and reaching it fails with
        // `ENOMEM` rather than `EINVAL`: the filters are each valid, there
        // are simply too many of them.
        //
        // Linux adds up the lengths of the *converted* programs here, since
        // those are what it runs and converting inflates them. The programs
        // here run as they were written, so the count is of the instructions
        // as written, and this limit is therefore reached later than Linux's
        // would be.
        let mut total = program.len();
        let mut next = prev.as_ref();
        while let Some(filter) = next {
            total += filter.program.len() + INSN_PENALTY_PER_FILTER;
            next = filter.prev.as_ref();
        }
        if total > MAX_INSNS_PER_PATH {
            return_errno_with_message!(Errno::ENOMEM, "the thread has too many filters");
        }

        Ok(Arc::new(SeccompFilter { program, prev }))
    }

    /// Installs a filter built by [`Self::prepare_attach`] on the thread.
    ///
    /// Returns `EINVAL` if the thread is in the strict mode, which
    /// [`Self::prepare_attach`] has already turned down, so that a caller which
    /// has called it cannot see this failure.
    pub(crate) fn commit_attach(&self, filter: &Arc<SeccompFilter>) -> Result<()> {
        *self.filters.lock() = Some(filter.clone());

        // The chain is filled in before the mode is published, so that a system
        // call which reads the filter mode is guaranteed to find the filter it
        // is supposed to run. Installing on top of an existing filter finds the
        // mode already set, which `set_mode` accepts.
        self.set_mode(SeccompMode::Filter)
    }

    /// Returns whether this thread can be moved onto the chain of filters that
    /// `filter` is the head of.
    ///
    /// This is the question `SECCOMP_FILTER_FLAG_TSYNC` puts to every thread of
    /// a group before it confines any of them. A thread can be moved if its own
    /// filters are among the ones that `filter` is installed on top of, so that
    /// the move only ever adds to what it is confined by; a thread that has no
    /// filter at all has nothing to lose and can always be moved. A thread in
    /// the strict mode cannot: a filter is not something that mode can hold.
    ///
    /// The filters are compared by identity, not by what the programs in them
    /// say. Two threads that installed equal programs still hold two different
    /// filters, and neither is an ancestor of the other, because a filter is
    /// only ever added to per thread: what makes one chain an extension of
    /// another is that the threads share the nodes, which they do when one of
    /// them forked from the other.
    pub(crate) fn can_adopt(&self, filter: &Arc<SeccompFilter>) -> bool {
        match self.mode() {
            SeccompMode::Disabled => true,
            SeccompMode::Filter => is_ancestor(self.filters.lock().as_ref(), Some(filter)),
            SeccompMode::Strict => false,
        }
    }

    /// Moves this thread onto the chain of filters that `filter` is the head
    /// of, which is how `SECCOMP_FILTER_FLAG_TSYNC` confines the threads of a
    /// group with the filter one of them installed.
    ///
    /// Returns whether the thread was moved. The caller has to have established
    /// with [`Self::can_adopt`] that this thread is one that can be moved, and
    /// a thread that gained a filter in the meantime is still one: the question
    /// and the move are put to the thread by the same caller, which holds the
    /// lock that every seccomp operation takes for the whole of a sync.
    ///
    /// The question is asked again here rather than taken on trust, because the
    /// answer a caller holds is one it got before it made any change, and a
    /// thread that entered the strict mode in between is one that no filter can
    /// be added to. Moving it anyway would leave it in a mode that holds a
    /// filter it never runs; moving it without asking would take whatever
    /// filter it installed in the meantime away from it.
    pub(crate) fn adopt_filter(&self, filter: &Arc<SeccompFilter>) -> bool {
        let mut filters = self.filters.lock();

        if self.mode() == SeccompMode::Strict {
            return false;
        }

        // The chain is filled in before the mode is published here as well, for
        // the reason given in `commit_attach`.
        *filters = Some(filter.clone());

        // The strict mode is the one mode `set_mode` turns down and it has just
        // been ruled out, so this always succeeds. A caller that reached here
        // without asking is the one case where it would not, which is what the
        // assertion is for.
        let entered = self.set_mode(SeccompMode::Filter).is_ok();
        debug_assert!(entered, "the strict mode was ruled out above");

        true
    }

    /// Runs every filter the thread has installed against `data`, and returns
    /// the verdict that wins.
    ///
    /// The verdicts are weighed by taking the smallest action under
    /// [`action_only`], which is what Linux's `seccomp_run_filters()` does. The
    /// data half of a verdict takes no part in the comparison.
    ///
    /// Every filter runs, even once one of them has asked for the thread to be
    /// killed: the verdicts are all reached first and only then weighed against
    /// one another.
    pub(crate) fn run_filters(&self, data: &SeccompData) -> u32 {
        // The chain is taken out of the lock before it is walked, so that
        // running filters never holds the lock.
        let head = self.filters.lock().clone();
        let Some(mut filter) = head else {
            // Unreachable: the mode only becomes `Filter` once a filter has
            // been attached. A thread that is filtering with nothing to run is
            // not a state to guess about, and killing it is the reading of that
            // state which cannot be wrong. Linux decides the same way here.
            return SECCOMP_RET_KILL_PROCESS;
        };

        let mut verdict = SECCOMP_RET_ALLOW;
        loop {
            let ret = filter.program.run(data);
            if action_only(ret) < action_only(verdict) {
                verdict = ret;
            }

            // The chain is walked from the newest filter to the oldest, which
            // is the order Linux installs them in.
            match filter.prev.clone() {
                Some(prev) => filter = prev,
                None => return verdict,
            }
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

#[cfg(ktest)]
mod test {
    use ostd::prelude::*;

    use super::*;
    use crate::seccomp::bpf::{JEQ_K, LD_W_ABS, RET_K};

    /// Writes an instruction out, so that a program reads as a list of them.
    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

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

    /// A filter that reaches one fixed verdict, whatever the system call is.
    fn verdict(ret: u32) -> Program {
        Program::new(vec![insn(RET_K, 0, 0, ret)])
    }

    /// The structure a filter sees for the system call numbered `nr`.
    fn data(nr: i32) -> SeccompData {
        SeccompData {
            nr,
            arch: 0,
            instruction_pointer: 0,
            args: [0; 6],
        }
    }

    /// A thread that installs `program` and so ends up in the filter mode.
    fn filtered(program: Program) -> SeccompState {
        let state = SeccompState::new();
        state.attach_filter(program).unwrap();
        state
    }

    #[ktest]
    fn installing_a_filter_moves_the_thread_into_the_filter_mode() {
        let state = filtered(verdict(SECCOMP_RET_ALLOW));
        assert_eq!(state.mode(), SeccompMode::Filter);
    }

    #[ktest]
    fn a_filter_that_allows_lets_the_system_call_through() {
        let state = filtered(verdict(SECCOMP_RET_ALLOW));
        assert_eq!(state.run_filters(&data(0)), SECCOMP_RET_ALLOW);
    }

    #[ktest]
    fn an_errno_outranks_an_allow() {
        // The two filters disagree, and the more restrictive verdict is the one
        // that counts. It has to win whichever order they were installed in.
        let allow = SECCOMP_RET_ALLOW;
        let errno = SECCOMP_RET_ERRNO | 13;

        let state = filtered(verdict(allow));
        state.attach_filter(verdict(errno)).unwrap();
        assert_eq!(state.run_filters(&data(0)), errno);

        let state = filtered(verdict(errno));
        state.attach_filter(verdict(allow)).unwrap();
        assert_eq!(state.run_filters(&data(0)), errno);
    }

    #[ktest]
    fn killing_the_thread_outranks_an_errno() {
        let state = filtered(verdict(SECCOMP_RET_ERRNO | 13));
        state
            .attach_filter(verdict(SECCOMP_RET_KILL_THREAD))
            .unwrap();
        assert_eq!(state.run_filters(&data(0)), SECCOMP_RET_KILL_THREAD);
    }

    #[ktest]
    fn killing_the_process_outranks_every_other_verdict() {
        // This is the case that the signed comparison exists for. The action of
        // `SECCOMP_RET_KILL_PROCESS` is `0x8000_0000`, so read as an unsigned
        // number it would be the *largest* action and would lose to an `errno`;
        // read as the signed number it is, it is the smallest and wins. Linux
        // weighs the two the second way, so a filter that reaches these two
        // verdicts kills the process.
        let errno = SECCOMP_RET_ERRNO | 13;

        let state = filtered(verdict(errno));
        state
            .attach_filter(verdict(SECCOMP_RET_KILL_PROCESS))
            .unwrap();
        assert_eq!(state.run_filters(&data(0)), SECCOMP_RET_KILL_PROCESS);

        let state = filtered(verdict(SECCOMP_RET_KILL_PROCESS));
        state.attach_filter(verdict(errno)).unwrap();
        assert_eq!(state.run_filters(&data(0)), SECCOMP_RET_KILL_PROCESS);
    }

    #[ktest]
    fn a_tie_between_verdicts_is_broken_by_the_newest_filter() {
        // Both filters refuse with an `errno`, and only the numbers differ, so
        // the two verdicts weigh the same and the walk has to break the tie
        // somehow. It examines the newest filter first and takes a verdict only
        // when it is *strictly* lower, so the data half of the tie-break is
        // decided by install order: the newer filter's number survives.
        //
        // Verified against Linux 7.0.14 with a probe rather than inferred:
        // installing `errno 13` and then `errno 1` makes a refused call return
        // `EPERM`, and installing them the other way round returns `EACCES`.
        let state = filtered(verdict(SECCOMP_RET_ERRNO | 13));
        state.attach_filter(verdict(SECCOMP_RET_ERRNO | 1)).unwrap();
        assert_eq!(state.run_filters(&data(0)), SECCOMP_RET_ERRNO | 1);

        let state = filtered(verdict(SECCOMP_RET_ERRNO | 1));
        state
            .attach_filter(verdict(SECCOMP_RET_ERRNO | 13))
            .unwrap();
        assert_eq!(state.run_filters(&data(0)), SECCOMP_RET_ERRNO | 13);
    }

    #[ktest]
    fn every_filter_in_the_chain_runs() {
        // The chain is three filters deep, and the verdicts have to be weighed
        // across all of them rather than the walk stopping at the first one
        // that says anything. `KILL_THREAD` is installed last so that nothing
        // but a full walk can find it.
        let state = filtered(verdict(SECCOMP_RET_ALLOW));
        state
            .attach_filter(verdict(SECCOMP_RET_ERRNO | 13))
            .unwrap();
        state
            .attach_filter(verdict(SECCOMP_RET_KILL_THREAD))
            .unwrap();

        assert_eq!(state.run_filters(&data(0)), SECCOMP_RET_KILL_THREAD);
    }

    #[ktest]
    fn a_filter_decides_using_the_system_call_it_is_given() {
        // A filter that is not a fixed verdict, so that this exercises the path
        // from the system call being inspected into the program: allow system
        // call 1 and refuse everything else.
        let program = Program::new(vec![
            insn(LD_W_ABS, 0, 0, 0),
            insn(JEQ_K, 0, 1, 1),
            insn(RET_K, 0, 0, SECCOMP_RET_ALLOW),
            insn(RET_K, 0, 0, SECCOMP_RET_ERRNO | 1),
        ]);

        let state = filtered(program);
        assert_eq!(state.run_filters(&data(1)), SECCOMP_RET_ALLOW);
        assert_eq!(state.run_filters(&data(2)), SECCOMP_RET_ERRNO | 1);
    }

    #[ktest]
    fn the_strict_mode_cannot_take_a_filter() {
        let state = SeccompState::new();
        assert!(state.set_mode(SeccompMode::Strict).is_ok());

        assert_eq!(
            state
                .attach_filter(verdict(SECCOMP_RET_ALLOW))
                .unwrap_err()
                .error(),
            Errno::EINVAL
        );
        // The filter must not have been left behind in the chain either: the
        // thread is in the strict mode, which never runs one.
        assert_eq!(state.mode(), SeccompMode::Strict);
        assert!(state.filters.lock().is_none());
    }

    #[ktest]
    fn a_cloned_thread_shares_the_filters_of_its_parent() {
        let parent = filtered(verdict(SECCOMP_RET_ERRNO | 13));

        let child = SeccompState::new_from(&parent);
        assert_eq!(child.mode(), SeccompMode::Filter);
        assert_eq!(child.run_filters(&data(0)), SECCOMP_RET_ERRNO | 13);
    }

    #[ktest]
    fn preparing_a_filter_does_not_install_it() {
        // `prepare_attach` is what a caller that may still change its mind uses,
        // so it must leave the thread exactly as it was. This is what lets
        // `SECCOMP_FILTER_FLAG_TSYNC` turn down a group without having confined
        // any of it.
        let state = filtered(verdict(SECCOMP_RET_ALLOW));
        let filter = state.prepare_attach(verdict(SECCOMP_RET_KILL_PROCESS));

        assert!(filter.is_ok());
        assert_eq!(state.run_filters(&data(0)), SECCOMP_RET_ALLOW);
    }

    #[ktest]
    fn a_thread_without_a_filter_of_its_own_can_adopt_any_filter() {
        // A thread that is not confined has nothing to lose, so it can be moved
        // onto any chain, however long it is.
        let caller = filtered(verdict(SECCOMP_RET_ALLOW));
        let filter = caller
            .prepare_attach(verdict(SECCOMP_RET_ERRNO | 13))
            .unwrap();

        let other = SeccompState::new();
        assert!(other.can_adopt(&filter));
    }

    #[ktest]
    fn a_thread_can_adopt_a_filter_installed_above_its_own() {
        // The child forked before the parent installed its second filter, so
        // the chain the child holds is a prefix of the one the parent has now.
        // The new filter goes on top of the parent's chain, and the child's
        // filters are still a prefix of the result, so the child can be moved.
        let parent = filtered(verdict(SECCOMP_RET_ALLOW));
        let child = SeccompState::new_from(&parent);
        parent
            .attach_filter(verdict(SECCOMP_RET_ERRNO | 13))
            .unwrap();

        let filter = parent
            .prepare_attach(verdict(SECCOMP_RET_ERRNO | 1))
            .unwrap();
        assert!(child.can_adopt(&filter));

        assert!(child.adopt_filter(&filter));
        assert_eq!(child.mode(), SeccompMode::Filter);
        assert_eq!(child.run_filters(&data(0)), SECCOMP_RET_ERRNO | 1);

        // The thread that installed the filter is the last to be moved onto it,
        // and only once every other thread has been: a caller that moves the
        // others first can still turn back if one of them cannot be moved, as
        // long as it has not moved itself. So building the filter has left the
        // parent where it was, and the new verdict is the child's alone.
        assert_eq!(parent.run_filters(&data(0)), SECCOMP_RET_ERRNO | 13);

        parent.commit_attach(&filter).unwrap();
        assert_eq!(parent.run_filters(&data(0)), SECCOMP_RET_ERRNO | 1);
    }

    #[ktest]
    fn a_thread_cannot_adopt_a_filter_that_does_not_reach_back_to_its_own() {
        // Two threads that each installed a filter of their own hold two
        // different filters, even though the programs in them are equal: a
        // filter is only shared with a thread that forked from the one that
        // installed it. Moving either onto the other's chain would take a
        // filter away from it, which seccomp never does.
        let caller = filtered(verdict(SECCOMP_RET_ALLOW));
        let other = filtered(verdict(SECCOMP_RET_ALLOW));

        let filter = caller
            .prepare_attach(verdict(SECCOMP_RET_ERRNO | 13))
            .unwrap();
        assert!(!other.can_adopt(&filter));
    }

    #[ktest]
    fn a_thread_in_the_strict_mode_cannot_adopt_a_filter() {
        let caller = filtered(verdict(SECCOMP_RET_ALLOW));
        let filter = caller
            .prepare_attach(verdict(SECCOMP_RET_ERRNO | 13))
            .unwrap();

        let other = SeccompState::new();
        assert!(other.set_mode(SeccompMode::Strict).is_ok());
        assert!(!other.can_adopt(&filter));
    }

    #[ktest]
    fn a_thread_that_entered_the_strict_mode_is_not_moved_onto_a_filter() {
        // A sync asks whether a thread can be moved before it moves any thread,
        // so a thread can be one it approved and stop being one afterwards.
        // Moving it anyway would put a filter in the chain of a thread that is
        // in a mode that never runs one, and would do it by way of a path that
        // has no answer for the thread it could not move.
        let caller = filtered(verdict(SECCOMP_RET_ALLOW));
        let filter = caller
            .prepare_attach(verdict(SECCOMP_RET_ERRNO | 13))
            .unwrap();

        let other = SeccompState::new();
        assert!(other.can_adopt(&filter));

        assert!(other.set_mode(SeccompMode::Strict).is_ok());
        assert!(!other.adopt_filter(&filter));

        // The thread is left exactly as it was, rather than holding a filter it
        // never runs.
        assert_eq!(other.mode(), SeccompMode::Strict);
        assert!(other.filters.lock().is_none());
    }

    #[ktest]
    fn a_chain_of_filters_is_freed_without_a_stack_frame_per_filter() {
        // A chain holds as many filters as the instruction budget allows, which
        // is thousands of them, and freeing it has to cost the same whatever
        // its length. Letting each node free the one behind it would need a
        // frame per filter and take more stack than a kernel stack has; this
        // overflows the stack rather than failing an assertion if the freeing
        // is not iterative.
        //
        // The chain is built a node at a time here rather than by installing
        // filters, because `prepare_attach` walks the whole chain to count its
        // instructions and so costs more the longer the chain gets, while what
        // is being tested is the freeing.
        let count = MAX_INSNS_PER_PATH / (1 + INSN_PENALTY_PER_FILTER);
        let program = || Program::new(vec![insn(RET_K, 0, 0, SECCOMP_RET_ALLOW)]);

        let mut chain = Arc::new(SeccompFilter {
            program: program(),
            prev: None,
        });
        for _ in 1..count {
            chain = Arc::new(SeccompFilter {
                program: program(),
                prev: Some(chain),
            });
        }

        drop(chain);
    }

    #[ktest]
    fn a_thread_may_not_hold_more_filters_than_the_limit_allows() {
        // The limit is on the total that the chain amounts to, so filters are
        // added until one more would take the thread over it. The penalty that
        // each filter in a chain is charged is what makes the last one fail
        // slightly before its own instructions alone would.
        let state = SeccompState::new();
        let program = || Program::new(vec![insn(RET_K, 0, 0, SECCOMP_RET_ALLOW); BPF_MAXINSNS]);

        for _ in 0..MAX_INSNS_PER_PATH / (BPF_MAXINSNS + INSN_PENALTY_PER_FILTER) {
            assert!(state.attach_filter(program()).is_ok());
        }
        assert_eq!(
            state.attach_filter(program()).unwrap_err().error(),
            Errno::ENOMEM
        );
    }

    #[ktest]
    fn each_verdict_reads_back_as_the_action_it_names() {
        assert_eq!(
            SeccompAction::from_verdict(SECCOMP_RET_ALLOW),
            SeccompAction::Allow
        );
        assert_eq!(
            SeccompAction::from_verdict(SECCOMP_RET_ERRNO | 13),
            SeccompAction::Errno(13)
        );
        assert_eq!(
            SeccompAction::from_verdict(SECCOMP_RET_TRAP),
            SeccompAction::Trap(0)
        );
        assert_eq!(
            SeccompAction::from_verdict(SECCOMP_RET_KILL_THREAD),
            SeccompAction::KillThread
        );
        assert_eq!(
            SeccompAction::from_verdict(SECCOMP_RET_KILL_PROCESS),
            SeccompAction::KillProcess
        );
    }

    #[ktest]
    fn an_error_number_is_capped_at_the_largest_one_a_system_call_can_return() {
        // The data half of a verdict is wider than an error number, so a filter
        // may ask for one that cannot be returned. Linux caps it rather than
        // refusing the verdict. As with the verdicts above, the number a filter
        // asks for is the one the system call fails with.
        assert_eq!(
            SeccompAction::from_verdict(SECCOMP_RET_ERRNO | 0xffff),
            SeccompAction::Errno(MAX_ERRNO)
        );
        assert_eq!(
            SeccompAction::from_verdict(SECCOMP_RET_ERRNO | (MAX_ERRNO as u32 + 1)),
            SeccompAction::Errno(MAX_ERRNO)
        );
        assert_eq!(
            SeccompAction::from_verdict(SECCOMP_RET_ERRNO),
            SeccompAction::Errno(0)
        );
    }

    #[ktest]
    fn the_data_of_a_trap_reaches_the_handler_whole() {
        // Unlike an error number, the data of a trap is not capped: it is
        // reported to the signal handler as it is, so the filter can put
        // whatever it likes there.
        assert_eq!(
            SeccompAction::from_verdict(SECCOMP_RET_TRAP | 0x1234),
            SeccompAction::Trap(0x1234)
        );
        assert_eq!(
            SeccompAction::from_verdict(SECCOMP_RET_TRAP | 0xffff),
            SeccompAction::Trap(0xffff)
        );
    }

    #[ktest]
    fn a_verdict_naming_an_action_that_is_not_implemented_kills_the_process() {
        // User notification, tracing and logging are all real seccomp actions,
        // and none of them is implemented here. A verdict asking for one of them
        // must not be mistaken for permission.
        let unimplemented = [
            0x7fc0_0000, // SECCOMP_RET_USER_NOTIF
            0x7ff0_0000, // SECCOMP_RET_TRACE
            0x7ffc_0000, // SECCOMP_RET_LOG
            0x1234_0000, // nothing at all
        ];

        for verdict in unimplemented {
            assert_eq!(
                SeccompAction::from_verdict(verdict),
                SeccompAction::KillProcess,
                "verdict {verdict:#010x} should have killed the process"
            );
        }
    }
}
