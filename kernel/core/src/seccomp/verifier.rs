// SPDX-License-Identifier: MPL-2.0

//! Validation of a classic-BPF program before it becomes a seccomp filter.
//!
//! Linux validates a seccomp program in two passes: `bpf_check_classic()`,
//! which it shares with socket filters, and then `seccomp_check_filter()`, which
//! is seccomp's own and is the narrower of the two. There are no socket filters
//! here, so this module fuses them into one pass that accepts what the two
//! accept together. Because the shared pass is a superset — it allows the loads
//! that index into a packet, and `BPF_MOD` — the fusion is simply seccomp's own
//! instruction set, which [`super::bpf::ALLOWED_OPCODES`] lists, plus the bounds
//! checks that both passes make.
//!
//! Everything an invalid program can get wrong is settled here, so that
//! [`super::interpreter`] can run a program without re-checking it.
//!
//! Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/net/core/filter.c>
//! and <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/seccomp.c>.

use super::{
    SECCOMP_DATA_SIZE,
    bpf::{
        ALU_DIV_K, ALU_LSH_K, ALU_RSH_K, BPF_MAXINSNS, BPF_MEMWORDS, JA, JEQ_K, JEQ_X, JGE_K,
        JGE_X, JGT_K, JGT_X, JSET_K, JSET_X, LD_MEM, LD_W_ABS, LDX_MEM, RET_A, RET_K, ST, STX,
        SockFilter,
    },
    interpreter::Program,
};
use crate::prelude::*;

/// Checks that `program` is one a seccomp filter is allowed to contain, and
/// turns it into something that may be run.
///
/// Everything that running a filter assumes is established here: that every
/// instruction has known semantics, that every jump lands inside the program,
/// that an absolute load reads a whole word from within the structure being
/// inspected, and that a scratch word is never read before it has been written.
/// Returning a [`Program`] rather than a bare success is what keeps those
/// assumptions true for the interpreter, which re-checks none of them.
pub(crate) fn verify(program: Vec<SockFilter>) -> Result<Program> {
    if program.is_empty() || program.len() > BPF_MAXINSNS {
        return_errno_with_message!(
            Errno::EINVAL,
            "a filter must contain between 1 and BPF_MAXINSNS instructions"
        );
    }

    for (pc, insn) in program.iter().enumerate() {
        check_instruction(&program, pc, insn)?;
    }

    // A program that can reach its end without returning has no verdict, so
    // there would be nothing to say about the system call.
    if !matches!(program[program.len() - 1].code, RET_K | RET_A) {
        return_errno_with_message!(Errno::EINVAL, "a filter must end by returning a verdict");
    }

    check_scratch_memory(&program)?;

    Ok(Program::new(program))
}

/// Applies the bounds checks that depend on an instruction's operands.
fn check_instruction(program: &[SockFilter], pc: usize, insn: &SockFilter) -> Result<()> {
    if !insn.is_allowed() {
        return_errno_with_message!(
            Errno::EINVAL,
            "the filter contains an instruction seccomp does not allow"
        );
    }

    let len = program.len();

    match insn.code {
        // A divisor that is known to be zero can be rejected now. One that
        // arrives in `X` cannot be, and the interpreter handles it instead.
        //
        // There is no matching check for `BPF_MOD`, which Linux makes in the
        // pass it shares with socket filters: seccomp rejects every `BPF_MOD`
        // outright, so it never reaches this point.
        ALU_DIV_K if insn.k == 0 => {
            return_errno_with_message!(Errno::EINVAL, "the filter divides by a constant zero");
        }
        // The register forms are unchecked here for the same reason: the
        // interpreter masks the shift count, as classic BPF does.
        ALU_LSH_K | ALU_RSH_K if insn.k >= 32 => {
            return_errno_with_message!(
                Errno::EINVAL,
                "the filter shifts by a constant of 32 or more"
            );
        }
        LD_MEM | LDX_MEM | ST | STX if insn.k as usize >= BPF_MEMWORDS => {
            return_errno_with_message!(
                Errno::EINVAL,
                "the filter names a scratch word that does not exist"
            );
        }
        // A jump must land on an instruction that exists. Together with jumps
        // going only forward, which is all classic BPF offers, this is what
        // makes the program terminate.
        JA if insn.k as usize >= len - pc - 1 => {
            return_errno_with_message!(Errno::EINVAL, "the filter jumps past its last instruction");
        }
        JEQ_K | JEQ_X | JGE_K | JGE_X | JGT_K | JGT_X | JSET_K | JSET_X
            if pc + insn.jt as usize + 1 >= len || pc + insn.jf as usize + 1 >= len =>
        {
            return_errno_with_message!(Errno::EINVAL, "the filter jumps past its last instruction");
        }
        // This is the bound that makes the interpreter's read of the
        // structure safe. It reads a whole word, so the word has to start
        // inside the structure and not straddle its end.
        LD_W_ABS if insn.k >= SECCOMP_DATA_SIZE || insn.k % 4 != 0 => {
            return_errno_with_message!(
                Errno::EINVAL,
                "the filter reads outside the system call it is inspecting"
            );
        }
        _ => {}
    }

    Ok(())
}

/// Checks that no scratch word is read before it has been written.
///
/// This is Linux's `check_load_and_stores()`. It walks the program once,
/// carrying a bit per scratch word saying whether that word has been written on
/// *every* way of reaching the instruction being looked at. Each instruction
/// that can be jumped to also remembers the set it was reached with, and the
/// sets are intersected as the walk arrives, so a word has to be written on all
/// incoming paths before it counts as written.
///
/// One pass in instruction order is enough because jumps only go forward: by
/// the time an instruction is visited, every instruction that can reach it has
/// already been visited.
fn check_scratch_memory(program: &[SockFilter]) -> Result<()> {
    // What is known to be written on the way to each instruction, for the
    // instructions that can be jumped to.
    let mut reached_with = vec![u16::MAX; program.len()];
    let mut written: u16 = 0;

    for (pc, insn) in program.iter().enumerate() {
        written &= reached_with[pc];

        match insn.code {
            ST | STX => written |= 1 << insn.k,
            LD_MEM | LDX_MEM if written & (1 << insn.k) == 0 => {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "the filter reads a scratch word before writing it"
                );
            }
            JA => {
                reached_with[pc + 1 + insn.k as usize] &= written;
                written = u16::MAX;
            }
            JEQ_K | JEQ_X | JGE_K | JGE_X | JGT_K | JGT_X | JSET_K | JSET_X => {
                reached_with[pc + 1 + insn.jt as usize] &= written;
                reached_with[pc + 1 + insn.jf as usize] &= written;
                // Only one of the two branches is taken, so the fall-through
                // carries nothing that was learned before the jump; what each
                // branch knows is recorded above instead.
                written = u16::MAX;
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::*;

    use super::*;
    use crate::{
        prelude::Result,
        seccomp::bpf::{ALU_DIV_X, ALU_RSH_X, LD_IMM},
    };

    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    /// Checks a program, so that the tests can write one out as an array
    /// literal rather than having to build a `Vec` by hand.
    fn check(program: impl Into<Vec<SockFilter>>) -> Result<Program> {
        verify(program.into())
    }

    /// A program consisting only of a verdict, which is the smallest valid one.
    fn verdict() -> SockFilter {
        insn(RET_K, 0, 0, 0x7fff0000)
    }

    #[ktest]
    fn a_minimal_program_is_accepted() {
        assert!(check([verdict()]).is_ok());
    }

    #[ktest]
    fn an_empty_program_is_rejected() {
        assert_eq!(check([]).unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn a_program_longer_than_the_maximum_is_rejected() {
        let program = vec![verdict(); BPF_MAXINSNS + 1];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn a_program_of_exactly_the_maximum_length_is_accepted() {
        let program = vec![verdict(); BPF_MAXINSNS];
        assert!(check(program).is_ok());
    }

    #[ktest]
    fn a_program_must_end_by_returning_a_verdict() {
        let program = [verdict(), insn(LD_IMM, 0, 0, 0)];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn instructions_seccomp_does_not_allow_are_rejected() {
        // Each of these is a real classic-BPF instruction that the shared
        // verifier accepts, but seccomp's own does not. They are written out as
        // literals because this module deliberately has no name for them.
        let rejected = [
            0x28, // LD | H | ABS: reading a halfword of the structure
            0x30, // LD | B | ABS: reading a byte of the structure
            0x40, // LD | W | IND: reading at a computed offset
            0xb1, // LDX | B | MSH: loading a header length
            0x94, // ALU | MOD | K: the two BPFs disagree on what this means
            0x9c, // ALU | MOD | X
        ];

        for code in rejected {
            let program = [insn(code, 0, 0, 0), verdict()];
            assert_eq!(
                check(program).unwrap_err().error(),
                Errno::EINVAL,
                "opcode {code:#04x} should have been rejected"
            );
        }
    }

    #[ktest]
    fn an_absolute_load_may_read_the_last_word() {
        // 60 is the last offset a whole word fits in, and the last word holds
        // the high half of the sixth argument.
        let program = [insn(LD_W_ABS, 0, 0, 60), verdict()];
        assert!(check(program).is_ok());
    }

    #[ktest]
    fn an_absolute_load_past_the_end_is_rejected() {
        let program = [insn(LD_W_ABS, 0, 0, SECCOMP_DATA_SIZE), verdict()];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn an_absolute_load_that_is_not_word_aligned_is_rejected() {
        for k in [1, 2, 3, 6] {
            let program = [insn(LD_W_ABS, 0, 0, k), verdict()];
            assert_eq!(
                check(program).unwrap_err().error(),
                Errno::EINVAL,
                "offset {k} should have been rejected"
            );
        }
    }

    #[ktest]
    fn dividing_by_a_constant_zero_is_rejected() {
        let program = [insn(ALU_DIV_K, 0, 0, 0), verdict()];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn dividing_by_a_register_is_accepted() {
        // Whether `X` is zero is not knowable here, so this is not the
        // verifier's to reject.
        let program = [insn(ALU_DIV_X, 0, 0, 0), verdict()];
        assert!(check(program).is_ok());
    }

    #[ktest]
    fn shifting_by_a_constant_of_32_or_more_is_rejected() {
        let program = [insn(ALU_LSH_K, 0, 0, 32), verdict()];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);

        let program = [insn(ALU_LSH_K, 0, 0, 31), verdict()];
        assert!(check(program).is_ok());
    }

    #[ktest]
    fn shifting_by_a_register_is_accepted() {
        let program = [insn(ALU_RSH_X, 0, 0, 0), verdict()];
        assert!(check(program).is_ok());
    }

    #[ktest]
    fn a_jump_onto_the_last_instruction_is_accepted() {
        // From the first of two instructions, a jump of zero lands on the
        // second, which is the last one.
        let program = [insn(JA, 0, 0, 0), verdict()];
        assert!(check(program).is_ok());
    }

    #[ktest]
    fn a_jump_past_the_last_instruction_is_rejected() {
        let program = [insn(JA, 0, 0, 1), verdict()];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn a_conditional_jump_past_the_last_instruction_is_rejected() {
        // Both destinations have to be in range, and a conditional jump has
        // two of them.
        let program = [insn(JEQ_K, 1, 0, 0), verdict()];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);

        let program = [insn(JEQ_K, 0, 1, 0), verdict()];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);

        let program = [insn(JEQ_K, 0, 0, 0), verdict()];
        assert!(check(program).is_ok());
    }

    #[ktest]
    fn a_scratch_word_that_does_not_exist_is_rejected() {
        let program = [insn(ST, 0, 0, BPF_MEMWORDS as u32), verdict()];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn reading_a_scratch_word_before_writing_it_is_rejected() {
        let program = [insn(LD_MEM, 0, 0, 0), verdict()];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn reading_a_scratch_word_after_writing_it_is_accepted() {
        let program = [insn(ST, 0, 0, 0), insn(LD_MEM, 0, 0, 0), verdict()];
        assert!(check(program).is_ok());
    }

    #[ktest]
    fn writing_a_scratch_word_on_one_branch_does_not_count_on_the_other() {
        // The write is on the branch that a match takes, so an arrival by the
        // other branch knows nothing about the word.
        let program = [
            insn(JEQ_K, 0, 1, 0), // taken: on to the store; not taken: past it
            insn(ST, 0, 0, 0),
            insn(LD_MEM, 0, 0, 0),
            verdict(),
        ];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn writing_a_scratch_word_on_both_branches_is_accepted() {
        // The two stores sit on the two arms of the branch, and both arms then
        // jump to the same read. Linux accepts this program; the test below is
        // the near miss that it rejects instead.
        let program = [
            insn(JEQ_K, 1, 0, 0), // taken: past the first store, to the jump
            insn(ST, 0, 0, 0),
            insn(JA, 0, 0, 0), // both arms land together on the second store
            insn(ST, 0, 0, 0),
            insn(LD_MEM, 0, 0, 0),
            verdict(),
        ];
        assert!(check(program).is_ok());
    }

    #[ktest]
    fn a_store_that_every_branch_skips_does_not_count_as_an_initialisation() {
        // Reading this program suggests that both arms store, but the arm taken
        // at the first branch jumps past both stores, and the check does not
        // reason about which arm is which: it only knows what is written on
        // *every* way of arriving. Linux rejects this program, and a verifier
        // that accepted it would let a filter read a scratch word it never set.
        let program = [
            insn(JEQ_K, 0, 1, 0), // not taken: past the first store
            insn(ST, 0, 0, 0),
            insn(JEQ_K, 1, 0, 0), // taken: past the second store, to the read
            insn(ST, 0, 0, 0),
            insn(LD_MEM, 0, 0, 0),
            verdict(),
        ];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);
    }

    #[ktest]
    fn a_read_no_path_can_reach_is_still_rejected() {
        // An instruction after a verdict can never run, but the check does not
        // reason about reachability, and Linux's does not either. Being
        // conservative here costs nothing and cannot be wrong.
        let program = [verdict(), insn(LD_MEM, 0, 0, 0), verdict()];
        assert_eq!(check(program).unwrap_err().error(), Errno::EINVAL);
    }
}
