// SPDX-License-Identifier: MPL-2.0

//! Running a verified classic-BPF program.
//!
//! The interpreter is deliberately trusting: it assumes everything
//! [`super::verifier`] establishes about a program and re-checks none of it.
//! [`Program`] can only be built by the verifier, which is what keeps that
//! assumption true. In particular, every index below is within bounds and
//! every jump lands inside the program *because the verifier said so*, and the
//! `unreachable` arms exist only because its allowlist is closed.
//!
//! Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/kernel/bpf/core.c>
//! and <https://elixir.bootlin.com/linux/v6.16.5/source/net/core/filter.c>.

use super::{
    SECCOMP_DATA_SIZE, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD, SeccompData,
    bpf::{
        ALU_ADD_K, ALU_ADD_X, ALU_AND_K, ALU_AND_X, ALU_DIV_K, ALU_DIV_X, ALU_LSH_K, ALU_LSH_X,
        ALU_MUL_K, ALU_MUL_X, ALU_NEG, ALU_OR_K, ALU_OR_X, ALU_RSH_K, ALU_RSH_X, ALU_SUB_K,
        ALU_SUB_X, ALU_XOR_K, ALU_XOR_X, BPF_MEMWORDS, JA, JEQ_K, JEQ_X, JGE_K, JGE_X, JGT_K,
        JGT_X, JSET_K, JSET_X, LD_IMM, LD_MEM, LD_W_ABS, LD_W_LEN, LDX_IMM, LDX_MEM, LDX_W_LEN,
        RET_A, RET_K, ST, STX, SockFilter, TAX, TXA,
    },
};
use crate::prelude::*;

/// A classic-BPF program that has been checked and may be run.
#[derive(Debug)]
pub(crate) struct Program {
    instructions: Vec<SockFilter>,
}

impl Program {
    /// Wraps `instructions` as a runnable program.
    ///
    /// [`super::verifier::verify`] is the only caller, and it is the only thing
    /// that may be: [`Program::run`] depends on every guarantee that function
    /// makes, and does not repeat any of its checks.
    pub(super) fn new(instructions: Vec<SockFilter>) -> Self {
        Self { instructions }
    }

    /// Returns how many instructions the program is made of.
    pub(super) fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Runs the program against `data` and returns the verdict it reaches.
    ///
    /// The return value is a raw `SECCOMP_RET_*` value, which the caller
    /// decodes. A program that divides by a register holding zero returns
    /// [`SECCOMP_RET_KILL_THREAD`], which is what classic BPF does: the
    /// conversion Linux performs makes such a division return zero from the
    /// whole program, and zero is that verdict.
    pub(super) fn run(&self, data: &SeccompData) -> u32 {
        let mut accumulator: u32 = 0;
        let mut index: u32 = 0;
        let mut memory = [0u32; BPF_MEMWORDS];
        let mut pc = 0;

        loop {
            let insn = self.instructions[pc];

            // How far past the next instruction to go: nothing for the
            // instructions that fall through, and the jump's offset for the
            // ones that do not.
            let jump = match insn.code {
                // Reading the system call being inspected.
                LD_W_ABS => {
                    accumulator = data.word_at(insn.k);
                    0
                }
                LD_W_LEN => {
                    accumulator = SECCOMP_DATA_SIZE;
                    0
                }
                LDX_W_LEN => {
                    index = SECCOMP_DATA_SIZE;
                    0
                }

                // Constants.
                LD_IMM => {
                    accumulator = insn.k;
                    0
                }
                LDX_IMM => {
                    index = insn.k;
                    0
                }

                // Scratch memory.
                LD_MEM => {
                    accumulator = memory[insn.k as usize];
                    0
                }
                LDX_MEM => {
                    index = memory[insn.k as usize];
                    0
                }
                ST => {
                    memory[insn.k as usize] = accumulator;
                    0
                }
                STX => {
                    memory[insn.k as usize] = index;
                    0
                }

                // Moving a value between the two registers.
                TAX => {
                    index = accumulator;
                    0
                }
                TXA => {
                    accumulator = index;
                    0
                }

                // Arithmetic and logic. These are the wide operations, so they
                // wrap rather than trap.
                ALU_ADD_K => {
                    accumulator = accumulator.wrapping_add(insn.k);
                    0
                }
                ALU_ADD_X => {
                    accumulator = accumulator.wrapping_add(index);
                    0
                }
                ALU_SUB_K => {
                    accumulator = accumulator.wrapping_sub(insn.k);
                    0
                }
                ALU_SUB_X => {
                    accumulator = accumulator.wrapping_sub(index);
                    0
                }
                ALU_MUL_K => {
                    accumulator = accumulator.wrapping_mul(insn.k);
                    0
                }
                ALU_MUL_X => {
                    accumulator = accumulator.wrapping_mul(index);
                    0
                }
                // A constant divisor is nonzero here: the verifier rejects a
                // zero one.
                ALU_DIV_K => {
                    accumulator /= insn.k;
                    0
                }
                ALU_DIV_X => {
                    if index == 0 {
                        return SECCOMP_RET_KILL_THREAD;
                    }
                    accumulator /= index;
                    0
                }
                ALU_OR_K => {
                    accumulator |= insn.k;
                    0
                }
                ALU_OR_X => {
                    accumulator |= index;
                    0
                }
                ALU_AND_K => {
                    accumulator &= insn.k;
                    0
                }
                ALU_AND_X => {
                    accumulator &= index;
                    0
                }
                // A constant shift count is below 32 here, for the same reason.
                ALU_LSH_K => {
                    accumulator <<= insn.k;
                    0
                }
                ALU_RSH_K => {
                    accumulator >>= insn.k;
                    0
                }
                // A register shift count is not, so it is masked: shifting by
                // more than 31 shifts by the count modulo 32.
                ALU_LSH_X => {
                    accumulator <<= index & 31;
                    0
                }
                ALU_RSH_X => {
                    accumulator >>= index & 31;
                    0
                }
                ALU_XOR_K => {
                    accumulator ^= insn.k;
                    0
                }
                ALU_XOR_X => {
                    accumulator ^= index;
                    0
                }
                ALU_NEG => {
                    accumulator = accumulator.wrapping_neg();
                    0
                }

                // Jumps. The offsets are relative to the following instruction,
                // and they only ever go forward.
                JA => insn.k as usize,
                JEQ_K => Self::branch(accumulator == insn.k, &insn),
                JEQ_X => Self::branch(accumulator == index, &insn),
                JGT_K => Self::branch(accumulator > insn.k, &insn),
                JGT_X => Self::branch(accumulator > index, &insn),
                JGE_K => Self::branch(accumulator >= insn.k, &insn),
                JGE_X => Self::branch(accumulator >= index, &insn),
                JSET_K => Self::branch(accumulator & insn.k != 0, &insn),
                JSET_X => Self::branch(accumulator & index != 0, &insn),

                // The verdict.
                RET_K => return insn.k,
                RET_A => return accumulator,

                // The verifier accepts nothing outside the set above, so this
                // cannot be reached. Ending the process rather than panicking
                // keeps a mistake here from taking the machine down, and is the
                // safer way to be wrong about a system call.
                _ => return SECCOMP_RET_KILL_PROCESS,
            };

            pc += jump + 1;
        }
    }

    /// Returns how far to jump when a conditional jump's condition holds.
    fn branch(taken: bool, insn: &SockFilter) -> usize {
        if taken {
            insn.jt as usize
        } else {
            insn.jf as usize
        }
    }
}

#[cfg(ktest)]
mod test {
    use ostd::prelude::*;

    use super::*;
    use crate::seccomp::{SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, verifier::verify};

    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    /// Builds and checks a program, as installing a filter would.
    fn build(instructions: Vec<SockFilter>) -> Program {
        verify(instructions).unwrap()
    }

    /// The structure a filter sees for a system call, with the arguments given.
    fn data(nr: i32, args: [u64; 6]) -> SeccompData {
        SeccompData {
            nr,
            arch: 0,
            instruction_pointer: 0,
            args,
        }
    }

    #[ktest]
    fn a_verdict_reached_immediately_is_returned() {
        let program = build(vec![insn(RET_K, 0, 0, SECCOMP_RET_ALLOW)]);
        assert_eq!(program.run(&data(0, [0; 6])), SECCOMP_RET_ALLOW);
    }

    #[ktest]
    fn the_accumulator_holds_a_returned_verdict() {
        let program = build(vec![insn(RET_A, 0, 0, 0)]);
        assert_eq!(program.run(&data(0, [0; 6])), 0);
    }

    #[ktest]
    fn a_filter_can_read_the_system_call_number() {
        // Reading the number the filter is deciding about is the whole point of
        // a filter, so this is the one test that must not be clever.
        let program = build(vec![insn(LD_W_ABS, 0, 0, 0), insn(RET_A, 0, 0, 0)]);
        assert_eq!(program.run(&data(42, [0; 6])), 42);
    }

    #[ktest]
    fn a_filter_can_read_an_argument() {
        let mut args = [0u64; 6];
        args[2] = 0x1234_5678_9abc_def0;

        // The low word of the third argument sits at offset 16 + 2 * 8.
        let program = build(vec![insn(LD_W_ABS, 0, 0, 32), insn(RET_A, 0, 0, 0)]);
        assert_eq!(program.run(&data(0, args)), 0x9abc_def0);
    }

    #[ktest]
    fn a_filter_can_read_the_length_of_the_structure() {
        let program = build(vec![insn(LD_W_LEN, 0, 0, 0), insn(RET_A, 0, 0, 0)]);
        assert_eq!(program.run(&data(0, [0; 6])), SECCOMP_DATA_SIZE);
    }

    #[ktest]
    fn a_filter_can_write_and_read_scratch_memory() {
        let program = build(vec![
            insn(LD_IMM, 0, 0, 7),
            insn(ST, 0, 0, 3),
            insn(LD_IMM, 0, 0, 0),
            insn(LD_MEM, 0, 0, 3),
            insn(RET_A, 0, 0, 0),
        ]);
        assert_eq!(program.run(&data(0, [0; 6])), 7);
    }

    #[ktest]
    fn scratch_words_are_separate_from_each_other() {
        let program = build(vec![
            insn(LD_IMM, 0, 0, 1),
            insn(ST, 0, 0, 0),
            insn(LD_IMM, 0, 0, 2),
            insn(ST, 0, 0, 1),
            insn(LD_MEM, 0, 0, 0),
            insn(RET_A, 0, 0, 0),
        ]);
        assert_eq!(program.run(&data(0, [0; 6])), 1);
    }

    #[ktest]
    fn a_filter_can_move_values_between_its_registers() {
        // Into `X` and back out again.
        let program = build(vec![
            insn(LD_IMM, 0, 0, 9),
            insn(TAX, 0, 0, 0),
            insn(LD_IMM, 0, 0, 0),
            insn(TXA, 0, 0, 0),
            insn(RET_A, 0, 0, 0),
        ]);
        assert_eq!(program.run(&data(0, [0; 6])), 9);
    }

    #[ktest]
    fn arithmetic_wraps_rather_than_trapping() {
        // Subtracting past zero gives a large number rather than failing.
        let program = build(vec![
            insn(LD_IMM, 0, 0, 0),
            insn(ALU_SUB_K, 0, 0, 1),
            insn(RET_A, 0, 0, 0),
        ]);
        assert_eq!(program.run(&data(0, [0; 6])), u32::MAX);
    }

    #[ktest]
    fn a_division_by_a_register_holding_zero_kills_the_thread() {
        // Classic BPF makes this return zero from the program, and a verdict of
        // zero is the one that kills the thread. The instructions after the
        // division do not run.
        let program = build(vec![
            insn(LDX_IMM, 0, 0, 0),
            insn(LD_IMM, 0, 0, 5),
            insn(ALU_DIV_X, 0, 0, 0),
            insn(RET_K, 0, 0, SECCOMP_RET_ALLOW),
        ]);
        assert_eq!(program.run(&data(0, [0; 6])), SECCOMP_RET_KILL_THREAD);
    }

    #[ktest]
    fn a_division_by_a_nonzero_register_divides() {
        let program = build(vec![
            insn(LDX_IMM, 0, 0, 4),
            insn(LD_IMM, 0, 0, 12),
            insn(ALU_DIV_X, 0, 0, 0),
            insn(RET_A, 0, 0, 0),
        ]);
        assert_eq!(program.run(&data(0, [0; 6])), 3);
    }

    #[ktest]
    fn a_shift_count_coming_from_a_register_is_masked() {
        // Shifting by 32 shifts by nothing, and shifting by 33 shifts by one.
        let program = build(vec![
            insn(LDX_IMM, 0, 0, 32),
            insn(LD_IMM, 0, 0, 1),
            insn(ALU_LSH_X, 0, 0, 0),
            insn(RET_A, 0, 0, 0),
        ]);
        assert_eq!(program.run(&data(0, [0; 6])), 1);

        let program = build(vec![
            insn(LDX_IMM, 0, 0, 33),
            insn(LD_IMM, 0, 0, 1),
            insn(ALU_LSH_X, 0, 0, 0),
            insn(RET_A, 0, 0, 0),
        ]);
        assert_eq!(program.run(&data(0, [0; 6])), 2);
    }

    #[ktest]
    fn a_conditional_jump_decides_where_to_go_next() {
        // Allow if the number is 1, and refuse with an errno otherwise, which is
        // the shape nearly every real filter has.
        let program = build(vec![
            insn(LD_W_ABS, 0, 0, 0),
            insn(JEQ_K, 0, 1, 1),
            insn(RET_K, 0, 0, SECCOMP_RET_ALLOW),
            insn(RET_K, 0, 0, SECCOMP_RET_ERRNO | 13),
        ]);

        assert_eq!(program.run(&data(1, [0; 6])), SECCOMP_RET_ALLOW);
        assert_eq!(
            program.run(&data(2, [0; 6])),
            SECCOMP_RET_ERRNO | 13,
            "a number other than 1 should have taken the other branch"
        );
    }

    #[ktest]
    fn an_unconditional_jump_skips_instructions() {
        let program = build(vec![
            insn(JA, 0, 0, 1),
            insn(RET_K, 0, 0, SECCOMP_RET_ERRNO | 13),
            insn(RET_K, 0, 0, SECCOMP_RET_ALLOW),
        ]);
        assert_eq!(program.run(&data(0, [0; 6])), SECCOMP_RET_ALLOW);
    }

    #[ktest]
    fn a_comparison_may_be_against_a_register() {
        let program = build(vec![
            insn(LDX_IMM, 0, 0, 5),
            insn(LD_W_ABS, 0, 0, 0),
            insn(JGT_X, 0, 1, 0), // is the number greater than 5?
            insn(RET_K, 0, 0, SECCOMP_RET_ALLOW),
            insn(RET_K, 0, 0, SECCOMP_RET_ERRNO | 13),
        ]);

        assert_eq!(program.run(&data(6, [0; 6])), SECCOMP_RET_ALLOW);
        assert_eq!(program.run(&data(5, [0; 6])), SECCOMP_RET_ERRNO | 13);
    }

    #[ktest]
    fn a_bit_test_splits_on_a_single_bit() {
        let program = build(vec![
            insn(LD_W_ABS, 0, 0, 0),
            insn(JSET_K, 0, 1, 0b10),
            insn(RET_K, 0, 0, SECCOMP_RET_ALLOW),
            insn(RET_K, 0, 0, SECCOMP_RET_ERRNO | 13),
        ]);

        assert_eq!(program.run(&data(0b10, [0; 6])), SECCOMP_RET_ALLOW);
        assert_eq!(program.run(&data(0b01, [0; 6])), SECCOMP_RET_ERRNO | 13);
    }
}
