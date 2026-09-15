// SPDX-License-Identifier: MPL-2.0

//! The classic BPF instruction set, as far as seccomp uses it.
//!
//! This module only describes the *encoding*. Which instructions a filter is
//! allowed to contain is decided by [`super::verifier`], and what an
//! instruction means is decided by [`super::interpreter`].
//!
//! Reference: <https://elixir.bootlin.com/linux/v6.16.5/source/include/uapi/linux/bpf_common.h>.

use crate::prelude::*;

/// The number of scratch words a program may use, `M[0]` through `M[15]`.
pub(super) const BPF_MEMWORDS: usize = 16;

/// The largest program that can be installed in a single call.
pub(crate) const BPF_MAXINSNS: usize = 4096;

// The instruction classes, held in the low three bits of `code`.
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_STX: u16 = 0x03;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

// The access sizes, held in bits 3 and 4. Only the word size is usable by a
// seccomp filter, so the other two are not named here.
const BPF_W: u16 = 0x00;

// The addressing modes, held in the top three bits. Likewise, only these three
// name an instruction a filter may contain; the packet-indexed and multi-byte
// modes are rejected by [`super::verifier`].
const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;

// The ALU operations, held in the top four bits.
const BPF_ADD: u16 = 0x00;
const BPF_SUB: u16 = 0x10;
const BPF_MUL: u16 = 0x20;
const BPF_DIV: u16 = 0x30;
const BPF_OR: u16 = 0x40;
const BPF_AND: u16 = 0x50;
const BPF_LSH: u16 = 0x60;
const BPF_RSH: u16 = 0x70;
const BPF_NEG: u16 = 0x80;
const BPF_XOR: u16 = 0xa0;

// The jump operations, held in the top four bits. Note that classic BPF has no
// "not equal" jump; a filter builds one by swapping `jt` and `jf`.
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;

// The second operand of an ALU or jump instruction. `BPF_K` takes it from the
// instruction's `k`, `BPF_X` from the `X` register.
const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;

// The `BPF_MISC` operations, held in the top five bits.
const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

// `BPF_RET` selects the `A` register as its result with this bit, rather than
// taking a constant from `k`.
const BPF_A: u16 = 0x10;

// Each instruction gets a name of its own, rather than being spelled out as its
// parts at every use. This is not just for readability: Rust reads `|` inside a
// pattern as an or-pattern, so `BPF_LD | BPF_MEM` in a `match` arm would mean
// "either `BPF_LD` or `BPF_MEM`" — which is not what it says in C, and would
// silently match far more than intended.
//
// The names follow the ones in `<linux/bpf_common.h>`, so the two can be read
// side by side.

// Loads.
pub(super) const LD_IMM: u16 = BPF_LD | BPF_IMM;
pub(super) const LD_W_ABS: u16 = BPF_LD | BPF_W | BPF_ABS;
pub(super) const LD_W_LEN: u16 = BPF_LD | BPF_W | BPF_LEN;
pub(super) const LD_MEM: u16 = BPF_LD | BPF_MEM;
pub(super) const LDX_IMM: u16 = BPF_LDX | BPF_IMM;
pub(super) const LDX_W_LEN: u16 = BPF_LDX | BPF_W | BPF_LEN;
pub(super) const LDX_MEM: u16 = BPF_LDX | BPF_MEM;

// Stores into scratch memory.
pub(super) const ST: u16 = BPF_ST;
pub(super) const STX: u16 = BPF_STX;

// Register moves.
pub(super) const TAX: u16 = BPF_MISC | BPF_TAX;
pub(super) const TXA: u16 = BPF_MISC | BPF_TXA;

// Arithmetic and logic, with a constant and with the `X` register.
pub(super) const ALU_ADD_K: u16 = BPF_ALU | BPF_ADD | BPF_K;
pub(super) const ALU_ADD_X: u16 = BPF_ALU | BPF_ADD | BPF_X;
pub(super) const ALU_SUB_K: u16 = BPF_ALU | BPF_SUB | BPF_K;
pub(super) const ALU_SUB_X: u16 = BPF_ALU | BPF_SUB | BPF_X;
pub(super) const ALU_MUL_K: u16 = BPF_ALU | BPF_MUL | BPF_K;
pub(super) const ALU_MUL_X: u16 = BPF_ALU | BPF_MUL | BPF_X;
pub(super) const ALU_DIV_K: u16 = BPF_ALU | BPF_DIV | BPF_K;
pub(super) const ALU_DIV_X: u16 = BPF_ALU | BPF_DIV | BPF_X;
pub(super) const ALU_OR_K: u16 = BPF_ALU | BPF_OR | BPF_K;
pub(super) const ALU_OR_X: u16 = BPF_ALU | BPF_OR | BPF_X;
pub(super) const ALU_AND_K: u16 = BPF_ALU | BPF_AND | BPF_K;
pub(super) const ALU_AND_X: u16 = BPF_ALU | BPF_AND | BPF_X;
pub(super) const ALU_LSH_K: u16 = BPF_ALU | BPF_LSH | BPF_K;
pub(super) const ALU_LSH_X: u16 = BPF_ALU | BPF_LSH | BPF_X;
pub(super) const ALU_RSH_K: u16 = BPF_ALU | BPF_RSH | BPF_K;
pub(super) const ALU_RSH_X: u16 = BPF_ALU | BPF_RSH | BPF_X;
pub(super) const ALU_XOR_K: u16 = BPF_ALU | BPF_XOR | BPF_K;
pub(super) const ALU_XOR_X: u16 = BPF_ALU | BPF_XOR | BPF_X;
pub(super) const ALU_NEG: u16 = BPF_ALU | BPF_NEG;

// Jumps. `JA` is unconditional; the rest compare `A` against `k` or `X`.
pub(super) const JA: u16 = BPF_JMP | BPF_JA;
pub(super) const JEQ_K: u16 = BPF_JMP | BPF_JEQ | BPF_K;
pub(super) const JEQ_X: u16 = BPF_JMP | BPF_JEQ | BPF_X;
pub(super) const JGT_K: u16 = BPF_JMP | BPF_JGT | BPF_K;
pub(super) const JGT_X: u16 = BPF_JMP | BPF_JGT | BPF_X;
pub(super) const JGE_K: u16 = BPF_JMP | BPF_JGE | BPF_K;
pub(super) const JGE_X: u16 = BPF_JMP | BPF_JGE | BPF_X;
pub(super) const JSET_K: u16 = BPF_JMP | BPF_JSET | BPF_K;
pub(super) const JSET_X: u16 = BPF_JMP | BPF_JSET | BPF_X;

// Verdicts.
pub(super) const RET_K: u16 = BPF_RET | BPF_K;
pub(super) const RET_A: u16 = BPF_RET | BPF_A;

/// The instructions that a seccomp filter may contain.
///
/// This is an allowlist rather than a blacklist, as it is in Linux: a filter
/// that names an instruction we have not thought about is rejected outright,
/// rather than being run with semantics nobody has checked.
///
/// The set is narrower than classic BPF in general allows, because most of the
/// difference is meaningless here. A seccomp filter inspects a fixed-size
/// structure, so there is no packet to index into: the `BPF_IND` loads, the
/// halfword and byte reads, the multi-byte load and every `BPF_MSH` are all
/// rejected. So is `BPF_MOD`, whose classic and extended semantics disagree.
/// This is exactly the set Linux's `seccomp_check_filter()` accepts.
#[rustfmt::skip]
pub(super) const ALLOWED_OPCODES: [u16; 41] = [
    // Reading the system call the filter is inspecting.
    LD_W_ABS, LD_W_LEN, LDX_W_LEN,
    // Constants.
    LD_IMM, LDX_IMM,
    // Scratch memory.
    LD_MEM, LDX_MEM, ST, STX,
    // Moving a value between the two registers.
    TAX, TXA,
    // Arithmetic and logic.
    ALU_ADD_K, ALU_ADD_X, ALU_SUB_K, ALU_SUB_X, ALU_MUL_K, ALU_MUL_X, ALU_DIV_K, ALU_DIV_X,
    ALU_OR_K, ALU_OR_X, ALU_AND_K, ALU_AND_X, ALU_LSH_K, ALU_LSH_X, ALU_RSH_K, ALU_RSH_X,
    ALU_XOR_K, ALU_XOR_X, ALU_NEG,
    // Jumps. These are all forward-only, which the verifier enforces: that is
    // what makes the program terminate without needing to look for cycles.
    JA, JEQ_K, JEQ_X, JGT_K, JGT_X, JGE_K, JGE_X, JSET_K, JSET_X,
    // Verdicts. The last instruction of a program must be one of these.
    RET_K, RET_A,
];

/// One classic BPF instruction.
///
/// The layout is fixed by the seccomp ABI, and the field names follow
/// `<linux/filter.h>` so that the two can be read side by side. There is no
/// implicit padding to worry about: `code`, `jt` and `jf` fill the first word,
/// and `k` the second.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(crate) struct SockFilter {
    /// The encoded instruction.
    pub code: u16,
    /// How far to jump when a conditional jump is taken.
    pub jt: u8,
    /// How far to jump when a conditional jump is not taken.
    pub jf: u8,
    /// The immediate operand, or an offset or index, depending on `code`.
    pub k: u32,
}

impl SockFilter {
    /// Returns whether this instruction is one a seccomp filter may contain.
    pub(super) fn is_allowed(&self) -> bool {
        ALLOWED_OPCODES.contains(&self.code)
    }
}

/// A program, as userspace describes it to `seccomp(2)`.
///
/// The pointer is a user address, so this is only ever read out of user memory
/// and never dereferenced directly.
#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
pub(crate) struct SockFprog {
    /// The number of instructions that `filter` points at.
    pub len: u16,
    /// The address of the first instruction.
    pub filter: Vaddr,
}
