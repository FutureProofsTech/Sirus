//! Bounded Mixed Boolean-Arithmetic expression expansion.
//!
//! Every rewrite is an exact modular identity over 64-bit wrapping arithmetic.
//! The expander is budgeted: it can return the original subtree when the node
//! budget is exhausted, so it always terminates and never silently changes
//! semantics.

use crate::error::{CoreError, Result};
use crate::shared::chacha::ChaCha20;
use crate::shared::derive::Seed;

/// Maximum expression nodes in one statement.
pub const MAX_EXPR_NODES: usize = 4096;

/// Deterministic build RNG derived from the plan seed.
#[derive(Clone, Debug)]
pub(crate) struct BuildRng {
    stream: ChaCha20,
}

impl BuildRng {
    #[inline]
    pub(crate) fn new(seed: &Seed, domain: u64) -> Self {
        let mut nonce = [0_u8; 12];
        let bytes = domain.to_le_bytes();
        let mut index = 0_usize;
        while index < 8 {
            if let (Some(slot), Some(byte)) = (nonce.get_mut(index), bytes.get(index)) {
                *slot = *byte;
            }
            index = index.saturating_add(1);
        }
        Self {
            stream: ChaCha20::new(*seed, nonce),
        }
    }

    #[inline]
    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.stream.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    #[inline]
    pub(crate) fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        let modulus = u64::try_from(bound).unwrap_or(u64::MAX);
        usize::try_from(self.next_u64() % modulus).unwrap_or(0)
    }
}

/// Expression operation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ExprOp {
    /// Register leaf.
    Reg,
    /// Constant leaf.
    #[default]
    Const,
    /// Wrapping addition.
    Add,
    /// Wrapping subtraction.
    Sub,
    /// Wrapping multiplication.
    Mul,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Bitwise NOT.
    Not,
    /// Wrapping negation.
    Neg,
    /// Left shift.
    Shl,
    /// Logical right shift.
    ShrU,
    /// Arithmetic right shift.
    ShrS,
    /// Rotate left.
    RotL,
    /// Rotate right.
    RotR,
    /// Boolean equality.
    CmpEq,
    /// Unsigned less-than.
    CmpLtU,
    /// Signed less-than.
    CmpLtS,
    /// Unsigned less-than-or-equal.
    CmpLeU,
    /// Signed less-than-or-equal.
    CmpLeS,
    /// Ternary select.
    Select,
}

/// Expression node. `a` and `b` are operands; `c` is the false/third operand for
/// ternary operations. `imm` stores register ids or constant values for leaves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExprNode {
    pub(crate) op: ExprOp,
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
    pub(crate) imm: u64,
}

/// Fixed expression arena.
#[derive(Clone, Debug)]
pub(crate) struct ExprArena {
    nodes: [ExprNode; MAX_EXPR_NODES],
    len: usize,
}

impl ExprArena {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            nodes: [ExprNode::default(); MAX_EXPR_NODES],
            len: 0,
        }
    }

    #[inline]
    pub(crate) const fn reset(&mut self) {
        self.len = 0;
    }

    #[inline]
    pub(crate) fn node(&self, id: u32) -> Option<ExprNode> {
        self.nodes
            .get(usize::try_from(id).ok()?)
            .copied()
            .filter(|_| usize::try_from(id).unwrap_or(usize::MAX) < self.len)
    }

    #[inline]
    pub(crate) fn push(&mut self, node: ExprNode) -> Option<u32> {
        if self.len >= MAX_EXPR_NODES {
            return None;
        }
        let id = u32::try_from(self.len).ok()?;
        if let Some(slot) = self.nodes.get_mut(self.len) {
            *slot = node;
            self.len = self.len.saturating_add(1);
            Some(id)
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn reg(&mut self, register: u8) -> Result<u32> {
        self.push(ExprNode {
            op: ExprOp::Reg,
            a: 0,
            b: 0,
            c: 0,
            imm: u64::from(register),
        })
        .ok_or(CoreError::CapacityExceeded)
    }

    #[inline]
    pub(crate) fn constant(&mut self, value: u64) -> Result<u32> {
        self.push(ExprNode {
            op: ExprOp::Const,
            a: 0,
            b: 0,
            c: 0,
            imm: value,
        })
        .ok_or(CoreError::CapacityExceeded)
    }

    #[inline]
    pub(crate) fn unary(&mut self, op: ExprOp, a: u32) -> Result<u32> {
        self.push(ExprNode {
            op,
            a,
            b: 0,
            c: 0,
            imm: 0,
        })
        .ok_or(CoreError::CapacityExceeded)
    }

    #[inline]
    pub(crate) fn binary(&mut self, op: ExprOp, a: u32, b: u32) -> Result<u32> {
        self.push(ExprNode {
            op,
            a,
            b,
            c: 0,
            imm: 0,
        })
        .ok_or(CoreError::CapacityExceeded)
    }

    #[inline]
    pub(crate) fn ternary(&mut self, op: ExprOp, a: u32, b: u32, c: u32) -> Result<u32> {
        self.push(ExprNode {
            op,
            a,
            b,
            c,
            imm: 0,
        })
        .ok_or(CoreError::CapacityExceeded)
    }
}

impl Default for ExprArena {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

struct Expander<'a> {
    arena: &'a mut ExprArena,
    rng: &'a mut BuildRng,
    remaining: u16,
}

impl Expander<'_> {
    #[inline]
    fn push(&mut self, node: ExprNode) -> Option<u32> {
        if self.remaining == 0 {
            return None;
        }
        let id = self.arena.push(node);
        if id.is_some() {
            self.remaining = self.remaining.saturating_sub(1);
        }
        id
    }

    #[inline]
    fn constant(&mut self, value: u64) -> Option<u32> {
        self.push(ExprNode {
            op: ExprOp::Const,
            a: 0,
            b: 0,
            c: 0,
            imm: value,
        })
    }

    fn expand(&mut self, id: u32, depth: u8) -> u32 {
        let Some(node) = self.arena.node(id) else {
            return id;
        };
        if depth == 0 || self.remaining == 0 {
            return id;
        }
        if matches!(node.op, ExprOp::Reg | ExprOp::Const) {
            return id;
        }
        let a = self.expand(node.a, depth.saturating_sub(1));
        let b = if matches!(
            node.op,
            ExprOp::Mul
                | ExprOp::And
                | ExprOp::Or
                | ExprOp::Xor
                | ExprOp::Shl
                | ExprOp::ShrU
                | ExprOp::ShrS
                | ExprOp::RotL
                | ExprOp::RotR
                | ExprOp::CmpEq
                | ExprOp::CmpLtU
                | ExprOp::CmpLtS
                | ExprOp::CmpLeU
                | ExprOp::CmpLeS
                | ExprOp::Select
        ) {
            self.expand(node.b, depth.saturating_sub(1))
        } else {
            node.b
        };
        let c = if matches!(node.op, ExprOp::Select) {
            self.expand(node.c, depth.saturating_sub(1))
        } else {
            node.c
        };
        let base = if a == node.a && b == node.b && c == node.c {
            id
        } else {
            match self.push(ExprNode {
                op: node.op,
                a,
                b,
                c,
                imm: node.imm,
            }) {
                Some(new_id) => new_id,
                None => return id,
            }
        };
        if self.rng.below(100) >= 99 {
            return base;
        }
        let Some(rewritten) = self.rewrite(node.op, a, b) else {
            return base;
        };
        self.expand(rewritten, depth.saturating_sub(1))
    }

    fn rewrite(&mut self, op: ExprOp, a: u32, b: u32) -> Option<u32> {
        match op {
            ExprOp::Add => {
                let xor = self.push(ExprNode {
                    op: ExprOp::Xor,
                    a,
                    b,
                    c: 0,
                    imm: 0,
                })?;
                let and = self.push(ExprNode {
                    op: ExprOp::And,
                    a,
                    b,
                    c: 0,
                    imm: 0,
                })?;
                let one = self.constant(1)?;
                let shifted = self.push(ExprNode {
                    op: ExprOp::Shl,
                    a: and,
                    b: one,
                    c: 0,
                    imm: 0,
                })?;
                self.push(ExprNode {
                    op: ExprOp::Add,
                    a: xor,
                    b: shifted,
                    c: 0,
                    imm: 0,
                })
            }
            ExprOp::Sub => {
                let not_b = self.push(ExprNode {
                    op: ExprOp::Not,
                    a: b,
                    b: 0,
                    c: 0,
                    imm: 0,
                })?;
                let partial = self.push(ExprNode {
                    op: ExprOp::Add,
                    a,
                    b: not_b,
                    c: 0,
                    imm: 0,
                })?;
                let one = self.constant(1)?;
                self.push(ExprNode {
                    op: ExprOp::Add,
                    a: partial,
                    b: one,
                    c: 0,
                    imm: 0,
                })
            }
            ExprOp::Xor => {
                let or = self.push(ExprNode {
                    op: ExprOp::Or,
                    a,
                    b,
                    c: 0,
                    imm: 0,
                })?;
                let and = self.push(ExprNode {
                    op: ExprOp::And,
                    a,
                    b,
                    c: 0,
                    imm: 0,
                })?;
                self.push(ExprNode {
                    op: ExprOp::Sub,
                    a: or,
                    b: and,
                    c: 0,
                    imm: 0,
                })
            }
            ExprOp::And => {
                let or = self.push(ExprNode {
                    op: ExprOp::Or,
                    a,
                    b,
                    c: 0,
                    imm: 0,
                })?;
                let xor = self.push(ExprNode {
                    op: ExprOp::Xor,
                    a,
                    b,
                    c: 0,
                    imm: 0,
                })?;
                self.push(ExprNode {
                    op: ExprOp::Sub,
                    a: or,
                    b: xor,
                    c: 0,
                    imm: 0,
                })
            }
            ExprOp::Or => {
                let xor = self.push(ExprNode {
                    op: ExprOp::Xor,
                    a,
                    b,
                    c: 0,
                    imm: 0,
                })?;
                let and = self.push(ExprNode {
                    op: ExprOp::And,
                    a,
                    b,
                    c: 0,
                    imm: 0,
                })?;
                self.push(ExprNode {
                    op: ExprOp::Add,
                    a: xor,
                    b: and,
                    c: 0,
                    imm: 0,
                })
            }
            ExprOp::Not => {
                let all_ones = self.constant(u64::MAX)?;
                self.push(ExprNode {
                    op: ExprOp::Xor,
                    a,
                    b: all_ones,
                    c: 0,
                    imm: 0,
                })
            }
            _ => None,
        }
    }
}

/// Expands an expression tree with bounded randomized MBA rewrites.
#[inline]
pub(crate) fn expand(
    arena: &mut ExprArena,
    root: u32,
    rng: &mut BuildRng,
    depth: u8,
    budget: u16,
) -> u32 {
    if budget == 0 || depth == 0 || arena.node(root).is_none() {
        return root;
    }
    let mut expander = Expander {
        arena,
        rng,
        remaining: budget,
    };
    expander.expand(root, depth)
}

/// Multiplies a value by a data-dependent odd number and by that number's
/// modular inverse. The inverse is computed with six wrapping Newton steps,
/// which is exact for every 64-bit odd input.
pub(crate) fn inverse_wrap(
    arena: &mut ExprArena,
    value: u32,
    anchor: u8,
    _rng: &mut BuildRng,
) -> u32 {
    let Ok(anchor_leaf) = arena.reg(anchor) else {
        return value;
    };
    let Ok(one) = arena.constant(1) else {
        return value;
    };
    let Ok(two) = arena.constant(2) else {
        return value;
    };
    let Ok(odd) = arena.binary(ExprOp::Or, anchor_leaf, one) else {
        return value;
    };

    // Modular inverse of an odd operand. Six Newton steps give at least 192
    // correct low bits starting from the three bits supplied by odd * odd.
    let mut inverse = odd;
    let mut step = 0_u8;
    while step < 6 {
        let Ok(product) = arena.binary(ExprOp::Mul, odd, inverse) else {
            return value;
        };
        let Ok(correction) = arena.binary(ExprOp::Sub, two, product) else {
            return value;
        };
        let Ok(next) = arena.binary(ExprOp::Mul, inverse, correction) else {
            return value;
        };
        inverse = next;
        step = step.saturating_add(1);
    }

    let Ok(scaled) = arena.binary(ExprOp::Mul, value, odd) else {
        return value;
    };
    arena.binary(ExprOp::Mul, scaled, inverse).unwrap_or(value)
}

/// Wraps a value in exact non-linear identities.
///
/// The first identity recombines the low and high parts of the value with a
/// variable shift. The second multiplies the value by a data-dependent odd
/// number and by that number's modular inverse. Both transformations are exact
/// for every 64-bit input, but they are not linear MBA forms: a simplifier must
/// reason about variable shifts and modular multiplication rather than only
/// bitwise-linear algebra.
pub(crate) fn nonlinear_wrap(
    arena: &mut ExprArena,
    value: u32,
    anchor: u8,
    rng: &mut BuildRng,
) -> u32 {
    let Ok(anchor_leaf) = arena.reg(anchor) else {
        return value;
    };
    let Ok(one) = arena.constant(1) else {
        return value;
    };

    // Variable-shift split: x == ((x >> s) << s) | (x & ((1 << s) - 1)).
    let shift_source = match rng.below(2) {
        0 => anchor_leaf,
        _ => value,
    };
    let Ok(sixty_three) = arena.constant(63) else {
        return value;
    };
    let Ok(shift) = arena.binary(ExprOp::And, shift_source, sixty_three) else {
        return value;
    };
    let Ok(shifted_one) = arena.binary(ExprOp::Shl, one, shift) else {
        return value;
    };
    let Ok(mask) = arena.binary(ExprOp::Sub, shifted_one, one) else {
        return value;
    };
    let Ok(low) = arena.binary(ExprOp::And, value, mask) else {
        return value;
    };
    let Ok(high_shifted) = arena.binary(ExprOp::ShrU, value, shift) else {
        return value;
    };
    let Ok(high) = arena.binary(ExprOp::Shl, high_shifted, shift) else {
        return value;
    };
    let Ok(split) = arena.binary(ExprOp::Or, low, high) else {
        return value;
    };
    inverse_wrap(arena, split, anchor, rng)
}

#[cfg(test)]
mod tests {
    use super::{BuildRng, ExprArena, ExprOp, expand, inverse_wrap, nonlinear_wrap};
    use crate::shared::derive::Seed;
    use std::io::Write as _;

    fn evaluate(arena: &ExprArena, id: u32, registers: &[u64; 64]) -> u64 {
        let Some(node) = arena.node(id) else {
            return 0;
        };
        match node.op {
            ExprOp::Reg => registers
                .get(usize::try_from(node.imm).unwrap_or(usize::MAX))
                .copied()
                .unwrap_or(0),
            ExprOp::Const => node.imm,
            ExprOp::Add => {
                evaluate(arena, node.a, registers).wrapping_add(evaluate(arena, node.b, registers))
            }
            ExprOp::Sub => {
                evaluate(arena, node.a, registers).wrapping_sub(evaluate(arena, node.b, registers))
            }
            ExprOp::Mul => {
                evaluate(arena, node.a, registers).wrapping_mul(evaluate(arena, node.b, registers))
            }
            ExprOp::And => evaluate(arena, node.a, registers) & evaluate(arena, node.b, registers),
            ExprOp::Or => evaluate(arena, node.a, registers) | evaluate(arena, node.b, registers),
            ExprOp::Xor => evaluate(arena, node.a, registers) ^ evaluate(arena, node.b, registers),
            ExprOp::Not => !evaluate(arena, node.a, registers),
            ExprOp::Neg => evaluate(arena, node.a, registers).wrapping_neg(),
            ExprOp::Shl => evaluate(arena, node.a, registers)
                .wrapping_shl(u32::try_from(evaluate(arena, node.b, registers) & 63).unwrap_or(0)),
            ExprOp::ShrU => evaluate(arena, node.a, registers)
                .wrapping_shr(u32::try_from(evaluate(arena, node.b, registers) & 63).unwrap_or(0)),
            ExprOp::ShrS => {
                let value = i64::from_ne_bytes(evaluate(arena, node.a, registers).to_ne_bytes());
                let shift = u32::try_from(evaluate(arena, node.b, registers) & 63).unwrap_or(0);
                u64::from_ne_bytes(value.wrapping_shr(shift).to_ne_bytes())
            }
            ExprOp::RotL => evaluate(arena, node.a, registers)
                .rotate_left(u32::try_from(evaluate(arena, node.b, registers) & 63).unwrap_or(0)),
            ExprOp::RotR => evaluate(arena, node.a, registers)
                .rotate_right(u32::try_from(evaluate(arena, node.b, registers) & 63).unwrap_or(0)),
            ExprOp::CmpEq => {
                u64::from(evaluate(arena, node.a, registers) == evaluate(arena, node.b, registers))
            }
            ExprOp::CmpLtU => {
                u64::from(evaluate(arena, node.a, registers) < evaluate(arena, node.b, registers))
            }
            ExprOp::CmpLtS => u64::from(
                i64::from_ne_bytes(evaluate(arena, node.a, registers).to_ne_bytes())
                    < i64::from_ne_bytes(evaluate(arena, node.b, registers).to_ne_bytes()),
            ),
            ExprOp::CmpLeU => {
                u64::from(evaluate(arena, node.a, registers) <= evaluate(arena, node.b, registers))
            }
            ExprOp::CmpLeS => u64::from(
                i64::from_ne_bytes(evaluate(arena, node.a, registers).to_ne_bytes())
                    <= i64::from_ne_bytes(evaluate(arena, node.b, registers).to_ne_bytes()),
            ),
            ExprOp::Select => {
                if evaluate(arena, node.a, registers) != 0 {
                    evaluate(arena, node.b, registers)
                } else {
                    evaluate(arena, node.c, registers)
                }
            }
        }
    }

    fn check(op: ExprOp) {
        let seed = [0x42_u8; 32];
        let mut rng = BuildRng::new(&seed, 0x1234);
        let mut arena = ExprArena::new();
        let left = arena.reg(1).expect("left");
        let right = arena.reg(2).expect("right");
        let root = match op {
            ExprOp::Not | ExprOp::Neg => arena.unary(op, left).expect("unary"),
            _ => arena.binary(op, left, right).expect("binary"),
        };
        let expanded = expand(&mut arena, root, &mut rng, 3, 512);
        let mut registers = [0_u64; 64];
        let values = [
            0,
            1,
            2,
            7,
            63,
            64,
            u64::MAX,
            u64::MAX - 1,
            0x8000_0000_0000_0000,
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
        ];
        for first in values {
            for second in values {
                if let Some(slot) = registers.get_mut(1) {
                    *slot = first;
                }
                if let Some(slot) = registers.get_mut(2) {
                    *slot = second;
                }
                let original = evaluate(&arena, root, &registers);
                let rewritten = evaluate(&arena, expanded, &registers);
                assert_eq!(original, rewritten, "op {op:?} {first:#x} {second:#x}");
            }
        }
    }

    #[test]
    fn every_rewrite_preserves_semantics() {
        for op in [
            ExprOp::Add,
            ExprOp::Sub,
            ExprOp::And,
            ExprOp::Or,
            ExprOp::Xor,
            ExprOp::Not,
            ExprOp::Neg,
        ] {
            check(op);
        }
    }

    #[test]
    fn nonlinear_wrap_preserves_semantics_and_uses_hard_operations() {
        let seed = [0x5a_u8; 32];
        let mut rng = BuildRng::new(&seed, 0x4e4f_4e4c);
        let mut arena = ExprArena::new();
        let left = arena.reg(1).expect("left");
        let right = arena.reg(2).expect("right");
        let root = arena.binary(ExprOp::Add, left, right).expect("root");
        let expanded = expand(&mut arena, root, &mut rng, 3, 512);
        let wrapped = nonlinear_wrap(&mut arena, expanded, 3, &mut rng);
        let mut registers = [0_u64; 64];
        let values = [
            0,
            1,
            2,
            7,
            63,
            64,
            0x8000_0000_0000_0000,
            u64::MAX,
            0x5555_5555_5555_5555,
            0xaaaa_aaaa_aaaa_aaaa,
        ];
        let mut saw_mul = false;
        let mut saw_shift = false;
        let mut index = 0_u32;
        while let Some(node) = arena.node(index) {
            saw_mul |= node.op == ExprOp::Mul;
            saw_shift |= matches!(node.op, ExprOp::Shl | ExprOp::ShrU);
            index = index.saturating_add(1);
        }
        assert!(saw_mul && saw_shift);
        let mut random = 0x1234_5678_9abc_def0_u64;
        let mut check = |first: u64, second: u64| {
            if let Some(slot) = registers.get_mut(1) {
                *slot = first;
            }
            if let Some(slot) = registers.get_mut(2) {
                *slot = second;
            }
            if let Some(slot) = registers.get_mut(3) {
                *slot = first.rotate_left(17) ^ second;
            }
            assert_eq!(
                evaluate(&arena, expanded, &registers),
                evaluate(&arena, wrapped, &registers)
            );
        };
        for first in values {
            for second in values {
                check(first, second);
            }
        }
        let random_samples = if cfg!(miri) { 100 } else { 10_000 };
        let mut sample = 0_usize;
        while sample < random_samples {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let first = random;
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            check(first, random);
            sample = sample.saturating_add(1);
        }
    }

    #[test]
    fn zero_budget_returns_original() {
        let seed: Seed = [7_u8; 32];
        let mut rng = BuildRng::new(&seed, 1);
        let mut arena = ExprArena::new();
        let left = arena.reg(1).expect("left");
        let right = arena.reg(2).expect("right");
        let root = arena.binary(ExprOp::Add, left, right).expect("root");
        assert_eq!(expand(&mut arena, root, &mut rng, 4, 0), root);
        assert_eq!(expand(&mut arena, root, &mut rng, 0, 100), root);
    }

    #[test]
    fn expansion_is_deterministic_for_a_seed() {
        let seed: Seed = [9_u8; 32];
        let mut first_rng = BuildRng::new(&seed, 3);
        let mut second_rng = BuildRng::new(&seed, 3);
        let mut first = ExprArena::new();
        let mut second = ExprArena::new();
        let a = first.reg(1).expect("a");
        let b = first.reg(2).expect("b");
        let root = first.binary(ExprOp::Xor, a, b).expect("root");
        let a = second.reg(1).expect("a");
        let b = second.reg(2).expect("b");
        let second_root = second.binary(ExprOp::Xor, a, b).expect("root");
        let first_expanded = expand(&mut first, root, &mut first_rng, 2, 64);
        let second_expanded = expand(&mut second, second_root, &mut second_rng, 2, 64);
        assert_eq!(first_expanded, second_expanded);
    }

    fn render_expression<W: std::io::Write>(
        arena: &ExprArena,
        id: u32,
        out: &mut W,
    ) -> std::io::Result<()> {
        let Some(node) = arena.node(id) else {
            return write!(out, "0");
        };
        match node.op {
            ExprOp::Reg => {
                let symbol = match node.imm {
                    1 => "x",
                    2 => "y",
                    other => {
                        return write!(out, "r{other}");
                    }
                };
                write!(out, "{symbol}")
            }
            ExprOp::Const => write!(out, "{}", node.imm),
            ExprOp::Not => {
                write!(out, "(~")?;
                render_expression(arena, node.a, out)?;
                write!(out, ")")
            }
            ExprOp::Neg => {
                write!(out, "(-")?;
                render_expression(arena, node.a, out)?;
                write!(out, ")")
            }
            ExprOp::Select => {
                write!(out, "(")?;
                render_expression(arena, node.a, out)?;
                write!(out, " ? ")?;
                render_expression(arena, node.b, out)?;
                write!(out, " : ")?;
                render_expression(arena, node.c, out)?;
                write!(out, ")")
            }
            operation => {
                let symbol = match operation {
                    ExprOp::Add => "+",
                    ExprOp::Sub => "-",
                    ExprOp::Mul => "*",
                    ExprOp::And => "&",
                    ExprOp::Or => "|",
                    ExprOp::Xor => "^",
                    ExprOp::Shl => "<<",
                    ExprOp::ShrU | ExprOp::ShrS => ">>",
                    ExprOp::RotL => "<<<",
                    ExprOp::RotR => ">>>",
                    ExprOp::CmpEq => "==",
                    ExprOp::CmpLtU | ExprOp::CmpLtS => "<",
                    ExprOp::CmpLeU | ExprOp::CmpLeS => "<=",
                    ExprOp::Reg | ExprOp::Const | ExprOp::Not | ExprOp::Neg | ExprOp::Select => {
                        return write!(out, "0");
                    }
                };
                write!(out, "(")?;
                render_expression(arena, node.a, out)?;
                write!(out, " {symbol} ")?;
                render_expression(arena, node.b, out)?;
                write!(out, ")")
            }
        }
    }

    /// Writes the exact post-MBA expressions consumed by the external
    /// de-obfuscator corpus. This test only runs when the path is requested.
    #[test]
    #[ignore = "writes a corpus only when SIRUS_MBA_CORPUS is set"]
    fn mba_audit_corpus() {
        let Ok(path) = std::env::var("SIRUS_MBA_CORPUS") else {
            return;
        };
        let file = std::fs::File::create(path).expect("corpus file");
        let mut out = std::io::BufWriter::new(file);
        let operations = [
            (ExprOp::Add, "x + y"),
            (ExprOp::Sub, "x - y"),
            (ExprOp::And, "x & y"),
            (ExprOp::Or, "x | y"),
            (ExprOp::Xor, "x ^ y"),
            (ExprOp::Not, "~x"),
        ];
        for (depth, seed_byte, budget) in [(1_u8, 0x11_u8, 64_u16), (2, 0x22, 128), (3, 0x33, 512)]
        {
            let seed = [seed_byte; 32];
            for (operation_index, (operation, ground_truth)) in operations.into_iter().enumerate() {
                let operation_domain = 0x4d42_415f
                    + u64::from(depth)
                    + (u64::try_from(operation_index).unwrap_or(0) << 16);
                let mut rng = BuildRng::new(&seed, operation_domain);
                let mut arena = ExprArena::new();
                let left = arena.reg(1).expect("left");
                let right = arena.reg(2).expect("right");
                let root = if operation == ExprOp::Not {
                    arena.unary(operation, left).expect("root")
                } else {
                    arena.binary(operation, left, right).expect("root")
                };
                let expanded = expand(&mut arena, root, &mut rng, depth, budget);
                writeln!(out, "# mode=linear depth={depth} op={operation:?}").expect("header");
                render_expression(&arena, expanded, &mut out).expect("expression");
                writeln!(out, "\t{ground_truth}").expect("ground truth");
                if depth == 3 {
                    let wrapped = nonlinear_wrap(&mut arena, expanded, 1, &mut rng);
                    writeln!(out, "# mode=nonlinear depth={depth} op={operation:?}")
                        .expect("header");
                    render_expression(&arena, wrapped, &mut out).expect("expression");
                    writeln!(out, "\t{ground_truth}").expect("ground truth");
                    let inverse = inverse_wrap(&mut arena, expanded, 1, &mut rng);
                    writeln!(out, "# mode=inverse depth={depth} op={operation:?}").expect("header");
                    render_expression(&arena, inverse, &mut out).expect("expression");
                    writeln!(out, "\t{ground_truth}").expect("ground truth");
                }
            }
        }
    }
}
