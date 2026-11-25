//! Internal representation, bounded collections, and CFG types.
//!
//! Every shipped collection is fixed-capacity and allocation-free. The
//! capacities are part of the fail-closed contract: a function that does not
//! fit is rejected rather than spilled to a heap.

use crate::error::Result;

/// Maximum number of basic blocks in one protected program.
pub const MAX_BLOCKS: usize = 256;
/// Maximum number of IR operations in one protected program.
pub const MAX_IR_OPS: usize = 8192;
/// Maximum number of protected functions sharing one payload.
pub const MAX_FUNCTIONS: usize = 8;
/// Maximum payload size in bytes.
pub const MAX_PAYLOAD: usize = 65_536;
/// Maximum size of one native function in bytes.
pub const MAX_FUNCTION_BYTES: usize = 16_384;
/// Maximum read-only data embedded for one protected program.
pub const MAX_DATA_BYTES: usize = 2_048;
/// Maximum number of stack arguments copied into the private VM stack.
pub const MAX_STACK_ARGS: usize = 6;

/// Operand width in bits.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Width {
    /// Eight bits.
    W8,
    /// Sixteen bits.
    W16,
    /// Thirty-two bits.
    W32,
    /// Sixty-four bits.
    #[default]
    W64,
}

impl Width {
    /// Constructs a width from a byte count.
    #[inline]
    #[must_use]
    pub const fn from_bytes(bytes: u8) -> Option<Self> {
        match bytes {
            1 => Some(Self::W8),
            2 => Some(Self::W16),
            4 => Some(Self::W32),
            8 => Some(Self::W64),
            _ => None,
        }
    }

    /// Returns the width in bytes.
    #[inline]
    #[must_use]
    pub const fn bytes(self) -> u8 {
        match self {
            Self::W8 => 1,
            Self::W16 => 2,
            Self::W32 => 4,
            Self::W64 => 8,
        }
    }

    /// Returns the width in bits.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            Self::W8 => 8,
            Self::W16 => 16,
            Self::W32 => 32,
            Self::W64 => 64,
        }
    }

    /// Returns the low-bit mask for the width.
    #[inline]
    #[must_use]
    pub const fn mask(self) -> u64 {
        match self {
            Self::W8 => 0xff,
            Self::W16 => 0xffff,
            Self::W32 => 0xffff_ffff,
            Self::W64 => u64::MAX,
        }
    }

    /// Returns the index of the sign bit.
    #[inline]
    #[must_use]
    pub const fn sign_bit(self) -> u32 {
        self.bits().saturating_sub(1)
    }
}

/// A fixed-capacity vector with checked operations and no allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedVec<T: Copy + Default, const N: usize> {
    data: [T; N],
    len: usize,
}

impl<T: Copy + Default, const N: usize> BoundedVec<T, N> {
    /// Creates an empty vector.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: [T::default(); N],
            len: 0,
        }
    }

    /// Returns the number of items.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the vector is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns whether the vector is full.
    #[inline]
    #[must_use]
    pub const fn is_full(&self) -> bool {
        self.len >= N
    }

    /// Returns the fixed capacity.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Appends an item.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::CoreError::CapacityExceeded`] when the fixed capacity is full.
    #[inline]
    pub fn push(&mut self, value: T) -> Result<()> {
        if self.len >= N {
            return Err(crate::error::CoreError::CapacityExceeded);
        }
        if let Some(slot) = self.data.get_mut(self.len) {
            *slot = value;
            self.len = self.len.saturating_add(1);
            Ok(())
        } else {
            Err(crate::error::CoreError::CapacityExceeded)
        }
    }

    /// Gets an item by index.
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        if index < self.len {
            self.data.get(index)
        } else {
            None
        }
    }

    /// Gets a mutable item by index.
    #[inline]
    #[must_use]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index < self.len {
            self.data.get_mut(index)
        } else {
            None
        }
    }

    /// Returns the last item.
    #[inline]
    #[must_use]
    pub fn last(&self) -> Option<&T> {
        if self.len == 0 {
            None
        } else {
            self.data.get(self.len.saturating_sub(1))
        }
    }

    /// Removes the last item.
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let index = self.len.saturating_sub(1);
        let value = self.data.get(index).copied();
        if value.is_some() {
            self.len = index;
        }
        value
    }

    /// Clears the vector.
    #[inline]
    pub const fn clear(&mut self) {
        self.len = 0;
    }

    /// Shrinks the initialized prefix.
    #[inline]
    pub const fn truncate(&mut self, length: usize) {
        if length < self.len {
            self.len = length;
        }
    }

    /// Iterates over items.
    #[inline]
    pub const fn iter(&self) -> BoundedIter<'_, T, N> {
        BoundedIter {
            vector: self,
            index: 0,
        }
    }

    /// Returns the initialized contents as a slice.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.data.get(..self.len).unwrap_or(&[])
    }

    /// Returns the initialized contents as a mutable slice.
    #[inline]
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.data.get_mut(..self.len).unwrap_or(&mut [])
    }

    /// Returns whether the vector contains a value.
    #[inline]
    #[must_use]
    pub fn contains(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        let mut index = 0_usize;
        while index < self.len {
            if self.data.get(index) == Some(value) {
                return true;
            }
            index = index.saturating_add(1);
        }
        false
    }

    /// Inserts a value in sorted order using `less`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::CoreError::CapacityExceeded`] when the fixed capacity is full.
    #[inline]
    pub fn insert_sorted_by<F>(&mut self, value: T, less: F) -> Result<()>
    where
        F: Fn(&T, &T) -> bool,
    {
        if self.len >= N {
            return Err(crate::error::CoreError::CapacityExceeded);
        }
        let mut position = self.len;
        while position > 0 {
            let previous = position.saturating_sub(1);
            let Some(existing) = self.data.get(previous) else {
                return Err(crate::error::CoreError::CapacityExceeded);
            };
            if !less(&value, existing) {
                break;
            }
            let copied = *existing;
            if let Some(slot) = self.data.get_mut(position) {
                *slot = copied;
            }
            position = previous;
        }
        if let Some(slot) = self.data.get_mut(position) {
            *slot = value;
            self.len = self.len.saturating_add(1);
            Ok(())
        } else {
            Err(crate::error::CoreError::CapacityExceeded)
        }
    }

    /// Removes adjacent duplicates after the vector has been sorted.
    #[inline]
    pub fn dedup(&mut self)
    where
        T: PartialEq,
    {
        let mut write = 0_usize;
        let mut read = 0_usize;
        while read < self.len {
            let Some(value) = self.data.get(read).copied() else {
                break;
            };
            let duplicate = if write == 0 {
                false
            } else {
                self.data.get(write.saturating_sub(1)) == Some(&value)
            };
            if !duplicate {
                if let Some(slot) = self.data.get_mut(write) {
                    *slot = value;
                }
                write = write.saturating_add(1);
            }
            read = read.saturating_add(1);
        }
        self.len = write;
    }

    /// Sorts the initialized prefix with an insertion sort.
    #[inline]
    pub fn sort_unstable_by<F>(&mut self, less: F)
    where
        F: Fn(&T, &T) -> bool,
    {
        let mut index = 1_usize;
        while index < self.len {
            let mut position = index;
            while position > 0 {
                let previous = position.saturating_sub(1);
                let Some(left) = self.data.get(previous).copied() else {
                    break;
                };
                let Some(right) = self.data.get(position).copied() else {
                    break;
                };
                if !less(&right, &left) {
                    break;
                }
                if let Some(slot) = self.data.get_mut(position) {
                    *slot = left;
                }
                if let Some(slot) = self.data.get_mut(previous) {
                    *slot = right;
                }
                position = previous;
            }
            index = index.saturating_add(1);
        }
    }
}

impl<T: Copy + Default, const N: usize> Default for BoundedVec<T, N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Fixed-capacity byte buffer with checked operations and no allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteBuf<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> ByteBuf<N> {
    /// Creates an empty buffer.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            data: [0_u8; N],
            len: 0,
        }
    }

    /// Returns the number of initialized bytes.
    #[inline]
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the buffer is empty.
    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the fixed capacity.
    #[inline]
    #[must_use]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Appends one byte.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::CoreError::PayloadTooLarge`] when the fixed capacity is full.
    #[inline]
    pub fn push(&mut self, byte: u8) -> Result<()> {
        if self.len >= N {
            return Err(crate::error::CoreError::PayloadTooLarge);
        }
        if let Some(slot) = self.data.get_mut(self.len) {
            *slot = byte;
            self.len = self.len.saturating_add(1);
            Ok(())
        } else {
            Err(crate::error::CoreError::PayloadTooLarge)
        }
    }

    /// Appends a slice.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::CoreError::PayloadTooLarge`] when the fixed capacity is full.
    #[inline]
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> Result<()> {
        for byte in bytes {
            self.push(*byte)?;
        }
        Ok(())
    }

    /// Gets one byte.
    #[inline]
    #[must_use]
    pub fn get(&self, index: usize) -> Option<u8> {
        if index < self.len {
            self.data.get(index).copied()
        } else {
            None
        }
    }

    /// Gets one byte mutably.
    #[inline]
    #[must_use]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut u8> {
        if index < self.len {
            self.data.get_mut(index)
        } else {
            None
        }
    }

    /// Returns the initialized contents.
    #[inline]
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.data.get(..self.len).unwrap_or(&[])
    }

    /// Clears the buffer.
    #[inline]
    pub const fn clear(&mut self) {
        self.len = 0;
    }

    /// Shrinks the buffer.
    #[inline]
    pub const fn truncate(&mut self, length: usize) {
        if length < self.len {
            self.len = length;
        }
    }
}

impl<const N: usize> Default for ByteBuf<N> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Iterator over a bounded vector.
#[derive(Debug)]
pub struct BoundedIter<'a, T: Copy + Default, const N: usize> {
    vector: &'a BoundedVec<T, N>,
    index: usize,
}

impl<'a, T: Copy + Default, const N: usize> IntoIterator for &'a BoundedVec<T, N> {
    type Item = &'a T;
    type IntoIter = BoundedIter<'a, T, N>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T: Copy + Default, const N: usize> Iterator for BoundedIter<'a, T, N> {
    type Item = &'a T;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let value = self.vector.get(self.index);
        if value.is_some() {
            self.index = self.index.saturating_add(1);
        }
        value
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.vector.len().saturating_sub(self.index);
        (remaining, Some(remaining))
    }
}

impl<T: Copy + Default, const N: usize> ExactSizeIterator for BoundedIter<'_, T, N> {}

/// Internal operation. All values are 64-bit bit patterns; signed semantics are
/// explicit in the operation name.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IrOp {
    /// No operation.
    #[default]
    Nop,
    /// Register copy.
    Mov {
        /// Destination.
        dst: u8,
        /// Source.
        src: u8,
    },
    /// Immediate move.
    MovImm {
        /// Destination.
        dst: u8,
        /// Immediate value.
        value: u64,
    },
    /// Addition.
    Add {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        src: u8,
    },
    /// Addition by immediate.
    AddImm {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        value: u64,
    },
    /// Subtraction.
    Sub {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        src: u8,
    },
    /// Subtraction by immediate.
    SubImm {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        value: u64,
    },
    /// Wrapping multiplication.
    Mul {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        src: u8,
    },
    /// Bitwise AND.
    And {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        src: u8,
    },
    /// Bitwise AND with immediate.
    AndImm {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        value: u64,
    },
    /// Bitwise OR.
    Or {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        src: u8,
    },
    /// Bitwise OR with immediate.
    OrImm {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        value: u64,
    },
    /// Bitwise XOR.
    Xor {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        src: u8,
    },
    /// Bitwise XOR with immediate.
    XorImm {
        /// Destination and left operand.
        dst: u8,
        /// Right operand.
        value: u64,
    },
    /// Bitwise NOT.
    Not {
        /// Destination and operand.
        dst: u8,
    },
    /// Two's-complement negation.
    Neg {
        /// Destination and operand.
        dst: u8,
    },
    /// Left shift; shift count is masked to 63.
    Shl {
        /// Destination and value.
        dst: u8,
        /// Shift count register.
        src: u8,
    },
    /// Left shift by immediate.
    ShlImm {
        /// Destination and value.
        dst: u8,
        /// Shift count.
        value: u64,
    },
    /// Logical right shift.
    ShrU {
        /// Destination and value.
        dst: u8,
        /// Shift count register.
        src: u8,
    },
    /// Logical right shift by immediate.
    ShrUImm {
        /// Destination and value.
        dst: u8,
        /// Shift count.
        value: u64,
    },
    /// Arithmetic right shift.
    ShrS {
        /// Destination and value.
        dst: u8,
        /// Shift count register.
        src: u8,
    },
    /// Arithmetic right shift by immediate.
    ShrSImm {
        /// Destination and value.
        dst: u8,
        /// Shift count.
        value: u64,
    },
    /// Rotate left.
    RotL {
        /// Destination and value.
        dst: u8,
        /// Rotate count register.
        src: u8,
    },
    /// Rotate left by immediate.
    RotLImm {
        /// Destination and value.
        dst: u8,
        /// Rotate count.
        value: u64,
    },
    /// Rotate right.
    RotR {
        /// Destination and value.
        dst: u8,
        /// Rotate count register.
        src: u8,
    },
    /// Rotate right by immediate.
    RotRImm {
        /// Destination and value.
        dst: u8,
        /// Rotate count.
        value: u64,
    },
    /// Boolean equality.
    CmpEq {
        /// Destination boolean.
        dst: u8,
        /// Left operand.
        lhs: u8,
        /// Right operand.
        rhs: u8,
    },
    /// Unsigned less-than.
    CmpLtU {
        /// Destination boolean.
        dst: u8,
        /// Left operand.
        lhs: u8,
        /// Right operand.
        rhs: u8,
    },
    /// Signed less-than.
    CmpLtS {
        /// Destination boolean.
        dst: u8,
        /// Left operand.
        lhs: u8,
        /// Right operand.
        rhs: u8,
    },
    /// Unsigned less-than-or-equal.
    CmpLeU {
        /// Destination boolean.
        dst: u8,
        /// Left operand.
        lhs: u8,
        /// Right operand.
        rhs: u8,
    },
    /// Signed less-than-or-equal.
    CmpLeS {
        /// Destination boolean.
        dst: u8,
        /// Left operand.
        lhs: u8,
        /// Right operand.
        rhs: u8,
    },
    /// Branchless selection.
    Select {
        /// Destination.
        dst: u8,
        /// Boolean condition.
        cond: u8,
        /// Value when condition is non-zero.
        when_true: u8,
        /// Value when condition is zero.
        when_false: u8,
    },
    /// Load from private virtual memory.
    Load {
        /// Destination.
        dst: u8,
        /// Address register.
        addr: u8,
        /// Access width.
        width: Width,
    },
    /// Store to private virtual memory.
    Store {
        /// Address register.
        addr: u8,
        /// Value register.
        src: u8,
        /// Access width.
        width: Width,
    },
}

/// Terminator of a basic block.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Terminator {
    /// Unconditional control transfer.
    Jump {
        /// Target block.
        target: u16,
    },
    /// Conditional transfer.
    Branch {
        /// Boolean condition register.
        cond: u8,
        /// Target when non-zero.
        when_true: u16,
        /// Target when zero.
        when_false: u16,
    },
    /// Return the value in the named register.
    Return {
        /// Return value register.
        value: u8,
    },
    /// Direct call to another protected function.
    Call {
        /// Target function index in the protection set.
        target: u16,
        /// Native address of the instruction after the call.
        return_va: u64,
        /// Resolved caller block that starts at `return_va`.
        return_block: u16,
    },
    /// Fail closed.
    #[default]
    Trap,
}

/// A decoded basic block.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Block {
    /// Native start address, used for diagnostics.
    pub start_va: u64,
    /// Index of the first operation.
    pub ops_start: u16,
    /// Number of internal operations.
    pub ops_len: u16,
    /// Control-flow terminator.
    pub terminator: Terminator,
}

/// One lifted native function.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiftedFunction {
    /// Entry block id.
    pub entry_block: u16,
    /// Basic blocks.
    pub blocks: BoundedVec<Block, MAX_BLOCKS>,
    /// Shared operation arena indexed by block ranges.
    pub ops: BoundedVec<IrOp, MAX_IR_OPS>,
    /// Native byte length that was lifted.
    pub byte_len: u64,
    /// Read-only data referenced by RIP-relative operands.
    pub data: ByteBuf<MAX_DATA_BYTES>,
    /// Program-wide base offset of `data` in private VM memory.
    pub data_base: usize,
    /// Number of stack arguments referenced by this function.
    pub stack_args: u8,
}

impl LiftedFunction {
    /// Returns the operations of a block.
    #[inline]
    #[must_use]
    pub fn block_ops(&self, block: &Block) -> Option<&[IrOp]> {
        let start = usize::from(block.ops_start);
        let end = start.checked_add(usize::from(block.ops_len))?;
        if end > self.ops.len() {
            return None;
        }
        self.ops.as_slice().get(start..end)
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedVec, MAX_IR_OPS, Width};
    use crate::error::CoreError;

    #[test]
    fn bounded_vector_never_overflows() {
        let mut vector = BoundedVec::<u32, 2>::new();
        assert!(vector.is_empty());
        assert_eq!(vector.push(1), Ok(()));
        assert_eq!(vector.push(2), Ok(()));
        assert!(vector.is_full());
        assert_eq!(vector.push(3), Err(CoreError::CapacityExceeded));
        assert_eq!(vector.len(), 2);
        assert_eq!(vector.get(0), Some(&1));
        assert_eq!(vector.get(2), None);
    }

    #[test]
    fn sorted_insertion_and_dedup() {
        let mut vector = BoundedVec::<u32, 8>::new();
        assert_eq!(vector.insert_sorted_by(5, u32::lt), Ok(()));
        assert_eq!(vector.insert_sorted_by(1, u32::lt), Ok(()));
        assert_eq!(vector.insert_sorted_by(3, u32::lt), Ok(()));
        assert_eq!(vector.insert_sorted_by(3, u32::lt), Ok(()));
        vector.dedup();
        assert_eq!(vector.as_slice(), &[1, 3, 5]);
    }

    #[test]
    fn width_masks_and_sign_bits_are_exact() {
        assert_eq!(Width::W8.mask(), 0xff);
        assert_eq!(Width::W16.mask(), 0xffff);
        assert_eq!(Width::W32.mask(), 0xffff_ffff);
        assert_eq!(Width::W64.mask(), u64::MAX);
        assert_eq!(Width::W8.sign_bit(), 7);
        assert_eq!(Width::W64.sign_bit(), 63);
        assert_eq!(Width::from_bytes(3), None);
    }

    #[test]
    fn capacity_is_declared() {
        let vector = BoundedVec::<u8, MAX_IR_OPS>::new();
        assert_eq!(vector.capacity(), MAX_IR_OPS);
    }

    #[test]
    fn byte_buffer_is_checked() {
        let mut buffer = super::ByteBuf::<2>::new();
        assert_eq!(buffer.push(1), Ok(()));
        assert_eq!(buffer.push(2), Ok(()));
        assert_eq!(buffer.push(3), Err(CoreError::PayloadTooLarge));
        assert_eq!(buffer.as_slice(), &[1, 2]);
        buffer.truncate(1);
        assert_eq!(buffer.as_slice(), &[1]);
    }
    #[test]
    fn bounded_vector_full_interface() {
        let mut vector = BoundedVec::<u32, 4>::new();
        assert_eq!(vector.capacity(), 4);
        assert!(vector.is_empty());
        assert_eq!(vector.last(), None);
        assert_eq!(vector.pop(), None);
        assert_eq!(vector.push(9), Ok(()));
        assert_eq!(vector.push(2), Ok(()));
        assert_eq!(vector.push(7), Ok(()));
        assert_eq!(vector.last(), Some(&7));
        assert!(vector.contains(&2));
        assert!(!vector.contains(&5));
        *vector.get_mut(0).expect("get_mut") = 1;
        vector.sort_unstable_by(|left, right| left < right);
        assert_eq!(vector.as_slice(), &[1, 2, 7]);
        assert_eq!(vector.iter().count(), 3);
        let mut sum = 0_u32;
        for value in &vector {
            sum += *value;
        }
        assert_eq!(sum, 10);
        assert_eq!(vector.pop(), Some(7));
        vector.truncate(1);
        assert_eq!(vector.as_mut_slice(), &[1]);
        vector.clear();
        assert!(vector.is_empty());
        let default = BoundedVec::<u8, 1>::default();
        assert!(default.is_empty());
    }

    #[test]
    fn byte_buffer_full_interface() {
        let mut buffer = super::ByteBuf::<4>::new();
        assert_eq!(buffer.capacity(), 4);
        assert!(buffer.is_empty());
        assert_eq!(buffer.get(0), None);
        assert_eq!(buffer.push(1), Ok(()));
        assert_eq!(buffer.extend_from_slice(&[2, 3]), Ok(()));
        assert_eq!(buffer.as_slice(), &[1, 2, 3]);
        assert_eq!(buffer.get(1), Some(2));
        *buffer.get_mut(1).expect("get_mut") = 9;
        assert_eq!(buffer.as_slice(), &[1, 9, 3]);
        buffer.truncate(2);
        assert_eq!(buffer.as_slice(), &[1, 9]);
        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(
            buffer.extend_from_slice(&[1, 2, 3, 4, 5]),
            Err(CoreError::PayloadTooLarge)
        );
        let default = super::ByteBuf::<1>::default();
        assert!(default.is_empty());
    }

    #[test]
    fn widths_cover_all_bit_sizes() {
        for (bytes, bits, mask, sign) in [
            (1_u8, 8_u32, 0xff_u64, 7_u32),
            (2, 16, 0xffff, 15),
            (4, 32, 0xffff_ffff, 31),
            (8, 64, u64::MAX, 63),
        ] {
            let width = Width::from_bytes(bytes).expect("width");
            assert_eq!(width.bits(), bits);
            assert_eq!(width.mask(), mask);
            assert_eq!(width.sign_bit(), sign);
            assert_eq!(width.bytes(), bytes);
        }
        assert_eq!(Width::default(), Width::W64);
    }

    #[test]
    fn lifted_block_ops_are_bounded() {
        let function = super::LiftedFunction {
            entry_block: 0,
            blocks: BoundedVec::new(),
            ops: BoundedVec::new(),
            byte_len: 0,
            data: super::ByteBuf::new(),
            data_base: 0,
            stack_args: 0,
        };
        let block = super::Block {
            start_va: 0,
            ops_start: 0,
            ops_len: 0,
            terminator: super::Terminator::Trap,
        };
        assert_eq!(function.block_ops(&block), Some(&[][..]));
        let invalid = super::Block {
            start_va: 0,
            ops_start: 100,
            ops_len: 1,
            terminator: super::Terminator::Trap,
        };
        assert_eq!(function.block_ops(&invalid), None);
    }
}
