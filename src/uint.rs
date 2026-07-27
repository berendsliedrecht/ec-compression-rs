use core::cmp::Ordering;

use crate::bytes::KeyBytes;
use crate::error::Error;

const LIMBS: usize = 9;

/// Fixed-width 576-bit unsigned integer.
///
/// Wide enough to hold a P-521 field element with headroom for the
/// intermediate values of the modular arithmetic used by this crate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct U576 {
    /// Little-endian limb order.
    limbs: [u64; LIMBS],
}

impl U576 {
    pub const ZERO: Self = Self::from_u64(0);
    pub const ONE: Self = Self::from_u64(1);

    /// Maximum number of bytes in the big-endian encoding.
    pub const MAX_BYTES: usize = LIMBS * 8;

    pub const fn from_u64(value: u64) -> Self {
        let mut limbs = [0u64; LIMBS];
        limbs[0] = value;
        Self { limbs }
    }

    /// Parses a big-endian hex string.
    ///
    /// Intended for compile-time constants; panics on invalid characters or
    /// when the value does not fit in 576 bits.
    pub const fn from_be_hex(hex: &str) -> Self {
        let bytes = hex.as_bytes();
        assert!(
            bytes.len() <= LIMBS * 16,
            "hex value does not fit in 576 bits"
        );

        let mut limbs = [0u64; LIMBS];
        let mut i = 0;
        while i < bytes.len() {
            let character = bytes[bytes.len() - 1 - i];
            let value = match character {
                b'0'..=b'9' => character - b'0',
                b'a'..=b'f' => character - b'a' + 10,
                b'A'..=b'F' => character - b'A' + 10,
                _ => panic!("invalid hex character"),
            };
            limbs[i / 16] |= (value as u64) << ((i % 16) * 4);
            i += 1;
        }

        Self { limbs }
    }

    /// Parses big-endian bytes, ignoring leading zeroes.
    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyBytes);
        }

        let significant = match bytes.iter().position(|&byte| byte != 0) {
            Some(index) => &bytes[index..],
            None => return Ok(Self::ZERO),
        };
        if significant.len() > Self::MAX_BYTES {
            return Err(Error::ValueTooLarge);
        }

        let mut limbs = [0u64; LIMBS];
        for (i, &byte) in significant.iter().rev().enumerate() {
            limbs[i / 8] |= (byte as u64) << ((i % 8) * 8);
        }

        Ok(Self { limbs })
    }

    /// Minimal big-endian encoding: no leading zeroes, at least one byte.
    pub fn to_be_bytes(&self) -> KeyBytes {
        self.to_be_bytes_padded(usize::max(1, self.bit_length().div_ceil(8)))
    }

    /// Big-endian encoding zero-padded to exactly `width` bytes; the value
    /// must fit in `width` bytes and `width` must be at most [`Self::MAX_BYTES`].
    pub fn to_be_bytes_padded(&self, width: usize) -> KeyBytes {
        debug_assert!(width <= Self::MAX_BYTES);
        debug_assert!(self.bit_length().div_ceil(8) <= width);
        let mut buffer = [0u8; Self::MAX_BYTES];
        for i in 0..width {
            buffer[width - 1 - i] = (self.limbs[i / 8] >> ((i % 8) * 8)) as u8;
        }
        KeyBytes::from_slice(&buffer[..width])
    }

    pub fn bit_length(&self) -> usize {
        for i in (0..LIMBS).rev() {
            if self.limbs[i] != 0 {
                return i * 64 + (64 - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    pub fn bit(&self, index: usize) -> bool {
        debug_assert!(index < LIMBS * 64);
        (self.limbs[index / 64] >> (index % 64)) & 1 == 1
    }

    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    pub fn is_even(&self) -> bool {
        self.limbs[0] & 1 == 0
    }

    /// Addition; the sum must fit in 576 bits.
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        let mut limbs = [0u64; LIMBS];
        let mut carry = 0u128;
        for (limb, (&a, &b)) in limbs.iter_mut().zip(self.limbs.iter().zip(&rhs.limbs)) {
            let sum = a as u128 + b as u128 + carry;
            *limb = sum as u64;
            carry = sum >> 64;
        }
        debug_assert_eq!(carry, 0, "U576 addition overflow");
        Self { limbs }
    }

    /// Subtraction; `self` must be greater than or equal to `rhs`.
    pub(crate) fn sub(&self, rhs: &Self) -> Self {
        let mut limbs = [0u64; LIMBS];
        let mut borrow = false;
        for (limb, (&a, &b)) in limbs.iter_mut().zip(self.limbs.iter().zip(&rhs.limbs)) {
            let (difference, underflow_a) = a.overflowing_sub(b);
            let (difference, underflow_b) = difference.overflowing_sub(borrow as u64);
            *limb = difference;
            borrow = underflow_a | underflow_b;
        }
        debug_assert!(!borrow, "U576 subtraction underflow");
        Self { limbs }
    }

    /// Doubling; the result must fit in 576 bits.
    pub(crate) fn shl1(&self) -> Self {
        let mut limbs = [0u64; LIMBS];
        let mut carry = 0u64;
        for (limb, &value) in limbs.iter_mut().zip(&self.limbs) {
            *limb = (value << 1) | carry;
            carry = value >> 63;
        }
        debug_assert_eq!(carry, 0, "U576 shift overflow");
        Self { limbs }
    }

    pub(crate) fn shr1(&self) -> Self {
        let mut limbs = [0u64; LIMBS];
        let mut carry = 0u64;
        for (limb, &value) in limbs.iter_mut().zip(&self.limbs).rev() {
            *limb = (value >> 1) | (carry << 63);
            carry = value & 1;
        }
        Self { limbs }
    }

    /// `self mod modulus` via binary long division; `modulus` must be at most
    /// 575 bits so intermediate values cannot overflow.
    pub(crate) fn rem(&self, modulus: &Self) -> Self {
        debug_assert!(!modulus.is_zero(), "modulus must not be zero");
        debug_assert!(modulus.bit_length() < LIMBS * 64);

        if self < modulus {
            return *self;
        }

        let mut remainder = Self::ZERO;
        for i in (0..self.bit_length()).rev() {
            remainder = remainder.shl1();
            if self.bit(i) {
                remainder.limbs[0] |= 1;
            }
            if &remainder >= modulus {
                remainder = remainder.sub(modulus);
            }
        }
        remainder
    }
}

impl Ord for U576 {
    fn cmp(&self, other: &Self) -> Ordering {
        for i in (0..LIMBS).rev() {
            match self.limbs[i].cmp(&other.limbs[i]) {
                Ordering::Equal => continue,
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U576 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
