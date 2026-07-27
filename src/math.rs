use crate::error::Error;
use crate::uint::U576;

/// `(a + b) mod modulus`; both operands must already be reduced.
pub(crate) fn add_mod(a: &U576, b: &U576, modulus: &U576) -> U576 {
    let mut sum = a.add(b);
    if &sum >= modulus {
        sum = sum.sub(modulus);
    }
    sum
}

/// `(a * b) mod modulus` via double-and-add; both operands must already be
/// reduced.
pub(crate) fn mul_mod(a: &U576, b: &U576, modulus: &U576) -> U576 {
    debug_assert!(a < modulus && b < modulus);

    let mut result = U576::ZERO;
    for i in (0..b.bit_length()).rev() {
        result = result.shl1();
        if &result >= modulus {
            result = result.sub(modulus);
        }
        if b.bit(i) {
            result = result.add(a);
            if &result >= modulus {
                result = result.sub(modulus);
            }
        }
    }
    result
}

/// `base ^ exponent mod modulus` via square-and-multiply.
///
/// The modulus must be non-zero and at most 575 bits.
pub fn mod_pow(base: &U576, exponent: &U576, modulus: &U576) -> U576 {
    assert!(!modulus.is_zero(), "modulus must not be zero");
    if modulus == &U576::ONE {
        return U576::ZERO;
    }

    let base = base.rem(modulus);
    let mut result = U576::ONE;
    for i in (0..exponent.bit_length()).rev() {
        result = mul_mod(&result, &result, modulus);
        if exponent.bit(i) {
            result = mul_mod(&result, &base, modulus);
        }
    }
    result
}

/// Finds a square root of `n` modulo `p`.
///
/// `p` must be an odd prime congruent to 3 (mod 4) — which holds for the
/// primes of all supported curves — so the only possible root is
/// `n^((p + 1) / 4)`, and squaring the candidate suffices to verify it.
pub fn mod_sqrt(n: &U576, p: &U576) -> Result<U576, Error> {
    let n = n.rem(p);
    let candidate = mod_pow(&n, &p.add(&U576::ONE).shr1().shr1(), p);
    if mul_mod(&candidate, &candidate, p) == n {
        Ok(candidate)
    } else {
        Err(Error::NoSquareRoot)
    }
}
