use crate::uint::U576;

/// Short-Weierstrass curve parameters: `y^2 = x^3 + ax + b (mod p)`.
///
/// Only the provided constants can be constructed; all of their primes are
/// congruent to 3 (mod 4), which [`crate::mod_sqrt`] relies on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurveParams {
    pub(crate) p: U576,
    pub(crate) a: U576,
    pub(crate) b: U576,
    pub(crate) point_bit_length: usize,
    pub(crate) names: &'static [&'static str],
}

impl CurveParams {
    /// Smallest number of bytes a coordinate can be encoded in.
    pub(crate) fn coordinate_bytes_floor(&self) -> usize {
        self.point_bit_length / 8
    }

    /// Number of bytes needed to encode a full-width coordinate.
    pub(crate) fn coordinate_bytes_ceil(&self) -> usize {
        self.point_bit_length.div_ceil(8)
    }
}

pub const SECP256R1: CurveParams = CurveParams {
    p: U576::from_be_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
    a: U576::from_be_hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
    b: U576::from_be_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
    point_bit_length: 256,
    names: &["secp256r1", "p256", "p-256"],
};

pub const SECP384R1: CurveParams = CurveParams {
    p: U576::from_be_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    ),
    a: U576::from_be_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
    ),
    b: U576::from_be_hex(
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    ),
    point_bit_length: 384,
    names: &["secp384r1", "p384", "p-384"],
};

pub const SECP521R1: CurveParams = CurveParams {
    p: U576::from_be_hex(
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    a: U576::from_be_hex(
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
    ),
    b: U576::from_be_hex(
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
    ),
    point_bit_length: 521,
    names: &["secp521r1", "p521", "p-521"],
};

pub const SECP256K1: CurveParams = CurveParams {
    p: U576::from_be_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
    a: U576::from_be_hex("0"),
    b: U576::from_be_hex("7"),
    point_bit_length: 256,
    names: &["secp256k1", "k256", "k-256"],
};

/// Looks up one of the supported curves by any of its (case-insensitive) names.
pub fn get_curve_params_by_name(name: &str) -> Option<&'static CurveParams> {
    const ALL: [&CurveParams; 4] = [&SECP256K1, &SECP256R1, &SECP384R1, &SECP521R1];
    ALL.into_iter()
        .find(|curve| curve.names.iter().any(|n| n.eq_ignore_ascii_case(name)))
}
