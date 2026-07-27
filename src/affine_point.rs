use crate::bytes::KeyBytes;
use crate::curve_params::CurveParams;
use crate::error::Error;
use crate::math::{add_mod, mod_sqrt, mul_mod};
use crate::uint::U576;

pub const PREFIX_COMPRESSED_Y_IS_EVEN: u8 = 0x02;
pub const PREFIX_COMPRESSED_Y_IS_ODD: u8 = 0x03;
pub const PREFIX_UNCOMPRESSED: u8 = 0x04;

/// Maximum size of a single encoded coordinate: a full-width P-521
/// coordinate (66 bytes).
pub const MAX_COORDINATE_BYTES: usize = 66;

// The length checks accept coordinates that lost leading zero bytes, which
// only makes a difference for curves whose width is not a whole number of
// bytes (P-521)
fn has_valid_compressed_length(public_key: &[u8], curve: &CurveParams) -> bool {
    public_key.len() > curve.coordinate_bytes_floor()
        && public_key.len() <= curve.coordinate_bytes_ceil() + 1
}

fn has_valid_decompressed_length(public_key: &[u8], curve: &CurveParams) -> bool {
    public_key.len() > curve.coordinate_bytes_floor() * 2
        && public_key.len() <= curve.coordinate_bytes_ceil() * 2 + 1
}

/// `x^3 + ax + b (mod p)`; `x` must be reduced.
fn curve_equation_rhs(x: &U576, curve: &CurveParams) -> U576 {
    let p = &curve.p;
    let x_squared = mul_mod(x, x, p);
    let x_cubed = mul_mod(&x_squared, x, p);
    let ax = mul_mod(&curve.a, x, p);
    add_mod(&add_mod(&x_cubed, &ax, p), &curve.b, p)
}

/// An elliptic curve point in affine coordinates.
///
/// Inputs may have leading zero bytes stripped from their coordinates; the
/// encoded forms are always canonical SEC1, with every coordinate padded to
/// the full width of the curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AffinePoint {
    x: U576,
    y: U576,
    coordinate_length: usize,
}

impl AffinePoint {
    /// Creates a point from big-endian coordinate bytes, which may be shorter
    /// than the curve width when leading zero bytes were stripped.
    pub fn new(x: &[u8], y: &[u8], curve: &CurveParams) -> Result<Self, Error> {
        let coordinate_length = curve.coordinate_bytes_ceil();
        if x.len() > coordinate_length || y.len() > coordinate_length {
            return Err(Error::ValueTooLarge);
        }
        Ok(Self {
            x: U576::from_be_bytes(x)?,
            y: U576::from_be_bytes(y)?,
            coordinate_length,
        })
    }

    /// Creates a point from coordinate values.
    pub fn from_uints(x: &U576, y: &U576, curve: &CurveParams) -> Result<Self, Error> {
        let coordinate_length = curve.coordinate_bytes_ceil();
        if x.bit_length() > coordinate_length * 8 || y.bit_length() > coordinate_length * 8 {
            return Err(Error::ValueTooLarge);
        }
        Ok(Self {
            x: *x,
            y: *y,
            coordinate_length,
        })
    }

    pub fn x(&self) -> U576 {
        self.x
    }

    pub fn y(&self) -> U576 {
        self.y
    }

    /// Recovers the full point from a compressed form (`02`/`03` prefix) by
    /// solving the curve equation for y.
    pub fn from_compressed_point(
        compressed_form: &[u8],
        curve: &CurveParams,
    ) -> Result<Self, Error> {
        let prefix = compressed_form.first();
        if !matches!(
            prefix,
            Some(&PREFIX_COMPRESSED_Y_IS_EVEN | &PREFIX_COMPRESSED_Y_IS_ODD)
        ) || !has_valid_compressed_length(compressed_form, curve)
        {
            return Err(Error::InvalidCompressedForm);
        }

        let is_y_even = compressed_form[0] == PREFIX_COMPRESSED_Y_IS_EVEN;
        let x = U576::from_be_bytes(&compressed_form[1..])?;
        let y = Self::find_associated_y(is_y_even, &x, curve)?;

        Self::from_uints(&x, &y, curve)
    }

    /// Splits an uncompressed form (`04` prefix) into its coordinates and
    /// verifies that the point lies on the curve.
    pub fn from_decompressed_point(
        decompressed_form: &[u8],
        curve: &CurveParams,
    ) -> Result<Self, Error> {
        if decompressed_form.first() != Some(&PREFIX_UNCOMPRESSED)
            || !has_valid_decompressed_length(decompressed_form, curve)
        {
            return Err(Error::InvalidDecompressedForm);
        }

        // An odd number of coordinate bytes means one coordinate lost a
        // leading zero byte; assume it was x, so y gets the extra byte
        let coordinates = &decompressed_form[1..];
        let x_length = coordinates.len() / 2;
        let point = Self::new(&coordinates[..x_length], &coordinates[x_length..], curve)?;

        if !point.is_on_curve(curve) {
            return Err(Error::PointNotOnCurve);
        }

        Ok(point)
    }

    fn find_associated_y(is_y_even: bool, x: &U576, curve: &CurveParams) -> Result<U576, Error> {
        let p = &curve.p;
        if x >= p {
            return Err(Error::XCoordinateOutOfRange);
        }

        // y'^2 = x^3 + ax + b (mod p)
        let y_prime = mod_sqrt(&curve_equation_rhs(x, curve), p)?;
        Ok(if y_prime.is_even() == is_y_even {
            y_prime
        } else {
            p.sub(&y_prime)
        })
    }

    /// Whether the point satisfies the curve equation `y^2 = x^3 + ax + b (mod p)`.
    pub fn is_on_curve(&self, curve: &CurveParams) -> bool {
        let p = &curve.p;
        if &self.x >= p || &self.y >= p {
            return false;
        }
        mul_mod(&self.y, &self.y, p) == curve_equation_rhs(&self.x, curve)
    }

    /// The compressed SEC1 encoding: a parity prefix (`02`/`03`) followed by
    /// the full-width x coordinate.
    pub fn compressed_form(&self) -> KeyBytes {
        let prefix = if self.y.is_even() {
            PREFIX_COMPRESSED_Y_IS_EVEN
        } else {
            PREFIX_COMPRESSED_Y_IS_ODD
        };
        let x = self.x.to_be_bytes_padded(self.coordinate_length);
        KeyBytes::concat(&[&[prefix], &x])
    }

    /// The uncompressed SEC1 encoding: an `04` prefix followed by both
    /// full-width coordinates.
    pub fn decompressed_form(&self) -> KeyBytes {
        let x = self.x.to_be_bytes_padded(self.coordinate_length);
        let y = self.y.to_be_bytes_padded(self.coordinate_length);
        KeyBytes::concat(&[&[PREFIX_UNCOMPRESSED], &x, &y])
    }
}
