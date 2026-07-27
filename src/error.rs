use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The compressed key does not have a valid prefix or length for the curve.
    InvalidCompressedForm,
    /// The decompressed key does not have a valid prefix or length for the curve.
    InvalidDecompressedForm,
    /// The x coordinate is outside of the plane.
    XCoordinateOutOfRange,
    /// The coordinates do not satisfy the curve equation.
    PointNotOnCurve,
    /// The value is not a quadratic residue modulo p, so no square root exists.
    NoSquareRoot,
    /// An empty byte slice cannot represent a value.
    EmptyBytes,
    /// The value does not fit in the fixed-size buffer or integer.
    ValueTooLarge,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidCompressedForm => "invalid format for compressed form",
            Self::InvalidDecompressedForm => "invalid format for decompressed form",
            Self::XCoordinateOutOfRange => "x coordinate is outside of the plane",
            Self::PointNotOnCurve => "point is not on the curve",
            Self::NoSquareRoot => "no solution: value is not a quadratic residue modulo p",
            Self::EmptyBytes => "empty byte slices are not supported",
            Self::ValueTooLarge => "value is too large for the fixed-size representation",
        };
        f.write_str(message)
    }
}

impl core::error::Error for Error {}
