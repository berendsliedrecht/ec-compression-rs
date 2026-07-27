use crate::affine_point::AffinePoint;
use crate::bytes::KeyBytes;
use crate::curve_params::CurveParams;
use crate::error::Error;

/// Decompresses a compressed public key (`02`/`03` prefix) into its
/// uncompressed form (`04` prefix).
pub fn decompress_public_key(
    compressed_public_key: &[u8],
    curve: &CurveParams,
) -> Result<KeyBytes, Error> {
    Ok(AffinePoint::from_compressed_point(compressed_public_key, curve)?.decompressed_form())
}

/// Like [`decompress_public_key`], but returns the input unchanged when it
/// cannot be decompressed. Errors only when the input is larger than
/// [`crate::MAX_KEY_BYTES`] and cannot be returned.
pub fn decompress_public_key_if_possible(
    public_key: &[u8],
    curve: &CurveParams,
) -> Result<KeyBytes, Error> {
    match decompress_public_key(public_key, curve) {
        Ok(decompressed) => Ok(decompressed),
        Err(_) => KeyBytes::new(public_key),
    }
}

/// Compresses an uncompressed public key (`04` prefix) into its compressed
/// form (`02`/`03` prefix).
pub fn compress_public_key(
    decompressed_public_key: &[u8],
    curve: &CurveParams,
) -> Result<KeyBytes, Error> {
    Ok(AffinePoint::from_decompressed_point(decompressed_public_key, curve)?.compressed_form())
}

/// Like [`compress_public_key`], but returns the input unchanged when it
/// cannot be compressed. Errors only when the input is larger than
/// [`crate::MAX_KEY_BYTES`] and cannot be returned.
pub fn compress_public_key_if_possible(
    public_key: &[u8],
    curve: &CurveParams,
) -> Result<KeyBytes, Error> {
    match compress_public_key(public_key, curve) {
        Ok(compressed) => Ok(compressed),
        Err(_) => KeyBytes::new(public_key),
    }
}

/// Checks the prefix and length, and that the decoded point lies on the curve.
pub fn is_valid_compressed_public_key_format(public_key: &[u8], curve: &CurveParams) -> bool {
    AffinePoint::from_compressed_point(public_key, curve).is_ok()
}

/// Checks the prefix and length, and that the point lies on the curve.
pub fn is_valid_decompressed_public_key_format(public_key: &[u8], curve: &CurveParams) -> bool {
    AffinePoint::from_decompressed_point(public_key, curve).is_ok()
}

pub fn is_valid_public_key_format(public_key: &[u8], curve: &CurveParams) -> bool {
    is_valid_compressed_public_key_format(public_key, curve)
        || is_valid_decompressed_public_key_format(public_key, curve)
}
