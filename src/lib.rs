//! Compression and decompression of elliptic curve public keys.
//!
//! Supports secp256k1, secp256r1 (P-256), secp384r1 (P-384) and
//! secp521r1 (P-521). The crate is `no_std` without `alloc` and has no
//! dependencies.
//!
//! ```
//! use ec_compression::{compress_public_key, decompress_public_key, SECP256K1};
//!
//! let compressed = [
//!     0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
//!     0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
//!     0xf8, 0x17, 0x98,
//! ];
//!
//! let decompressed = decompress_public_key(&compressed, &SECP256K1).unwrap();
//! assert_eq!(decompressed[0], 0x04);
//! assert_eq!(compress_public_key(&decompressed, &SECP256K1).unwrap(), compressed);
//! ```

#![no_std]

mod affine_point;
mod bytes;
mod crypto;
mod curve_params;
mod error;
mod math;
mod uint;

pub use affine_point::{
    AffinePoint, MAX_COORDINATE_BYTES, PREFIX_COMPRESSED_Y_IS_EVEN, PREFIX_COMPRESSED_Y_IS_ODD,
    PREFIX_UNCOMPRESSED,
};
pub use bytes::{KeyBytes, MAX_KEY_BYTES};
pub use crypto::{
    compress_public_key, compress_public_key_if_possible, decompress_public_key,
    decompress_public_key_if_possible, is_valid_compressed_public_key_format,
    is_valid_decompressed_public_key_format, is_valid_public_key_format,
};
pub use curve_params::{
    get_curve_params_by_name, CurveParams, SECP256K1, SECP256R1, SECP384R1, SECP521R1,
};
pub use error::Error;
pub use math::{mod_pow, mod_sqrt};
pub use uint::U576;
