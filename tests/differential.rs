//! Differential tests against the RustCrypto curve crates: random points
//! must compress and decompress to exactly the same canonical SEC1 bytes.

use ec_compression::{
    compress_public_key, decompress_public_key, SECP256K1, SECP256R1, SECP384R1, SECP521R1,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;

const ITERATIONS: usize = 32;

macro_rules! differential_roundtrip {
    ($name:ident, $curve_crate:ident, $params:expr) => {
        #[test]
        fn $name() {
            for _ in 0..ITERATIONS {
                let public_key = $curve_crate::SecretKey::random(&mut rand_core::OsRng).public_key();
                let uncompressed = public_key.to_encoded_point(false);
                let compressed = public_key.to_encoded_point(true);

                let ours = compress_public_key(uncompressed.as_bytes(), $params).unwrap();
                assert_eq!(ours.as_slice(), compressed.as_bytes());

                let ours = decompress_public_key(compressed.as_bytes(), $params).unwrap();
                assert_eq!(ours.as_slice(), uncompressed.as_bytes());
            }
        }
    };
}

differential_roundtrip!(secp256k1_matches_k256, k256, &SECP256K1);
differential_roundtrip!(secp256r1_matches_p256, p256, &SECP256R1);
differential_roundtrip!(secp384r1_matches_p384, p384, &SECP384R1);
differential_roundtrip!(secp521r1_matches_p521, p521, &SECP521R1);
