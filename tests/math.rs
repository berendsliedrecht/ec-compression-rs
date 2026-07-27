mod common;

use common::hex;
use ec_compression::{
    compress_public_key, decompress_public_key, decompress_public_key_if_possible,
    get_curve_params_by_name, mod_pow, mod_sqrt, SECP384R1, U576,
};

#[test]
fn uint_byte_roundtrip() {
    let bytes = hex("00c6858e06b70404e9cd9e3ecb66");
    let value = U576::from_be_bytes(&bytes).unwrap();
    // Leading zero bytes are stripped by the minimal encoding
    assert_eq!(value.to_be_bytes().as_slice(), &bytes[1..]);

    assert_eq!(U576::ZERO.to_be_bytes().as_slice(), &[0u8][..]);
    assert!(U576::from_be_bytes(&[]).is_err());
}

#[test]
fn mod_pow_matches_small_values() {
    let result = mod_pow(
        &U576::from_u64(4),
        &U576::from_u64(13),
        &U576::from_u64(497),
    );
    assert_eq!(result, U576::from_u64(445));

    assert_eq!(
        mod_pow(&U576::from_u64(10), &U576::from_u64(100), &U576::ONE),
        U576::ZERO
    );
}

#[test]
fn mod_sqrt_small_values() {
    // 2 is a quadratic residue mod 7 (3 * 3 = 9 = 2 mod 7)
    let root = mod_sqrt(&U576::from_u64(2), &U576::from_u64(7)).unwrap();
    assert!(root == U576::from_u64(3) || root == U576::from_u64(4));

    // 5 is not a quadratic residue mod 7
    assert!(mod_sqrt(&U576::from_u64(5), &U576::from_u64(7)).is_err());
}

#[test]
fn curve_lookup_by_name() {
    assert_eq!(get_curve_params_by_name("P-384"), Some(&SECP384R1));
    assert_eq!(get_curve_params_by_name("SECP384R1"), Some(&SECP384R1));
    assert_eq!(get_curve_params_by_name("unknown"), None);
}

#[test]
fn compress_decompress_roundtrip_all_curves() {
    let compressed_generators = [
        ("secp256k1", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        ("p256", "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        ("p384", "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
        ("p521", "0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"),
    ];

    for (name, compressed_hex) in compressed_generators {
        let curve = get_curve_params_by_name(name).unwrap();
        let compressed = hex(compressed_hex);

        let decompressed = decompress_public_key(&compressed, curve).unwrap();
        let recompressed = compress_public_key(&decompressed, curve).unwrap();

        // The recompressed key encodes the same point; compare as integers so
        // stripped leading zero bytes (P-521) do not matter
        assert_eq!(
            U576::from_be_bytes(&recompressed[1..]).unwrap(),
            U576::from_be_bytes(&compressed[1..]).unwrap()
        );
        assert_eq!(recompressed[0], compressed[0]);
    }
}

#[test]
fn decompress_if_possible_returns_input_on_invalid_key() {
    let not_a_key = [0x01u8, 0x02, 0x03];
    let result = decompress_public_key_if_possible(&not_a_key, &SECP384R1).unwrap();
    assert_eq!(result.as_slice(), &not_a_key[..]);
}
