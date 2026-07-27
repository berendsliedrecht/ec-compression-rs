mod common;

use common::hex;
use ec_compression::{
    decompress_public_key, is_valid_public_key_format, AffinePoint, SECP256K1, SECP384R1,
    SECP521R1,
};

#[test]
fn secp256k1_decompress_public_key() {
    let decompressed = decompress_public_key(
        &hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        &SECP256K1,
    )
    .unwrap();

    assert_eq!(
        decompressed.as_slice(),
        &hex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")[..]
    );
}

// P-521 JWK vectors: canonical (full-width) uncompressed keys must
// round-trip through from_decompressed_point unchanged.

fn assert_p521_roundtrip(x_hex: &str, y_hex: &str) {
    let mut uncompressed = vec![0x04];
    uncompressed.extend(hex(x_hex));
    uncompressed.extend(hex(y_hex));

    let point = AffinePoint::from_decompressed_point(&uncompressed, &SECP521R1).unwrap();
    assert_eq!(point.decompressed_form().as_slice(), &uncompressed[..]);
}

// A key whose x coordinate lost its leading zero byte is still accepted, and
// re-encodes to the canonical full-width form.
#[test]
fn secp521r1_stripped_leading_zero_normalizes_to_canonical() {
    let canonical = {
        let mut key = vec![0x04];
        key.extend(hex("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"));
        key.extend(hex("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"));
        key
    };
    // Same key with the 65-byte x coordinate (leading zero stripped)
    let stripped = [&canonical[..1], &canonical[2..]].concat();

    let point = AffinePoint::from_decompressed_point(&stripped, &SECP521R1).unwrap();
    assert_eq!(point.decompressed_form().as_slice(), &canonical[..]);
}

#[test]
fn secp521r1_jwk_x1_y0() {
    assert_p521_roundtrip(
        "01b6f2896913e22d2eaa7739881abf530a0cac5641146786b725e0533cae58d7e5e5c644ad3abbfd5c7e29dbbb22639ca595b274c6cd36288c042e55f72d6b8eb87e",
        "00bd62d23f6bba3663a139497b6ae91bbc4719e7e88af3c41901630de6190d07dee11f3e4f0351de52cabdc9b5d00570c2fac25104254f9b2796e5ef9f083bdfa899",
    );
}

#[test]
fn secp521r1_jwk_x0_y0() {
    assert_p521_roundtrip(
        "0031d2fe2d2aec275ff470d4322efbf94e99b1ba33266d14134d83fb04406237adc4501b4dbbea7ff8913cc7c8bba4f8011bb1599b1631aec540353fae621256529c",
        "00d49bce448121bf52088f67713b143d8d36b7020c968ea153e0875fc92126fcc69126e0cf4fd399a0d2afafde2d36adbd06614bef9ea3cd94980e73313702243d23",
    );
}

#[test]
fn secp521r1_jwk_x1_y1() {
    assert_p521_roundtrip(
        "01d9209464857e059e5dc0f6d9ce6294ddf4612fd959fe1ae41ae692707f15f79046687664e80658a8c03683b883f16b73a31b3aa9256ec6db2544573d2971990064",
        "0144474076ea7939af28ca89133ebf7c7eb777327e066b8cf408937de1c36ae075b238dca352beb2b9b021e6941df63e8209cb5943a375a7ae6e3b68eea97267afd6",
    );
}

#[test]
fn secp521r1_jwk_x0_y1() {
    assert_p521_roundtrip(
        "001e399aa3e39369c7715a5a5af5bb9ac9db3bdf249b8b8688e759be989e19bd780ecb4afa0f36cdb9bef3c063daf57d5f21e26918a6e512680d8109fecadfd3543f",
        "01e7725ca48544adedc559e43cd329618fb656d08a9e1c36e65309bed21d2e2be4b3a881c25a5facdee06303bf6bed691c16ef6318f65c152dd210776cd88eea19fc",
    );
}

#[test]
fn is_valid_public_key_format_checks_prefix_length_and_point() {
    let compressed = hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    let uncompressed = hex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

    assert!(is_valid_public_key_format(&compressed, &SECP256K1));
    assert!(is_valid_public_key_format(&uncompressed, &SECP256K1));

    // Wrong prefix
    let mut bad_prefix = compressed.clone();
    bad_prefix[0] = 0x01;
    assert!(!is_valid_public_key_format(&bad_prefix, &SECP256K1));

    // Wrong length
    assert!(!is_valid_public_key_format(&compressed[..32], &SECP256K1));
    assert!(!is_valid_public_key_format(&uncompressed[..64], &SECP256K1));

    // Wrong curve
    assert!(!is_valid_public_key_format(&compressed, &SECP384R1));

    // Valid format, but x = 0 is not on secp256k1
    let mut zero_x = vec![0x02];
    zero_x.extend([0u8; 32]);
    assert!(!is_valid_public_key_format(&zero_x, &SECP256K1));

    // Valid format, but x is not smaller than p
    let mut oversized_x = vec![0x02];
    oversized_x.extend([0xffu8; 32]);
    assert!(!is_valid_public_key_format(&oversized_x, &SECP256K1));

    // Tweaking y makes the equation fail
    let mut off_curve = uncompressed.clone();
    off_curve[64] ^= 0x01;
    assert!(!is_valid_public_key_format(&off_curve, &SECP256K1));
}
