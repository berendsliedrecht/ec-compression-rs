mod common;

use common::hex;
use ec_compression::{AffinePoint, SECP256K1, SECP256R1, SECP384R1, SECP521R1, U576};

#[test]
fn secp256k1_from_compressed() {
    let point = AffinePoint::from_compressed_point(
        &hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        &SECP256K1,
    )
    .unwrap();

    assert_eq!(
        point.x(),
        U576::from_be_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    );
    assert_eq!(
        point.y(),
        U576::from_be_hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    );
}

#[test]
fn secp256k1_from_decompressed() {
    let point = AffinePoint::from_decompressed_point(
        &hex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
        &SECP256K1,
    )
    .unwrap();

    assert_eq!(
        point.x(),
        U576::from_be_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    );
    assert_eq!(
        point.y(),
        U576::from_be_hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    );
}

#[test]
fn secp256k1_compress_and_decompress_generator_point() {
    let point = AffinePoint::from_uints(
        &U576::from_be_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        &U576::from_be_hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
        &SECP256K1,
    )
    .unwrap();

    assert_eq!(point.compressed_form().len(), 33);
    assert_eq!(point.decompressed_form().len(), 65);

    assert_eq!(
        point.compressed_form().as_slice(),
        &hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")[..]
    );
    assert_eq!(
        point.decompressed_form().as_slice(),
        &hex("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")[..]
    );
}

#[test]
fn secp256r1_from_compressed() {
    let point = AffinePoint::from_compressed_point(
        &hex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        &SECP256R1,
    )
    .unwrap();

    assert_eq!(
        point.x(),
        U576::from_be_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
    );
    assert_eq!(
        point.y(),
        U576::from_be_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    );
}

#[test]
fn secp256r1_from_decompressed() {
    let point = AffinePoint::from_decompressed_point(
        &hex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        &SECP256R1,
    )
    .unwrap();

    assert_eq!(
        point.x(),
        U576::from_be_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
    );
    assert_eq!(
        point.y(),
        U576::from_be_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
    );
}

#[test]
fn secp384r1_from_compressed() {
    let point = AffinePoint::from_compressed_point(
        &hex("03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
        &SECP384R1,
    )
    .unwrap();

    assert_eq!(
        point.x(),
        U576::from_be_hex(
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"
        )
    );
    assert_eq!(
        point.y(),
        U576::from_be_hex(
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
        )
    );
}

#[test]
fn secp384r1_compress_and_decompress_generator_point() {
    let point = AffinePoint::from_uints(
        &U576::from_be_hex(
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"
        ),
        &U576::from_be_hex(
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"
        ),
        &SECP384R1,
    )
    .unwrap();

    assert_eq!(point.compressed_form().len(), 49);
    assert_eq!(point.decompressed_form().len(), 97);
}

#[test]
fn secp521r1_from_compressed() {
    let point = AffinePoint::from_compressed_point(
        &hex("0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"),
        &SECP521R1,
    )
    .unwrap();

    assert_eq!(
        point.x(),
        U576::from_be_hex(
            "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"
        )
    );
    assert_eq!(
        point.y(),
        U576::from_be_hex(
            "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"
        )
    );
}

#[test]
fn secp521r1_from_decompressed_with_stripped_leading_zero_on_x() {
    // 132 bytes total: x lost its leading zero byte (65 bytes), y is 66 bytes
    let point = AffinePoint::from_decompressed_point(
        &hex("04c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"),
        &SECP521R1,
    )
    .unwrap();

    assert_eq!(
        point.x(),
        U576::from_be_hex(
            "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"
        )
    );
    assert_eq!(
        point.y(),
        U576::from_be_hex(
            "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"
        )
    );
}

#[test]
fn secp521r1_compress_and_decompress_generator_point() {
    let point = AffinePoint::from_uints(
        &U576::from_be_hex(
            "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66"
        ),
        &U576::from_be_hex(
            "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650"
        ),
        &SECP521R1,
    )
    .unwrap();

    // Encoded forms are canonical: both coordinates padded to 66 bytes
    assert_eq!(point.compressed_form().len(), 67);
    assert_eq!(point.decompressed_form().len(), 133);

    assert_eq!(
        point.compressed_form().as_slice(),
        &hex("0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66")[..]
    );
}
