# ec-compression

Compression and decompression of elliptic curve public keys. A Rust port of
[ec-compression-ts](https://github.com/berendsliedrecht/ec-compression-ts).

- Supported curves: secp256k1, secp256r1 (P-256), secp384r1 (P-384), secp521r1 (P-521)
- `no_std` without `alloc`
- Zero dependencies

## Usage

```rust
use ec_compression::{
    compress_public_key, decompress_public_key, get_curve_params_by_name,
    AffinePoint, SECP256K1, SECP256R1,
};

// Decompress a compressed (02/03-prefixed) key into its 04-prefixed form
let decompressed = decompress_public_key(&compressed_key, &SECP256K1)?;

// Or work with curves by name
let curve = get_curve_params_by_name("p-256").unwrap();
let compressed = compress_public_key(&decompressed_key, curve)?;

// Lower-level access to the affine coordinates
let point = AffinePoint::from_compressed_point(&compressed_key, &SECP256R1)?;
let (x, y) = (point.x(), point.y());
```

Compression drops the y coordinate and records only its parity (`02` even,
`03` odd). Decompression solves `y^2 = x^3 + ax + b (mod p)` to recover it;
the primes of all supported curves are congruent to 3 (mod 4), so the square
root is simply `n^((p + 1) / 4)`. Uncompressed inputs are verified to lie on
the curve.

Inputs whose coordinates lost leading zero bytes (as some JWK producers emit
for P-521) are accepted; output is always canonical SEC1, with coordinates
padded to the full curve width.

> **Note**: this crate performs no constant-time guarantees and only operates
> on *public* keys. Do not use it with secret material.

## License

MIT
