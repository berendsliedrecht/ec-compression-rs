use core::fmt;
use core::ops::Deref;

use crate::error::Error;

/// Maximum encoded key size: an uncompressed P-521 key with two full-width
/// coordinates (1 prefix byte + 66 + 66).
pub const MAX_KEY_BYTES: usize = 133;

/// A fixed-capacity byte buffer for key material.
///
/// Used instead of an allocated vector so the crate works on `no_std`
/// targets without `alloc`. Dereferences to `&[u8]`.
#[derive(Clone, Copy)]
pub struct KeyBytes {
    buffer: [u8; MAX_KEY_BYTES],
    length: usize,
}

impl KeyBytes {
    /// Copies `bytes` into a new buffer, erroring when they exceed
    /// [`MAX_KEY_BYTES`].
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_KEY_BYTES {
            return Err(Error::ValueTooLarge);
        }
        Ok(Self::from_slice(bytes))
    }

    /// `bytes` must fit within [`MAX_KEY_BYTES`].
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        let mut buffer = [0u8; MAX_KEY_BYTES];
        buffer[..bytes.len()].copy_from_slice(bytes);
        Self {
            buffer,
            length: bytes.len(),
        }
    }

    /// The combined parts must fit within [`MAX_KEY_BYTES`].
    pub(crate) fn concat(parts: &[&[u8]]) -> Self {
        let mut buffer = [0u8; MAX_KEY_BYTES];
        let mut length = 0;
        for part in parts {
            buffer[length..length + part.len()].copy_from_slice(part);
            length += part.len();
        }
        Self { buffer, length }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.length]
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl Deref for KeyBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for KeyBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for KeyBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for KeyBytes {}

impl PartialEq<[u8]> for KeyBytes {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<&[u8]> for KeyBytes {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for KeyBytes {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_slice() == other
    }
}

impl fmt::Debug for KeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyBytes(0x")?;
        for byte in self.as_slice() {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}
