//!Simple `no_std` UUID generator.
//!
//!Features:
//!
//!- `prng` - Enables v4 using pseudo random, allowing unique, but predictable UUIDs.
//!- `orng` - Enables v4 using OS random, allowing unique UUIDs.
//!- `sha1` - Enables v5.

#![no_std]
#![warn(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

use core::fmt;

type StrBuf = str_buf::StrBuf<[u8; 36]>;

///When this namespace is specified, the name string is a fully-qualified domain name
pub const NAMESPACE_DNS: Uuid = Uuid::from_bytes([
     0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
]);

///When this namespace is specified, the name string is a URL
pub const NAMESPACE_URL: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x11, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
]);

///When this namespace is specified, the name string is an ISO OID
pub const NAMESPACE_OID: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
]);

///When this namespace is specified, the name string is an X.500 DN in DER or a text output format.
pub const NAMESPACE_X500: Uuid = Uuid::from_bytes([
    0x6b, 0xa7, 0xb8, 0x14, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8
]);

#[inline(always)]
const fn byte_to_hex(byt: u8, idx: usize) -> u8 {
    const BASE: usize = 4;
    const BASE_DIGIT: usize = (1 << BASE) - 1;
    const HEX_DIGITS: [u8; 16] = [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f'];

    HEX_DIGITS[((byt as usize) >> (BASE * idx)) & BASE_DIGIT]
}

/// The version of the UUID, denoting the generating algorithm.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Version {
    /// Special case for `nil` UUID.
    Nil = 0,
    /// Version 1: MAC address.
    Mac,
    /// Version 2: DCE Security.
    Dce,
    /// Version 3: MD5 hash.
    Md5,
    /// Version 4: Random.
    Random,
    /// Version 5: SHA-1 hash.
    Sha1,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
///Universally unique identifier, consisting of 128-bits, as according to RFC4122
pub struct Uuid {
    data: [u8; 16]
}

impl Uuid {
    #[inline]
    ///Creates zero UUID
    pub const fn nil() -> Self {
        Self::from_bytes([0; 16])
    }

    #[inline]
    ///Creates new Uuid from raw bytes.
    pub const fn from_bytes(data: [u8; 16]) -> Self {
        Self { data }
    }

    #[inline]
    ///Get underlying raw bytes
    pub const fn bytes(&self) -> [u8; 16] {
        self.data
    }

    #[inline]
    ///Checks if `UUID` version is equal to the provided `version`
    pub const fn is_version(&self, version: Version) -> bool {
        (self.data[6] >> 4) == version as u8
    }

    #[inline]
    ///Checks if `UUID` variant is set, it only cares about RFC4122 byte
    pub const fn is_variant(&self) -> bool {
        (self.data[8] & 0xc0) == 0x80
    }

    #[cfg(feature = "osrng")]
    #[inline]
    ///Generates UUID `v4` using OS RNG from [getrandom](https://crates.io/crates/getrandom)
    ///
    ///Only available when `osrng` feature is enabled.
    pub fn v4() -> Self {
        #[cold]
        fn random_unavailable(error: getrandom::Error) -> ! {
            panic!("OS RNG is not available for use: {}", error)
        }

        let mut bytes = [0; 16];
        if let Err(error) = getrandom::getrandom(&mut bytes[..]) {
            random_unavailable(error)
        }

        Self::from_bytes(bytes).set_variant().set_version(Version::Random)
    }

    #[cfg(feature = "prng")]
    #[inline]
    ///Generates UUID `v4` using PRNG from [wyhash](https://crates.io/crates/wy)
    ///
    ///Only available when `prng` feature is enabled.
    ///
    ///This random variant generates predictable UUID, even though they are unique.
    ///Which means that each time program starts, it is initialized with the same seed and
    ///therefore would repeat UUIDs
    ///
    ///This random is useful when you want to generate predictable but random UUIDs
    ///Otherwise use `v4`
    pub fn prng() -> Self {
        static RANDOM: wy::AtomicRandom = wy::AtomicRandom::new(9);
        let right = u128::from(RANDOM.gen());
        let left = u128::from(RANDOM.gen());
        Self::from_bytes(((left << 64) |  right).to_ne_bytes()).set_variant().set_version(Version::Random)
    }

    #[cfg(feature = "sha1")]
    ///Generates UUID `v5` by using `sha1` hasher
    ///
    ///Only available when `sha1` feature is enabled.
    pub fn v5(namespace: Uuid, name: &[u8]) -> Self {
        use core::{ptr, mem};

        let mut sha1 = sha1::Sha1::new();

        sha1.update(&namespace.data);
        sha1.update(name);

        let sha1 = sha1.digest().bytes();
        let mut uuid = mem::MaybeUninit::<[u8; 16]>::uninit();
        let uuid = unsafe {
            ptr::copy_nonoverlapping(sha1.as_ptr(), uuid.as_mut_ptr() as _, 16);
            uuid.assume_init()
        };

        Self::from_bytes(uuid).set_variant().set_version(Version::Sha1)
    }

    #[inline]
    ///Adds variant byte to the corresponding field.
    ///
    ///This implementation only cares about RFC4122, there is no option to set other variant.
    ///
    ///Useful when user is supplied with random bytes, and wants to create UUID from it.
    pub const fn set_variant(mut self) -> Self {
        self.data[8] = (self.data[8] & 0x3f) | 0x80;
        self
    }

    #[inline]
    ///Adds version byte to the corresponding field.
    ///
    ///Useful when user is supplied with random bytes, and wants to create UUID from it.
    pub const fn set_version(mut self, version: Version) -> Self {
        self.data[6] = (self.data[6] & 0x0f) | ((version as u8) << 4);
        self
    }

    #[inline]
    ///Creates textual representation of UUID in a static buffer.
    pub const fn as_str(&self) -> StrBuf {
        let storage = [
            byte_to_hex(self.data[0], 1),
            byte_to_hex(self.data[0], 0),
            byte_to_hex(self.data[1], 1),
            byte_to_hex(self.data[1], 0),
            byte_to_hex(self.data[2], 1),
            byte_to_hex(self.data[2], 0),
            byte_to_hex(self.data[3], 1),
            byte_to_hex(self.data[3], 0),
            b'-',
            byte_to_hex(self.data[4], 1),
            byte_to_hex(self.data[4], 0),
            byte_to_hex(self.data[5], 1),
            byte_to_hex(self.data[5], 0),
            b'-',
            byte_to_hex(self.data[6], 1),
            byte_to_hex(self.data[6], 0),
            byte_to_hex(self.data[7], 1),
            byte_to_hex(self.data[7], 0),
            b'-',
            byte_to_hex(self.data[8], 1),
            byte_to_hex(self.data[8], 0),
            byte_to_hex(self.data[9], 1),
            byte_to_hex(self.data[9], 0),
            b'-',
            byte_to_hex(self.data[10], 1),
            byte_to_hex(self.data[10], 0),
            byte_to_hex(self.data[11], 1),
            byte_to_hex(self.data[11], 0),
            byte_to_hex(self.data[12], 1),
            byte_to_hex(self.data[12], 0),
            byte_to_hex(self.data[13], 1),
            byte_to_hex(self.data[13], 0),
            byte_to_hex(self.data[14], 1),
            byte_to_hex(self.data[14], 0),
            byte_to_hex(self.data[15], 1),
            byte_to_hex(self.data[15], 0),
        ];

        unsafe {
            StrBuf::from_storage(storage, StrBuf::capacity() as u8)
        }
    }
}

impl fmt::Display for Uuid {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str(self.as_str().as_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn should_convert_byte_to_hex() {
        assert_eq!([byte_to_hex(254, 1), byte_to_hex(254, 0)], *b"fe");
        assert_eq!([byte_to_hex(255, 1), byte_to_hex(255, 0)], *b"ff");
        assert_eq!([byte_to_hex(1, 1), byte_to_hex(1, 0)], *b"01");
        assert_eq!([byte_to_hex(15, 1), byte_to_hex(15, 0)], *b"0f");
        assert_eq!([byte_to_hex(0, 1), byte_to_hex(0, 0)], *b"00");
    }
}
