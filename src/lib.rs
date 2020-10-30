//!Minimal `no_std` UUID implementation.
//!
//!## Features:
//!
//!- `prng` - Enables v4 using pseudo random, allowing unique, but predictable UUIDs;
//!- `orng` - Enables v4 using OS random, allowing unique UUIDs;
//!- `sha1` - Enables v5;
//!- `serde` - Enables `serde` support;

#![warn(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

use core::{ptr, fmt, time};

#[cfg(feature = "serde")]
mod serde;

type StrBuf = str_buf::StrBuf<[u8; 36]>;
const SEP: char = '-';

#[inline(always)]
const fn byte_to_hex(byt: u8, idx: usize) -> u8 {
    const BASE: usize = 4;
    const BASE_DIGIT: usize = (1 << BASE) - 1;
    const HEX_DIGITS: [u8; 16] = [b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f'];

    HEX_DIGITS[((byt as usize) >> (BASE * idx)) & BASE_DIGIT]
}

#[inline]
fn hex_to_byte(hex: &[u8], cursor: usize, error_offset: usize) -> Result<u8, ParseError> {
    let left = match hex[cursor] {
        chr @ b'0'..=b'9' => chr - b'0',
        chr @ b'a'..=b'f' => chr - b'a' + 10,
        chr @ b'A'..=b'F' => chr - b'A' + 10,
        chr => return Err(ParseError::InvalidByte(chr, cursor + error_offset)),
    };

    let right = match hex[cursor + 1] {
        chr @ b'0'..=b'9' => chr - b'0',
        chr @ b'a'..=b'f' => chr - b'a' + 10,
        chr @ b'A'..=b'F' => chr - b'A' + 10,
        chr => return Err(ParseError::InvalidByte(chr, cursor + 1 + error_offset)),
    };

    Ok(left * 16 + right)
}

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

#[derive(Clone, Debug, Copy)]
///Timestamp for use with `v1` algorithm.
pub struct Timestamp {
    ticks: u64,
    counter: u16
}

const V1_NS_TICKS: u64 = 0x01B2_1DD2_1381_4000;

impl Timestamp {
    #[inline(always)]
    ///Creates timestamp from raw parts, as per RFC4122.
    ///
    ///- `ticks` is number of 100-nanoseconds intervals elapsed since 15 Oct 1582 00:00:00.00.
    ///- `counter` is value used to differentiate between timestamps generated to avoid collision
    ///in case of rapid generation.
    pub const fn from_parts(ticks: u64, counter: u16) -> Self {
        Self {
            ticks,
            counter,
        }
    }

    ///Creates instance from unix timestamp, namely it takes seconds and subsec_nanos.
    ///
    ///Note it doesn't set counter, if needed it must be set manually
    pub const fn from_unix(time: time::Duration) -> Self {
        let ticks = V1_NS_TICKS + time.as_secs() * 10_000_000 + (time.subsec_nanos() as u64) / 100;
        Self::from_parts(ticks, 0)
    }

    ///Sets counter to further avoid chance of collision between timestamps.
    ///
    ///Useful if clock is not guaranteed to be monotonically increasing.
    ///Otherwise there is no benefit in setting the counter.
    pub const fn set_counter(mut self, counter: u16) -> Self {
        self.counter = counter;
        self
    }

    ///Retrieves timestamp as raw parts
    pub const fn into_parts(self) -> (u64, u16) {
        (self.ticks, self.counter)
    }
}

const UUID_SIZE: usize = 16;
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, PartialOrd, Ord)]
///Universally unique identifier, consisting of 128-bits, as according to RFC4122
pub struct Uuid {
    data: [u8; UUID_SIZE]
}

impl Uuid {
    #[inline]
    ///Creates zero UUID
    pub const fn nil() -> Self {
        Self::from_bytes([0; UUID_SIZE])
    }

    #[inline]
    ///Creates new Uuid from raw bytes.
    pub const fn from_bytes(data: [u8; UUID_SIZE]) -> Self {
        Self { data }
    }

    #[inline]
    ///Access underlying bytes as slice.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    #[inline]
    ///Get underlying raw bytes
    pub const fn bytes(&self) -> [u8; UUID_SIZE] {
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

    ///Generates UUID from time and mac address
    pub const fn v1(timestamp: Timestamp, mac: [u8; 6]) -> Self {
        let time_low = (timestamp.ticks & 0xFFFF_FFFF) as u32;
        let time_mid = ((timestamp.ticks >> 32) & 0xFFFF) as u16;
        let time_high_and_version = (((timestamp.ticks >> 48) & 0x0FFF) as u16) | (1 << 12);

        Self::from_bytes([
            (time_low >> 24) as u8,
            (time_low >> 16) as u8,
            (time_low >> 8) as u8,
            time_low as u8,
            (time_mid >> 8) as u8,
            time_mid as u8,
            (time_high_and_version >> 8) as u8,
            time_high_and_version as u8,
            (((timestamp.counter & 0x3F00) >> 8) as u8) | 0x80,
            (timestamp.counter & 0xFF) as u8,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        ])
    }

    #[cfg(feature = "osrng")]
    ///Generates UUID `v4` using OS RNG from [getrandom](https://crates.io/crates/getrandom)
    ///
    ///Only available when `osrng` feature is enabled.
    pub fn v4() -> Self {
        #[cold]
        fn random_unavailable(error: getrandom::Error) -> ! {
            panic!("OS RNG is not available for use: {}", error)
        }

        let mut bytes = [0; UUID_SIZE];
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
    ///This random is useful when you want to generate predictable but unique UUIDs
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
        use core::{mem};

        let mut sha1 = sha1::Sha1::new();

        sha1.update(&namespace.data);
        sha1.update(name);

        let sha1 = sha1.digest().bytes();
        let mut uuid = mem::MaybeUninit::<[u8; UUID_SIZE]>::uninit();
        let uuid = unsafe {
            ptr::copy_nonoverlapping(sha1.as_ptr(), uuid.as_mut_ptr() as _, UUID_SIZE);
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

    #[inline(always)]
    ///Creates new instance by parsing provided string.
    ///
    ///Supports only simple sequence of characters and `-` separated.
    pub fn parse_str(input: &str) -> Result<Self, ParseError> {
        core::str::FromStr::from_str(input)
    }

    #[inline]
    ///Creates textual representation of UUID in a static buffer.
    pub const fn to_str(&self) -> StrBuf {
        let storage = [
            byte_to_hex(self.data[0], 1),
            byte_to_hex(self.data[0], 0),
            byte_to_hex(self.data[1], 1),
            byte_to_hex(self.data[1], 0),
            byte_to_hex(self.data[2], 1),
            byte_to_hex(self.data[2], 0),
            byte_to_hex(self.data[3], 1),
            byte_to_hex(self.data[3], 0),
            SEP as u8,
            byte_to_hex(self.data[4], 1),
            byte_to_hex(self.data[4], 0),
            byte_to_hex(self.data[5], 1),
            byte_to_hex(self.data[5], 0),
            SEP as u8,
            byte_to_hex(self.data[6], 1),
            byte_to_hex(self.data[6], 0),
            byte_to_hex(self.data[7], 1),
            byte_to_hex(self.data[7], 0),
            SEP as u8,
            byte_to_hex(self.data[8], 1),
            byte_to_hex(self.data[8], 0),
            byte_to_hex(self.data[9], 1),
            byte_to_hex(self.data[9], 0),
            SEP as u8,
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
        fmt.write_str(self.to_str().as_str())
    }
}

impl Default for Uuid {
    #[inline(always)]
    fn default() -> Self {
        Self::nil()
    }
}

impl AsRef<[u8]> for Uuid {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
///Error happening when parsing invalid uuid.
pub enum ParseError {
    ///Input has invalid length.
    InvalidLength(usize),
    ///Group has invalid len.
    ///
    ///1. Group number;
    ///3. Actual len;
    InvalidGroupLen(u8, usize),
    ///Invalid character is encountered.
    ///
    ///1. Character byte;
    ///2. Position from 0;
    InvalidByte(u8, usize)
}

impl fmt::Display for ParseError {
    #[inline(always)]
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::InvalidLength(len) => fmt.write_fmt(format_args!("Invalid length {}", len)),
            ParseError::InvalidGroupLen(idx, len) => fmt.write_fmt(format_args!("Group {} has unexpected length {}", idx, len)),
            ParseError::InvalidByte(byte, pos) => fmt.write_fmt(format_args!("Invalid character '{:x}' at position {}", byte, pos)),
        }
    }
}

impl core::str::FromStr for Uuid {
    type Err = ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        use core::mem::MaybeUninit;

        if input.len() == StrBuf::capacity() {
            let mut input = input.split(SEP);

            //First is always present even when `-` is missing
            //But after that we always fail if group len is invalid
            let time_low = input.next().unwrap();
            if time_low.len() != 8 {
                return Err(ParseError::InvalidGroupLen(1, time_low.len()));
            }

            let time_mid = input.next().unwrap();
            if time_mid.len() != 4 {
                return Err(ParseError::InvalidGroupLen(2, time_mid.len()));
            }

            let time_hi_version = input.next().unwrap();
            if time_hi_version.len() != 4 {
                return Err(ParseError::InvalidGroupLen(3, time_hi_version.len()));
            }

            let clock_seq = input.next().unwrap();
            if clock_seq.len() != 4 {
                return Err(ParseError::InvalidGroupLen(4, clock_seq.len()));
            }

            let node = input.next().unwrap();
            if node.len() != 12 {
                return Err(ParseError::InvalidGroupLen(5, node.len()));
            }

            let mut chunks = [
                time_low.as_bytes().chunks(2),
                time_mid.as_bytes().chunks(2),
                time_hi_version.as_bytes().chunks(2),
                clock_seq.as_bytes().chunks(2),
                node.as_bytes().chunks(2),
            ];

            let mut uuid = MaybeUninit::<[u8; UUID_SIZE]>::uninit();

            let mut cursor = 0;
            for (idx, chunks) in chunks.iter_mut().enumerate() {
                for chunk in chunks {
                    let byte = hex_to_byte(chunk, 0, cursor * 2 + idx)?;

                    unsafe {
                        ptr::write((uuid.as_mut_ptr() as *mut u8).add(cursor), byte);
                    }

                    cursor += 1;
                }
            }

            Ok(Self::from_bytes(unsafe { uuid.assume_init() }))
        } else if input.len() == StrBuf::capacity() - 4 {
            Ok(Self::from_bytes([
                hex_to_byte(input.as_bytes(), 0, 0)?,
                hex_to_byte(input.as_bytes(), 2, 0)?,
                hex_to_byte(input.as_bytes(), 4, 0)?,
                hex_to_byte(input.as_bytes(), 6, 0)?,
                hex_to_byte(input.as_bytes(), 8, 0)?,
                hex_to_byte(input.as_bytes(), 10, 0)?,
                hex_to_byte(input.as_bytes(), 12, 0)?,
                hex_to_byte(input.as_bytes(), 14, 0)?,
                hex_to_byte(input.as_bytes(), 16, 0)?,
                hex_to_byte(input.as_bytes(), 18, 0)?,
                hex_to_byte(input.as_bytes(), 20, 0)?,
                hex_to_byte(input.as_bytes(), 22, 0)?,
                hex_to_byte(input.as_bytes(), 24, 0)?,
                hex_to_byte(input.as_bytes(), 26, 0)?,
                hex_to_byte(input.as_bytes(), 28, 0)?,
                hex_to_byte(input.as_bytes(), 30, 0)?,
            ]))
        } else {
            Err(ParseError::InvalidLength(input.len()))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::byte_to_hex;

    #[test]
    fn should_convert_byte_to_hex() {
        assert_eq!([byte_to_hex(254, 1), byte_to_hex(254, 0)], *b"fe");
        assert_eq!([byte_to_hex(255, 1), byte_to_hex(255, 0)], *b"ff");
        assert_eq!([byte_to_hex(1, 1), byte_to_hex(1, 0)], *b"01");
        assert_eq!([byte_to_hex(15, 1), byte_to_hex(15, 0)], *b"0f");
        assert_eq!([byte_to_hex(0, 1), byte_to_hex(0, 0)], *b"00");
    }
}
