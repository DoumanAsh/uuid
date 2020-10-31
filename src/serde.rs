use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};

use crate::{UUID_SIZE, Uuid};

impl Serialize for Uuid {
    #[inline]
    fn serialize<SER: Serializer>(&self, ser: SER) -> Result<SER::Ok, SER::Error> {
        match ser.is_human_readable() {
            true => ser.serialize_str(&self.to_str()),
            false => {
                use serde::ser::SerializeTuple;

                let mut data = ser.serialize_tuple(UUID_SIZE)?;
                for byt in self.data.iter() {
                    data.serialize_element(byt)?;
                }
                data.end()
            }
        }
    }
}

struct StrVisitor;

impl<'de> serde::de::Visitor<'de> for StrVisitor {
    type Value = Uuid;

    #[inline(always)]
    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("a uuid string")
    }

    #[inline]
    fn visit_str<E: serde::de::Error>(self, input: &str) -> Result<Self::Value, E> {
        Uuid::parse_str(input).map_err(|err| serde::de::Error::custom(format_args!("Not a valid uuid: {}", err)))
    }

    #[inline]
    fn visit_bytes<E: serde::de::Error>(self, input: &[u8]) -> Result<Self::Value, E> {
        Uuid::parse_ascii_bytes(input).map_err(|err| serde::de::Error::custom(format_args!("Not a valid uuid: {}", err)))
    }
}

struct BytesVisitor;

impl<'de> serde::de::Visitor<'de> for BytesVisitor {
    type Value = Uuid;

    #[inline(always)]
    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("raw uuid bytes with size 16")
    }

    #[inline]
    fn visit_seq<S: serde::de::SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let bytes = [
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(0, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(1, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(2, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(3, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(4, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(5, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(6, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(7, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(8, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(9, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(10, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(11, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(12, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(13, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(14, &self)),
            },
            match seq.next_element()? {
                Some(val) => val,
                None => return Err(serde::de::Error::invalid_length(15, &self)),
            },
        ];

        Ok(Self::Value::from_bytes(bytes))
    }
}

impl<'de> Deserialize<'de> for Uuid {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        match des.is_human_readable() {
            true => des.deserialize_str(StrVisitor),
            false => des.deserialize_tuple(UUID_SIZE, BytesVisitor),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Uuid;

    use serde::de::Deserialize;
    use serde::de::value::{BorrowedStrDeserializer, SeqDeserializer, Error as ValueError};

    #[cfg(feature = "osrng")]
    #[test]
    fn serialize_and_deserialize() {
        let uuid = Uuid::v4();
        let uuid_str = uuid.to_str();
        let des = BorrowedStrDeserializer::<ValueError>::new(uuid_str.as_str());
        let res = Uuid::deserialize(des).expect("Unexpected fail");
        assert_eq!(res, uuid);
    }

    #[test]
    fn deserialize_str() {
        let uuid = Uuid::parse_str("60ecb7b6-ba34-5aad-a9ef-9020b1ea210a").unwrap();
        let des = BorrowedStrDeserializer::<ValueError>::new("60ecb7b6-ba34-5aad-a9ef-9020b1ea210a");
        let res = Uuid::deserialize(des).expect("Unexpected fail");
        assert_eq!(res, uuid);

        let uuid = Uuid::parse_str("60ecb7b6ba345aada9ef9020b1ea210a").unwrap();
        let des = BorrowedStrDeserializer::<ValueError>::new("60ecb7b6ba345aada9ef9020b1ea210a");
        let res = Uuid::deserialize(des).expect("Unexpected fail");
        assert_eq!(res, uuid);
    }

    #[test]
    fn deserialize_array_as_human_format() {
        let uuid = Uuid::parse_str("60ecb7b6-ba34-5aad-a9ef-9020b1ea210a").unwrap();
        let uuid_bytes = uuid.bytes();

        let des = SeqDeserializer::<_, ValueError>::new(uuid_bytes.iter().map(|byt| *byt));
        Uuid::deserialize(des).unwrap_err();
    }

    #[test]
    fn deserialize_array_bincode() {
        let uuid = Uuid::parse_str("60ecb7b6-ba34-5aad-a9ef-9020b1ea210a").unwrap();
        let serialized = bincode::serialize(&uuid).unwrap();

        let res: Uuid = bincode::deserialize(&serialized).expect("Unexpected fail");
        assert_eq!(res, uuid);
    }

    #[test]
    fn deserialize_bincode_invalid_len() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        bincode::deserialize::<Uuid>(&bytes).unwrap_err();
    }
}
