use lolid::Uuid;

#[test]
fn should_convert_uuid_to_str() {
    let uuid = Uuid::nil().to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "00000000-0000-0000-0000-000000000000");
    assert!(Uuid::nil().is_version(lolid::Version::Nil));
    assert!(!Uuid::nil().is_variant());

    let uuid = Uuid::from_bytes([254, 255, 100, 1, 0, 255, 255, 253, 40, 20, 150, 125, 130, 140, 200, 99]);
    assert_eq!(uuid.to_string().len(), 36);
    assert_eq!(uuid.to_string(), "feff6401-00ff-fffd-2814-967d828cc863");
    let uuid = uuid.set_variant().set_version(lolid::Version::Random);
    assert_eq!(uuid.to_string(), "feff6401-00ff-4ffd-a814-967d828cc863");
    let uuid = uuid.set_variant().set_version(lolid::Version::Random);
    assert_eq!(uuid.to_string(), "feff6401-00ff-4ffd-a814-967d828cc863");
}

#[test]
fn check_v1() {
    const MAC: [u8; 6] = [1, 2, 3, 4, 5, 6];

    let time = core::time::Duration::new(1_496_854_535, 812_946_000);
    let uuid = Uuid::v1(lolid::Timestamp::from_unix(time), MAC);

    assert!(uuid.is_version(lolid::Version::Mac));
    assert!(!uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());
    assert_eq!(uuid.as_str().as_str(), "20616934-4ba2-11e7-8000-010203040506");

    let uuid_next = Uuid::v1(lolid::Timestamp::from_unix(time).set_counter(1), MAC);
    assert!(uuid_next.is_version(lolid::Version::Mac));
    assert!(!uuid_next.is_version(lolid::Version::Sha1));
    assert!(uuid_next.is_variant());
    assert_ne!(uuid.as_str().as_str(), uuid_next.as_str().as_str());
    assert_eq!(uuid_next.as_str().as_str(), "20616934-4ba2-11e7-8001-010203040506");
}

#[cfg(feature = "prng")]
#[test]
fn check_random_uuid4_prng() {
    let uuid = Uuid::prng();
    assert!(uuid.is_version(lolid::Version::Random));
    assert!(!uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());
    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_ne!(uuid, Uuid::prng().to_string());
}

#[cfg(feature = "osrng")]
#[test]
fn check_random_uuid4_osrng() {
    let uuid = Uuid::v4();
    assert!(uuid.is_version(lolid::Version::Random));
    assert!(!uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());
    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_ne!(uuid, Uuid::v4().to_string());
}

#[cfg(feature = "sha1")]
#[test]
fn check_random_uuid5() {
    let uuid = Uuid::v5(lolid::NAMESPACE_DNS, "lolka".as_bytes());
    assert!(uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "2a91f5dc-61a9-5079-aa2b-f82dc6f6e524");
    let parsed = Uuid::parse_str(uuid.as_str()).unwrap();
    assert_eq!(parsed.to_string(), uuid);

    let uuid = Uuid::v5(lolid::NAMESPACE_URL, "lolka".as_bytes());
    assert!(uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "60ecb7b6-ba34-5aad-a9ef-9020b1ea210a");
}

#[test]
fn check_parse_str() {
    let parsed = Uuid::parse_str("60ecb7b6-ba34-5aad-a9ef-9020b1ea210a").unwrap();
    assert!(parsed.is_variant());
    assert!(parsed.is_version(lolid::Version::Sha1));

    let parsed = Uuid::parse_str("60ecb7b6ba345aada9ef9020b1ea210a").unwrap();
    assert!(parsed.is_variant());
    assert!(parsed.is_version(lolid::Version::Sha1));

    let err = Uuid::parse_str(",0ecb7b6-ba34-5aad-a9ef-9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidByte(b',', 0));

    let err = Uuid::parse_str("60ecb7b6-ba34-5aad-a9ef-9020b1ea210,").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidByte(b',', 35));

    let err = Uuid::parse_str(",0ecb7b6ba345aada9ef9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidByte(b',', 0));

    let err = Uuid::parse_str("60ecb7b6ba345aada9ef9020b1ea210,").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidByte(b',', 31));

    let err = Uuid::parse_str("60ecb7b6ba345aada9ef9020b1ea210ag").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidLength(33));

    let err = Uuid::parse_str("60ecb7b-ba34-5aad-a9ef-9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidLength(35));

    let err = Uuid::parse_str("60ecb7b6gba34g5aadga9efg9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidGroupLen(1, 36));

    let err = Uuid::parse_str("60ecb7b6-ba34g5aad-a9ef-9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidGroupLen(2, 9));

    let err = Uuid::parse_str("60ecb7b6-ba34-5aadga9ef-9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidGroupLen(3, 9));

    let err = Uuid::parse_str("60ecb7b6-ba34-5aad-a9efg9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidGroupLen(4, 17));

    let err = Uuid::parse_str("60ecb7b6-ba34-5aad-a9ef-9020b1ea210a-").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidLength(37));
}
