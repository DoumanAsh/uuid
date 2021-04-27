use lolid::Uuid;

#[test]
fn should_convert_from_guid() {
    let uuid = Uuid::from_guid(0x4a35229d, 0x5527, 0x4f30, [0x86, 0x47, 0x9d, 0xc5, 0x4e, 0x1e, 0xe1, 0xe8]);
    assert!(uuid.is_version(lolid::Version::Random));
    assert!(uuid.is_variant());
    assert_eq!(uuid.to_str(), "4a35229d-5527-4f30-8647-9dc54e1ee1e8");
}

#[test]
fn should_fail_to_create_from_invalid_slice() {
    assert!(Uuid::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).is_none());
    assert!(Uuid::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]).is_some());
    assert!(Uuid::from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]).is_none());
}

#[test]
fn should_convert_uuid_to_str() {
    let uuid = Uuid::nil().to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "00000000-0000-0000-0000-000000000000");
    assert!(Uuid::nil().is_version(lolid::Version::Nil));
    assert!(!Uuid::nil().is_variant());

    let uuid = Uuid::from_slice(&[254, 255, 100, 1, 0, 255, 255, 253, 40, 20, 150, 125, 130, 140, 200, 99]).unwrap();
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
    assert_eq!(uuid.to_str().as_str(), "20616934-4ba2-11e7-8000-010203040506");

    let uuid_next = Uuid::v1(lolid::Timestamp::from_unix(time).set_counter(1), MAC);
    assert!(uuid_next.is_version(lolid::Version::Mac));
    assert!(!uuid_next.is_version(lolid::Version::Sha1));
    assert!(uuid_next.is_variant());
    assert_ne!(uuid.to_str().as_str(), uuid_next.to_str().as_str());
    assert_eq!(uuid_next.to_str().as_str(), "20616934-4ba2-11e7-8001-010203040506");
}

#[cfg(feature = "std")]
#[test]
fn check_v1_std() {
    const MAC: [u8; 6] = [1, 2, 3, 4, 5, 6];

    let uuid_before = Uuid::v1(lolid::Timestamp::now(), MAC);
    let uuid_after = Uuid::v1(lolid::Timestamp::now(), MAC);
    assert_ne!(uuid_after, uuid_before);
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

#[cfg(feature = "md5")]
#[test]
fn check_uuid3() {
    let uuid = Uuid::v3(lolid::NAMESPACE_DNS, "example.org".as_bytes());
    assert!(uuid.is_version(lolid::Version::Md5));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "04738bdf-b25a-3829-a801-b21a1d25095b");

    let uuid = Uuid::v3(lolid::NAMESPACE_DNS, "rust-lang.org".as_bytes());
    assert!(uuid.is_version(lolid::Version::Md5));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "c6db027c-615c-3b4d-959e-1a917747ca5a");

    let uuid = Uuid::v3(lolid::NAMESPACE_URL, "rust-lang.org".as_bytes());
    assert!(uuid.is_version(lolid::Version::Md5));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "7ed45aaf-e75b-3130-8e33-ee4d9253b19f");

    let uuid = Uuid::v3(lolid::NAMESPACE_OID, "rust-lang.org".as_bytes());
    assert!(uuid.is_version(lolid::Version::Md5));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "6506a0ec-4d79-3e18-8c2b-f2b6b34f2b6d");

    let uuid = Uuid::v3(lolid::NAMESPACE_X500, "rust-lang.org".as_bytes());
    assert!(uuid.is_version(lolid::Version::Md5));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "bcee7a9c-52f1-30c6-a3cc-8c72ba634990");
}

#[cfg(feature = "sha1")]
#[test]
fn check_uuid5() {
    let uuid = Uuid::v5(lolid::NAMESPACE_DNS, "example.org".as_bytes());
    assert!(uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "aad03681-8b63-5304-89e0-8ca8f49461b5");

    let uuid = Uuid::v5(lolid::NAMESPACE_DNS, "rust-lang.org".as_bytes());
    assert!(uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "c66bbb60-d62e-5f17-a399-3a0bd237c503");

    let uuid = Uuid::v5(lolid::NAMESPACE_URL, "rust-lang.org".as_bytes());
    assert!(uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "c48d927f-4122-5413-968c-598b1780e749");

    let uuid = Uuid::v5(lolid::NAMESPACE_OID, "rust-lang.org".as_bytes());
    assert!(uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "8ef61ecb-977a-5844-ab0f-c25ef9b8d5d6");

    let uuid = Uuid::v5(lolid::NAMESPACE_X500, "rust-lang.org".as_bytes());
    assert!(uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "26c9c3e9-49b7-56da-8b9f-a0fb916a71a3");
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

    let err = Uuid::parse_str("60ecb7b6-ba34-5aa,-a9ef-9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidByte(b',', 17));

    let err = Uuid::parse_str("60ecb7b6-ba3,-5aad-a9ef-9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidByte(b',', 12));

    let err = Uuid::parse_str("60ecb7b6-ba34-5aad-a9e,-9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidByte(b',', 22));

    let err = Uuid::parse_str(",0ecb7b6ba345aada9ef9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidByte(b',', 0));

    let err = Uuid::parse_str("60ecb7b6ba345aada9ef9020b1ea210,").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidByte(b',', 31));

    let err = Uuid::parse_str("60ecb7b6ba345aada9ef9020b1ea210ag").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidLength(33));

    let err = Uuid::parse_str("60ecb7b-ba34-5aad-a9ef-9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidLength(35));

    let err = Uuid::parse_str("60ecb7b6gba34g5aadga9efg9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidGroup(1));

    let err = Uuid::parse_str("60ecb7b6-ba34g5aad-a9ef-9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidGroup(2));

    let err = Uuid::parse_str("60ecb7b6-ba34-5aadga9ef-9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidGroup(3));

    let err = Uuid::parse_str("60ecb7b6-ba34-5aad-a9efg9020b1ea210a").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidGroup(4));

    let err = Uuid::parse_str("60ecb7b6-ba34-5aad-a9ef-9020b1ea210a-").unwrap_err();
    assert_eq!(err, lolid::ParseError::InvalidLength(37));
}
