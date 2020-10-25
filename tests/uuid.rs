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

    let uuid = Uuid::v5(lolid::NAMESPACE_URL, "lolka".as_bytes());
    assert!(uuid.is_version(lolid::Version::Sha1));
    assert!(uuid.is_variant());

    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "60ecb7b6-ba34-5aad-a9ef-9020b1ea210a");
}
