use lolid::Uuid;

#[test]
fn should_convert_uuid_to_str() {
    let uuid = Uuid::nil().to_string();
    assert_eq!(uuid.len(), 36);
    assert_eq!(uuid, "00000000-0000-0000-0000-000000000000");

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
    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_ne!(uuid, Uuid::prng().to_string());
}

#[cfg(feature = "osrng")]
#[test]
fn check_random_uuid4_osrng() {
    let uuid = Uuid::osrng();
    assert!(uuid.is_version(lolid::Version::Random));
    assert!(!uuid.is_version(lolid::Version::Sha1));
    let uuid = uuid.to_string();
    assert_eq!(uuid.len(), 36);
    assert_ne!(uuid, Uuid::osrng().to_string());
}
