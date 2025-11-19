// TODO: Gate Tests
// #![cfg(feature = "os-keychain-tests")]
#![cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]

use backend::pinset::keychain::{KeyAttributes, KeyIdentifier, Keychain, SecureKey};
use serial_test::serial;

fn unique_id(prefix: &str) -> KeyIdentifier {
    use rand::{Rng, distributions::Alphanumeric};
    let suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    KeyIdentifier::new(
        "com.p2p-password-manager.test".to_string(),
        format!("{prefix}-{}-{suffix}", std::process::id()),
    )
}

#[test]
#[serial]
fn raw_bytes_round_trip_including_nul_and_non_utf8() {
    let kc = match Keychain::new() {
        Ok(k) => k,
        Err(_) => return,
    };

    let id = unique_id("raw-roundtrip");
    let attrs = KeyAttributes::new(id.clone());

    // Clean up
    let _ = kc.delete_key(&id);

    // Includes NULs and non-UTF-8
    let data = vec![0x00, 0xff, 0x01, 0x00, 0xfe, 0x7f, 0x80, 0xc3, 0x28];
    let key = SecureKey::from(data.clone());

    kc.store_key(key, attrs).expect("store raw key");

    let out = kc.retrieve_key(&id).expect("retrieve raw key");
    assert_eq!(out.as_bytes(), &data[..]);

    let _ = kc.delete_key(&id);
}

#[test]
#[serial]
fn update_preserves_raw_bytes() {
    let kc = Keychain::new().unwrap();
    let id = unique_id("raw-update");
    let attrs = KeyAttributes::new(id.clone());
    let _ = kc.delete_key(&id);

    let v1 = vec![0x00, 0x01, 0xff];
    kc.store_key(SecureKey::from(v1.clone()), attrs.clone())
        .unwrap();

    let v2 = vec![0xaa, 0xbb, 0x00, 0xcc];
    kc.update_key(SecureKey::from(v2.clone()), attrs).unwrap();

    let out = kc.retrieve_key(&id).unwrap();
    assert_eq!(out.as_bytes(), &v2[..]);

    let _ = kc.delete_key(&id);
}
