// Expected bytes were independently matched by Python hashlib/hmac and Go
// x/crypto. Ed25519 TEST1 is the public RFC8032 section7.1 vector.
use p2pnet_crypto::{expand, extract, hash, hash2, hkdf2, hkdf3, hmac, keyed_hash, Ed25519KeyPair};
fn bytes<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value).unwrap().try_into().unwrap()
}
#[test]
fn m08_hash_and_hmac_match_independent_fixed_bytes() {
    let cases = [
    ("", "", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", "eaf4bb25938f4d20e72656bbbc7a9bf63c0c18537333c35bdb67db1402661acd"),
    ("000102", "030a11", "e8f91c6ef232a041452ab0e149070cdd7dd1769e75b3a5921be37876c45c9900", "2c9f39ec1a1f1a452e0c70621edb88d3ca017531231ed5aa47b3418fc9fe165e"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e", "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc", "e57cb79487dd57902432b250733813bd96a84efce59f650fac26e6696aefafc3", "05030c7c6672e6955702acf6ed9bfc6dac1801c94cd22b15f32e3024d133da55"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bc", "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e", "19fe6a360646360464581aa20181930f5b0c06728dbc687968e5145187be22a1"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40", "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3", "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472", "49ea6973cd0aa1602bfc59bb13d95993f9a2bc3fed202b6ebb4a6e1e0ba63058"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80", "030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c", "5bd169e67c82c2c2e98ef7008bdf261f2ddf30b1c00f9e7f275bb3e8a28dc9a2", "92fa08a5d6c7e93d02273a9ae9a9c15b62a5a7028cee7d0b5a8d9b48da9fc225"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfe", "03", "f03f5789d3336b80d002d59fdf918bdb775b00956ed5528e86aa994acb38fe2d", "196833b92efdf2c24bd17da0e48998f1383e929cac8906ef4fe1ee1521490a0c"),
 ];
    for (message, key, expected_hash, expected_mac) in cases {
        let message = hex::decode(message).unwrap();
        let key = hex::decode(key).unwrap();
        assert_eq!(hex::encode(hash(&message)), expected_hash);
        let split = message.len() / 2;
        assert_eq!(
            hex::encode(hash2(&message[..split], &message[split..])),
            expected_hash
        );
        assert_eq!(hex::encode(hmac(&key, &message)), expected_mac);
        assert_eq!(hex::encode(keyed_hash(&key, &message)), expected_mac);
    }
}
#[test]
fn m08_hkdf_matches_independent_extract_and_blocks() {
    let ck = bytes::<32>("4242424242424242424242424242424242424242424242424242424242424242");
    let ikm = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").unwrap();
    let info = hex::decode("7032776c616e20636f6d7061746962696c6974792066697874757265").unwrap();
    let prk = extract(&ck, &ikm);
    assert_eq!(
        hex::encode(prk),
        "754a1b6f5b7595f726cbcac143ddd0a714b19cb625f4da9b17e37c8104280f37"
    );
    let expected = [
        bytes::<32>("003af5e8bdf836d8ef75a29c3c484e1aaee06af2ae0639d4f98ab92662a33810"),
        bytes::<32>("853922a360e82647de345bb0b9b6efc5788c75ec67036c6dc6bf2ff80726d49a"),
        bytes::<32>("913cf63d66510a48bb0d157a952f524be3d48d08e15e65c47da40c422409389e"),
    ];
    for n in 1..=3 {
        assert_eq!(expand(&prk, &[], n), expected[..usize::from(n)]);
    }
    assert_eq!(hkdf2(&ck, &ikm), (expected[0], expected[1]));
    assert_eq!(hkdf3(&ck, &ikm), (expected[0], expected[1], expected[2]));
    let expected = [
        bytes::<32>("02ffbf779e5fcf3e2b577af90a21708b4097880e6ce76d70c9457aabe48746aa"),
        bytes::<32>("be580c6c2b3c44498733d7154bf9b32b86ea37325f94346f442ad9ff12cdca56"),
        bytes::<32>("0264716ba8bbb3c7c92967ff8653f559ecac52b4f5447237a7c9278fc0e7825d"),
    ];
    for n in 1..=3 {
        assert_eq!(expand(&prk, &info, n), expected[..usize::from(n)]);
    }
}
#[test]
fn m08_rfc8032_public_seed_and_signature_match_go() {
    let seed = bytes::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = bytes::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = bytes::<64>("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    let kp = Ed25519KeyPair::from_private_key(&seed);
    assert_eq!(kp.public_key(), public);
    assert_eq!(kp.private_key(), seed);
    assert_eq!(kp.sign(b""), signature);
    assert!(Ed25519KeyPair::verify(&public, b"", &signature).is_ok());
    assert!(Ed25519KeyPair::verify(&public, b"changed", &signature).is_err());
    let mut changed_signature = signature;
    changed_signature[0] ^= 1;
    let mut changed_public = public;
    changed_public[0] ^= 1;
    assert!(Ed25519KeyPair::verify(&public, b"", &changed_signature).is_err());
    assert!(Ed25519KeyPair::verify(&changed_public, b"", &signature).is_err());
}
