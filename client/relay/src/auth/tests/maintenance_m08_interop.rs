#[test]
fn m08_go_pkcs8_and_eddsa_jws_are_compatible() {
    use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    let original = hex::decode("302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
    let key = SigningKey::from_pkcs8_der(&original).unwrap();
    assert_eq!(
        hex::encode(key.to_bytes()),
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    );
    assert_eq!(
        hex::encode(key.verifying_key().to_bytes()),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    // Both optional-public-key encodings are legal; reparse the new writer's
    // output instead of demanding that DER optional fields stay identical.
    let encoded = key.to_pkcs8_der().unwrap();
    assert_eq!(
        SigningKey::from_pkcs8_der(encoded.as_bytes())
            .unwrap()
            .to_bytes(),
        key.to_bytes()
    );
    let token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6InB1YmxpYy1jb21wYXRpYmlsaXR5LWZpeHR1cmUifQ.eyJzdWIiOiJwdWJsaWMtY29tcGF0aWJpbGl0eS1maXh0dXJlIiwiaWF0Ijo0MTAwMDAwMDAwLCJleHAiOjQyMDAwMDAwMDB9.QbP2lEo16N6UUHAO1O7yNjParLjLSeOIwuX_tRLd93VqBWj0hh37-oPEOgCK9cctbIcpn87usezVS3-JzHjwCQ";
    let public =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
    let policy = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    // This generic fixture exercises signatures/DER only. Production relay
    // policy and all existing claim rejection tests remain separate.
    let decoded = jsonwebtoken::decode::<serde_json::Value>(
        token,
        &jsonwebtoken::DecodingKey::from_ed_der(&public),
        &policy,
    )
    .unwrap();
    assert_eq!(decoded.claims["sub"], "public-compatibility-fixture");
    let mut altered = token.as_bytes().to_vec();
    let last = altered.len() - 2;
    altered[last] = if altered[last] == b'A' { b'B' } else { b'A' };
    assert!(jsonwebtoken::decode::<serde_json::Value>(
        std::str::from_utf8(&altered).unwrap(),
        &jsonwebtoken::DecodingKey::from_ed_der(&public),
        &policy
    )
    .is_err());
}
