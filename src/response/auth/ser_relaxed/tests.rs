use super::{
    super::{super::super::request::register::USER_HANDLE_MIN_LEN, AuthenticatorAttachment},
    DiscoverableAuthenticationRelaxed, DiscoverableCustomAuthentication,
    NonDiscoverableAuthenticationRelaxed, NonDiscoverableCustomAuthentication,
};
use rsa::sha2::{Digest as _, Sha256};
use serde::de::{Error as _, Unexpected};
use serde_json::Error;
#[expect(clippy::unwrap_used, reason = "OK in tests")]
#[expect(clippy::indexing_slicing, reason = "comments justify correctness")]
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "a lot to test"
)]
#[test]
fn eddsa_authentication_deserialize_data_mismatch() {
    let c_data_json = serde_json::json!({}).to_string();
    let auth_data: [u8; 37] = [
        // `rpIdHash`.
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        // `flags`.
        0b0000_0101,
        // `signCount`.
        0,
        0,
        0,
        0,
    ];
    let b64_cdata_json = base64url_nopad::encode(c_data_json.as_bytes());
    let b64_adata = base64url_nopad::encode(auth_data.as_slice());
    let b64_sig = base64url_nopad::encode([].as_slice());
    let b64_user = base64url_nopad::encode(b"\x00".as_slice());
    // Base case is valid.
    assert!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "authenticatorAttachment": "cross-platform",
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .is_ok_and(
            |auth| auth.0.response.client_data_json == c_data_json.as_bytes()
                && auth.0.response.authenticator_data_and_c_data_hash[..37] == auth_data
                && auth.0.response.authenticator_data_and_c_data_hash[37..]
                    == *Sha256::digest(c_data_json.as_bytes())
                && matches!(
                    auth.0.authenticator_attachment,
                    AuthenticatorAttachment::CrossPlatform
                )
        )
    );
    // `id` and `rawId` mismatch.
    let mut err = Error::invalid_value(
        Unexpected::Bytes(
            base64url_nopad::decode(b"ABABABABABABABABABABAA")
                .unwrap()
                .as_slice(),
        ),
        &format!("id and rawId to match: CredentialId({:?})", [0u8; 16]).as_str(),
    )
    .to_string()
    .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "ABABABABABABABABABABAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "authenticatorAttachment": "cross-platform",
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // missing `id`.
    err = Error::missing_field("id").to_string().into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "authenticatorAttachment": "cross-platform",
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `id`.
    err = Error::invalid_type(Unexpected::Other("null"), &"CredentialId")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": null,
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // missing `rawId`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // `null` `rawId`.
    err = Error::invalid_type(Unexpected::Other("null"), &"CredentialId")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": null,
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `authenticatorData`.
    err = Error::missing_field("authenticatorData")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `authenticatorData`.
    err = Error::invalid_type(Unexpected::Other("null"), &"AuthenticatorData")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": null,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `signature`.
    err = Error::missing_field("signature").to_string().into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `signature`.
    err = Error::invalid_type(Unexpected::Other("null"), &"base64url-encoded data")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": null,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `userHandle`.
    drop(
        serde_json::from_str::<NonDiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // `null` `userHandle`.
    drop(
        serde_json::from_str::<NonDiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": null,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // `null` `authenticatorAttachment`.
    assert!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "authenticatorAttachment": null,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .is_ok_and(|auth| matches!(
            auth.0.authenticator_attachment,
            AuthenticatorAttachment::None
        ))
    );
    // Unknown `authenticatorAttachment`.
    err = Error::invalid_value(
        Unexpected::Str("Platform"),
        &"'platform' or 'cross-platform'",
    )
    .to_string()
    .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "authenticatorAttachment": "Platform",
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `clientDataJSON`.
    err = Error::missing_field("clientDataJSON")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `clientDataJSON`.
    err = Error::invalid_type(Unexpected::Other("null"), &"base64url-encoded data")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": null,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `response`.
    err = Error::missing_field("response").to_string().into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `response`.
    err = Error::invalid_type(Unexpected::Other("null"), &"AuthenticatorAssertion")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": null,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Empty `response`.
    err = Error::missing_field("clientDataJSON")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {},
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `clientExtensionResults`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // `null` `clientExtensionResults`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": null,
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // Missing `type`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // `null` `type`.
    err = Error::invalid_type(Unexpected::Other("null"), &"public-key")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": null
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Not exactly `public-type` `type`.
    err = Error::invalid_value(Unexpected::Str("Public-key"), &"public-key")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "Public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null`.
    err = Error::invalid_type(Unexpected::Other("null"), &"PublicKeyCredential")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!(null).to_string().as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Empty.
    err = Error::missing_field("response").to_string().into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({}).to_string().as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Unknown field in `response`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                    "foo": true,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // Duplicate field in `response`.
    err = Error::duplicate_field("userHandle")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            format!(
                "{{
                   \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"response\": {{
                       \"clientDataJSON\": \"{b64_cdata_json}\",
                       \"authenticatorData\": \"{b64_adata}\",
                       \"signature\": \"{b64_sig}\",
                       \"userHandle\": \"{b64_user}\",
                       \"userHandle\": \"{b64_user}\"
                   }},
                   \"clientExtensionResults\": {{}},
                   \"type\": \"public-key\"
                 }}"
            )
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Unknown field in `PublicKeyCredential`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key",
                "foo": true,
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // Duplicate field in `PublicKeyCredential`.
    err = Error::duplicate_field("id").to_string().into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            format!(
                "{{
                   \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"response\": {{
                       \"clientDataJSON\": \"{b64_cdata_json}\",
                       \"authenticatorData\": \"{b64_adata}\",
                       \"signature\": \"{b64_sig}\",
                       \"userHandle\": \"{b64_user}\"
                   }},
                   \"clientExtensionResults\": {{}},
                   \"type\": \"public-key\"
                 }}"
            )
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Base case is valid.
    assert!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "authenticatorAttachment": "cross-platform",
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .is_ok_and(
            |auth| auth.0.response.client_data_json == c_data_json.as_bytes()
                && auth.0.response.authenticator_data_and_c_data_hash[..37] == auth_data
                && auth.0.response.authenticator_data_and_c_data_hash[37..]
                    == *Sha256::digest(c_data_json.as_bytes())
                && matches!(
                    auth.0.authenticator_attachment,
                    AuthenticatorAttachment::CrossPlatform
                )
        )
    );
    // missing `id`.
    err = Error::missing_field("id").to_string().into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "authenticatorAttachment": "cross-platform",
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `id`.
    err = Error::invalid_type(Unexpected::Other("null"), &"CredentialId")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": null,
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `authenticatorData`.
    err = Error::missing_field("authenticatorData")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "signature": b64_sig,
                "userHandle": b64_user,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `authenticatorData`.
    err = Error::invalid_type(Unexpected::Other("null"), &"AuthenticatorData")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": null,
                "signature": b64_sig,
                "userHandle": b64_user,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `signature`.
    err = Error::missing_field("signature").to_string().into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "userHandle": b64_user,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `signature`.
    err = Error::invalid_type(Unexpected::Other("null"), &"base64url-encoded data")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": null,
                "userHandle": b64_user,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `userHandle`.
    drop(
        serde_json::from_str::<NonDiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // `null` `userHandle`.
    drop(
        serde_json::from_str::<NonDiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": null,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // `null` `authenticatorAttachment`.
    assert!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "authenticatorAttachment": null,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .is_ok_and(|auth| matches!(
            auth.0.authenticator_attachment,
            AuthenticatorAttachment::None
        ))
    );
    // Unknown `authenticatorAttachment`.
    err = Error::invalid_value(
        Unexpected::Str("Platform"),
        &"'platform' or 'cross-platform'",
    )
    .to_string()
    .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "authenticatorAttachment": "Platform",
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `clientDataJSON`.
    err = Error::missing_field("clientDataJSON")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `clientDataJSON`.
    err = Error::invalid_type(Unexpected::Other("null"), &"base64url-encoded data")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": null,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Empty.
    err = Error::missing_field("authenticatorData")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({}).to_string().as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `clientExtensionResults`.
    err = Error::missing_field("clientExtensionResults")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `clientExtensionResults`.
    err = Error::invalid_type(Unexpected::Other("null"), &"ClientExtensionsOutputs")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "clientExtensionResults": null,
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    drop(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "clientExtensionResults": {},
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // `null` `type`.
    err = Error::invalid_type(Unexpected::Other("null"), &"public-key")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "clientExtensionResults": {},
                "type": null
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Not exactly `public-type` `type`.
    err = Error::invalid_value(Unexpected::Str("Public-key"), &"public-key")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "clientExtensionResults": {},
                "type": "Public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null`.
    err = Error::invalid_type(Unexpected::Other("null"), &"CustomAuthentication")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!(null).to_string().as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Unknown field.
    err = Error::unknown_field(
        "foo",
        [
            "authenticatorAttachment",
            "authenticatorData",
            "clientDataJSON",
            "clientExtensionResults",
            "id",
            "signature",
            "type",
            "userHandle",
        ]
        .as_slice(),
    )
    .to_string()
    .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "clientDataJSON": b64_cdata_json,
                "authenticatorData": b64_adata,
                "signature": b64_sig,
                "userHandle": b64_user,
                "foo": true,
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Duplicate field.
    err = Error::duplicate_field("userHandle")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableCustomAuthentication<USER_HANDLE_MIN_LEN>>(
            format!(
                "{{
                   \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"clientDataJSON\": \"{b64_cdata_json}\",
                   \"authenticatorData\": \"{b64_adata}\",
                   \"signature\": \"{b64_sig}\",
                   \"userHandle\": \"{b64_user}\",
                   \"userHandle\": \"{b64_user}\"
                   \"clientExtensionResults\": {{}},
                   \"type\": \"public-key\"
                 }}"
            )
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
}
#[expect(clippy::unwrap_used, reason = "OK in tests")]
#[expect(clippy::indexing_slicing, reason = "comments justify correctness")]
#[expect(clippy::too_many_lines, reason = "a lot to test")]
#[test]
fn client_extensions() {
    let c_data_json = serde_json::json!({}).to_string();
    let auth_data: [u8; 37] = [
        // `rpIdHash`.
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        // `flags`.
        0b0000_0101,
        // `signCount`.
        0,
        0,
        0,
        0,
    ];
    let b64_cdata_json = base64url_nopad::encode(c_data_json.as_bytes());
    let b64_adata = base64url_nopad::encode(auth_data.as_slice());
    let b64_sig = base64url_nopad::encode([].as_slice());
    let b64_user = base64url_nopad::encode(b"\x00".as_slice());
    // Base case is valid.
    assert!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "authenticatorAttachment": "cross-platform",
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .is_ok_and(
            |auth| auth.0.response.client_data_json == c_data_json.as_bytes()
                && auth.0.response.authenticator_data_and_c_data_hash[..37] == auth_data
                && auth.0.response.authenticator_data_and_c_data_hash[37..]
                    == *Sha256::digest(c_data_json.as_bytes())
                && matches!(
                    auth.0.authenticator_attachment,
                    AuthenticatorAttachment::CrossPlatform
                )
        )
    );
    // `null` `prf`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "prf": null
                },
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // Unknown `clientExtensionResults`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "Prf": null
                },
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // Duplicate field.
    let mut err = Error::duplicate_field("prf").to_string().into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            format!(
                "{{
                   \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"response\": {{
                       \"clientDataJSON\": \"{b64_cdata_json}\",
                       \"authenticatorData\": \"{b64_adata}\",
                       \"signature\": \"{b64_sig}\",
                       \"userHandle\": \"{b64_user}\"
                   }},
                   \"clientExtensionResults\": {{
                       \"prf\": null,
                       \"prf\": null
                   }},
                   \"type\": \"public-key\"
                 }}"
            )
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `results`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "prf": {
                        "results": null,
                    }
                },
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // Duplicate field in `prf`.
    err = Error::duplicate_field("results").to_string().into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            format!(
                "{{
                   \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"response\": {{
                       \"clientDataJSON\": \"{b64_cdata_json}\",
                       \"authenticatorData\": \"{b64_adata}\",
                       \"signature\": \"{b64_sig}\",
                       \"userHandle\": \"{b64_user}\"
                   }},
                   \"clientExtensionResults\": {{
                       \"prf\": {{
                           \"results\": null,
                           \"results\": null
                       }}
                   }},
                   \"type\": \"public-key\"
                 }}"
            )
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `first`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "prf": {
                        "results": {},
                    }
                },
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // `null` `first`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "prf": {
                        "results": {
                            "first": null
                        },
                    }
                },
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // `null` `second`.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "prf": {
                        "results": {
                            "first": null,
                            "second": null
                        },
                    }
                },
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // Non-`null` `first`.
    err = Error::invalid_type(Unexpected::Option, &"null")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "prf": {
                        "results": {
                            "first": ""
                        },
                    }
                },
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Non-`null` `second`.
    err = Error::invalid_type(Unexpected::Option, &"null")
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "prf": {
                        "results": {
                            "first": null,
                            "second": ""
                        },
                    }
                },
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // `enabled` is still not allowed.
    err = Error::unknown_field("enabled", ["results"].as_slice())
        .to_string()
        .into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "prf": {
                        "enabled": true,
                        "results": null
                    }
                },
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
    // Unknown `prf` field.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "prf": {
                        "foo": true,
                        "results": null
                    }
                },
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // Unknown `results` field.
    drop(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata_json,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {
                    "prf": {
                        "results": {
                            "first": null,
                            "Second": null
                        }
                    }
                },
                "type": "public-key"
            })
            .to_string()
            .as_str(),
        )
        .unwrap(),
    );
    // Duplicate field in `results`.
    err = Error::duplicate_field("first").to_string().into_bytes();
    assert_eq!(
        serde_json::from_str::<DiscoverableAuthenticationRelaxed<USER_HANDLE_MIN_LEN>>(
            format!(
                "{{
                   \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                   \"response\": {{
                       \"clientDataJSON\": \"{b64_cdata_json}\",
                       \"authenticatorData\": \"{b64_adata}\",
                       \"signature\": \"{b64_sig}\",
                       \"userHandle\": \"{b64_user}\"
                   }},
                   \"clientExtensionResults\": {{
                       \"prf\": {{
                           \"results\": {{
                               \"first\": null,
                               \"first\": null
                           }}
                       }}
                   }},
                   \"type\": \"public-key\"
                 }}"
            )
            .as_str()
        )
        .unwrap_err()
        .to_string()
        .into_bytes()
        .get(..err.len()),
        Some(err.as_slice())
    );
}
