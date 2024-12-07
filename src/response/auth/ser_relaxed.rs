#[cfg(doc)]
use super::super::Challenge;
use super::{
    super::{
        auth::ser::{
            AuthenticatorAssertionVisitor, ClientExtensionsOutputs, ClientExtensionsOutputsVisitor,
            AUTH_ASSERT_FIELDS, EXT_FIELDS,
        },
        ser::{AuthenticationExtensionsPrfOutputsHelper, ClientExtensions, PublicKeyCredential},
        ser_relaxed::AuthenticationExtensionsPrfValuesRelaxed,
    },
    Authentication, AuthenticatorAssertion,
};
use core::marker::PhantomData;
#[cfg(doc)]
use data_encoding::BASE64URL_NOPAD;
use serde::de::{Deserialize, Deserializer};
/// `newtype` around `ClientExtensionsOutputs` with a "relaxed" [`Self::deserialize`] implementation.
struct ClientExtensionsOutputsRelaxed(pub ClientExtensionsOutputs);
impl ClientExtensions for ClientExtensionsOutputsRelaxed {
    fn empty() -> Self {
        Self(ClientExtensionsOutputs::empty())
    }
}
impl<'de> Deserialize<'de> for ClientExtensionsOutputsRelaxed {
    /// Same as [`ClientExtensionsOutputs::deserialize`] except unknown keys are ignored.
    ///
    /// Note that duplicate keys are still forbidden.
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_struct(
                "ClientExtensionsOutputsRelaxed",
                EXT_FIELDS,
                ClientExtensionsOutputsVisitor::<
                    true,
                    AuthenticationExtensionsPrfOutputsHelper<
                        true,
                        false,
                        AuthenticationExtensionsPrfValuesRelaxed,
                    >,
                >(PhantomData),
            )
            .map(Self)
    }
}
/// `newtype` around `AuthenticatorAssertion` with a "relaxed" [`Self::deserialize`] implementation.
#[derive(Debug)]
pub struct AuthenticatorAssertionRelaxed(pub AuthenticatorAssertion);
impl<'de> Deserialize<'de> for AuthenticatorAssertionRelaxed {
    /// Same as [`AuthenticatorAssertion::deserialize`] except unknown keys are ignored.
    ///
    /// Note that duplicate keys are still forbidden.
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_struct(
                "AuthenticatorAssertionRelaxed",
                AUTH_ASSERT_FIELDS,
                AuthenticatorAssertionVisitor::<true>,
            )
            .map(Self)
    }
}
/// `newtype` around `Authentication` with a "relaxed" [`Self::deserialize`] implementation.
#[derive(Debug)]
pub struct AuthenticationRelaxed(pub Authentication);
impl<'de> Deserialize<'de> for AuthenticationRelaxed {
    /// Same as [`Authentication::deserialize`] except unknown keys are ignored;
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-authenticationresponsejson-response) is deserialized
    /// via [`AuthenticatorAssertionRelaxed::deserialize`];
    /// [`clientExtensionResults`](https://www.w3.org/TR/webauthn-3/#dom-authenticationresponsejson-clientextensionresults)
    /// is deserialized such unknown keys are ignored but duplicate keys are forbidden,
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsclientoutputs-prf) is `null` or an
    /// [`AuthenticationExtensionsPRFOutputs`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfoutputs)
    /// such that unknown keys are allowed but duplicate keys are forbidden,
    /// [`enabled`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-enabled)
    /// is forbidden (including being assigned `null`),
    /// [`results`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-results) must not exist,
    /// be `null`, or be an
    /// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues)
    /// where unknown keys are ignored, duplicate keys are forbidden,
    /// [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first) is not required but
    /// if it exists it must be `null`, and
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second) can exist but
    /// must be `null` if so; and only
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-authenticationresponsejson-id) and `response` are required. For
    /// the other fields, they are allowed to not exist or be `null`.
    ///
    /// Note that duplicate keys are still forbidden, and data matching still applies when applicable.
    #[expect(clippy::unreachable, reason = "when there is a bug, we want to crash")]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        PublicKeyCredential::<
            true,
            false,
            AuthenticatorAssertionRelaxed,
            ClientExtensionsOutputsRelaxed,
        >::deserialize(deserializer)
        .map(|cred| {
            Self(Authentication {
                raw_id: cred.id.unwrap_or_else(|| {
                    unreachable!("there is a bug in PublicKeyCredential::deserialize")
                }),
                response: cred.response.0,
                authenticator_attachment: cred.authenticator_attachment,
            })
        })
    }
}
#[cfg(test)]
mod tests {
    use super::{
        super::{super::BASE64URL_NOPAD_ENC, AuthenticatorAttachment},
        AuthenticationRelaxed,
    };
    use rsa::sha2::{Digest as _, Sha256};
    use serde::de::{Error as _, Unexpected};
    use serde_json::Error;
    #[test]
    fn eddsa_authentication_deserialize_data_mismatch() {
        let c_data_json = serde_json::json!({}).to_string();
        let auth_data = [
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
        let b64_cdata = BASE64URL_NOPAD_ENC.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD_ENC.encode(auth_data.as_slice());
        let b64_sig = BASE64URL_NOPAD_ENC.encode([].as_slice());
        let b64_user = BASE64URL_NOPAD_ENC.encode(b"\x00".as_slice());
        // Base case is valid.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
        .map_or(false, |auth| auth.0.response.client_data_json
            == c_data_json.as_bytes()
            && auth.0.response.authenticator_data_and_c_data_hash[..37] == auth_data
            && auth.0.response.authenticator_data_and_c_data_hash[37..]
                == *Sha256::digest(c_data_json.as_bytes()).as_slice()
            && matches!(
                auth.0.authenticator_attachment,
                AuthenticatorAttachment::CrossPlatform
            )));
        // `id` and `rawId` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Bytes(
                BASE64URL_NOPAD_ENC
                    .decode("ABABABABABABABABABABAA".as_bytes())
                    .unwrap()
                    .as_slice(),
            ),
            &format!("id and rawId to match: CredentialId({:?})", [0; 16]).as_str(),
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "ABABABABABABABABABABAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // missing `id`.
        err = Error::missing_field("id").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `id`.
        err = Error::invalid_type(Unexpected::Other("null"), &"id")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": null,
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // missing `rawId`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
        .is_ok());
        // `null` `rawId`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": null,
                "response": {
                    "clientDataJSON": b64_cdata,
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
        .is_ok());
        // Missing `authenticatorData`.
        err = Error::missing_field("authenticatorData")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `authenticatorData`.
        err = Error::invalid_type(Unexpected::Other("null"), &"AuthenticatorData")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // Missing `signature`.
        err = Error::missing_field("signature").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `signature`.
        err = Error::invalid_type(Unexpected::Other("null"), &"base64url-encoded data")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // Missing `userHandle`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .is_ok());
        // `null` `userHandle`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": null,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .is_ok());
        // `null` `authenticatorAttachment`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
        .map_or(false, |auth| matches!(
            auth.0.authenticator_attachment,
            AuthenticatorAttachment::None
        )));
        // Unknown `authenticatorAttachment`.
        err = Error::invalid_value(
            Unexpected::Str("Platform"),
            &"'platform' or 'cross-platform'",
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // Missing `clientDataJSON`.
        err = Error::missing_field("clientDataJSON")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `clientDataJSON`.
        err = Error::invalid_type(Unexpected::Other("null"), &"base64url-encoded data")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
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
            .into_bytes()[..err.len()],
            err
        );
        // Missing `response`.
        err = Error::missing_field("response").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `response`.
        err = Error::invalid_type(Unexpected::Other("null"), &"AuthenticatorAssertion")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
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
            .into_bytes()[..err.len()],
            err
        );
        // Empty `response`.
        err = Error::missing_field("clientDataJSON")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
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
            .into_bytes()[..err.len()],
            err
        );
        // Missing `clientExtensionResults`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .is_ok());
        // `null` `clientExtensionResults`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": null,
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .is_ok());
        // Missing `type`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
            })
            .to_string()
            .as_str()
        )
        .is_ok());
        // `null` `type`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
        .is_ok());
        // Not exactly `public-type` `type`.
        err = Error::invalid_value(Unexpected::Str("Public-key"), &"public-key")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // `null`.
        err = Error::invalid_type(Unexpected::Other("null"), &"PublicKeyCredential")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!(null).to_string().as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Empty.
        err = Error::missing_field("response").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({}).to_string().as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Unknown field in `response`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                    "foo": true,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
        )
        .is_ok());
        // Duplicate field in `response`.
        err = Error::duplicate_field("userHandle")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
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
            .into_bytes()[..err.len()],
            err
        );
        // Unknown field in `PublicKeyCredential`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                },
                "clientExtensionResults": {},
                "type": "public-key",
                "foo": true,
            })
            .to_string()
            .as_str()
        )
        .is_ok());
        // Duplicate field in `PublicKeyCredential`.
        err = Error::duplicate_field("id").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
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
            .into_bytes()[..err.len()],
            err
        );
    }
    #[test]
    fn client_extensions() {
        let c_data_json = serde_json::json!({}).to_string();
        let auth_data = [
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
        let b64_cdata = BASE64URL_NOPAD_ENC.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD_ENC.encode(auth_data.as_slice());
        let b64_sig = BASE64URL_NOPAD_ENC.encode([].as_slice());
        let b64_user = BASE64URL_NOPAD_ENC.encode(b"\x00".as_slice());
        // Base case is valid.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
        .map_or(false, |auth| auth.0.response.client_data_json
            == c_data_json.as_bytes()
            && auth.0.response.authenticator_data_and_c_data_hash[..37] == auth_data
            && auth.0.response.authenticator_data_and_c_data_hash[37..]
                == *Sha256::digest(c_data_json.as_bytes()).as_slice()
            && matches!(
                auth.0.authenticator_attachment,
                AuthenticatorAttachment::CrossPlatform
            )));
        // `null` `prf`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
            .as_str()
        )
        .is_ok());
        // Unknown `clientExtensionResults`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
            .as_str()
        )
        .is_ok());
        // Duplicate field.
        let mut err = Error::duplicate_field("prf").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `results`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
            .as_str()
        )
        .is_ok());
        // Duplicate field in `prf`.
        err = Error::duplicate_field("results").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
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
            .into_bytes()[..err.len()],
            err
        );
        // Missing `first`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
            .as_str()
        )
        .is_ok());
        // `null` `first`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
            .as_str()
        )
        .is_ok());
        // `null` `second`.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
            .as_str()
        )
        .is_ok());
        // Non-`null` `first`.
        err = Error::invalid_type(Unexpected::Option, &"null")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // Non-`null` `second`.
        err = Error::invalid_type(Unexpected::Option, &"null")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // `enabled` is still not allowed.
        err = Error::unknown_field("enabled", ["results"].as_slice())
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // Unknown `prf` field.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
            .as_str()
        )
        .is_ok());
        // Unknown `results` field.
        assert!(serde_json::from_str::<AuthenticationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
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
            .as_str()
        )
        .is_ok());
        // Duplicate field in `results`.
        err = Error::duplicate_field("first").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
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
            .into_bytes()[..err.len()],
            err
        );
    }
}
