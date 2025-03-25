#![expect(
    clippy::question_mark_used,
    reason = "noisy, opinionated, and likely doesn't prevent bugs or improve APIs"
)]
#[cfg(doc)]
use super::super::{Challenge, CredentialId};
use super::{
    super::{
        auth::ser::{
            AUTH_ASSERT_FIELDS, AuthData, AuthenticatorAssertionVisitor, ClientExtensionsOutputs,
            ClientExtensionsOutputsVisitor, EXT_FIELDS,
        },
        ser::{
            AuthenticationExtensionsPrfOutputsHelper, Base64DecodedVal, ClientExtensions,
            PublicKeyCredential, Type,
        },
        ser_relaxed::AuthenticationExtensionsPrfValuesRelaxed,
    },
    Authentication, AuthenticatorAssertion, AuthenticatorAttachment, UserHandle,
};
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
};
#[cfg(doc)]
use data_encoding::BASE64URL_NOPAD;
use serde::de::{Deserialize, Deserializer, Error, MapAccess, Visitor};
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
pub struct AuthenticatorAssertionRelaxed<User>(pub AuthenticatorAssertion<User>);
impl<'de, User> Deserialize<'de> for AuthenticatorAssertionRelaxed<User>
where
    UserHandle<User>: Deserialize<'de>,
{
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
                AuthenticatorAssertionVisitor::<true, User>::new(),
            )
            .map(Self)
    }
}
/// `newtype` around `Authentication` with a "relaxed" [`Self::deserialize`] implementation.
#[derive(Debug)]
pub struct AuthenticationRelaxed<User>(pub Authentication<User>);
impl<'de, User> Deserialize<'de> for AuthenticationRelaxed<User>
where
    UserHandle<User>: Deserialize<'de>,
{
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
            AuthenticatorAssertionRelaxed<User>,
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
/// `newtype` around `Authentication` with a custom [`Self::deserialize`] implementation.
#[derive(Debug)]
pub struct CustomAuthentication<User>(pub Authentication<User>);
impl<'de, User> Deserialize<'de> for CustomAuthentication<User>
where
    UserHandle<User>: Deserialize<'de>,
{
    /// Despite the spec having a
    /// [pre-defined format](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson) that clients
    /// can follow, the downside is the superfluous data it contains.
    ///
    /// There simply is no reason to send the [`CredentialId`] _two_ times. This redundant data puts RPs in
    /// a position where they either ignore the data or parse the data to ensure no contradictions exist
    /// (e.g., [FIDO conformance requires one to verify `id` and `rawId` exist and match](https://github.com/w3c/webauthn/issues/2119#issuecomment-2287875401)).
    ///
    /// While [`Authentication::deserialize`] _strictly_ adheres to the JSON definition, this implementation
    /// strictly disallows superfluous data. Specifically the following JSON is required to be sent where duplicate
    /// and unknown keys are disallowed:
    ///
    /// ```json
    /// {
    ///   "authenticatorAttachment":null|"platform"|"cross-platform",
    ///   "authenticatorData":<base64url string>,
    ///   "clientDataJSON":<base64url string>,
    ///   "clientExtensionResults":{}|{"prf":null}|{"prf":{}}|{"prf":{"results":null}}|{"prf":{"results":{"first":null}}}|{"prf":{"results":{"first":null,"second":null}}},
    ///   "id":<see CredentialId::deserialize>,
    ///   "signature":<base64url string>,
    ///   "type":null|"public-key",
    ///   "userHandle":null|<see UserHandle::deserialize>
    /// }
    /// ```
    ///
    /// All of the above keys are required with the exceptions of `"authenticatorAttachment"`, `"type"`, and
    /// `"userHandle"`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::{request::register::USER_HANDLE_MIN_LEN, response::auth::ser_relaxed::CustomAuthentication};
    /// assert!(
    ///     // The below payload is technically valid, but `AuthenticationServerState::verify` will fail
    ///     // since the authenticatorData is not valid. This is true for `Authentication::deserialize`
    ///     // as well since authenticatorData parsing is always deferred.
    ///     serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
    ///         r#"{
    ///             "authenticatorData": "AA",
    ///             "authenticatorAttachment": "cross-platform",
    ///             "clientExtensionResults": {},
    ///             "clientDataJSON": "AA",
    ///             "id": "AAAAAAAAAAAAAAAAAAAAAA",
    ///             "signature": "AA",
    ///             "type": "public-key",
    ///             "userHandle": "AA"
    ///         }"#
    ///     ).is_ok());
    /// ```
    #[expect(
        clippy::too_many_lines,
        reason = "want to hide; thus don't put in outer scope"
    )]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `CustomAuthentication`.
        struct CustomAuthenticationVisitor<U>(PhantomData<fn() -> U>);
        impl<'d, U> Visitor<'d> for CustomAuthenticationVisitor<U>
        where
            UserHandle<U>: Deserialize<'d>,
        {
            type Value = CustomAuthentication<U>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("CustomAuthentication")
            }
            #[expect(
                clippy::too_many_lines,
                reason = "want to hide; thus don't put in outer scope"
            )]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Fields in the JSON.
                enum Field {
                    /// `authenticatorAttachment` key.
                    AuthenticatorAttachment,
                    /// `authenticatorData` key.
                    AuthenticatorData,
                    /// `clientDataJSON` key.
                    ClientDataJson,
                    /// `clientExtensionResults` key.
                    ClientExtensionResults,
                    /// `id` key.
                    Id,
                    /// `signature` key.
                    Signature,
                    /// `type` key.
                    Type,
                    /// `userHandle` key.
                    UserHandle,
                }
                impl<'e> Deserialize<'e> for Field {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: Deserializer<'e>,
                    {
                        /// `Visitor` for `Field`.
                        struct FieldVisitor;
                        impl Visitor<'_> for FieldVisitor {
                            type Value = Field;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                write!(
                                    formatter,
                                    "'{AUTHENTICATOR_ATTACHMENT}', '{AUTHENTICATOR_DATA}', '{CLIENT_DATA_JSON}', '{CLIENT_EXTENSION_RESULTS}', '{ID}', '{SIGNATURE}', '{TYPE}', or '{USER_HANDLE}'"
                                )
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    AUTHENTICATOR_ATTACHMENT => Ok(Field::AuthenticatorAttachment),
                                    AUTHENTICATOR_DATA => Ok(Field::AuthenticatorData),
                                    CLIENT_DATA_JSON => Ok(Field::ClientDataJson),
                                    CLIENT_EXTENSION_RESULTS => Ok(Field::ClientExtensionResults),
                                    ID => Ok(Field::Id),
                                    SIGNATURE => Ok(Field::Signature),
                                    TYPE => Ok(Field::Type),
                                    USER_HANDLE => Ok(Field::UserHandle),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                let mut authenticator_attachment = None;
                let mut authenticator_data = None;
                let mut client_data_json = None;
                let mut ext = false;
                let mut id = None;
                let mut signature = None;
                let mut typ = false;
                let mut user_handle = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::AuthenticatorAttachment => {
                            if authenticator_attachment.is_some() {
                                return Err(Error::duplicate_field(AUTHENTICATOR_ATTACHMENT));
                            }
                            authenticator_attachment = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::AuthenticatorData => {
                            if authenticator_data.is_some() {
                                return Err(Error::duplicate_field(AUTHENTICATOR_DATA));
                            }
                            authenticator_data =
                                map.next_value::<AuthData>().map(|val| Some(val.0))?;
                        }
                        Field::ClientDataJson => {
                            if client_data_json.is_some() {
                                return Err(Error::duplicate_field(CLIENT_DATA_JSON));
                            }
                            client_data_json = map
                                .next_value::<Base64DecodedVal>()
                                .map(|val| Some(val.0))?;
                        }
                        Field::ClientExtensionResults => {
                            if ext {
                                return Err(Error::duplicate_field(CLIENT_EXTENSION_RESULTS));
                            }
                            ext = map.next_value::<ClientExtensionsOutputs>().map(|_| true)?;
                        }
                        Field::Id => {
                            if id.is_some() {
                                return Err(Error::duplicate_field(ID));
                            }
                            id = map.next_value().map(Some)?;
                        }
                        Field::Signature => {
                            if signature.is_some() {
                                return Err(Error::duplicate_field(SIGNATURE));
                            }
                            signature = map
                                .next_value::<Base64DecodedVal>()
                                .map(|val| Some(val.0))?;
                        }
                        Field::Type => {
                            if typ {
                                return Err(Error::duplicate_field(TYPE));
                            }
                            typ = map.next_value::<Option<Type>>().map(|_| true)?;
                        }
                        Field::UserHandle => {
                            if user_handle.is_some() {
                                return Err(Error::duplicate_field(USER_HANDLE));
                            }
                            user_handle = map.next_value::<Option<_>>().map(Some)?;
                        }
                    }
                }
                authenticator_data
                    .ok_or_else(|| Error::missing_field(AUTHENTICATOR_DATA))
                    .and_then(|auth_data| {
                        client_data_json
                            .ok_or_else(|| Error::missing_field(CLIENT_DATA_JSON))
                            .and_then(|c_data| {
                                id.ok_or_else(|| Error::missing_field(ID))
                                    .and_then(|raw_id| {
                                        signature
                                            .ok_or_else(|| Error::missing_field(SIGNATURE))
                                            .and_then(|sig| {
                                                if ext {
                                                    Ok(CustomAuthentication(Authentication {
                                                        response: AuthenticatorAssertion::new_inner(
                                                            c_data,
                                                            auth_data,
                                                            sig,
                                                            user_handle.unwrap_or_default(),
                                                        ),
                                                        authenticator_attachment:
                                                            authenticator_attachment.map_or(
                                                                AuthenticatorAttachment::None,
                                                                |auth_attach| {
                                                                    auth_attach.unwrap_or(
                                                                    AuthenticatorAttachment::None,
                                                                )
                                                                },
                                                            ),
                                                        raw_id,
                                                    }))
                                                } else {
                                                    Err(Error::missing_field(
                                                        CLIENT_EXTENSION_RESULTS,
                                                    ))
                                                }
                                            })
                                    })
                            })
                    })
            }
        }
        /// `authenticatorAttachment` key.
        const AUTHENTICATOR_ATTACHMENT: &str = "authenticatorAttachment";
        /// `authenticatorData` key.
        const AUTHENTICATOR_DATA: &str = "authenticatorData";
        /// `clientDataJSON` key.
        const CLIENT_DATA_JSON: &str = "clientDataJSON";
        /// `clientExtensionResults` key.
        const CLIENT_EXTENSION_RESULTS: &str = "clientExtensionResults";
        /// `id` key.
        const ID: &str = "id";
        /// `signature` key.
        const SIGNATURE: &str = "signature";
        /// `type` key.
        const TYPE: &str = "type";
        /// `userHandle` key.
        const USER_HANDLE: &str = "userHandle";
        /// Fields.
        const FIELDS: &[&str; 8] = &[
            AUTHENTICATOR_ATTACHMENT,
            AUTHENTICATOR_DATA,
            CLIENT_DATA_JSON,
            CLIENT_EXTENSION_RESULTS,
            ID,
            SIGNATURE,
            TYPE,
            USER_HANDLE,
        ];
        deserializer.deserialize_struct(
            "CustomAuthentication",
            FIELDS,
            CustomAuthenticationVisitor(PhantomData),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::{
        super::{super::super::request::register::USER_HANDLE_MIN_LEN, AuthenticatorAttachment},
        AuthenticationRelaxed, CustomAuthentication,
    };
    use data_encoding::BASE64URL_NOPAD;
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
        let b64_cdata = BASE64URL_NOPAD.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD.encode(auth_data.as_slice());
        let b64_sig = BASE64URL_NOPAD.encode([].as_slice());
        let b64_user = BASE64URL_NOPAD.encode(b"\x00".as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
                ))
        );
        // `id` and `rawId` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Bytes(
                BASE64URL_NOPAD
                    .decode("ABABABABABABABABABABAA".as_bytes())
                    .unwrap()
                    .as_slice(),
            ),
            &format!("id and rawId to match: CredentialId({:?})", [0; 16]).as_str(),
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // `null` `rawId`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Missing `authenticatorData`.
        err = Error::missing_field("authenticatorData")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // `null` `userHandle`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // `null` `authenticatorAttachment`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // `null` `clientExtensionResults`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Missing `type`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // `null` `type`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Not exactly `public-type` `type`.
        err = Error::invalid_value(Unexpected::Str("Public-key"), &"public-key")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({}).to_string().as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Unknown field in `response`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Duplicate field in `response`.
        err = Error::duplicate_field("userHandle")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Duplicate field in `PublicKeyCredential`.
        err = Error::duplicate_field("id").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
        // Base case is valid.
        assert!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .map_or(false, |auth| auth.0.response.client_data_json
                == c_data_json.as_bytes()
                && auth.0.response.authenticator_data_and_c_data_hash[..37] == auth_data
                && auth.0.response.authenticator_data_and_c_data_hash[37..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && matches!(
                    auth.0.authenticator_attachment,
                    AuthenticatorAttachment::CrossPlatform
                ))
        );
        // missing `id`.
        err = Error::missing_field("id").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `id`.
        err = Error::invalid_type(Unexpected::Other("null"), &"CredentialId")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": null,
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // Missing `authenticatorData`.
        err = Error::missing_field("authenticatorData")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `authenticatorData`.
        err = Error::invalid_type(Unexpected::Other("null"), &"AuthenticatorData")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // Missing `signature`.
        err = Error::missing_field("signature").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `signature`.
        err = Error::invalid_type(Unexpected::Other("null"), &"base64url-encoded data")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // Missing `userHandle`.
        assert!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .is_ok()
        );
        // `null` `userHandle`.
        assert!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": null,
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .is_ok()
        );
        // `null` `authenticatorAttachment`.
        assert!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .map_or(false, |auth| matches!(
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
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // Missing `clientDataJSON`.
        err = Error::missing_field("clientDataJSON")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `clientDataJSON`.
        err = Error::invalid_type(Unexpected::Other("null"), &"base64url-encoded data")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .into_bytes()[..err.len()],
            err
        );
        // Empty.
        err = Error::missing_field("authenticatorData")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({}).to_string().as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `clientExtensionResults`.
        err = Error::missing_field("clientExtensionResults")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // `null` `clientExtensionResults`.
        err = Error::invalid_type(Unexpected::Other("null"), &"ClientExtensionsOutputs")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        assert!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                    "clientExtensionResults": {},
                })
                .to_string()
                .as_str()
            )
            .is_ok()
        );
        assert!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "signature": b64_sig,
                    "userHandle": b64_user,
                    "clientExtensionResults": {},
                    "type": null
                })
                .to_string()
                .as_str()
            )
            .is_ok()
        );
        // Not exactly `public-type` `type`.
        err = Error::invalid_value(Unexpected::Str("Public-key"), &"public-key")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // `null`.
        err = Error::invalid_type(Unexpected::Other("null"), &"CustomAuthentication")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!(null).to_string().as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
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
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientDataJSON": b64_cdata,
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
            .into_bytes()[..err.len()],
            err
        );
        // Duplicate field.
        err = Error::duplicate_field("userHandle")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomAuthentication<[u8; USER_HANDLE_MIN_LEN]>>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"clientDataJSON\": \"{b64_cdata}\",
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
        let b64_cdata = BASE64URL_NOPAD.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD.encode(auth_data.as_slice());
        let b64_sig = BASE64URL_NOPAD.encode([].as_slice());
        let b64_user = BASE64URL_NOPAD.encode(b"\x00".as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
                ))
        );
        // `null` `prf`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Unknown `clientExtensionResults`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Duplicate field.
        let mut err = Error::duplicate_field("prf").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Duplicate field in `prf`.
        err = Error::duplicate_field("results").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // `null` `first`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // `null` `second`.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Non-`null` `first`.
        err = Error::invalid_type(Unexpected::Option, &"null")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Unknown `results` field.
        assert!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
            .is_ok()
        );
        // Duplicate field in `results`.
        err = Error::duplicate_field("first").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<AuthenticationRelaxed<[u8; USER_HANDLE_MIN_LEN]>>(
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
