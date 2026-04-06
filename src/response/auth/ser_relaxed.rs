#[cfg(test)]
mod tests;
#[cfg(doc)]
use super::super::{Challenge, CredentialId};
use super::{
    super::{
        super::request::register::{USER_HANDLE_MAX_LEN, UserHandle},
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
    Authentication, AuthenticatorAssertion, AuthenticatorAttachment,
};
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
};
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
pub struct AuthenticatorAssertionRelaxed<const USER_LEN: usize, const DISCOVERABLE: bool>(
    pub AuthenticatorAssertion<USER_LEN, DISCOVERABLE>,
);
impl<'de, const USER_LEN: usize, const DISCOVERABLE: bool> Deserialize<'de>
    for AuthenticatorAssertionRelaxed<USER_LEN, DISCOVERABLE>
where
    UserHandle<USER_LEN>: Deserialize<'de>,
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
                AuthenticatorAssertionVisitor::<true, USER_LEN, DISCOVERABLE>,
            )
            .map(Self)
    }
}
/// `newtype` around `Authentication` with a "relaxed" [`Self::deserialize`] implementation.
#[derive(Debug)]
pub struct AuthenticationRelaxed<const USER_LEN: usize, const DISCOVERABLE: bool>(
    pub Authentication<USER_LEN, DISCOVERABLE>,
);
impl<'de, const USER_LEN: usize, const DISCOVERABLE: bool> Deserialize<'de>
    for AuthenticationRelaxed<USER_LEN, DISCOVERABLE>
where
    UserHandle<USER_LEN>: Deserialize<'de>,
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
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-authenticationresponsejson-id) and `response` are required.
    /// `rawId` and `type` and allowed to not exist. For the other fields, they are allowed to not exist or be `null`.
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
            AuthenticatorAssertionRelaxed<USER_LEN, DISCOVERABLE>,
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
/// `AuthenticationRelaxed` with a required `UserHandle`.
pub type DiscoverableAuthenticationRelaxed<const USER_LEN: usize> =
    AuthenticationRelaxed<USER_LEN, true>;
/// `AuthenticationRelaxed` with a required `UserHandle64`.
pub type DiscoverableAuthenticationRelaxed64 = AuthenticationRelaxed<USER_HANDLE_MAX_LEN, true>;
/// `AuthenticationRelaxed` with a required `UserHandle16`.
pub type DiscoverableAuthenticationRelaxed16 = AuthenticationRelaxed<16, true>;
/// `AuthenticationRelaxed` with an optional `UserHandle`.
pub type NonDiscoverableAuthenticationRelaxed<const USER_LEN: usize> =
    AuthenticationRelaxed<USER_LEN, false>;
/// `AuthenticationRelaxed` with an optional `UserHandle64`.
pub type NonDiscoverableAuthenticationRelaxed64 = AuthenticationRelaxed<USER_HANDLE_MAX_LEN, false>;
/// `AuthenticationRelaxed` with an optional `UserHandle16`.
pub type NonDiscoverableAuthenticationRelaxed16 = AuthenticationRelaxed<16, false>;
/// `newtype` around `Authentication` with a custom [`Self::deserialize`] implementation.
#[derive(Debug)]
pub struct CustomAuthentication<const USER_LEN: usize, const DISCOVERABLE: bool>(
    pub Authentication<USER_LEN, DISCOVERABLE>,
);
impl<'de, const USER_LEN: usize, const DISCOVERABLE: bool> Deserialize<'de>
    for CustomAuthentication<USER_LEN, DISCOVERABLE>
where
    UserHandle<USER_LEN>: Deserialize<'de>,
{
    /// Despite the spec having a
    /// [pre-defined format](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson) that clients
    /// can follow, the downside is the superfluous data it contains.
    ///
    /// There simply is no reason to send the [`CredentialId`] twice. This redundant data puts RPs in
    /// a position where they either ignore the data or parse the data to ensure no contradictions exist
    /// (e.g., [FIDO conformance requires one to verify `id` and `rawId` exist and match](https://github.com/w3c/webauthn/issues/2119#issuecomment-2287875401)).
    ///
    /// While [`Authentication::deserialize`] _strictly_ adheres to the JSON definition, this implementation
    /// strictly disallows superfluous data. Specifically the following JSON is required to be sent where duplicate
    /// and unknown keys are disallowed:
    ///
    /// ```json
    /// {
    ///   "authenticatorAttachment": null | "platform" | "cross-platform",
    ///   "authenticatorData": <base64url string>,
    ///   "clientDataJSON": <base64url string>,
    ///   "clientExtensionResults": {
    ///     "prf": null | PRFJSON
    ///   },
    ///   "id": <see CredentialId::deserialize>,
    ///   "signature": <base64url string>,
    ///   "type": "public-key",
    ///   "userHandle": null | <see UserHandle::deserialize>
    /// }
    /// // PRFJSON:
    /// {
    ///   "results": null | PRFOutputsJSON
    /// }
    /// // PRFOutputsJSON:
    /// {
    ///   "first": null,
    ///   "second": null
    /// }
    /// ```
    ///
    /// `"userHandle"` is required to exist and not be `null` iff `DISCOVERABLE`. When it does exist and
    /// is not `null`, then it is deserialized via [`UserHandle::deserialize`]. All of the remaining keys are
    /// required with the exceptions of `"authenticatorAttachment"` and `"type"`. `"prf"` is not required in the
    /// `clientExtensionResults` object, `"results"` is required in the `PRFJSON` object, and `"first"`
    /// (but not `"second"`) is required in `PRFOutputsJSON`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::{request::register::{UserHandle, USER_HANDLE_MIN_LEN}, response::auth::ser_relaxed::CustomAuthentication};
    /// assert!(
    ///     // The below payload is technically valid, but `AuthenticationServerState::verify` will fail
    ///     // since the authenticatorData is not valid. This is true for `Authentication::deserialize`
    ///     // as well since authenticatorData parsing is always deferred.
    ///     serde_json::from_str::<CustomAuthentication<USER_HANDLE_MIN_LEN, true>>(
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
        struct CustomAuthenticationVisitor<const LEN: usize, const DISC: bool>;
        impl<'d, const LEN: usize, const DISC: bool> Visitor<'d> for CustomAuthenticationVisitor<LEN, DISC>
        where
            UserHandle<LEN>: Deserialize<'d>,
        {
            type Value = CustomAuthentication<LEN, DISC>;
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
                            typ = map.next_value::<Type>().map(|_| true)?;
                        }
                        Field::UserHandle => {
                            if user_handle.is_some() {
                                return Err(Error::duplicate_field(USER_HANDLE));
                            }
                            user_handle = map.next_value().map(Some)?;
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
                                                    if DISC {
                                                        user_handle.ok_or_else(|| Error::missing_field(USER_HANDLE))
                                                    } else {
                                                        user_handle.map_or_else(|| Ok(None), Ok)
                                                    }.map(|user| {
                                                        CustomAuthentication(Authentication {
                                                            response: AuthenticatorAssertion::new_inner(
                                                                c_data,
                                                                auth_data,
                                                                sig,
                                                                user,
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
                                                        })
                                                    })
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
        deserializer.deserialize_struct("CustomAuthentication", FIELDS, CustomAuthenticationVisitor)
    }
}
/// `CustomAuthentication` with a required `UserHandle`.
pub type DiscoverableCustomAuthentication<const USER_LEN: usize> =
    CustomAuthentication<USER_LEN, true>;
/// `CustomAuthentication` with a required `UserHandle64`.
pub type DiscoverableCustomAuthentication64 = CustomAuthentication<USER_HANDLE_MAX_LEN, true>;
/// `CustomAuthentication` with a required `UserHandle16`.
pub type DiscoverableCustomAuthentication16 = CustomAuthentication<16, true>;
/// `CustomAuthentication` with an optional `UserHandle`.
pub type NonDiscoverableCustomAuthentication<const USER_LEN: usize> =
    CustomAuthentication<USER_LEN, false>;
/// `CustomAuthentication` with an optional `UserHandle64`.
pub type NonDiscoverableCustomAuthentication64 = CustomAuthentication<USER_HANDLE_MAX_LEN, false>;
/// `CustomAuthentication` with an optional `UserHandle16`.
pub type NonDiscoverableCustomAuthentication16 = CustomAuthentication<16, false>;
