use super::{
    super::{
        super::response::ser::{Base64DecodedVal, PublicKeyCredential},
        ser::{
            AuthenticationExtensionsPrfOutputsHelper, AuthenticationExtensionsPrfValues,
            ClientExtensions,
        },
    },
    Authentication, AuthenticatorAssertion, UserHandle,
    error::UnknownCredentialOptions,
};
#[cfg(doc)]
use super::{AuthenticatorAttachment, CredentialId};
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
    str,
};
use rsa::sha2::{Sha256, digest::OutputSizeUser as _};
use serde::{
    de::{Deserialize, Deserializer, Error, IgnoredAny, MapAccess, Unexpected, Visitor},
    ser::{Serialize, SerializeStruct as _, Serializer},
};
/// Authenticator data.
pub(super) struct AuthData(pub Vec<u8>);
impl<'e> Deserialize<'e> for AuthData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'e>,
    {
        /// `Visitor` for `AuthData`.
        struct AuthDataVisitor;
        impl Visitor<'_> for AuthDataVisitor {
            type Value = AuthData;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("AuthenticatorData")
            }
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "comment justifies its correctness"
            )]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                base64url_nopad::decode_len(v.len())
                    .ok_or_else(|| E::invalid_value(Unexpected::Str(v), &"base64url-encoded value"))
                    .and_then(|len| {
                        // The decoded length is 3/4 of the encoded length, so overflow could only occur
                        // if usize::MAX / 4 < 32 => usize::MAX < 128 < u16::MAX; thus overflow is not
                        // possible.
                        // We add 32 since the SHA-256 hash of `clientDataJSON` will be added to the
                        // raw authenticator data by `AuthenticatorDataAssertion::new`.
                        let mut auth_data = vec![0; len + Sha256::output_size()];
                        auth_data.truncate(len);
                        base64url_nopad::decode_buffer_exact(v.as_bytes(), auth_data.as_mut_slice())
                            .map_err(E::custom)
                            .map(|()| AuthData(auth_data))
                    })
            }
        }
        deserializer.deserialize_str(AuthDataVisitor)
    }
}
/// `Visitor` for `AuthenticatorAssertion`.
///
/// Unknown fields are ignored and only `clientDataJSON`, `authenticatorData`, and `signature` are required iff
/// `RELAXED`.
pub(super) struct AuthenticatorAssertionVisitor<
    const RELAXED: bool,
    const USER_LEN: usize,
    const DISCOVERABLE: bool,
>;
impl<'d, const R: bool, const LEN: usize, const DISC: bool> Visitor<'d>
    for AuthenticatorAssertionVisitor<R, LEN, DISC>
where
    UserHandle<LEN>: Deserialize<'d>,
{
    type Value = AuthenticatorAssertion<LEN, DISC>;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatorAssertion")
    }
    #[expect(clippy::too_many_lines, reason = "107 lines is fine")]
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'d>,
    {
        /// Fields in `AuthenticatorAssertionResponseJSON`.
        enum Field<const IGNORE_UNKNOWN: bool> {
            /// `clientDataJSON`.
            ClientDataJson,
            /// `authenticatorData`.
            AuthenticatorData,
            /// `signature`.
            Signature,
            /// `userHandle`.
            UserHandle,
            /// Unknown field.
            Other,
        }
        impl<'e, const I: bool> Deserialize<'e> for Field<I> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'e>,
            {
                /// `Visitor` for `Field`.
                struct FieldVisitor<const IGNORE_UNKNOWN: bool>;
                impl<const IG: bool> Visitor<'_> for FieldVisitor<IG> {
                    type Value = Field<IG>;
                    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                        write!(
                            formatter,
                            "'{CLIENT_DATA_JSON}', '{AUTHENTICATOR_DATA}', '{SIGNATURE}', or '{USER_HANDLE}'"
                        )
                    }
                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            CLIENT_DATA_JSON => Ok(Field::ClientDataJson),
                            AUTHENTICATOR_DATA => Ok(Field::AuthenticatorData),
                            SIGNATURE => Ok(Field::Signature),
                            USER_HANDLE => Ok(Field::UserHandle),
                            _ => {
                                if IG {
                                    Ok(Field::Other)
                                } else {
                                    Err(E::unknown_field(v, AUTH_ASSERT_FIELDS))
                                }
                            }
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor::<I>)
            }
        }
        let mut client_data = None;
        let mut auth = None;
        let mut sig = None;
        let mut user_handle = None;
        while let Some(key) = map.next_key::<Field<R>>()? {
            match key {
                Field::ClientDataJson => {
                    if client_data.is_some() {
                        return Err(Error::duplicate_field(CLIENT_DATA_JSON));
                    }
                    client_data = map
                        .next_value::<Base64DecodedVal>()
                        .map(|c_data| c_data.0)
                        .map(Some)?;
                }
                Field::AuthenticatorData => {
                    if auth.is_some() {
                        return Err(Error::duplicate_field(AUTHENTICATOR_DATA));
                    }
                    auth = map
                        .next_value::<AuthData>()
                        .map(|auth_data| Some(auth_data.0))?;
                }
                Field::Signature => {
                    if sig.is_some() {
                        return Err(Error::duplicate_field(SIGNATURE));
                    }
                    sig = map
                        .next_value::<Base64DecodedVal>()
                        .map(|signature| signature.0)
                        .map(Some)?;
                }
                Field::UserHandle => {
                    if user_handle.is_some() {
                        return Err(Error::duplicate_field(USER_HANDLE));
                    }
                    user_handle = map.next_value().map(Some)?;
                }
                Field::Other => map.next_value::<IgnoredAny>().map(|_| ())?,
            }
        }
        client_data
            .ok_or_else(|| Error::missing_field(CLIENT_DATA_JSON))
            .and_then(|client_data_json| {
                auth.ok_or_else(|| Error::missing_field(AUTHENTICATOR_DATA))
                    .and_then(|authenticator_data| {
                        sig.ok_or_else(|| Error::missing_field(SIGNATURE))
                            .and_then(|signature| {
                                if DISC {
                                    user_handle.ok_or_else(|| Error::missing_field(USER_HANDLE))
                                } else {
                                    user_handle.map_or_else(|| Ok(None), Ok)
                                }
                                .map(|user| {
                                    AuthenticatorAssertion::new_inner(
                                        client_data_json,
                                        authenticator_data,
                                        signature,
                                        user,
                                    )
                                })
                            })
                    })
            })
    }
}
/// `"clientDataJSON"`.
const CLIENT_DATA_JSON: &str = "clientDataJSON";
/// `"authenticatorData"`.
const AUTHENTICATOR_DATA: &str = "authenticatorData";
/// `"signature"`.
const SIGNATURE: &str = "signature";
/// `"userHandle"`.
const USER_HANDLE: &str = "userHandle";
/// Fields in `AuthenticatorAssertionResponseJSON`.
pub(super) const AUTH_ASSERT_FIELDS: &[&str; 4] =
    &[CLIENT_DATA_JSON, AUTHENTICATOR_DATA, SIGNATURE, USER_HANDLE];
impl<'de, const USER_LEN: usize, const DISCOVERABLE: bool> Deserialize<'de>
    for AuthenticatorAssertion<USER_LEN, DISCOVERABLE>
where
    UserHandle<USER_LEN>: Deserialize<'de>,
{
    /// Deserializes a `struct` based on
    /// [`AuthenticatorAssertionResponseJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorassertionresponsejson).
    ///
    /// Note unknown keys and duplicate keys are forbidden;
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponsejson-clientdatajson),
    /// [`authenticatorData`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponsejson-authenticatordata),
    /// and
    /// [`signature`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponsejson-signature) are
    /// base64url-decoded;
    /// [`userHandle`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponsejson-userhandle) is
    /// required and must not be `null` iff `DISCOVERABLE`. When it exists and is not `null`, it is deserialized
    /// via [`UserHandle::deserialize`]. All `required` fields in the `AuthenticatorAssertionResponseJSON` Web IDL
    /// `dictionary` exist (and are not `null`).
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "AuthenticatorAssertion",
            AUTH_ASSERT_FIELDS,
            AuthenticatorAssertionVisitor::<false, USER_LEN, DISCOVERABLE>,
        )
    }
}
/// Empty map of client extensions.
pub(super) struct ClientExtensionsOutputs;
/// `Visitor` for `ClientExtensionsOutputs`.
///
/// Unknown fields are ignored iff `RELAXED`.
pub(super) struct ClientExtensionsOutputsVisitor<const RELAXED: bool, PRF>(
    pub PhantomData<fn() -> PRF>,
);
impl<'d, const R: bool, P> Visitor<'d> for ClientExtensionsOutputsVisitor<R, P>
where
    P: for<'a> Deserialize<'a>,
{
    type Value = ClientExtensionsOutputs;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientExtensionsOutputs")
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'d>,
    {
        /// Allowed fields.
        enum Field<const IGNORE_UNKNOWN: bool> {
            /// `prf`.
            Prf,
            /// Unknown field.
            Other,
        }
        impl<'e, const I: bool> Deserialize<'e> for Field<I> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'e>,
            {
                /// `Visitor` for `Field`.
                ///
                /// Unknown fields are ignored iff `IGNORE_UNKNOWN`.
                struct FieldVisitor<const IGNORE_UNKNOWN: bool>;
                impl<const IG: bool> Visitor<'_> for FieldVisitor<IG> {
                    type Value = Field<IG>;
                    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                        write!(formatter, "'{PRF}'")
                    }
                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            PRF => Ok(Field::Prf),
                            _ => {
                                if IG {
                                    Ok(Field::Other)
                                } else {
                                    Err(E::unknown_field(v, EXT_FIELDS))
                                }
                            }
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor::<I>)
            }
        }
        let mut prf = None;
        while let Some(key) = map.next_key::<Field<R>>()? {
            match key {
                Field::Prf => {
                    if prf.is_some() {
                        return Err(Error::duplicate_field(PRF));
                    }
                    prf = map.next_value::<Option<P>>().map(Some)?;
                }
                Field::Other => map.next_value::<IgnoredAny>().map(|_| ())?,
            }
        }
        Ok(ClientExtensionsOutputs)
    }
}
impl ClientExtensions for ClientExtensionsOutputs {
    fn empty() -> Self {
        Self
    }
}
/// `"prf"`
const PRF: &str = "prf";
/// `AuthenticationExtensionsClientOutputsJSON` fields.
pub(super) const EXT_FIELDS: &[&str; 1] = &[PRF];
impl<'de> Deserialize<'de> for ClientExtensionsOutputs {
    /// Deserializes a `struct` based on
    /// [`AuthenticationExtensionsClientOutputsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientoutputsjson).
    ///
    /// Note that unknown and duplicate keys are forbidden and
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsclientoutputs-prf) is `null`
    /// or deserialized via [`AuthenticationExtensionsPrfOutputs::deserialize`].
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "ClientExtensionsOutputs",
            EXT_FIELDS,
            ClientExtensionsOutputsVisitor::<
                false,
                AuthenticationExtensionsPrfOutputsHelper<
                    false,
                    false,
                    AuthenticationExtensionsPrfValues,
                >,
            >(PhantomData),
        )
    }
}
impl<'de, const USER_LEN: usize, const DISCOVERABLE: bool> Deserialize<'de>
    for Authentication<USER_LEN, DISCOVERABLE>
where
    UserHandle<USER_LEN>: Deserialize<'de>,
{
    /// Deserializes a `struct` based on
    /// [`AuthenticationResponseJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson).
    ///
    /// Note that unknown and duplicate keys are forbidden;
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-authenticationresponsejson-id) and
    /// [`rawId`](https://www.w3.org/TR/webauthn-3/#dom-authenticationresponsejson-rawid) are deserialized
    /// via [`CredentialId::deserialize`];
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-authenticationresponsejson-response) is deserialized
    /// via [`AuthenticatorAssertion::deserialize`];
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-authenticationresponsejson-authenticatorattachment)
    /// is `null` or deserialized via [`AuthenticatorAttachment::deserialize`];
    /// [`clientExtensionResults`](https://www.w3.org/TR/webauthn-3/#dom-authenticationresponsejson-clientextensionresults)
    /// is deserialized such that it is an empty map or a map that only contains
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsclientoutputs-prf) which additionally must be
    /// `null` or an
    /// [`AuthenticationExtensionsPRFOutputs`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfoutputs)
    /// such that unknown and duplicate keys are forbidden,
    /// [`enabled`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-enabled)
    /// is forbidden (including being assigned `null`),
    /// [`results`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-results) must not exist,
    /// be `null`, or be an
    /// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues)
    /// with no unknown or duplicate keys,
    /// [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first) must exist but be
    /// `null`, and
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second) can exist but
    /// must be `null` if so; all `required` fields in the `AuthenticationResponseJSON` Web IDL `dictionary` exist
    /// (and are not `null`); [`type`](https://www.w3.org/TR/webauthn-3/#dom-authenticationresponsejson-type) is
    /// `"public-key"`; and the decoded `id` and decoded `rawId` are the same.
    #[expect(clippy::unreachable, reason = "when there is a bug, we want to crash")]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        PublicKeyCredential::<
            false,
            false,
            AuthenticatorAssertion<USER_LEN, DISCOVERABLE>,
            ClientExtensionsOutputs,
        >::deserialize(deserializer)
        .map(|cred| Self {
            raw_id: cred.id.unwrap_or_else(|| {
                unreachable!("there is a bug in PublicKeyCredential::deserialize")
            }),
            response: cred.response,
            authenticator_attachment: cred.authenticator_attachment,
        })
    }
}
impl Serialize for UnknownCredentialOptions<'_, '_> {
    /// Serializes `self` to conform with
    /// [`UnknownCredentialOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-unknowncredentialoptions).
    ///
    /// # Examples
    ///
    /// ```
    /// # use core::str::FromStr;
    /// # use webauthn_rp::{request::{AsciiDomain, RpId}, response::{auth::error::UnknownCredentialOptions, CredentialId}};
    /// # #[cfg(feature = "custom")]
    /// let credential_id = CredentialId::try_from(vec![0; 16])?;
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(
    ///     serde_json::to_string(&UnknownCredentialOptions {
    ///         rp_id: &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         credential_id: (&credential_id).into(),
    ///     })
    ///     .unwrap(),
    ///     r#"{"rpId":"example.com","credentialId":"AAAAAAAAAAAAAAAAAAAAAA"}"#
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("UnknownCredentialOptions", 2)
            .and_then(|mut ser| {
                ser.serialize_field("rpId", self.rp_id).and_then(|()| {
                    ser.serialize_field("credentialId", &self.credential_id)
                        .and_then(|()| ser.end())
                })
            })
    }
}
#[cfg(test)]
mod tests {
    use super::super::{
        super::super::request::register::USER_HANDLE_MIN_LEN, AuthenticatorAttachment,
        DiscoverableAuthentication, NonDiscoverableAuthentication,
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
        let b64_cdata_json = base64url_nopad::encode(c_data_json.as_bytes());
        let b64_adata = base64url_nopad::encode(auth_data.as_slice());
        let b64_sig = base64url_nopad::encode([].as_slice());
        let b64_user = base64url_nopad::encode(b"\x00".as_slice());
        let auth_data_len = 37;
        // Base case is valid.
        assert!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                |auth| auth.response.client_data_json == c_data_json.as_bytes()
                    && auth.response.authenticator_data_and_c_data_hash[..auth_data_len]
                        == auth_data
                    && auth.response.authenticator_data_and_c_data_hash[auth_data_len..]
                        == *Sha256::digest(c_data_json.as_bytes())
                    && matches!(
                        auth.authenticator_attachment,
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
        err = Error::missing_field("rawId").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
            Some(err.as_slice())
        );
        // `null` `rawId`.
        err = Error::invalid_type(Unexpected::Other("null"), &"CredentialId")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<NonDiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<NonDiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                auth.authenticator_attachment,
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
        err = Error::missing_field("clientExtensionResults")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
            Some(err.as_slice())
        );
        // `null` `clientExtensionResults`.
        err = Error::invalid_type(
            Unexpected::Other("null"),
            &"clientExtensionResults to be a map of allowed client extensions",
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
            Some(err.as_slice())
        );
        // Missing `type`.
        err = Error::missing_field("type").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
            Some(err.as_slice())
        );
        // `null` `type`.
        err = Error::invalid_type(Unexpected::Other("null"), &"public-key")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
                serde_json::json!({}).to_string().as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
            Some(err.as_slice())
        );
        // Unknown field in `response`.
        err = Error::unknown_field(
            "foo",
            [
                "clientDataJSON",
                "authenticatorData",
                "signature",
                "userHandle",
            ]
            .as_slice(),
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
            Some(err.as_slice())
        );
        // Duplicate field in `response`.
        err = Error::duplicate_field("userHandle")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
        err = Error::unknown_field(
            "foo",
            [
                "id",
                "type",
                "rawId",
                "response",
                "authenticatorAttachment",
                "clientExtensionResults",
            ]
            .as_slice(),
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
            Some(err.as_slice())
        );
        // Duplicate field in `PublicKeyCredential`.
        err = Error::duplicate_field("id").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
        let auth_data_len = 37;
        let b64_cdata_json = base64url_nopad::encode(c_data_json.as_bytes());
        let b64_adata = base64url_nopad::encode(auth_data.as_slice());
        let b64_sig = base64url_nopad::encode([].as_slice());
        let b64_user = base64url_nopad::encode(b"\x00".as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                |auth| auth.response.client_data_json == c_data_json.as_bytes()
                    && auth.response.authenticator_data_and_c_data_hash[..auth_data_len]
                        == auth_data
                    && auth.response.authenticator_data_and_c_data_hash[auth_data_len..]
                        == *Sha256::digest(c_data_json.as_bytes())
                    && matches!(
                        auth.authenticator_attachment,
                        AuthenticatorAttachment::CrossPlatform
                    )
            )
        );
        // `null` `prf`.
        drop(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
        let mut err = Error::unknown_field("Prf", ["prf"].as_slice())
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
            Some(err.as_slice())
        );
        // Duplicate field.
        err = Error::duplicate_field("prf").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
        err = Error::missing_field("first").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
            Some(err.as_slice())
        );
        // `null` `first`.
        drop(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
        // Unknown `prf` field.
        err = Error::unknown_field("enabled", ["results"].as_slice())
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
        // Unknown `results` field.
        err = Error::unknown_field("Second", ["first", "second"].as_slice())
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
            Some(err.as_slice())
        );
        // Duplicate field in `results`.
        err = Error::duplicate_field("first").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<DiscoverableAuthentication<USER_HANDLE_MIN_LEN>>(
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
}
