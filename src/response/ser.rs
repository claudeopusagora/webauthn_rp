extern crate alloc;
use super::{
    AllAcceptedCredentialsOptions, AuthTransports, AuthenticatorAttachment, AuthenticatorTransport,
    Challenge, CredentialId, CurrentUserDetailsOptions, Origin, SentChallenge,
};
use alloc::borrow::Cow;
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
};
use serde::{
    de::{Deserialize, Deserializer, Error, IgnoredAny, MapAccess, SeqAccess, Unexpected, Visitor},
    ser::{Serialize, SerializeSeq as _, SerializeStruct as _, Serializer},
};
/// [`"ble"`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-ble).
const BLE: &str = "ble";
/// [`"hybrid"`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-hybrid).
const HYBRID: &str = "hybrid";
/// [`"internal"`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-internal).
const INTERNAL: &str = "internal";
/// [`"nfc"`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-nfc).
const NFC: &str = "nfc";
/// [`"smart-card"`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-smart-card).
const SMART_CARD: &str = "smart-card";
/// [`"usb"`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-usb).
const USB: &str = "usb";
impl Serialize for AuthenticatorTransport {
    /// Serializes `self` as
    /// [`AuthenticatorTransport`](https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::AuthenticatorTransport;
    /// assert_eq!(
    ///     serde_json::to_string(&AuthenticatorTransport::Usb)?,
    ///     r#""usb""#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match *self {
            Self::Ble => BLE,
            Self::Hybrid => HYBRID,
            Self::Internal => INTERNAL,
            Self::Nfc => NFC,
            Self::SmartCard => SMART_CARD,
            Self::Usb => USB,
        })
    }
}
impl<'de> Deserialize<'de> for AuthenticatorTransport {
    /// Deserializes [`prim@str`] based on
    /// [`AuthenticatorTransport`](https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport).
    ///
    /// Note `"cable"` is also supported and will be interpreted as [`Self::Hybrid`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::AuthenticatorTransport;
    /// assert!(matches!(
    ///     serde_json::from_str::<AuthenticatorTransport>(r#""usb""#)?,
    ///     AuthenticatorTransport::Usb
    /// ));
    /// // Case matters.
    /// assert!(serde_json::from_str::<AuthenticatorTransport>(r#""Usb""#).is_err());
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `AuthenticatorTransport`.
        struct AuthenticatorTransportVisitor;
        impl Visitor<'_> for AuthenticatorTransportVisitor {
            type Value = AuthenticatorTransport;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("AuthenticatorTransport")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                /// Legacy version of [`Self::Hybrid`].
                const CA_BLE: &str = "cable";
                match v {
                    BLE => Ok(AuthenticatorTransport::Ble),
                    CA_BLE | HYBRID => Ok(AuthenticatorTransport::Hybrid),
                    INTERNAL => Ok(AuthenticatorTransport::Internal),
                    NFC => Ok(AuthenticatorTransport::Nfc),
                    SMART_CARD => Ok(AuthenticatorTransport::SmartCard),
                    USB => Ok(AuthenticatorTransport::Usb),
                    _ => Err(E::invalid_value(
                        Unexpected::Str(v),
                        &format!(
                            "'{BLE}', '{CA_BLE}', '{HYBRID}', '{INTERNAL}', '{NFC}', '{SMART_CARD}', or '{USB}'"
                        )
                        .as_str(),
                    )),
                }
            }
        }
        deserializer.deserialize_str(AuthenticatorTransportVisitor)
    }
}
impl Serialize for AuthTransports {
    /// Serializes `self` based on
    /// [`transports`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialdescriptor-transports).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::{AuthTransports, AuthenticatorTransport};
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(
    ///     serde_json::to_string(&AuthTransports::ALL)?,
    ///     r#"["ble","hybrid","internal","nfc","smart-card","usb"]"#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[expect(clippy::unreachable, reason = "there is a bug, so we want to crash")]
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let count = usize::try_from(self.count())
            .unwrap_or_else(|_e| unreachable!("there is a bug in AuthenticatorTransports::count"));
        serializer.serialize_seq(Some(count)).and_then(|mut ser| {
            if self.contains(AuthenticatorTransport::Ble) {
                ser.serialize_element(&AuthenticatorTransport::Ble)
            } else {
                Ok(())
            }
            .and_then(|()| {
                if self.contains(AuthenticatorTransport::Hybrid) {
                    ser.serialize_element(&AuthenticatorTransport::Hybrid)
                } else {
                    Ok(())
                }
                .and_then(|()| {
                    if self.contains(AuthenticatorTransport::Internal) {
                        ser.serialize_element(&AuthenticatorTransport::Internal)
                    } else {
                        Ok(())
                    }
                    .and_then(|()| {
                        if self.contains(AuthenticatorTransport::Nfc) {
                            ser.serialize_element(&AuthenticatorTransport::Nfc)
                        } else {
                            Ok(())
                        }
                        .and_then(|()| {
                            if self.contains(AuthenticatorTransport::SmartCard) {
                                ser.serialize_element(&AuthenticatorTransport::SmartCard)
                            } else {
                                Ok(())
                            }
                            .and_then(|()| {
                                if self.contains(AuthenticatorTransport::Usb) {
                                    ser.serialize_element(&AuthenticatorTransport::Usb)
                                } else {
                                    Ok(())
                                }
                                .and_then(|()| ser.end())
                            })
                        })
                    })
                })
            })
        })
    }
}
impl<'de> Deserialize<'de> for AuthTransports {
    /// Deserializes a sequence based on
    /// [`transports`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialdescriptor-transports).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::{AuthTransports, AuthenticatorTransport};
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(
    ///     serde_json::from_str::<AuthTransports>(
    ///         r#"["ble","hybrid","internal","nfc","smart-card","usb"]"#
    ///     )
    ///     ?.count(),
    ///     6
    /// );
    /// // Errors since `"foo"` is not valid.
    /// assert!(serde_json::from_str::<AuthTransports>(r#"["foo"]"#).is_err());
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `AuthTransports`.
        struct AuthTransportsVisitor;
        impl<'d> Visitor<'d> for AuthTransportsVisitor {
            type Value = AuthTransports;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("AuthTransports")
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'d>,
            {
                let mut transports = AuthTransports::new();
                while let Some(val) = seq.next_element::<AuthenticatorTransport>()? {
                    transports = transports.add_transport(val);
                }
                Ok(transports)
            }
        }
        deserializer.deserialize_seq(AuthTransportsVisitor)
    }
}
impl<T: AsRef<[u8]>> Serialize for CredentialId<T> {
    /// Serializes `self` into a [`prim@str`] based on
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialdescriptorjson-id).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::CredentialId;
    /// // `CredentialId::try_from` only exists when `custom` is enabled; and even then, it is
    /// // likely never needed since the `CredentialId` was originally sent from the client and is likely
    /// // stored in a database which would be fetched by `UserHandle` or `Authentication::raw_id`.
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(
    ///     serde_json::to_string(&CredentialId::try_from(vec![0; 16].into_boxed_slice())?).unwrap(),
    ///     r#""AAAAAAAAAAAAAAAAAAAAAA""#
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    ///```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(base64url_nopad::encode(self.0.as_ref()).as_str())
    }
}
impl<'de> Deserialize<'de> for CredentialId<Box<[u8]>> {
    /// Deserializes [`prim@str`] based on
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialdescriptorjson-id).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::CredentialId;
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(
    ///     serde_json::from_str::<CredentialId<_>>(r#""AAAAAAAAAAAAAAAAAAAAAA""#).unwrap(),
    ///     CredentialId::try_from(vec![0; 16].into_boxed_slice())?
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    ///```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `CredentialId`.
        struct CredentialIdVisitor;
        impl Visitor<'_> for CredentialIdVisitor {
            type Value = CredentialId<Box<[u8]>>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("CredentialId")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                /// Minimum possible encoded length of a `CredentialId`.
                const MIN_LEN: usize = base64url_nopad::encode_len(super::CRED_ID_MIN_LEN);
                /// Maximum possible encoded length of a `CredentialId`.
                const MAX_LEN: usize = base64url_nopad::encode_len(super::CRED_ID_MAX_LEN);
                if (MIN_LEN..=MAX_LEN).contains(&v.len()) {
                    base64url_nopad::decode(v.as_bytes())
                        .map_err(E::custom)
                        .map(|c| CredentialId(c.into_boxed_slice()))
                } else {
                    Err(E::invalid_value(
                        Unexpected::Str(v),
                        &"16 to 1023 bytes encoded in base64url without padding",
                    ))
                }
            }
        }
        deserializer.deserialize_str(CredentialIdVisitor)
    }
}
impl<'de> Deserialize<'de> for AuthenticatorAttachment {
    /// Deserializes [`prim@str`] based on
    /// [`AuthenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::AuthenticatorAttachment;
    /// assert!(matches!(
    ///     serde_json::from_str::<AuthenticatorAttachment>(r#""cross-platform""#)?,
    ///     AuthenticatorAttachment::CrossPlatform)
    /// );
    /// assert!(matches!(
    ///     serde_json::from_str::<AuthenticatorAttachment>(r#""platform""#)?,
    ///     AuthenticatorAttachment::Platform)
    /// );
    /// // Case matters.
    /// assert!(serde_json::from_str::<AuthenticatorAttachment>(r#""Platform""#).is_err());
    /// // `AuthenticatorAttachment::None` is not deserializable.
    /// assert!(serde_json::from_str::<AuthenticatorAttachment>(r#""""#).is_err());
    /// assert!(serde_json::from_str::<AuthenticatorAttachment>("null").is_err());
    /// assert!(serde_json::from_str::<AuthenticatorAttachment>(r#""none""#).is_err());
    /// assert!(serde_json::from_str::<AuthenticatorAttachment>(r#""None""#).is_err());
    /// # Ok::<_, serde_json::Error>(())
    ///```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `AuthenticatorAttachment`.
        struct AuthenticatorAttachmentVisitor;
        impl Visitor<'_> for AuthenticatorAttachmentVisitor {
            type Value = AuthenticatorAttachment;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("AuthenticatorAttachment")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                /// `"platform"`
                const PLATFORM: &str = "platform";
                /// `"cross-platform"`
                const CROSS_PLATFORM: &str = "cross-platform";
                match v {
                    PLATFORM => Ok(AuthenticatorAttachment::Platform),
                    CROSS_PLATFORM => Ok(AuthenticatorAttachment::CrossPlatform),
                    _ => Err(E::invalid_value(
                        Unexpected::Str(v),
                        &format!("'{PLATFORM}' or '{CROSS_PLATFORM}'").as_str(),
                    )),
                }
            }
        }
        deserializer.deserialize_str(AuthenticatorAttachmentVisitor)
    }
}
/// Container of data that was encoded in base64url.
pub(crate) struct Base64DecodedVal(pub Vec<u8>);
impl<'de> Deserialize<'de> for Base64DecodedVal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `Base64DecodedVal`.
        struct Base64DecodedValVisitor;
        impl Visitor<'_> for Base64DecodedValVisitor {
            type Value = Base64DecodedVal;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("base64url-encoded data")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                base64url_nopad::decode(v.as_bytes())
                    .map_err(E::custom)
                    .map(Base64DecodedVal)
            }
        }
        deserializer.deserialize_str(Base64DecodedValVisitor)
    }
}
impl<'de> Deserialize<'de> for SentChallenge {
    /// Deserializes `[u8]` or [`prim@str`] based on
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge).
    ///
    /// Specifically a `[u8]` or `str` is base64url-decoded and interpreted as a little-endian
    /// `u128`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::SentChallenge;
    /// assert_eq!(
    ///     serde_json::from_slice::<SentChallenge>(br#""AAAAAAAAAAAAAAAAAAAAAA""#)?,
    ///     SentChallenge(0)
    /// );
    /// # Ok::<_, serde_json::Error>(())
    ///```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `SentChallenge`.
        struct ChallengeVisitor;
        impl Visitor<'_> for ChallengeVisitor {
            type Value = SentChallenge;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "base64 encoding of the 16-byte challenge in a URL safe way without padding",
                )
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v.len() == Challenge::BASE64_LEN {
                    let mut data = [0; 16];
                    base64url_nopad::decode_buffer_exact(v, data.as_mut_slice())
                        .map_err(E::custom)
                        .map(|()| SentChallenge::from_array(data))
                } else {
                    Err(E::invalid_value(
                        Unexpected::Bytes(v),
                        &"22 bytes encoded in base64url without padding",
                    ))
                }
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_bytes(v.as_bytes())
            }
        }
        deserializer.deserialize_bytes(ChallengeVisitor)
    }
}
impl<'de: 'a, 'a> Deserialize<'de> for Origin<'a> {
    /// Deserializes [`prim@str`] by borrowing the data when possible.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate alloc;
    /// # use alloc::borrow::Cow;
    /// # use webauthn_rp::response::Origin;
    /// let origin_borrowed = "https://example.com";
    /// let origin_owned = "\\\\https://example.com";
    /// assert!(
    ///     matches!(serde_json::from_str::<Origin<'_>>(format!("\"{origin_borrowed}\"").as_str())?.0, Cow::Borrowed(val) if val == origin_borrowed)
    /// );
    /// assert!(
    ///     matches!(serde_json::from_str::<Origin<'_>>(format!("\"{origin_owned}\"").as_str())?.0, Cow::Owned(val) if *val.as_bytes() == origin_owned.as_bytes()[1..])
    /// );
    /// # Ok::<_, serde_json::Error>(())
    ///```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `Origin`.
        struct OriginVisitor<'b>(PhantomData<fn() -> &'b ()>);
        impl<'d: 'b, 'b> Visitor<'d> for OriginVisitor<'b> {
            type Value = Origin<'b>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("Origin")
            }
            fn visit_borrowed_str<E>(self, v: &'d str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(Origin(Cow::Borrowed(v)))
            }
            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(Origin(Cow::Owned(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_string(v.to_owned())
            }
        }
        deserializer.deserialize_str(OriginVisitor(PhantomData))
    }
}
/// `trait` that returns an empty instance of `Self`.
pub(super) trait ClientExtensions: Sized {
    /// Returns an empty instance of `Self`.
    fn empty() -> Self;
}
/// Response for both registration and authentication ceremonies.
///
/// [`Self::raw_id`] is always `Some` when `!RELAXED` or `!REG`.
///
/// `RELAXED` and `REG` are used purely for deserialization purposes.
pub(super) struct PublicKeyCredential<const RELAXED: bool, const REG: bool, AuthResp, Ext> {
    /// [`rawId`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-rawid).
    pub id: Option<CredentialId<Box<[u8]>>>,
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response).
    pub response: AuthResp,
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment).
    pub authenticator_attachment: AuthenticatorAttachment,
    /// [`getClientExtensionResults`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-getclientextensionresults).
    pub client_extension_results: Ext,
}
/// Deserializes the value for type.
pub(crate) struct Type;
impl<'e> Deserialize<'e> for Type {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'e>,
    {
        /// `Visitor` for `Type`.
        struct TypeVisitor;
        impl Visitor<'_> for TypeVisitor {
            type Value = Type;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(PUBLIC_KEY)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v == PUBLIC_KEY {
                    Ok(Type)
                } else {
                    Err(E::invalid_value(Unexpected::Str(v), &PUBLIC_KEY))
                }
            }
        }
        deserializer.deserialize_str(TypeVisitor)
    }
}
/// `Visitor` for `PublicKeyCredential`.
///
/// When `!RELAXED`, `REG` is ignored and all fields must exist and unknown fields are not allowed.
/// When `RELAXED`, unknown fields are ignored.
/// When `RELAXED` and `REG`, only `response` is required.
/// When `RELAXED` and `!REG`, only `id` and `response` are required.
struct PublicKeyCredentialVisitor<const RELAXED: bool, const REG: bool, R, E>(
    pub PhantomData<fn() -> (R, E)>,
);
impl<'d, const REL: bool, const REGI: bool, R, E> Visitor<'d>
    for PublicKeyCredentialVisitor<REL, REGI, R, E>
where
    R: Deserialize<'d>,
    E: for<'a> Deserialize<'a> + ClientExtensions,
{
    type Value = PublicKeyCredential<REL, REGI, R, E>;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicKeyCredential")
    }
    #[expect(
        clippy::too_many_lines,
        reason = "rather hide all the internal logic instead instead of moving into an outer scope"
    )]
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'d>,
    {
        /// `PublicKeyCredentialJSON` fields.
        enum Field<const IGNORE_UNKNOWN: bool> {
            /// `id`.
            Id,
            /// `type`.
            Type,
            /// `rawId`.
            RawId,
            /// `response`.
            Response,
            /// `authenticatorAttachment`.
            AuthenticatorAttachment,
            /// `clientExtensionResults`.
            ClientExtensionResults,
            /// Unknown field.
            Other,
        }
        impl<'e, const IGNORE: bool> Deserialize<'e> for Field<IGNORE> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'e>,
            {
                /// `Visitor` for `Field`.
                struct FieldVisitor<const IGNORE_UNKNOWN: bool>;
                impl<const IGN: bool> Visitor<'_> for FieldVisitor<IGN> {
                    type Value = Field<IGN>;
                    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                        write!(
                            formatter,
                            "'{ID}', '{TYPE}', '{RAW_ID}', '{RESPONSE}', '{AUTHENTICATOR_ATTACHMENT}', or '{CLIENT_EXTENSION_RESULTS}'"
                        )
                    }
                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            ID => Ok(Field::Id),
                            TYPE => Ok(Field::Type),
                            RAW_ID => Ok(Field::RawId),
                            RESPONSE => Ok(Field::Response),
                            AUTHENTICATOR_ATTACHMENT => Ok(Field::AuthenticatorAttachment),
                            CLIENT_EXTENSION_RESULTS => Ok(Field::ClientExtensionResults),
                            _ => {
                                if IGN {
                                    Ok(Field::Other)
                                } else {
                                    Err(E::unknown_field(v, REG_FIELDS))
                                }
                            }
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor::<IGNORE>)
            }
        }
        let mut opt_id = None;
        let mut typ = false;
        let mut raw = None;
        let mut resp = None;
        let mut attach = None;
        let mut ext = None;
        while let Some(key) = map.next_key::<Field<REL>>()? {
            match key {
                Field::Id => {
                    if opt_id.is_some() {
                        return Err(Error::duplicate_field(ID));
                    }
                    opt_id = map.next_value::<CredentialId<_>>().map(Some)?;
                }
                Field::Type => {
                    if typ {
                        return Err(Error::duplicate_field(TYPE));
                    }
                    typ = map.next_value::<Type>().map(|_| true)?;
                }
                Field::RawId => {
                    if raw.is_some() {
                        return Err(Error::duplicate_field(RAW_ID));
                    }
                    raw = map.next_value::<CredentialId<_>>().map(Some)?;
                }
                Field::Response => {
                    if resp.is_some() {
                        return Err(Error::duplicate_field(RESPONSE));
                    }
                    resp = map.next_value::<R>().map(Some)?;
                }
                Field::AuthenticatorAttachment => {
                    if attach.is_some() {
                        return Err(Error::duplicate_field(AUTHENTICATOR_ATTACHMENT));
                    }
                    attach = map.next_value().map(Some)?;
                }
                Field::ClientExtensionResults => {
                    if ext.is_some() {
                        return Err(Error::duplicate_field(CLIENT_EXTENSION_RESULTS));
                    }
                    ext = map.next_value::<Option<E>>().map(Some)?;
                }
                Field::Other => map.next_value::<IgnoredAny>().map(|_| ())?,
            }
        }
        resp.ok_or_else(|| Error::missing_field(RESPONSE))
            .and_then(|response| {
                opt_id.map_or_else(
                    || {
                        if REL && REGI {
                            Ok(None)
                        } else {
                            Err(Error::missing_field(ID))
                        }
                    },
                    |id| Ok(Some(id)),
                )
                .and_then(|id| {
                    raw.map_or_else(
                        || {
                            if REL {
                                Ok(())
                            } else {
                                Err(Error::missing_field(RAW_ID))
                            }
                        },
                        |raw_id| {
                            id.as_ref().map_or_else(
                                || Ok(()),
                                |i| {
                                    if raw_id == i {
                                        Ok(())
                                    } else {
                                        Err(Error::invalid_value(
                                            Unexpected::Bytes(raw_id.as_ref()),
                                            &format!("{ID} and {RAW_ID} to match: {i:?}").as_str(),
                                        ))
                                    }
                                },
                            )
                        }
                    )
                    .and_then(|()| {
                        ext.ok_or(false).and_then(|opt_ext| opt_ext.ok_or(true)).map_or_else(
                            |flag| {
                                if REL {
                                    Ok(E::empty())
                                } else if flag {
                                    Err(Error::invalid_type(Unexpected::Other("null"), &format!("{CLIENT_EXTENSION_RESULTS} to be a map of allowed client extensions").as_str()))
                                } else {
                                    Err(Error::missing_field(CLIENT_EXTENSION_RESULTS))
                                }
                            },
                            Ok
                        )
                        .and_then(|client_extension_results| {
                            if typ || REL {
                                Ok(PublicKeyCredential {
                                    id,
                                    response,
                                    authenticator_attachment: attach.flatten().unwrap_or(AuthenticatorAttachment::None),
                                    client_extension_results,
                                })
                            } else {
                                Err(Error::missing_field(TYPE))
                            }
                        })
                    })
                })
            })
    }
}
/// `"id"`.
const ID: &str = "id";
/// `"type"`.
const TYPE: &str = "type";
/// `"rawId"`.
const RAW_ID: &str = "rawId";
/// `"response"`.
const RESPONSE: &str = "response";
/// `"authenticatorAttachment"`.
const AUTHENTICATOR_ATTACHMENT: &str = "authenticatorAttachment";
/// `"clientExtensionResults"`.
const CLIENT_EXTENSION_RESULTS: &str = "clientExtensionResults";
/// `"public-key"`.
const PUBLIC_KEY: &str = "public-key";
/// Fields for `PublicKeyCredentialJSON`.
const REG_FIELDS: &[&str; 6] = &[
    ID,
    TYPE,
    RAW_ID,
    RESPONSE,
    AUTHENTICATOR_ATTACHMENT,
    CLIENT_EXTENSION_RESULTS,
];
impl<'de, const REL: bool, const REGI: bool, R, E> Deserialize<'de>
    for PublicKeyCredential<REL, REGI, R, E>
where
    R: Deserialize<'de>,
    E: for<'a> Deserialize<'a> + ClientExtensions,
{
    /// Deserializes a `struct` based on
    /// [`PublicKeyCredentialJSON`](https://www.w3.org/TR/webauthn-3/#typedefdef-publickeycredentialjson).
    ///
    /// `REL` iff unknown fields should be ignored and not cause an error.
    /// `REGI` iff `Self` is from a registration ceremony.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "PublicKeyCredential",
            REG_FIELDS,
            PublicKeyCredentialVisitor::<REL, REGI, _, _>(PhantomData),
        )
    }
}
use super::UserHandle;
impl<const USER_LEN: usize> Serialize for AllAcceptedCredentialsOptions<'_, '_, USER_LEN>
where
    UserHandle<USER_LEN>: Serialize,
{
    /// Serializes `self` to conform with
    /// [`AllAcceptedCredentialsOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-allacceptedcredentialsoptions).
    ///
    /// # Examples
    ///
    /// ```
    /// # use core::str::FromStr;
    /// # #[cfg(feature = "bin")]
    /// # use webauthn_rp::bin::Decode;
    /// # use webauthn_rp::{
    /// #     request::{register::{UserHandle, USER_HANDLE_MIN_LEN}, AsciiDomain, RpId},
    /// #     response::{error::CredentialIdErr, AllAcceptedCredentialsOptions, CredentialId},
    /// # };
    /// /// Retrieves the `CredentialId`s associated with `user_id` from the database.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// fn get_credential_ids(user_id: UserHandle<USER_HANDLE_MIN_LEN>) -> Result<Vec<CredentialId<Box<[u8]>>>, CredentialIdErr> {
    ///     // ⋮
    /// #     CredentialId::decode(vec![0; 16].into_boxed_slice()).map(|cred_id| vec![cred_id])
    /// }
    /// /// Retrieves the `UserHandle` from a session cookie.
    /// # #[cfg(feature = "custom")]
    /// fn get_user_handle() -> UserHandle<USER_HANDLE_MIN_LEN> {
    ///     // ⋮
    /// #     [0].into()
    /// }
    /// # #[cfg(feature = "custom")]
    /// let user_id = get_user_handle();
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(
    ///     serde_json::to_string(&AllAcceptedCredentialsOptions {
    ///         rp_id: &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         user_id: &user_id,
    ///         all_accepted_credential_ids: get_credential_ids(user_id)?,
    ///     })
    ///     .unwrap(),
    ///     r#"{"rpId":"example.com","userId":"AA","allAcceptedCredentialIds":["AAAAAAAAAAAAAAAAAAAAAA"]}"#
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("AllAcceptedCredentialsOptions", 3)
            .and_then(|mut ser| {
                ser.serialize_field("rpId", self.rp_id).and_then(|()| {
                    ser.serialize_field("userId", &self.user_id).and_then(|()| {
                        ser.serialize_field(
                            "allAcceptedCredentialIds",
                            &self.all_accepted_credential_ids,
                        )
                        .and_then(|()| ser.end())
                    })
                })
            })
    }
}
impl<const LEN: usize> Serialize for CurrentUserDetailsOptions<'_, '_, '_, '_, LEN>
where
    UserHandle<LEN>: Serialize,
{
    /// Serializes `self` to conform with
    /// [`CurrentUserDetailsOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-currentuserdetailsoptions).
    ///
    /// # Examples
    ///
    /// ```
    /// # use core::str::FromStr;
    /// # #[cfg(feature = "bin")]
    /// # use webauthn_rp::bin::Decode;
    /// # use webauthn_rp::{
    /// #     request::{register::{PublicKeyCredentialUserEntity, UserHandle, USER_HANDLE_MIN_LEN}, AsciiDomain, RpId},
    /// #     response::CurrentUserDetailsOptions,
    /// #     AggErr,
    /// # };
    /// /// Retrieves the `PublicKeyCredentialUserEntity` info associated with `user_id` from the database.
    /// # #[cfg(feature = "bin")]
    /// fn get_user_info(user_id: UserHandle<USER_HANDLE_MIN_LEN>) -> Result<(String, String), AggErr> {
    ///     // ⋮
    /// #     Ok(("foo".to_owned(), "foo".to_owned()))
    /// }
    /// /// Retrieves the `UserHandle` from a session cookie.
    /// # #[cfg(feature = "custom")]
    /// fn get_user_handle() -> UserHandle<USER_HANDLE_MIN_LEN> {
    ///     // ⋮
    /// #     [0].into()
    /// }
    /// # #[cfg(feature = "custom")]
    /// let user_handle = get_user_handle();
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let (name, display_name) = get_user_info(user_handle)?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(
    ///     serde_json::to_string(&CurrentUserDetailsOptions {
    ///         rp_id: &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         user: PublicKeyCredentialUserEntity { name: &name, id: &user_handle, display_name: &display_name, },
    ///     })
    ///     .unwrap(),
    ///     r#"{"rpId":"example.com","userId":"AA","name":"foo","displayName":"foo"}"#
    /// );
    /// # Ok::<_, AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("CurrentUserDetailsOptions", 4)
            .and_then(|mut ser| {
                ser.serialize_field("rpId", self.rp_id).and_then(|()| {
                    ser.serialize_field("userId", &self.user.id).and_then(|()| {
                        ser.serialize_field("name", &self.user.name).and_then(|()| {
                            ser.serialize_field("displayName", &self.user.display_name)
                                .and_then(|()| ser.end())
                        })
                    })
                })
            })
    }
}
/// JSON `null`.
pub(crate) struct Null;
impl<'de> Deserialize<'de> for Null {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `Null`.
        struct NullVisitor;
        impl Visitor<'_> for NullVisitor {
            type Value = Null;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("null")
            }
            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(Null)
            }
        }
        deserializer.deserialize_option(NullVisitor)
    }
}
/// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues).
pub(super) struct AuthenticationExtensionsPrfValues;
/// `Visitor` for `AuthenticationExtensionsPrfValues`.
///
/// Unknown fields are ignored iff `RELAXED`.`first` must always exist if `second` does.
/// `first` and `second` must be `null` if they exist. `first` must exist iff `!RELAXED`.
pub(super) struct AuthenticationExtensionsPrfValuesVisitor<const RELAXED: bool>;
impl<'d, const R: bool> Visitor<'d> for AuthenticationExtensionsPrfValuesVisitor<R> {
    type Value = AuthenticationExtensionsPrfValues;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticationExtensionsPrfValues")
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'d>,
    {
        /// Fields.
        enum Field<const IGNORE_UNKNOWN: bool> {
            /// `first` field.
            First,
            /// `second` field.
            Second,
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
                        write!(formatter, "'{FIRST}' or '{SECOND}'")
                    }
                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            FIRST => Ok(Field::First),
                            SECOND => Ok(Field::Second),
                            _ => {
                                if IG {
                                    Ok(Field::Other)
                                } else {
                                    Err(E::unknown_field(v, PRF_VALUES_FIELDS))
                                }
                            }
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }
        let mut first = None;
        let mut second = None;
        while let Some(key) = map.next_key::<Field<R>>()? {
            match key {
                Field::First => {
                    if first.is_some() {
                        return Err(Error::duplicate_field(FIRST));
                    }
                    first = map.next_value::<Null>().map(Some)?;
                }
                Field::Second => {
                    if second.is_some() {
                        return Err(Error::duplicate_field(SECOND));
                    }
                    second = map.next_value::<Null>().map(Some)?;
                }
                Field::Other => map.next_value::<IgnoredAny>().map(|_| ())?,
            }
        }
        if first.is_some() || (R && second.is_none()) {
            Ok(AuthenticationExtensionsPrfValues)
        } else {
            Err(Error::missing_field(FIRST))
        }
    }
}
/// `"first"`
const FIRST: &str = "first";
/// `"second"`
const SECOND: &str = "second";
/// `AuthenticationExtensionsPrfValues` fields.
pub(super) const PRF_VALUES_FIELDS: &[&str; 2] = &[FIRST, SECOND];
impl<'de> Deserialize<'de> for AuthenticationExtensionsPrfValues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "AuthenticationExtensionsPrfValues",
            PRF_VALUES_FIELDS,
            AuthenticationExtensionsPrfValuesVisitor::<false>,
        )
    }
}
/// [`AuthenticationExtensionsPRFOutputs`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfoutputs).
///
/// `RELAXED` iff unknown fields are ignored.
///
/// `REGISTRATION` iff
/// [`enabled`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-enabled)
/// is required (and must not be `null`); otherwise it's forbidden.
///
/// The contained `Option` is `Some` iff `REGISTRATION`.
pub(super) struct AuthenticationExtensionsPrfOutputsHelper<
    const RELAXED: bool,
    const REGISTRATION: bool,
    Prf,
>(pub Option<bool>, pub PhantomData<fn() -> Prf>);
/// `Visitor` for `AuthenticationExtensionsPrfOutputs`.
///
/// Unknown fields are ignored iff `RELAXED`.`enabled` must exist and not be `null` iff `REGISTRATION`.
struct AuthenticationExtensionsPrfOutputsVisitor<const RELAXED: bool, const REGISTRATION: bool, Prf>(
    PhantomData<fn() -> Prf>,
);
impl<'d, const REL: bool, const REG: bool, Prf> Visitor<'d>
    for AuthenticationExtensionsPrfOutputsVisitor<REL, REG, Prf>
where
    Prf: for<'a> Deserialize<'a>,
{
    type Value = AuthenticationExtensionsPrfOutputsHelper<REL, REG, Prf>;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticationExtensionsPrfOutputs")
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'d>,
    {
        /// Fields.
        enum Field<const IGNORE_UNKNOWN: bool, const REGI: bool> {
            /// `enabled` field.
            Enabled,
            /// `results` field.
            Results,
            /// Unknown field.
            Other,
        }
        impl<'e, const I: bool, const R: bool> Deserialize<'e> for Field<I, R> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'e>,
            {
                /// `Visitor` for `Field`.
                ///
                /// Unknown fields are ignored iff `IGNORE_UNKNOWN`.
                /// `enabled` is allowed to exist iff `REGI`.
                struct FieldVisitor<const IGNORE_UNKNOWN: bool, const REGI: bool>;
                impl<const IG: bool, const RE: bool> Visitor<'_> for FieldVisitor<IG, RE> {
                    type Value = Field<IG, RE>;
                    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                        if RE {
                            write!(formatter, "'{ENABLED}' or '{RESULTS}'")
                        } else {
                            write!(formatter, "'{RESULTS}'")
                        }
                    }
                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            ENABLED => {
                                if RE {
                                    Ok(Field::Enabled)
                                } else {
                                    Err(E::unknown_field(v, PRF_AUTH_OUTPUTS_FIELDS))
                                }
                            }
                            RESULTS => Ok(Field::Results),
                            _ => {
                                if IG {
                                    Ok(Field::Other)
                                } else if RE {
                                    Err(E::unknown_field(v, PRF_REG_OUTPUTS_FIELDS))
                                } else {
                                    Err(E::unknown_field(v, PRF_AUTH_OUTPUTS_FIELDS))
                                }
                            }
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }
        let mut enabled = None;
        let mut results = None;
        while let Some(key) = map.next_key::<Field<REL, REG>>()? {
            match key {
                Field::Enabled => {
                    if enabled.is_some() {
                        return Err(Error::duplicate_field(ENABLED));
                    }
                    enabled = map.next_value().map(Some)?;
                }
                Field::Results => {
                    if results.is_some() {
                        return Err(Error::duplicate_field(RESULTS));
                    }
                    results = map.next_value::<Option<Prf>>().map(Some)?;
                }
                Field::Other => map.next_value::<IgnoredAny>().map(|_| ())?,
            }
        }
        if REG {
            enabled.ok_or_else(|| Error::missing_field(ENABLED)).and_then(|e| {
                if e || results.is_none() {
                    Ok(())
                } else {
                    Err(Error::custom("prf must not have 'results', including a null 'results', if 'enabled' is false"))
                }
            })
        } else {
            Ok(())
        }.map(|()| AuthenticationExtensionsPrfOutputsHelper(enabled, PhantomData))
    }
}
/// `"enabled"`
const ENABLED: &str = "enabled";
/// `"results"`
const RESULTS: &str = "results";
/// `AuthenticationExtensionsPrfOutputs` field during registration.
const PRF_REG_OUTPUTS_FIELDS: &[&str; 2] = &[ENABLED, RESULTS];
/// `AuthenticationExtensionsPrfOutputs` field during authentication.
const PRF_AUTH_OUTPUTS_FIELDS: &[&str; 1] = &[RESULTS];
impl<'de, const REL: bool, const REG: bool, Prf> Deserialize<'de>
    for AuthenticationExtensionsPrfOutputsHelper<REL, REG, Prf>
where
    for<'a> Prf: Deserialize<'a>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "AuthenticationExtensionsPrfOutputs",
            if REG {
                PRF_REG_OUTPUTS_FIELDS
            } else {
                PRF_AUTH_OUTPUTS_FIELDS
            },
            AuthenticationExtensionsPrfOutputsVisitor::<REL, REG, Prf>(PhantomData),
        )
    }
}
