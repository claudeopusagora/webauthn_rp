use super::{
    super::response::ser::Base64DecodedVal, AsciiDomain, AsciiDomainStatic, Challenge,
    CredentialId, CredentialMediationRequirement, ExtensionReq, Hint, PrfInput,
    PublicKeyCredentialDescriptor, RpId, Url, UserVerificationRequirement, auth::PrfInputOwned,
};
use core::{
    fmt::{self, Formatter},
    str::FromStr as _,
};
use serde::{
    de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Unexpected, Visitor},
    ser::{Serialize, SerializeSeq as _, SerializeStruct as _, Serializer},
};
/// `"required"`.
const REQUIRED: &str = "required";
/// `"conditional"`.
const CONDITIONAL: &str = "conditional";
impl Serialize for CredentialMediationRequirement {
    /// Serializes `self` to conform with
    /// [`CredentialMediationRequirement`](https://www.w3.org/TR/credential-management-1/#enumdef-credentialmediationrequirement).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::CredentialMediationRequirement;
    /// assert_eq!(
    ///     serde_json::to_string(&CredentialMediationRequirement::Required)?,
    ///     r#""required""#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&CredentialMediationRequirement::Conditional)?,
    ///     r#""conditional""#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match *self {
            Self::Required => REQUIRED,
            Self::Conditional => CONDITIONAL,
        })
    }
}
impl Serialize for Challenge {
    /// Serializes `self` to conform with
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-challenge).
    ///
    /// Specifically [`Self::as_array`] is transformed into a base64url-encoded string.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Challenge;
    /// # // `Challenge::BASE64_LEN` is 22, but we add two for the quotes.
    /// assert_eq!(serde_json::to_string(&Challenge::new())?.len(), 24);
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(base64url_nopad::encode_buffer(
            self.as_array().as_slice(),
            [0; Self::BASE64_LEN].as_mut_slice(),
        ))
    }
}
impl Serialize for AsciiDomain {
    /// Serializes `self` as a [`prim@str`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::AsciiDomain;
    /// assert_eq!(
    ///     serde_json::to_string(&AsciiDomain::try_from("www.example.com".to_owned()).unwrap()).unwrap(),
    ///     r#""www.example.com""#
    /// );
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}
impl Serialize for AsciiDomainStatic {
    /// Serializes `self` as a [`prim@str`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::AsciiDomainStatic;
    /// assert_eq!(
    ///     serde_json::to_string(&AsciiDomainStatic::new("www.example.com").unwrap()).unwrap(),
    ///     r#""www.example.com""#
    /// );
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}
impl Serialize for Url {
    /// Serializes `self` as a [`prim@str`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use core::str::FromStr as _;
    /// # use webauthn_rp::request::Url;
    /// assert_eq!(
    ///     serde_json::to_string(&Url::from_str("ssh:foo").unwrap()).unwrap(),
    ///     r#""ssh:foo""#
    /// );
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}
impl Serialize for RpId {
    /// Serializes `self` as a [`prim@str`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{AsciiDomain, RpId};
    /// assert_eq!(
    ///     serde_json::to_string(&RpId::Domain(AsciiDomain::try_from("www.example.com".to_owned()).unwrap())).unwrap(),
    ///     r#""www.example.com""#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&RpId::Url("ssh:foo".parse().unwrap())).unwrap(),
    ///     r#""ssh:foo""#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}
impl<T> Serialize for PublicKeyCredentialDescriptor<T>
where
    CredentialId<T>: Serialize,
{
    /// Serializes `self` to conform with
    /// [`PublicKeyCredentialDescriptorJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptorjson).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// # use webauthn_rp::{bin::Decode, response::bin::DecodeAuthTransportsErr};
    /// # use webauthn_rp::{
    /// #     request::PublicKeyCredentialDescriptor,
    /// #     response::{AuthTransports, CredentialId},
    /// # };
    /// /// Retrieves the `AuthTransports` associated with the unique `cred_id`
    /// /// from the database.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// fn get_transports(cred_id: CredentialId<&[u8]>) -> Result<AuthTransports, DecodeAuthTransportsErr> {
    ///     // ⋮
    /// #     AuthTransports::decode(32)
    /// }
    /// // `CredentialId::try_from` only exists when `custom` is enabled; and even then, it is
    /// // likely never needed since the `CredentialId` was originally sent from the client and is likely
    /// // stored in a database which would be fetched by `UserHandle` or `Authentication::raw_id`.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let id = CredentialId::try_from(vec![0; 16])?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports = get_transports((&id).into())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(
    ///     serde_json::to_string(&PublicKeyCredentialDescriptor { id, transports }).unwrap(),
    ///     r#"{"type":"public-key","id":"AAAAAAAAAAAAAAAAAAAAAA","transports":["usb"]}"#
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("PublicKeyCredentialDescriptor", 3)
            .and_then(|mut ser| {
                ser.serialize_field("type", "public-key").and_then(|()| {
                    ser.serialize_field("id", &self.id).and_then(|()| {
                        ser.serialize_field("transports", &self.transports)
                            .and_then(|()| ser.end())
                    })
                })
            })
    }
}
impl Serialize for UserVerificationRequirement {
    /// Serializes `self` to conform with
    /// [`UserVerificationRequirement`](https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::UserVerificationRequirement;
    /// assert_eq!(
    ///     serde_json::to_string(&UserVerificationRequirement::Required)?,
    ///     r#""required""#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&UserVerificationRequirement::Discouraged)?,
    ///     r#""discouraged""#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&UserVerificationRequirement::Preferred)?,
    ///     r#""preferred""#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match *self {
            Self::Required => "required",
            Self::Discouraged => "discouraged",
            Self::Preferred => "preferred",
        })
    }
}
/// [`security-key`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhints-security-key).
const SECURITY_KEY: &str = "security-key";
/// [`client-device`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhints-client-device).
const CLIENT_DEVICE: &str = "client-device";
/// [`hybrid`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhints-hybrid).
const HYBRID: &str = "hybrid";
impl Serialize for Hint {
    /// Serializes `self` to conform with
    /// [`hints`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-hints).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Hint;
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::None)?,
    ///     r#"[]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::SecurityKey)?,
    ///     r#"["security-key"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::ClientDevice)?,
    ///     r#"["client-device"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::Hybrid)?,
    ///     r#"["hybrid"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::SecurityKeyClientDevice)?,
    ///     r#"["security-key","client-device"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::ClientDeviceSecurityKey)?,
    ///     r#"["client-device","security-key"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::SecurityKeyHybrid)?,
    ///     r#"["security-key","hybrid"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::HybridSecurityKey)?,
    ///     r#"["hybrid","security-key"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::ClientDeviceHybrid)?,
    ///     r#"["client-device","hybrid"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::HybridClientDevice)?,
    ///     r#"["hybrid","client-device"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::SecurityKeyClientDeviceHybrid)?,
    ///     r#"["security-key","client-device","hybrid"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::SecurityKeyHybridClientDevice)?,
    ///     r#"["security-key","hybrid","client-device"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::ClientDeviceSecurityKeyHybrid)?,
    ///     r#"["client-device","security-key","hybrid"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::ClientDeviceHybridSecurityKey)?,
    ///     r#"["client-device","hybrid","security-key"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::HybridSecurityKeyClientDevice)?,
    ///     r#"["hybrid","security-key","client-device"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&Hint::HybridClientDeviceSecurityKey)?,
    ///     r#"["hybrid","client-device","security-key"]"#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let count = match *self {
            Self::None => 0,
            Self::SecurityKey | Self::ClientDevice | Self::Hybrid => 1,
            Self::SecurityKeyClientDevice
            | Self::ClientDeviceSecurityKey
            | Self::SecurityKeyHybrid
            | Self::HybridSecurityKey
            | Self::ClientDeviceHybrid
            | Self::HybridClientDevice => 2,
            Self::SecurityKeyClientDeviceHybrid
            | Self::SecurityKeyHybridClientDevice
            | Self::ClientDeviceSecurityKeyHybrid
            | Self::ClientDeviceHybridSecurityKey
            | Self::HybridSecurityKeyClientDevice
            | Self::HybridClientDeviceSecurityKey => 3,
        };
        serializer.serialize_seq(Some(count)).and_then(|mut ser| {
            match *self {
                Self::None => Ok(()),
                Self::SecurityKey => ser.serialize_element(SECURITY_KEY),
                Self::ClientDevice => ser.serialize_element(CLIENT_DEVICE),
                Self::Hybrid => ser.serialize_element(HYBRID),
                Self::SecurityKeyClientDevice => ser
                    .serialize_element(SECURITY_KEY)
                    .and_then(|()| ser.serialize_element(CLIENT_DEVICE)),
                Self::ClientDeviceSecurityKey => ser
                    .serialize_element(CLIENT_DEVICE)
                    .and_then(|()| ser.serialize_element(SECURITY_KEY)),
                Self::SecurityKeyHybrid => ser
                    .serialize_element(SECURITY_KEY)
                    .and_then(|()| ser.serialize_element(HYBRID)),
                Self::HybridSecurityKey => ser
                    .serialize_element(HYBRID)
                    .and_then(|()| ser.serialize_element(SECURITY_KEY)),
                Self::ClientDeviceHybrid => ser
                    .serialize_element(CLIENT_DEVICE)
                    .and_then(|()| ser.serialize_element(HYBRID)),
                Self::HybridClientDevice => ser
                    .serialize_element(HYBRID)
                    .and_then(|()| ser.serialize_element(CLIENT_DEVICE)),
                Self::SecurityKeyClientDeviceHybrid => {
                    ser.serialize_element(SECURITY_KEY).and_then(|()| {
                        ser.serialize_element(CLIENT_DEVICE)
                            .and_then(|()| ser.serialize_element(HYBRID))
                    })
                }
                Self::SecurityKeyHybridClientDevice => {
                    ser.serialize_element(SECURITY_KEY).and_then(|()| {
                        ser.serialize_element(HYBRID)
                            .and_then(|()| ser.serialize_element(CLIENT_DEVICE))
                    })
                }
                Self::ClientDeviceSecurityKeyHybrid => {
                    ser.serialize_element(CLIENT_DEVICE).and_then(|()| {
                        ser.serialize_element(SECURITY_KEY)
                            .and_then(|()| ser.serialize_element(HYBRID))
                    })
                }
                Self::ClientDeviceHybridSecurityKey => {
                    ser.serialize_element(CLIENT_DEVICE).and_then(|()| {
                        ser.serialize_element(HYBRID)
                            .and_then(|()| ser.serialize_element(SECURITY_KEY))
                    })
                }
                Self::HybridSecurityKeyClientDevice => {
                    ser.serialize_element(HYBRID).and_then(|()| {
                        ser.serialize_element(SECURITY_KEY)
                            .and_then(|()| ser.serialize_element(CLIENT_DEVICE))
                    })
                }
                Self::HybridClientDeviceSecurityKey => {
                    ser.serialize_element(HYBRID).and_then(|()| {
                        ser.serialize_element(CLIENT_DEVICE)
                            .and_then(|()| ser.serialize_element(SECURITY_KEY))
                    })
                }
            }
            .and_then(|()| ser.end())
        })
    }
}
/// `"first"`.
const FIRST: &str = "first";
/// `"second"`.
const SECOND: &str = "second";
impl Serialize for PrfInput<'_, '_> {
    /// Serializes `self` to conform with
    /// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{PrfInput, ExtensionReq};
    /// assert_eq!(
    ///     serde_json::to_string(&PrfInput {
    ///         first: [0; 4].as_slice(),
    ///         second: Some([2; 1].as_slice()),
    ///     })?,
    ///     r#"{"first":"AAAAAA","second":"Ag"}"#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment justifies how overflow is not possible"
    )]
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            // The max value is 1 + 1 = 2, so overflow is not an issue.
            .serialize_struct("PrfInput", 1 + usize::from(self.second.is_some()))
            .and_then(|mut ser| {
                ser.serialize_field(FIRST, base64url_nopad::encode(self.first).as_str())
                    .and_then(|()| {
                        self.second
                            .as_ref()
                            .map_or(Ok(()), |second| {
                                ser.serialize_field(
                                    SECOND,
                                    base64url_nopad::encode(second).as_str(),
                                )
                            })
                            .and_then(|()| ser.end())
                    })
            })
    }
}
impl<'de> Deserialize<'de> for PrfInputOwned {
    /// Deserializes a `struct` based on
    /// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues).
    ///
    /// [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first) is required and
    /// must not be `null`.
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second) is not required
    /// and can be `null`.
    ///
    /// Note [`PrfInputOwned::ext_req`] is set to [`ExtensionReq::Allow`].
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `PrfInputOwned`.
        struct PrfInputOwnedVisitor;
        impl<'d> Visitor<'d> for PrfInputOwnedVisitor {
            type Value = PrfInputOwned;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("PrfInputOwned")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Field for `PrfInputOwned`.
                enum Field {
                    /// `first`.
                    First,
                    /// `second`.
                    Second,
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
                                write!(formatter, "'{FIRST}' or '{SECOND}'")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    FIRST => Ok(Field::First),
                                    SECOND => Ok(Field::Second),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                let mut fst = None;
                let mut snd = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::First => {
                            if fst.is_some() {
                                return Err(Error::duplicate_field(FIRST));
                            }
                            fst = map
                                .next_value::<Base64DecodedVal>()
                                .map(|val| Some(val.0))?;
                        }
                        Field::Second => {
                            if snd.is_some() {
                                return Err(Error::duplicate_field(SECOND));
                            }
                            snd = map
                                .next_value::<Option<Base64DecodedVal>>()
                                .map(|opt| Some(opt.map(|val| val.0)))?;
                        }
                    }
                }
                fst.ok_or_else(|| Error::missing_field(FIRST))
                    .map(|first| PrfInputOwned {
                        first,
                        second: snd.flatten(),
                        ext_req: ExtensionReq::Allow,
                    })
            }
        }
        const FIELDS: &[&str; 2] = &[FIRST, SECOND];
        deserializer.deserialize_struct("PrfInputOwned", FIELDS, PrfInputOwnedVisitor)
    }
}
impl<'de> Deserialize<'de> for AsciiDomain {
    /// Deserializes [`String`] based on [`Self::try_from`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::AsciiDomain;
    /// assert!(matches!(
    ///     serde_json::from_str::<AsciiDomain>(r#""example.com""#)?.as_ref(),
    ///     "example.com"
    /// ));
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).and_then(|dom| Self::try_from(dom).map_err(Error::custom))
    }
}
impl Deserialize<'static> for AsciiDomainStatic {
    /// Deserializes [`prim@str`] based on [`Self::new`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::AsciiDomainStatic;
    /// assert!(matches!(
    ///     serde_json::from_str::<AsciiDomainStatic>(r#""example.com""#)?.as_str(),
    ///     "example.com"
    /// ));
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'static>,
    {
        <&'static str>::deserialize(deserializer).and_then(|dom| {
            Self::new(dom)
                .ok_or_else(|| Error::custom("AsciiDomainStatic requires a valid ASCII domain"))
        })
    }
}
impl<'de> Deserialize<'de> for Url {
    /// Deserializes [`prim@str`] based on [`Self::from_str`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Url;
    /// assert!(matches!(
    ///     serde_json::from_str::<Url>(r#""ssh:foo""#)?.as_ref(),
    ///     "ssh:foo"
    /// ));
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `Url`
        struct UrlVisitor;
        impl Visitor<'_> for UrlVisitor {
            type Value = Url;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("Url")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Url::from_str(v).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(UrlVisitor)
    }
}
impl<'de> Deserialize<'de> for RpId {
    /// Deserializes a [`String`] based on [`Self::try_from`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::RpId;
    /// assert!(matches!(
    ///     serde_json::from_str::<RpId>(r#""example.com""#)?.as_ref(),
    ///     "example.com"
    /// ));
    /// assert!(matches!(
    ///     serde_json::from_str::<RpId>(r#""ssh:foo""#)?.as_ref(),
    ///     "ssh:foo"
    /// ));
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).and_then(|dom| Self::try_from(dom).map_err(Error::custom))
    }
}
/// Helper for `Hint::deserialize`.
enum HintHelper {
    /// `"security-key"`
    SecurityKey,
    /// `"client-device"`
    ClientDevice,
    /// `"hybrid"`
    Hybrid,
}
impl<'de> Deserialize<'de> for HintHelper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `HintHelper`.
        struct HintHelperVisitor;
        impl Visitor<'_> for HintHelperVisitor {
            type Value = HintHelper;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "'{SECURITY_KEY}', '{CLIENT_DEVICE}', or '{HYBRID}'"
                )
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match v {
                    SECURITY_KEY => Ok(HintHelper::SecurityKey),
                    CLIENT_DEVICE => Ok(HintHelper::ClientDevice),
                    HYBRID => Ok(HintHelper::Hybrid),
                    _ => Err(E::invalid_value(
                        Unexpected::Str(v),
                        &format!("'{SECURITY_KEY}', '{CLIENT_DEVICE}', or '{HYBRID}'").as_str(),
                    )),
                }
            }
        }
        deserializer.deserialize_str(HintHelperVisitor)
    }
}
impl<'de> Deserialize<'de> for Hint {
    /// Deserializes a sequence based on
    /// [`hints`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-hints).
    ///
    /// Note duplicates and unknown values will lead to an error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Hint;
    /// assert!(
    ///     matches!(
    ///         serde_json::from_str(r#"["security-key", "hybrid", "client-device"]"#)?,
    ///         Hint::SecurityKeyHybridClientDevice
    ///     )
    /// );
    /// assert!(
    ///     matches!(
    ///         serde_json::from_str(r#"["hybrid", "security-key", "client-device"]"#)?,
    ///         Hint::HybridSecurityKeyClientDevice
    ///     )
    /// );
    /// assert!(
    ///     matches!(
    ///         serde_json::from_str(r#"[]"#)?,
    ///         Hint::None
    ///     )
    /// );
    /// assert!(
    ///         serde_json::from_str::<Hint>(r#"["security-key", "hybrid", "hybrid"]"#).is_err()
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `Hint`.
        struct HintVisitor;
        impl<'d> Visitor<'d> for HintVisitor {
            type Value = Hint;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("unique sequence of hints")
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'d>,
            {
                let mut hint = Hint::None;
                while let Some(elem) = seq.next_element::<HintHelper>()? {
                    hint = match elem {
                        HintHelper::SecurityKey => match hint {
                            Hint::None => Hint::SecurityKey,
                            Hint::SecurityKey
                            | Hint::SecurityKeyClientDevice
                            | Hint::ClientDeviceSecurityKey
                            | Hint::SecurityKeyHybrid
                            | Hint::HybridSecurityKey
                            | Hint::SecurityKeyClientDeviceHybrid
                            | Hint::SecurityKeyHybridClientDevice
                            | Hint::ClientDeviceSecurityKeyHybrid
                            | Hint::ClientDeviceHybridSecurityKey
                            | Hint::HybridSecurityKeyClientDevice
                            | Hint::HybridClientDeviceSecurityKey => {
                                return Err(Error::custom(format!(
                                    "'{SECURITY_KEY}' hint appeared more than once"
                                )));
                            }
                            Hint::ClientDevice => Hint::ClientDeviceSecurityKey,
                            Hint::Hybrid => Hint::HybridSecurityKey,
                            Hint::ClientDeviceHybrid => Hint::ClientDeviceHybridSecurityKey,
                            Hint::HybridClientDevice => Hint::HybridClientDeviceSecurityKey,
                        },
                        HintHelper::ClientDevice => match hint {
                            Hint::None => Hint::ClientDevice,
                            Hint::SecurityKey => Hint::SecurityKeyClientDevice,
                            Hint::ClientDevice
                            | Hint::ClientDeviceSecurityKey
                            | Hint::SecurityKeyClientDevice
                            | Hint::ClientDeviceHybrid
                            | Hint::HybridClientDevice
                            | Hint::ClientDeviceSecurityKeyHybrid
                            | Hint::ClientDeviceHybridSecurityKey
                            | Hint::SecurityKeyClientDeviceHybrid
                            | Hint::SecurityKeyHybridClientDevice
                            | Hint::HybridClientDeviceSecurityKey
                            | Hint::HybridSecurityKeyClientDevice => {
                                return Err(Error::custom(format!(
                                    "'{CLIENT_DEVICE}' hint appeared more than once"
                                )));
                            }
                            Hint::Hybrid => Hint::HybridClientDevice,
                            Hint::SecurityKeyHybrid => Hint::SecurityKeyHybridClientDevice,
                            Hint::HybridSecurityKey => Hint::HybridSecurityKeyClientDevice,
                        },
                        HintHelper::Hybrid => match hint {
                            Hint::None => Hint::Hybrid,
                            Hint::Hybrid
                            | Hint::HybridClientDevice
                            | Hint::ClientDeviceHybrid
                            | Hint::HybridSecurityKey
                            | Hint::SecurityKeyHybrid
                            | Hint::HybridClientDeviceSecurityKey
                            | Hint::HybridSecurityKeyClientDevice
                            | Hint::ClientDeviceHybridSecurityKey
                            | Hint::ClientDeviceSecurityKeyHybrid
                            | Hint::SecurityKeyHybridClientDevice
                            | Hint::SecurityKeyClientDeviceHybrid => {
                                return Err(Error::custom(format!(
                                    "'{HYBRID}' hint appeared more than once"
                                )));
                            }
                            Hint::ClientDevice => Hint::ClientDeviceHybrid,
                            Hint::SecurityKey => Hint::SecurityKeyHybrid,
                            Hint::ClientDeviceSecurityKey => Hint::ClientDeviceSecurityKeyHybrid,
                            Hint::SecurityKeyClientDevice => Hint::SecurityKeyClientDeviceHybrid,
                        },
                    };
                }
                Ok(hint)
            }
        }
        deserializer.deserialize_seq(HintVisitor)
    }
}
impl<'de> Deserialize<'de> for CredentialMediationRequirement {
    /// Deserializes a [`prim@str`] based on
    /// [`CredentialMediationRequirement`](https://www.w3.org/TR/credential-management-1/#enumdef-credentialmediationrequirement).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::CredentialMediationRequirement;
    /// assert!(
    ///     matches!(
    ///         serde_json::from_str(r#""required""#)?,
    ///         CredentialMediationRequirement::Required,
    ///     )
    /// );
    /// assert!(
    ///     matches!(
    ///         serde_json::from_str(r#""conditional""#)?,
    ///         CredentialMediationRequirement::Conditional,
    ///     )
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `CredentialMediationRequirement`.
        struct CredentialMediationRequirementVisitor;
        impl Visitor<'_> for CredentialMediationRequirementVisitor {
            type Value = CredentialMediationRequirement;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                write!(formatter, "'{REQUIRED}' or '{CONDITIONAL}'")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match v {
                    REQUIRED => Ok(CredentialMediationRequirement::Required),
                    CONDITIONAL => Ok(CredentialMediationRequirement::Conditional),
                    _ => Err(E::invalid_value(
                        Unexpected::Str(v),
                        &format!("'{REQUIRED}' or '{CONDITIONAL}'").as_str(),
                    )),
                }
            }
        }
        deserializer.deserialize_str(CredentialMediationRequirementVisitor)
    }
}
/// Helper to deserialize the prf extension.
pub(super) struct PrfHelper(pub PrfInputOwned);
impl<'e> Deserialize<'e> for PrfHelper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'e>,
    {
        /// `Visitor` for `PrfHelper`.
        struct PrfHelperVisitor;
        impl<'f> Visitor<'f> for PrfHelperVisitor {
            type Value = PrfHelper;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("Prf")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'f>,
            {
                /// Field for `PrfHelper`.
                struct Field;
                impl<'g> Deserialize<'g> for Field {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: Deserializer<'g>,
                    {
                        /// `Visitor` for `Field`.
                        struct FieldVisitor;
                        impl Visitor<'_> for FieldVisitor {
                            type Value = Field;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                write!(formatter, "'{EVAL}'")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                if v == EVAL {
                                    Ok(Field)
                                } else {
                                    Err(E::unknown_field(v, FIELDS))
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                map.next_key::<Field>().and_then(|opt_key| {
                    opt_key
                        .ok_or_else(|| Error::missing_field(EVAL))
                        .and_then(|_k| {
                            map.next_value().and_then(|prf_input| {
                                map.next_key::<Field>().and_then(|opt_key2| {
                                    opt_key2.map_or_else(
                                        || Ok(PrfHelper(prf_input)),
                                        |_k2| Err(Error::duplicate_field(EVAL)),
                                    )
                                })
                            })
                        })
                })
            }
        }
        /// `"eval"`.
        const EVAL: &str = "eval";
        /// Fields for `PrfHelper`
        const FIELDS: &[&str; 1] = &[EVAL];
        deserializer.deserialize_struct("Prf", FIELDS, PrfHelperVisitor)
    }
}
