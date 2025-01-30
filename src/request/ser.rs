use super::{
    Challenge, CredentialId, Hint, PublicKeyCredentialDescriptor, RpId, UserVerificationRequirement,
};
use core::str;
use data_encoding::BASE64URL_NOPAD;
use serde::ser::{Serialize, SerializeSeq as _, SerializeStruct as _, Serializer};
impl Serialize for Challenge {
    /// Serializes `self` to conform with
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-challenge).
    ///
    /// Specifically `self` is interpreted as a little-endian array of 16 bytes that is then transformed into a
    /// base64url-encoded string.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Challenge;
    /// # // `Challenge::BASE64_LEN` is 22, but we add two for the quotes.
    /// assert_eq!(serde_json::to_string(&Challenge::new())?.len(), 24);
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[expect(clippy::unreachable, reason = "when there is a bug, we want to crash")]
    #[expect(
        clippy::little_endian_bytes,
        reason = "SentChallenge::deserialize and Challenge::serialize need to be consistent across architectures"
    )]
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut data = [0; Self::BASE64_LEN];
        BASE64URL_NOPAD.encode_mut(self.0.to_le_bytes().as_slice(), data.as_mut_slice());
        serializer.serialize_str(
            str::from_utf8(data.as_slice())
                // There is a bug, so crash and burn.
                .unwrap_or_else(|_| unreachable!("there is a bug in Challenge::serialize")),
        )
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
        /// [`security-key`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhints-security-key).
        const SECURITY_KEY: &str = "security-key";
        /// [`client-device`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhints-client-device).
        const CLIENT_DEVICE: &str = "client-device";
        /// [`hybrid`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhints-hybrid).
        const HYBRID: &str = "hybrid";
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
