extern crate alloc;
use super::{
    AuthenticatorAttachmentReq, AuthenticatorSelectionCriteria,
    CoseAlgorithmIdentifier, CoseAlgorithmIdentifiers, CredProtect, CrossPlatformHint, Extension,
    Hint, Nickname, PlatformHint, PublicKeyCredentialUserEntity,
    RegistrationClientState, ResidentKeyRequirement, RpId, UserHandle, Username,
};
use alloc::borrow::Cow;
#[cfg(doc)]
use core::str::FromStr;
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
    str,
};
use data_encoding::BASE64URL_NOPAD;
use serde::{
    de::{Deserialize, Deserializer, Error, Unexpected, Visitor},
    ser::{Serialize, SerializeSeq as _, SerializeStruct, Serializer},
};
impl Serialize for Nickname<'_> {
    /// Serializes `self` as a [`prim@str`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::Nickname;
    /// assert_eq!(
    ///     serde_json::to_string(&Nickname::try_from("Giuseppe Luigi Lagrangia")?).unwrap(),
    ///     r#""Giuseppe Luigi Lagrangia""#
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_ref())
    }
}
impl Serialize for Username<'_> {
    /// Serializes `self` as a [`prim@str`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::Username;
    /// assert_eq!(
    ///     serde_json::to_string(&Username::try_from("john.von.neumann")?).unwrap(),
    ///     r#""john.von.neumann""#
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_ref())
    }
}
/// [EdDSA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
const EDDSA: i16 = -8i16;
/// [ES256](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
const ES256: i16 = -7i16;
/// [ES384](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
const ES384: i16 = -35i16;
/// [RS256](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
const RS256: i16 = -257i16;
impl Serialize for CoseAlgorithmIdentifier {
    /// Serializes `self` into a `struct` based on
    /// [`PublicKeyCredentialParameters`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters).
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("PublicKeyCredentialParameters", 2)
            .and_then(|mut ser| {
                ser.serialize_field("type", "public-key").and_then(|()| {
                    ser.serialize_field("alg", &match *self {
                        Self::Eddsa => EDDSA,
                        Self::Es256 => ES256,
                        Self::Es384 => ES384,
                        Self::Rs256 => RS256,
                    })
                    .and_then(|()| ser.end())
                })
            })
    }
}
impl Serialize for CoseAlgorithmIdentifiers {
    /// Serializes `self` to conform with
    /// [`pubKeyCredParams`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-pubkeycredparams).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{CoseAlgorithmIdentifier,CoseAlgorithmIdentifiers};
    /// assert_eq!(
    ///     serde_json::to_string(&CoseAlgorithmIdentifiers::ALL)?,
    ///     r#"[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-257}]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&CoseAlgorithmIdentifiers::default().remove(CoseAlgorithmIdentifier::Es384))?,
    ///     r#"[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}]"#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment justifies correctness"
    )]
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // At most we add `1` four times which clearly cannot overflow or `usize`.
        serializer
            .serialize_seq(Some(usize::from(self.contains(CoseAlgorithmIdentifier::Eddsa)) + usize::from(self.contains(CoseAlgorithmIdentifier::Es256)) + usize::from(self.contains(CoseAlgorithmIdentifier::Es384)) + usize::from(self.contains(CoseAlgorithmIdentifier::Es384))))
            .and_then(|mut ser| {
                if self.contains(CoseAlgorithmIdentifier::Eddsa) {
                    ser.serialize_element(&CoseAlgorithmIdentifier::Eddsa)
                } else {
                    Ok(())
                }
                .and_then(|()| {
                    if self.contains(CoseAlgorithmIdentifier::Es256) {
                        ser.serialize_element(&CoseAlgorithmIdentifier::Es256)
                    } else {
                        Ok(())
                    }
                    .and_then(|()| {
                        if self.contains(CoseAlgorithmIdentifier::Es384) {
                            ser.serialize_element(&CoseAlgorithmIdentifier::Es384)
                        } else {
                            Ok(())
                        }
                        .and_then(|()| {
                            if self.contains(CoseAlgorithmIdentifier::Rs256) {
                                ser.serialize_element(&CoseAlgorithmIdentifier::Rs256)
                            } else {
                                Ok(())
                            }
                            .and_then(|()| ser.end())
                        })
                    })
                })
            })
    }
}
/// `"name"`.
const NAME: &str = "name";
/// `"id"`.
const ID: &str = "id";
/// `newtype` around `RpId` to be used to serialize `PublicKeyCredentialRpEntity`.
struct PublicKeyCredentialRpEntity<'a>(&'a RpId);
impl Serialize for PublicKeyCredentialRpEntity<'_> {
    /// Serializes `self` to conform with
    /// [`PublicKeyCredentialRpEntity`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrpentity).
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("PublicKeyCredentialRpEntity", 2)
            .and_then(|mut ser| {
                ser.serialize_field(NAME, self.0)
                    .and_then(|()| ser.serialize_field(ID, self.0).and_then(|()| ser.end()))
            })
    }
}
// We implement this separately from `user_serialize` for proper documentation and example purposes.
impl Serialize for UserHandle<1> {
    /// Serializes `self` to conform with
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentityjson-id).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::UserHandle;
    /// # #[cfg(feature = "custom")]
    /// // We create this manually purely for example. One should almost always
    /// // randomly generate this (e.g., `UserHandle::new`).
    /// let id = UserHandle::from([0]);
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(serde_json::to_string(&id)?, r#""AA""#);
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(BASE64URL_NOPAD.encode_mut_str(self.0.as_slice(), [0; crate::base64url_nopad_len(1).unwrap()].as_mut_slice()))
    }
}
/// Implements [`Serialize`] for [`UserHandle`] of array of length of the passed `usize` literal.
///
/// Only [`USER_HANDLE_MIN_LEN`]–[`USER_HANDLE_MAX_LEN`] inclusively are allowed to be passed.
macro_rules! user_serialize {
    ( $( $x:literal),* ) => {
        $(
impl Serialize for UserHandle<$x> {
    /// See [`UserHandle::serialize`].
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        
        serializer.serialize_str(BASE64URL_NOPAD.encode_mut_str(self.0.as_slice(), [0; crate::base64url_nopad_len($x).unwrap()].as_mut_slice()))
    }
}
        )*
    };
}
// MUST only pass `2`–[`USER_HANDLE_MAX_LEN`] inclusively.
user_serialize!(
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
);
impl<const LEN: usize> Serialize for PublicKeyCredentialUserEntity<'_, '_, '_, LEN>
where
    UserHandle<LEN>: Serialize,
{
    /// Serializes `self` to conform with
    /// [`PublicKeyCredentialUserEntityJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentityjson).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{PublicKeyCredentialUserEntity, UserHandle};
    /// # #[cfg(feature = "custom")]
    /// // We create this manually purely for example. One should almost always
    /// // randomly generate this (e.g., `UserHandle::new`).
    /// let id = UserHandle::from([0]);
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(
    ///     serde_json::to_string(&PublicKeyCredentialUserEntity {
    ///         name: "georg.cantor".try_into()?,
    ///         id: &id,
    ///         display_name: Some("Гео́рг Ка́нтор".try_into()?),
    ///     }).unwrap(),
    ///     r#"{"name":"georg.cantor","id":"AA","displayName":"Гео́рг Ка́нтор"}"#
    /// );
    /// // The display name gets serialized as an empty string
    /// // iff `Self::display_name` is `None`.
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(
    ///     serde_json::to_string(&PublicKeyCredentialUserEntity {
    ///         name: "georg.cantor".try_into()?,
    ///         id: &id,
    ///         display_name: None,
    ///     }).unwrap(),
    ///     r#"{"name":"georg.cantor","id":"AA","displayName":""}"#
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("PublicKeyCredentialUserEntity", 3)
            .and_then(|mut ser| {
                ser.serialize_field(NAME, &self.name).and_then(|()| {
                    ser.serialize_field(ID, &self.id).and_then(|()| {
                        ser.serialize_field(
                            "displayName",
                            self.display_name.as_ref().map_or("", |val| val.as_ref()),
                        )
                        .and_then(|()| ser.end())
                    })
                })
            })
    }
}
impl Serialize for ResidentKeyRequirement {
    /// Serializes `self` to conform with
    /// [`ResidentKeyRequirement`](https://www.w3.org/TR/webauthn-3/#enumdef-residentkeyrequirement).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::ResidentKeyRequirement;
    /// assert_eq!(
    ///     serde_json::to_string(&ResidentKeyRequirement::Required)?,
    ///     r#""required""#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&ResidentKeyRequirement::Discouraged)?,
    ///     r#""discouraged""#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&ResidentKeyRequirement::Preferred)?,
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
impl Serialize for CrossPlatformHint {
    /// Serializes `self` to conform with
    /// [`hints`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-hints).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::CrossPlatformHint;
    /// assert_eq!(
    ///     serde_json::to_string(&CrossPlatformHint::None)?,
    ///     r#"[]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&CrossPlatformHint::SecurityKey)?,
    ///     r#"["security-key"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&CrossPlatformHint::Hybrid)?,
    ///     r#"["hybrid"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&CrossPlatformHint::SecurityKeyHybrid)?,
    ///     r#"["security-key","hybrid"]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&CrossPlatformHint::HybridSecurityKey)?,
    ///     r#"["hybrid","security-key"]"#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Hint::from(*self).serialize(serializer)
    }
}
impl Serialize for PlatformHint {
    /// Serializes `self` to conform with
    /// [`hints`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-hints).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::PlatformHint;
    /// assert_eq!(
    ///     serde_json::to_string(&PlatformHint::None)?,
    ///     r#"[]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&PlatformHint::ClientDevice)?,
    ///     r#"["client-device"]"#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Hint::from(*self).serialize(serializer)
    }
}
impl Serialize for AuthenticatorSelectionCriteria {
    /// Serializes `self` to conform with
    /// [`AuthenticatorSelectionCriteria`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorselectioncriteria).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{AuthenticatorAttachmentReq, AuthenticatorSelectionCriteria, CrossPlatformHint};
    /// assert_eq!(
    ///     serde_json::to_string(&AuthenticatorSelectionCriteria::passkey())?,
    ///     r#"{"residentKey":"required","requireResidentKey":true,"userVerification":"required"}"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&AuthenticatorSelectionCriteria::second_factor())?,
    ///     r#"{"residentKey":"discouraged","requireResidentKey":false,"userVerification":"discouraged"}"#
    /// );
    /// let mut crit = AuthenticatorSelectionCriteria::passkey();
    /// crit.authenticator_attachment = AuthenticatorAttachmentReq::CrossPlatform(
    ///     CrossPlatformHint::SecurityKey,
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&crit)?,
    ///     r#"{"authenticatorAttachment":"cross-platform","residentKey":"required","requireResidentKey":true,"userVerification":"required"}"#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let count = if matches!(
            self.authenticator_attachment,
            AuthenticatorAttachmentReq::None(_)
        ) {
            3
        } else {
            4
        };
        serializer
            .serialize_struct("AuthenticatorSelectionCriteria", count)
            .and_then(|mut ser| {
                if count == 3 {
                    Ok(())
                } else {
                    ser.serialize_field(
                        "authenticatorAttachment",
                        if matches!(
                            self.authenticator_attachment,
                            AuthenticatorAttachmentReq::Platform(_)
                        ) {
                            "platform"
                        } else {
                            "cross-platform"
                        },
                    )
                }
                .and_then(|()| {
                    ser.serialize_field("residentKey", &self.resident_key)
                        .and_then(|()| {
                            ser.serialize_field(
                                "requireResidentKey",
                                &matches!(self.resident_key, ResidentKeyRequirement::Required),
                            )
                            .and_then(|()| {
                                ser.serialize_field("userVerification", &self.user_verification)
                                    .and_then(|()| ser.end())
                            })
                        })
                })
            })
    }
}
/// Helper that serializes prf registration information to conform with
/// [`AuthenticationExtensionsPRFInputs`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfinputs).
///
/// Since CTAP 2.2 does not allow PRF evaluation at creation time, we send an empty map.
struct Prf;
impl Serialize for Prf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("Prf", 0)
            .and_then(SerializeStruct::end)
    }
}
impl Serialize for Extension {
    /// Serializes `self` to conform with
    /// [`AuthenticationExtensionsClientInputsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientinputsjson).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{
    /// #     register::{CredProtect, Extension, FourToSixtyThree},
    /// #     ExtensionInfo, ExtensionReq,
    /// # };
    /// assert_eq!(serde_json::to_string(&Extension::default())?, r#"{}"#);
    /// assert_eq!(
    ///     serde_json::to_string(&Extension {
    ///         cred_props: Some(ExtensionReq::Allow),
    ///         cred_protect: CredProtect::UserVerificationRequired(false, ExtensionInfo::RequireEnforceValue),
    ///         min_pin_length: Some((FourToSixtyThree::new(16).unwrap_or_else(|| unreachable!("bug in FourToSixtyThree::new")), ExtensionInfo::AllowDontEnforceValue)),
    ///         prf: Some(ExtensionInfo::AllowEnforceValue)
    ///     })?,
    ///     r#"{"credProps":true,"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"minPinLength":true,"prf":{}}"#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment explains how overflow is not possible"
    )]
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        /// `credProps` key name.
        const CRED_PROPS: &str = "credProps";
        /// `minPinLength` key name.
        const MIN_PIN_LENGTH: &str = "minPinLength";
        /// `prf` key name.
        const PRF: &str = "prf";
        // The max is 1 + 2 + 1 + 1 = 5, so overflow is no concern.
        let count = usize::from(self.cred_props.is_some())
            + if matches!(self.cred_protect, CredProtect::None) {
                0
            } else {
                2
            }
            + usize::from(self.min_pin_length.is_some())
            + usize::from(self.prf.is_some());
        serializer
            .serialize_struct("Extension", count)
            .and_then(|mut ser| {
                self.cred_props
                    .map_or(Ok(()), |_| ser.serialize_field(CRED_PROPS, &true))
                    .and_then(|()| {
                        if matches!(self.cred_protect, CredProtect::None) {
                            Ok(())
                        } else {
                            let enforce_policy;
                            // [`credProtect`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-credProtect-extension)
                            // is serialized by serializing its fields directly and not as a map of fields.
                            ser.serialize_field(
                                "credentialProtectionPolicy",
                                match self.cred_protect {
                                    CredProtect::None => unreachable!(
                                        "Extensions is incorrectly serializing credProtect"
                                    ),
                                    CredProtect::UserVerificationOptional(enforce, _) => {
                                        enforce_policy = enforce;
                                        "userVerificationOptional"
                                    }
                                    CredProtect::UserVerificationOptionalWithCredentialIdList(
                                        enforce, _,
                                    ) => {
                                        enforce_policy = enforce;
                                        "userVerificationOptionalWithCredentialIDList"
                                    }
                                    CredProtect::UserVerificationRequired(enforce, _) => {
                                        enforce_policy = enforce;
                                        "userVerificationRequired"
                                    }
                                },
                            )
                            .and_then(|()| {
                                ser.serialize_field(
                                    "enforceCredentialProtectionPolicy",
                                    &enforce_policy,
                                )
                            })
                        }
                        .and_then(|()| {
                            self.min_pin_length
                                .map_or(Ok(()), |_| ser.serialize_field(MIN_PIN_LENGTH, &true))
                                .and_then(|()| {
                                    self.prf
                                        .map_or(Ok(()), |_| ser.serialize_field(PRF, &Prf))
                                        .and_then(|()| ser.end())
                                })
                        })
                    })
            })
    }
}
impl<'user_name, 'user_display_name, 'user_id, const USER_LEN: usize> Serialize for RegistrationClientState<'_, 'user_name, 'user_display_name, 'user_id, USER_LEN>
where
    PublicKeyCredentialUserEntity<'user_name, 'user_display_name, 'user_id, USER_LEN>: Serialize,
{
    /// Serializes `self` to conform with
    /// [`PublicKeyCredentialCreationOptionsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptionsjson).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// # use webauthn_rp::{bin::Decode, response::bin::DecodeAuthTransportsErr};
    /// # use webauthn_rp::{
    /// #     request::{
    /// #         register::{
    /// #             FourToSixtyThree, UserHandle64, AuthenticatorAttachmentReq, PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle
    /// #         },
    /// #         AsciiDomain, ExtensionInfo, Hint, RpId, PublicKeyCredentialDescriptor, Credentials, UserVerificationRequirement,
    /// #     },
    /// #     response::{AuthTransports, CredentialId},
    /// # };
    /// /// Retrieves the `AuthTransports` associated with the unique `cred_id`
    /// /// from the database.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// fn get_transports(cred_id: CredentialId<&[u8]>) -> Result<AuthTransports, DecodeAuthTransportsErr> {
    ///     // ⋮
    /// #     AuthTransports::decode(32)
    /// }
    /// let mut creds = Vec::with_capacity(1);
    /// // `CredentialId::try_from` only exists when `custom` is enabled; and even then, it is
    /// // likely never needed since the `CredentialId` was originally sent from the client and is likely
    /// // stored in a database which would be fetched by `UserHandle` or `Authentication::raw_id`.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let id = CredentialId::try_from(vec![0; 16])?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports = get_transports((&id).into())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// creds.push(PublicKeyCredentialDescriptor { id, transports });
    /// let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
    /// let user_handle = UserHandle64::new();
    /// let mut options = PublicKeyCredentialCreationOptions::passkey(&rp_id, PublicKeyCredentialUserEntity { name: "pierre.de.fermat".try_into()?, id: &user_handle, display_name: Some("Pierre de Fermat".try_into()?) }, creds);
    /// options.authenticator_selection.authenticator_attachment = AuthenticatorAttachmentReq::None(Hint::SecurityKey);
    /// options.extensions.min_pin_length = Some((FourToSixtyThree::new(16).unwrap_or_else(|| unreachable!("bug in FourToSixtyThree::new")), ExtensionInfo::RequireEnforceValue));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let client_state = serde_json::to_string(&options.start_ceremony()?.1).unwrap();
    /// let json = serde_json::json!({
    ///     "rp":{
    ///         "name":"example.com",
    ///         "id":"example.com"
    ///     },
    ///     "user":{
    ///         "name":"pierre.de.fermat",
    ///         "id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ///         "displayName":"Pierre de Fermat"
    ///     },
    ///     "challenge":"AAAAAAAAAAAAAAAAAAAAAA",
    ///     "pubKeyCredParams":[
    ///         {
    ///             "type":"public-key",
    ///             "alg":-8
    ///         },
    ///         {
    ///             "type":"public-key",
    ///             "alg":-7
    ///         },
    ///         {
    ///             "type":"public-key",
    ///             "alg":-35
    ///         },
    ///         {
    ///             "type":"public-key",
    ///             "alg":-257
    ///         },
    ///     ],
    ///     "timeout":300000,
    ///     "excludeCredentials":[
    ///         {
    ///             "type":"public-key",
    ///             "id":"AAAAAAAAAAAAAAAAAAAAAA",
    ///             "transports":["usb"]
    ///         }
    ///     ],
    ///     "authenticatorSelection":{
    ///         "residentKey":"required",
    ///         "requireResidentKey":true,
    ///         "userVerification":"required"
    ///     },
    ///     "hints":[
    ///         "security-key"
    ///     ],
    ///     "attestation":"none",
    ///     "attestationFormats":[
    ///         "none"
    ///     ],
    ///     "extensions":{
    ///         "credentialProtectionPolicy":"userVerificationRequired",
    ///         "enforceCredentialProtectionPolicy":false,
    ///         "minPinLength":true
    ///     }
    /// }).to_string();
    /// // Since `Challenge`s are randomly generated, we don't know what it will be.
    /// // Similarly since we randomly generated a 64-byte `UserHandle`, we don't know what
    /// // it will be; thus we test the JSON string for everything except those two.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(client_state.get(..88), json.get(..88));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(client_state.get(174..212), json.get(174..212));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(client_state.get(245..), json.get(245..));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        /// "none".
        const NONE: &str = "none";
        serializer
            .serialize_struct("RegistrationClientState", 11)
            .and_then(|mut ser| {
                ser.serialize_field("rp", &PublicKeyCredentialRpEntity(self.0.rp_id))
                    .and_then(|()| {
                        ser.serialize_field("user", &self.0.user).and_then(|()| {
                            ser.serialize_field("challenge", &self.0.challenge)
                                .and_then(|()| {
                                    ser.serialize_field(
                                        "pubKeyCredParams",
                                        &self.0.pub_key_cred_params,
                                    )
                                    .and_then(|()| {
                                        ser.serialize_field("timeout", &self.0.timeout).and_then(
                                            |()| {
                                                ser.serialize_field(
                                                    "excludeCredentials",
                                                    self.0.exclude_credentials.as_slice(),
                                                )
                                                .and_then(|()| {
                                                    ser.serialize_field(
                                                        "authenticatorSelection",
                                                        &self.0.authenticator_selection,
                                                    )
                                                    .and_then(|()| {
                                                        ser.serialize_field("hints", &match self.0.authenticator_selection.authenticator_attachment {
                                                            AuthenticatorAttachmentReq::None(hint) => hint,
                                                            AuthenticatorAttachmentReq::Platform(hint) => hint.into(),
                                                            AuthenticatorAttachmentReq::CrossPlatform(hint) => hint.into(),
                                                        }).and_then(|()| {
                                                            ser.serialize_field("attestation", NONE).and_then(|()| {
                                                                ser.serialize_field("attestationFormats", [NONE].as_slice()).and_then(|()| {
                                                                    ser.serialize_field("extensions", &self.0.extensions).and_then(|()| ser.end())
                                                                })
                                                            })
                                                        })
                                                    })
                                                })
                                            },
                                        )
                                    })
                                })
                        })
                    })
            })
    }
}
impl<'de: 'a, 'a> Deserialize<'de> for Nickname<'a> {
    /// Deserializes [`prim@str`] and parses it according to [`Self::try_from`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::Nickname;
    /// assert_eq!(
    ///     serde_json::from_str::<Nickname>(r#""Henri Poincaré""#)?.as_ref(),
    ///     "Henri Poincaré"
    /// );
    /// # Ok::<_, serde_json::Error>(())
    ///```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `Nickname`.
        struct NicknameVisitor<'b>(PhantomData<fn() -> &'b ()>);
        impl<'d: 'b, 'b> Visitor<'d> for NicknameVisitor<'b> {
            type Value = Nickname<'b>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("Nickname")
            }
            fn visit_borrowed_str<E>(self, v: &'d str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Nickname::try_from(v).map_err(E::custom)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Nickname::try_from(v)
                    .map_err(E::custom)
                    .map(|name| Nickname(Cow::Owned(name.0.into_owned())))
            }
        }
        deserializer.deserialize_str(NicknameVisitor(PhantomData))
    }
}
impl<'de: 'a, 'a> Deserialize<'de> for Username<'a> {
    /// Deserializes [`prim@str`] and parses it according to [`Self::try_from`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::Username;
    /// assert_eq!(
    ///     serde_json::from_str::<Username>(r#""augustin.cauchy""#)?.as_ref(),
    ///     "augustin.cauchy"
    /// );
    /// # Ok::<_, serde_json::Error>(())
    ///```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `Username`.
        struct UsernameVisitor<'b>(PhantomData<fn() -> &'b ()>);
        impl<'d: 'b, 'b> Visitor<'d> for UsernameVisitor<'b> {
            type Value = Username<'b>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("Username")
            }
            fn visit_borrowed_str<E>(self, v: &'d str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Username::try_from(v).map_err(E::custom)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Username::try_from(v)
                    .map_err(E::custom)
                    .map(|name| Username(Cow::Owned(name.0.into_owned())))
            }
        }
        deserializer.deserialize_str(UsernameVisitor(PhantomData))
    }
}
impl<'de, const LEN: usize> Deserialize<'de> for UserHandle<LEN>
where
    Self: Default,
{
    /// Deserializes [`prim@str`] based on
    /// [`userHandle`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponsejson-userhandle).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{UserHandle, USER_HANDLE_MIN_LEN};
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(
    ///     serde_json::from_str::<UserHandle<USER_HANDLE_MIN_LEN>>(r#""AA""#)?,
    ///     UserHandle::from([0])
    /// );
    /// # Ok::<_, serde_json::Error>(())
    ///```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `UserHandle`.
        struct UserHandleVisitor<const L: usize>;
        impl<const L: usize> Visitor<'_> for UserHandleVisitor<L>
        where
            UserHandle<L>: Default,
        {
            type Value = UserHandle<L>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("UserHandle")
            }
            #[expect(clippy::panic_in_result_fn, clippy::unreachable, reason = "we want to crash when there is a bug")]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                // Any value between `USER_HANDLE_MIN_LEN` and `USER_HANDLE_MAX_LEN` can be base64url encoded
                // without fear since that range is just 1 to 64, and 4/3 of 64 is less than `usize::MAX`.
                if crate::base64url_nopad_len(L).unwrap_or_else(|| unreachable!("there is a bug in webauthn_rp::base64url_nopad_len")) == v.len() {
                    let mut data = [0; L];
                    BASE64URL_NOPAD
                        .decode_mut(v.as_bytes(), data.as_mut_slice())
                        .map_err(|e| E::custom(e.error))
                        .map(|len| {
                            assert_eq!(len, L, "there is a bug in data_encoding::BASE64URL_NOPAD::decode_mut");
                            UserHandle(data)
                        })
                } else {
                    Err(E::invalid_value(
                        Unexpected::Str(v), &format!("{L} bytes encoded in base64url without padding").as_str()
                    ))
                }
            }
        }
        deserializer.deserialize_str(UserHandleVisitor)
    }
}
impl<'de> Deserialize<'de> for CoseAlgorithmIdentifier {
    /// Deserializes [`i16`] based on
    /// [COSE Algorithms](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `CoseAlgorithmIdentifier`.
        ///
        /// We visit all signed integral types sans `i8` just in case a `Deserializer` only implements one of them.
        struct CoseAlgorithmIdentifierVisitor;
        impl Visitor<'_> for CoseAlgorithmIdentifierVisitor {
            type Value = CoseAlgorithmIdentifier;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("CoseAlgorithmIdentifier")
            }
            fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match v {
                    EDDSA => Ok(CoseAlgorithmIdentifier::Eddsa),
                    ES256 => Ok(CoseAlgorithmIdentifier::Es256),
                    ES384=> Ok(CoseAlgorithmIdentifier::Es384),
                    RS256 => Ok(CoseAlgorithmIdentifier::Rs256),
                    _ => Err(E::invalid_value(
                        Unexpected::Signed(i64::from(v)),
                        &format!("{EDDSA}, {ES256}, {ES384}, or {RS256}").as_str(),
                    )),
                }
            }
            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
            where
                E: Error,
            {
                i16::try_from(v)
                    .map_err(E::custom)
                    .and_then(|val| self.visit_i16(val))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: Error,
            {
                i16::try_from(v)
                    .map_err(E::custom)
                    .and_then(|val| self.visit_i16(val))
            }
        }
        deserializer.deserialize_i16(CoseAlgorithmIdentifierVisitor)
    }
}
