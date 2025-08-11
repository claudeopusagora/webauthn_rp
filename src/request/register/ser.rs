extern crate alloc;
use super::{
    super::{
        super::response::ser::{Null, Type},
        auth::PrfInputOwned,
        ser::{DEFAULT_RP_ID, PrfHelper},
    },
    AuthenticatorAttachmentReq, AuthenticatorSelectionCriteria, Challenge, CoseAlgorithmIdentifier,
    CoseAlgorithmIdentifiers, CredProtect, CredentialCreationOptions,
    CredentialMediationRequirement, CrossPlatformHint, Extension, ExtensionInfo, ExtensionReq,
    FIVE_MINUTES, FourToSixtyThree, Hint, Nickname, PlatformHint, PrfInput,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialDescriptor,
    PublicKeyCredentialUserEntity, RegistrationClientState, ResidentKeyRequirement, RpId,
    UserHandle, UserVerificationRequirement, Username,
};
#[cfg(doc)]
use crate::response::AuthenticatorAttachment;
use alloc::borrow::Cow;
#[cfg(doc)]
use core::str::FromStr;
use core::{
    convert,
    fmt::{self, Formatter},
    marker::PhantomData,
    num::NonZeroU32,
    str,
};
use serde::{
    de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Unexpected, Visitor},
    ser::{Serialize, SerializeSeq as _, SerializeStruct as _, Serializer},
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
/// `"type"`
const TYPE: &str = "type";
/// `"public-key"`
const PUBLIC_KEY: &str = "public-key";
/// `"alg"`
const ALG: &str = "alg";
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
                ser.serialize_field(TYPE, PUBLIC_KEY).and_then(|()| {
                    ser.serialize_field(
                        ALG,
                        &match *self {
                            Self::Eddsa => EDDSA,
                            Self::Es256 => ES256,
                            Self::Es384 => ES384,
                            Self::Rs256 => RS256,
                        },
                    )
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
            .serialize_seq(Some(
                usize::from(self.contains(CoseAlgorithmIdentifier::Eddsa))
                    + usize::from(self.contains(CoseAlgorithmIdentifier::Es256))
                    + usize::from(self.contains(CoseAlgorithmIdentifier::Es384))
                    + usize::from(self.contains(CoseAlgorithmIdentifier::Es384)),
            ))
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
        serializer.serialize_str(base64url_nopad::encode_buffer(
            self.0.as_slice(),
            [0; base64url_nopad::encode_len(1)].as_mut_slice(),
        ))
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

        serializer.serialize_str(base64url_nopad::encode_buffer(self.0.as_slice(), [0; base64url_nopad::encode_len($x)].as_mut_slice()))
    }
}
        )*
    };
}
// MUST only pass `2`–[`USER_HANDLE_MAX_LEN`] inclusively.
user_serialize!(
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
);
/// `"displayName"`.
const DISPLAY_NAME: &str = "displayName";
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
                            DISPLAY_NAME,
                            self.display_name.as_ref().map_or("", |val| val.as_ref()),
                        )
                        .and_then(|()| ser.end())
                    })
                })
            })
    }
}
/// `"required"`
const REQUIRED: &str = "required";
/// `"discouraged"`
const DISCOURAGED: &str = "discouraged";
/// `"preferred"`
const PREFERRED: &str = "preferred";
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
            Self::Required => REQUIRED,
            Self::Discouraged => DISCOURAGED,
            Self::Preferred => PREFERRED,
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
/// `"platform"`.
const PLATFORM: &str = "platform";
/// `"cross-platform"`.
const CROSS_PLATFORM: &str = "cross-platform";
/// `"authenticatorAttachment"`.
const AUTHENTICATOR_ATTACHMENT: &str = "authenticatorAttachment";
/// `"residentKey"`.
const RESIDENT_KEY: &str = "residentKey";
/// `"requireResidentKey"`.
const REQUIRE_RESIDENT_KEY: &str = "requireResidentKey";
/// `"userVerification"`.
const USER_VERIFICATION: &str = "userVerification";
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
                        AUTHENTICATOR_ATTACHMENT,
                        if matches!(
                            self.authenticator_attachment,
                            AuthenticatorAttachmentReq::Platform(_)
                        ) {
                            PLATFORM
                        } else {
                            CROSS_PLATFORM
                        },
                    )
                }
                .and_then(|()| {
                    ser.serialize_field(RESIDENT_KEY, &self.resident_key)
                        .and_then(|()| {
                            ser.serialize_field(
                                REQUIRE_RESIDENT_KEY,
                                &matches!(self.resident_key, ResidentKeyRequirement::Required),
                            )
                            .and_then(|()| {
                                ser.serialize_field(USER_VERIFICATION, &self.user_verification)
                                    .and_then(|()| ser.end())
                            })
                        })
                })
            })
    }
}
/// Helper that serializes prf registration information to conform with
/// [`AuthenticationExtensionsPRFInputs`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfinputs).
struct Prf<'a, 'b>(PrfInput<'a, 'b>);
impl Serialize for Prf<'_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_struct("Prf", 1).and_then(|mut ser| {
            ser.serialize_field("eval", &self.0)
                .and_then(|()| ser.end())
        })
    }
}
/// `credProps` key name.
const CRED_PROPS: &str = "credProps";
/// `minPinLength` key name.
const MIN_PIN_LENGTH: &str = "minPinLength";
/// `prf` key name.
const PRF: &str = "prf";
/// `credentialProtectionPolicy` key name.
const CREDENTIAL_PROTECTION_POLICY: &str = "credentialProtectionPolicy";
/// `enforceCredentialProtectionPolicy` key name.
const ENFORCE_CREDENTIAL_PROTECTION_POLICY: &str = "enforceCredentialProtectionPolicy";
/// `"userVerificationOptional"`.
const USER_VERIFICATION_OPTIONAL: &str = "userVerificationOptional";
/// `"userVerificationOptionalWithCredentialIDList"`.
const USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST: &str =
    "userVerificationOptionalWithCredentialIDList";
/// `"userVerificationRequired"`.
const USER_VERIFICATION_REQUIRED: &str = "userVerificationRequired";
impl Serialize for Extension<'_, '_> {
    /// Serializes `self` to conform with
    /// [`AuthenticationExtensionsClientInputsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientinputsjson).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{
    /// #     register::{CredProtect, Extension, FourToSixtyThree},
    /// #     PrfInput, ExtensionInfo, ExtensionReq,
    /// # };
    /// assert_eq!(serde_json::to_string(&Extension::default())?, r#"{}"#);
    /// assert_eq!(
    ///     serde_json::to_string(&Extension {
    ///         cred_props: Some(ExtensionReq::Allow),
    ///         cred_protect: CredProtect::UserVerificationRequired(false, ExtensionInfo::RequireEnforceValue),
    ///         min_pin_length: Some((FourToSixtyThree::Sixteen, ExtensionInfo::AllowDontEnforceValue)),
    ///         prf: Some((PrfInput { first: [0].as_slice(), second: None, }, ExtensionInfo::AllowEnforceValue))
    ///     })?,
    ///     r#"{"credProps":true,"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"minPinLength":true,"prf":{"eval":{"first":"AA"}}}"#
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
                                CREDENTIAL_PROTECTION_POLICY,
                                match self.cred_protect {
                                    CredProtect::None => unreachable!(
                                        "Extensions is incorrectly serializing credProtect"
                                    ),
                                    CredProtect::UserVerificationOptional(enforce, _) => {
                                        enforce_policy = enforce;
                                        USER_VERIFICATION_OPTIONAL
                                    }
                                    CredProtect::UserVerificationOptionalWithCredentialIdList(
                                        enforce,
                                        _,
                                    ) => {
                                        enforce_policy = enforce;
                                        USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST
                                    }
                                    CredProtect::UserVerificationRequired(enforce, _) => {
                                        enforce_policy = enforce;
                                        USER_VERIFICATION_REQUIRED
                                    }
                                },
                            )
                            .and_then(|()| {
                                ser.serialize_field(
                                    ENFORCE_CREDENTIAL_PROTECTION_POLICY,
                                    &enforce_policy,
                                )
                            })
                        }
                        .and_then(|()| {
                            self.min_pin_length
                                .map_or(Ok(()), |_| ser.serialize_field(MIN_PIN_LENGTH, &true))
                                .and_then(|()| {
                                    self.prf
                                        .map_or(Ok(()), |(prf, _)| {
                                            ser.serialize_field(PRF, &Prf(prf))
                                        })
                                        .and_then(|()| ser.end())
                                })
                        })
                    })
            })
    }
}
/// `"rp"`
const RP: &str = "rp";
/// `"user"`
const USER: &str = "user";
/// `"challenge"`
const CHALLENGE: &str = "challenge";
/// `"pubKeyCredParams"`
const PUB_KEY_CRED_PARAMS: &str = "pubKeyCredParams";
/// `"timeout"`
const TIMEOUT: &str = "timeout";
/// `"excludeCredentials"`
const EXCLUDE_CREDENTIALS: &str = "excludeCredentials";
/// `"authenticatorSelection"`
const AUTHENTICATOR_SELECTION: &str = "authenticatorSelection";
/// `"hints"`
const HINTS: &str = "hints";
/// `"attestation"`
const ATTESTATION: &str = "attestation";
/// `"attestationFormats"`
const ATTESTATION_FORMATS: &str = "attestationFormats";
/// `"extensions"`
const EXTENSIONS: &str = "extensions";
/// "none".
const NONE: &str = "none";
impl<'user_name, 'user_display_name, 'user_id, const USER_LEN: usize> Serialize
    for PublicKeyCredentialCreationOptions<
        '_,
        'user_name,
        'user_display_name,
        'user_id,
        '_,
        '_,
        USER_LEN,
    >
where
    PublicKeyCredentialUserEntity<'user_name, 'user_display_name, 'user_id, USER_LEN>: Serialize,
{
    /// Serializes `self` to conform with
    /// [`PublicKeyCredentialCreationOptionsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptionsjson).
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("PublicKeyCredentialCreationOptions", 11)
            .and_then(|mut ser| {
                ser.serialize_field(RP, &PublicKeyCredentialRpEntity(self.rp_id))
                    .and_then(|()| {
                        ser.serialize_field(USER, &self.user).and_then(|()| {
                            ser.serialize_field(CHALLENGE, &self.challenge)
                                .and_then(|()| {
                                    ser.serialize_field(
                                        PUB_KEY_CRED_PARAMS,
                                        &self.pub_key_cred_params,
                                    )
                                    .and_then(|()| {
                                        ser.serialize_field(TIMEOUT, &self.timeout).and_then(
                                            |()| {
                                                ser.serialize_field(
                                                    EXCLUDE_CREDENTIALS,
                                                    self.exclude_credentials.as_slice(),
                                                )
                                                .and_then(|()| {
                                                    ser.serialize_field(
                                                        AUTHENTICATOR_SELECTION,
                                                        &self.authenticator_selection,
                                                    )
                                                    .and_then(|()| {
                                                        ser.serialize_field(HINTS, &match self.authenticator_selection.authenticator_attachment {
                                                            AuthenticatorAttachmentReq::None(hint) => hint,
                                                            AuthenticatorAttachmentReq::Platform(hint) => hint.into(),
                                                            AuthenticatorAttachmentReq::CrossPlatform(hint) => hint.into(),
                                                        }).and_then(|()| {
                                                            ser.serialize_field(ATTESTATION, NONE).and_then(|()| {
                                                                ser.serialize_field(ATTESTATION_FORMATS, [NONE].as_slice()).and_then(|()| {
                                                                    ser.serialize_field(EXTENSIONS, &self.extensions).and_then(|()| ser.end())
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
/// `"mediation"`.
const MEDIATION: &str = "mediation";
/// `"publicKey"`.
const PUBLIC_KEY_NO_HYPEN: &str = "publicKey";
impl<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    const USER_LEN: usize,
> Serialize
    for CredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
        USER_LEN,
    >
where
    PublicKeyCredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
        USER_LEN,
    >: Serialize,
{
    /// Serializes `self` to conform with
    /// [`CredentialCreationOptions`](https://www.w3.org/TR/credential-management-1/#dictdef-credentialcreationoptions).
    ///
    /// Note [`signal`](https://www.w3.org/TR/credential-management-1/#dom-credentialcreationoptions-signal)
    /// is not present, and [`publicKey`](https://www.w3.org/TR/credential-management-1/#sctn-cred-type-registry)
    /// is serialized according to [`PublicKeyCredentialCreationOptions::serialize`].
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("CredentialCreationOptions", 2)
            .and_then(|mut ser| {
                ser.serialize_field(MEDIATION, &self.mediation)
                    .and_then(|()| {
                        ser.serialize_field(PUBLIC_KEY_NO_HYPEN, &self.public_key)
                            .and_then(|()| ser.end())
                    })
            })
    }
}
impl<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    const USER_LEN: usize,
> Serialize
    for RegistrationClientState<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
        USER_LEN,
    >
where
    CredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
        USER_LEN,
    >: Serialize,
{
    /// Serializes `self` according to [`CredentialCreationOptions::serialize`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// # use webauthn_rp::{bin::Decode, response::bin::DecodeAuthTransportsErr};
    /// # use webauthn_rp::{
    /// #     request::{
    /// #         register::{
    /// #             FourToSixtyThree, UserHandle64, AuthenticatorAttachmentReq, CredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle
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
    /// let mut options = CredentialCreationOptions::passkey(&rp_id, PublicKeyCredentialUserEntity { name: "pierre.de.fermat".try_into()?, id: &user_handle, display_name: Some("Pierre de Fermat".try_into()?) }, creds);
    /// options.public_key.authenticator_selection.authenticator_attachment = AuthenticatorAttachmentReq::None(Hint::SecurityKey);
    /// options.public_key.extensions.min_pin_length = Some((FourToSixtyThree::Sixteen, ExtensionInfo::RequireEnforceValue));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let client_state = serde_json::to_string(&options.start_ceremony()?.1).unwrap_or_else(|_e| unreachable!("bug in RegistrationClientState::serialize"));
    /// let json = serde_json::json!({
    ///     "mediation":"required",
    ///     "publicKey":{
    ///         "rp":{
    ///             "name":"example.com",
    ///             "id":"example.com"
    ///         },
    ///         "user":{
    ///             "name":"pierre.de.fermat",
    ///             "id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ///             "displayName":"Pierre de Fermat"
    ///         },
    ///         "challenge":"AAAAAAAAAAAAAAAAAAAAAA",
    ///         "pubKeyCredParams":[
    ///             {
    ///                 "type":"public-key",
    ///                 "alg":-8
    ///             },
    ///             {
    ///                 "type":"public-key",
    ///                 "alg":-7
    ///             },
    ///             {
    ///                 "type":"public-key",
    ///                 "alg":-35
    ///             },
    ///             {
    ///                 "type":"public-key",
    ///                 "alg":-257
    ///             },
    ///         ],
    ///         "timeout":300000,
    ///         "excludeCredentials":[
    ///             {
    ///                 "type":"public-key",
    ///                 "id":"AAAAAAAAAAAAAAAAAAAAAA",
    ///                 "transports":["usb"]
    ///             }
    ///         ],
    ///         "authenticatorSelection":{
    ///             "residentKey":"required",
    ///             "requireResidentKey":true,
    ///             "userVerification":"required"
    ///         },
    ///         "hints":[
    ///             "security-key"
    ///         ],
    ///         "attestation":"none",
    ///         "attestationFormats":[
    ///             "none"
    ///         ],
    ///         "extensions":{
    ///             "credentialProtectionPolicy":"userVerificationRequired",
    ///             "enforceCredentialProtectionPolicy":false,
    ///             "minPinLength":true
    ///         }
    ///     }
    /// }).to_string();
    /// // Since `Challenge`s are randomly generated, we don't know what it will be.
    /// // Similarly since we randomly generated a 64-byte `UserHandle`, we don't know what
    /// // it will be; thus we test the JSON string for everything except those two.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(client_state.get(..124), json.get(..124));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(client_state.get(210..259), json.get(210..259));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(client_state.get(281..), json.get(281..));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
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
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if base64url_nopad::encode_len(L) == v.len() {
                    let mut data = [0; L];
                    base64url_nopad::decode_buffer_exact(v.as_bytes(), data.as_mut_slice())
                        .map_err(E::custom)
                        .map(|()| UserHandle(data))
                } else {
                    Err(E::invalid_value(
                        Unexpected::Str(v),
                        &format!("{L} bytes encoded in base64url without padding").as_str(),
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
                    ES384 => Ok(CoseAlgorithmIdentifier::Es384),
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
/// Helper to deserialize `PublicKeyCredentialRpEntity` with an optional `RpId`.
///
/// Used in [`ClientCredentialCreationOptions::deserialize`].
struct PublicKeyCredentialRpEntityHelper(RpId);
impl<'de> Deserialize<'de> for PublicKeyCredentialRpEntityHelper {
    /// Conforms to the following schema:
    ///
    /// ```json
    /// {
    ///   "id": null | <RpId>,
    ///   "name": null | "" | <RpId> | <Nickname>
    /// }
    /// ```
    ///
    /// None of the fields are required.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `PublicKeyCredentialRpEntityHelper`.
        struct PublicKeyCredentialRpEntityHelperVisitor;
        impl<'d> Visitor<'d> for PublicKeyCredentialRpEntityHelperVisitor {
            type Value = PublicKeyCredentialRpEntityHelper;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("PublicKeyCredentialRpEntityHelper")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Field for `PublicKeyCredentialRpEntityHelper`.
                enum Field {
                    /// `id`.
                    Id,
                    /// `name`.
                    Name,
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
                                write!(formatter, "'{ID}' or '{NAME}'")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    ID => Ok(Field::Id),
                                    NAME => Ok(Field::Name),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                /// Helper to deserialize `name`.
                struct Name;
                impl<'e> Deserialize<'e> for Name {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: Deserializer<'e>,
                    {
                        /// `Visitor` for `Name`.
                        struct NameVisitor;
                        impl Visitor<'_> for NameVisitor {
                            type Value = Name;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                formatter.write_str("RpId name")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                if v.is_empty() {
                                    Ok(Name)
                                } else {
                                    Nickname::try_from(v).map(|_n| Name).or_else(|_e| {
                                        RpId::try_from(v.to_owned())
                                            .map_err(E::custom)
                                            .map(|_r| Name)
                                    })
                                }
                            }
                        }
                        deserializer.deserialize_str(NameVisitor)
                    }
                }
                let mut id = None;
                let mut name = false;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Id => {
                            if id.is_some() {
                                return Err(Error::duplicate_field(ID));
                            }
                            id = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::Name => {
                            if name {
                                return Err(Error::duplicate_field(NAME));
                            }
                            name = map.next_value::<Option<Name>>().map(|_n| true)?;
                        }
                    }
                }
                Ok(PublicKeyCredentialRpEntityHelper(
                    id.flatten().unwrap_or(DEFAULT_RP_ID),
                ))
            }
        }
        /// Fields for `PublicKeyCredentialRpEntityHelper`.
        const FIELDS: &[&str; 2] = &[ID, NAME];
        deserializer.deserialize_struct(
            "PublicKeyCredentialRpEntityHelper",
            FIELDS,
            PublicKeyCredentialRpEntityHelperVisitor,
        )
    }
}
/// Similar to [`PublicKeyCredentialUserEntity`] except the [`UserHandle`] is owned.
///
/// This is primarily useful to assist [`ClientCredentialCreationOptions::deserialize`].
#[derive(Debug)]
pub struct PublicKeyCredentialUserEntityOwned<'name, 'display_name, const LEN: usize> {
    /// See [`PublicKeyCredentialUserEntity::name`].
    pub name: Username<'name>,
    /// See [`PublicKeyCredentialUserEntity::id`].
    pub id: UserHandle<LEN>,
    /// See [`PublicKeyCredentialUserEntity::display_name`].
    pub display_name: Option<Nickname<'display_name>>,
}
impl<'a: 'name + 'display_name + 'id, 'name, 'display_name, 'id, const LEN: usize>
    From<&'a PublicKeyCredentialUserEntityOwned<'_, '_, LEN>>
    for PublicKeyCredentialUserEntity<'name, 'display_name, 'id, LEN>
{
    #[inline]
    fn from(value: &'a PublicKeyCredentialUserEntityOwned<'_, '_, LEN>) -> Self {
        Self {
            name: (&value.name).into(),
            id: &value.id,
            display_name: value.display_name.as_ref().map(Into::into),
        }
    }
}
impl<const LEN: usize> Default for PublicKeyCredentialUserEntityOwned<'_, '_, LEN>
where
    UserHandle<LEN>: Default,
{
    #[inline]
    fn default() -> Self {
        Self {
            name: Username::blank(),
            id: UserHandle::default(),
            display_name: None,
        }
    }
}
impl<'de: 'name + 'display_name, 'name, 'display_name, const LEN: usize> Deserialize<'de>
    for PublicKeyCredentialUserEntityOwned<'name, 'display_name, LEN>
where
    UserHandle<LEN>: Default,
{
    /// Deserializes a `struct` according to
    /// [`PublicKeyCredentialUserEntityJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentityjson).
    ///
    /// Note none of the fields are required and all of them are allowed to be `null`.
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentityjson-id) is deserialized
    /// according to [`UserHandle::deserialize`],
    /// [`name`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentityjson-name) is deserialized
    /// according to [`Username::deserialize`], and
    /// [`displayName`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentityjson-displayname) is
    /// deserialized according to [`Nickname::deserialize`] where `""` is deserialized to `None` (since
    /// blank strings are not valid `Nickname`s).
    ///
    /// In the event `id` does not exist, a randomly generated `UserHandle` will be used. In the event `name`
    /// does not exist, `"blank"` will be used. In the event `displayName` does not exist, `None` will
    /// be used.
    ///
    /// Unknown or duplicate fields lead to an error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::ser::PublicKeyCredentialUserEntityOwned;
    /// let val = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<'_, '_, 16>>(r#"{"name":"paul.erdos","displayName":"Erdős Pál"}"#)?;
    /// assert_eq!(val.name.as_ref(), "paul.erdos");
    /// assert_eq!(val.display_name.as_ref().map(|v| v.as_ref()), Some("Erdős Pál"));
    /// assert_ne!(val.id.as_slice(), [0; 16]);
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[expect(clippy::too_many_lines, reason = "122 is fine")]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `PublicKeyCredentialUserEntityOwned`.
        struct PublicKeyCredentialUserEntityOwnedVisitor<'a, 'b, const L: usize>(
            PhantomData<fn() -> (&'a (), &'b ())>,
        );
        impl<'d: 'a + 'b, 'a, 'b, const L: usize> Visitor<'d>
            for PublicKeyCredentialUserEntityOwnedVisitor<'a, 'b, L>
        where
            UserHandle<L>: Default,
        {
            type Value = PublicKeyCredentialUserEntityOwned<'a, 'b, L>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("PublicKeyCredentialUserEntityOwned")
            }
            #[expect(clippy::too_many_lines, reason = "102 is fine")]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Field for `PublicKeyCredentialUserEntityOwned`.
                enum Field {
                    /// `id`.
                    Id,
                    /// `name`.
                    Name,
                    /// `displayName`
                    DisplayName,
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
                                write!(formatter, "'{ID}', '{NAME}', or '{DISPLAY_NAME}'")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    ID => Ok(Field::Id),
                                    NAME => Ok(Field::Name),
                                    DISPLAY_NAME => Ok(Field::DisplayName),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                /// Helper to deserialize `displayName`.
                struct DisplayName<'e>(Option<Nickname<'e>>);
                impl<'e: 'f, 'f> Deserialize<'e> for DisplayName<'f> {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: Deserializer<'e>,
                    {
                        /// `Visitor` for `DisplayName`.
                        struct DisplayNameVisitor<'g>(PhantomData<fn() -> &'g ()>);
                        impl<'g: 'h, 'h> Visitor<'g> for DisplayNameVisitor<'h> {
                            type Value = DisplayName<'h>;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                formatter.write_str("User display name")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                if v.is_empty() {
                                    Ok(DisplayName(None))
                                } else {
                                    Nickname::try_from(v).map_err(E::custom).map(|name| {
                                        DisplayName(Some(Nickname(Cow::Owned(name.0.into_owned()))))
                                    })
                                }
                            }
                            fn visit_borrowed_str<E>(self, v: &'g str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                if v.is_empty() {
                                    Ok(DisplayName(None))
                                } else {
                                    Nickname::try_from(v)
                                        .map_err(E::custom)
                                        .map(|n| DisplayName(Some(n)))
                                }
                            }
                        }
                        deserializer.deserialize_str(DisplayNameVisitor(PhantomData))
                    }
                }
                let mut user_handle = None;
                let mut username = None;
                let mut display = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Id => {
                            if user_handle.is_some() {
                                return Err(Error::duplicate_field(ID));
                            }
                            user_handle = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::Name => {
                            if username.is_some() {
                                return Err(Error::duplicate_field(NAME));
                            }
                            username = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::DisplayName => {
                            if display.is_some() {
                                return Err(Error::duplicate_field(DISPLAY_NAME));
                            }
                            display = map
                                .next_value::<Option<DisplayName<'_>>>()
                                .map(|n| n.map_or_else(|| Some(None), |disp| Some(disp.0)))?;
                        }
                    }
                }
                Ok(PublicKeyCredentialUserEntityOwned {
                    id: user_handle.flatten().unwrap_or_default(),
                    name: username.flatten().unwrap_or_else(Username::blank),
                    display_name: display.flatten(),
                })
            }
        }
        /// Fields for `PublicKeyCredentialUserEntityOwned`.
        const FIELDS: &[&str; 3] = &[ID, NAME, DISPLAY_NAME];
        deserializer.deserialize_struct(
            "PublicKeyCredentialUserEntityOwned",
            FIELDS,
            PublicKeyCredentialUserEntityOwnedVisitor(PhantomData),
        )
    }
}
/// `newtype` around `CoseAlgorithmIdentifier`.
struct PubParam(CoseAlgorithmIdentifier);
impl<'de> Deserialize<'de> for PubParam {
    /// Conforms to the following schema:
    ///
    /// ```json
    /// {
    ///   "alg": <CoseAlgorithmIdentifier>,
    ///   "type": "public-key",
    /// }
    /// ```
    ///
    /// `"alg"` is required.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `PubParam`.
        struct PubParamVisitor;
        impl<'d> Visitor<'d> for PubParamVisitor {
            type Value = PubParam;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("PubParam")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Field for `PubParam`.
                enum Field {
                    /// `"type"`.
                    Type,
                    /// `"alg"`.
                    Alg,
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
                                write!(formatter, "'{TYPE}' or '{ALG}'")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    TYPE => Ok(Field::Type),
                                    ALG => Ok(Field::Alg),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                let mut typ = false;
                let mut alg = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Type => {
                            if typ {
                                return Err(Error::duplicate_field(TYPE));
                            }
                            typ = map.next_value::<Type>().map(|_t| true)?;
                        }
                        Field::Alg => {
                            if alg.is_some() {
                                return Err(Error::duplicate_field(ALG));
                            }
                            alg = map.next_value().map(Some)?;
                        }
                    }
                }
                alg.ok_or_else(|| Error::missing_field(ALG)).map(PubParam)
            }
        }
        /// Fields for `PubParam`.
        const FIELDS: &[&str; 2] = &[TYPE, ALG];
        deserializer.deserialize_struct("PubParam", FIELDS, PubParamVisitor)
    }
}
impl<'de> Deserialize<'de> for CoseAlgorithmIdentifiers {
    /// Deserializes a sequence based on
    /// [`pubKeyCredParams`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-pubkeycredparams)
    /// except [`type`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialparameters-type) is not required.
    ///
    /// Note the sequence of [`CoseAlgorithmIdentifier`]s MUST match [`CoseAlgorithmIdentifier::cmp`] or an
    /// error will occur (e.g., if [`CoseAlgorithmIdentifier::Eddsa`] exists, then it must appear first).
    ///
    /// An empty sequence will be treated as [`Self::ALL`].
    ///
    /// Unknown or duplicate fields lead to an error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::CoseAlgorithmIdentifiers;
    /// assert!(serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-257}]"#).is_ok());
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `CoseAlgorithmIdentifiers`.
        struct CoseAlgorithmIdentifiersVisitor;
        impl<'d> Visitor<'d> for CoseAlgorithmIdentifiersVisitor {
            type Value = CoseAlgorithmIdentifiers;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("CoseAlgorithmIdentifiers")
            }
            #[expect(clippy::else_if_without_else, reason = "prefer it this way")]
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'d>,
            {
                let mut eddsa = false;
                let mut es256 = false;
                let mut es384 = false;
                let mut rs256 = false;
                while let Some(elem) = seq.next_element::<PubParam>()? {
                    match elem.0 {
                        CoseAlgorithmIdentifier::Eddsa => {
                            if eddsa {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained duplicate EdDSA values",
                                ));
                            } else if es256 || es384 || rs256 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained EdDSA, but it wasn't the first value",
                                ));
                            }
                            eddsa = true;
                        }
                        CoseAlgorithmIdentifier::Es256 => {
                            if es256 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained duplicate Es256 values",
                                ));
                            } else if es384 || rs256 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained Es256, but it was preceded by Es384 or Rs256",
                                ));
                            }
                            es256 = true;
                        }
                        CoseAlgorithmIdentifier::Es384 => {
                            if es384 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained duplicate Es384 values",
                                ));
                            } else if rs256 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained Es384, but it was preceded by Rs256",
                                ));
                            }
                            es384 = true;
                        }
                        CoseAlgorithmIdentifier::Rs256 => {
                            if rs256 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained duplicate Rs256 values",
                                ));
                            }
                            rs256 = true;
                        }
                    }
                }
                let mut algs = CoseAlgorithmIdentifiers(0);
                if eddsa {
                    algs = algs.add(CoseAlgorithmIdentifier::Eddsa);
                }
                if es256 {
                    algs = algs.add(CoseAlgorithmIdentifier::Es256);
                }
                if es384 {
                    algs = algs.add(CoseAlgorithmIdentifier::Es384);
                }
                if rs256 {
                    algs = algs.add(CoseAlgorithmIdentifier::Rs256);
                }
                Ok(if algs.0 == 0 {
                    CoseAlgorithmIdentifiers::ALL
                } else {
                    algs
                })
            }
        }
        deserializer.deserialize_seq(CoseAlgorithmIdentifiersVisitor)
    }
}
/// Helper for `UserVerificatonRequirement::deserialize` and [`ResidentKeyRequirement::deserialize`].
enum Requirement {
    /// Required.
    Required,
    /// Discouraged.
    Discouraged,
    /// Preferred.
    Preferred,
}
impl<'de> Deserialize<'de> for Requirement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `Requirement`.
        struct RequirementVisitor;
        impl Visitor<'_> for RequirementVisitor {
            type Value = Requirement;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                write!(formatter, "'{REQUIRED}', '{DISCOURAGED}', or '{PREFERRED}'")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match v {
                    REQUIRED => Ok(Requirement::Required),
                    DISCOURAGED => Ok(Requirement::Discouraged),
                    PREFERRED => Ok(Requirement::Preferred),
                    _ => Err(E::invalid_value(
                        Unexpected::Str(v),
                        &format!("'{REQUIRED}', '{DISCOURAGED}', or '{PREFERRED}'").as_str(),
                    )),
                }
            }
        }
        deserializer.deserialize_str(RequirementVisitor)
    }
}
impl From<Requirement> for ResidentKeyRequirement {
    #[inline]
    fn from(value: Requirement) -> Self {
        match value {
            Requirement::Required => Self::Required,
            Requirement::Discouraged => Self::Discouraged,
            Requirement::Preferred => Self::Preferred,
        }
    }
}
impl From<Requirement> for UserVerificationRequirement {
    #[inline]
    fn from(value: Requirement) -> Self {
        match value {
            Requirement::Required => Self::Required,
            Requirement::Discouraged => Self::Discouraged,
            Requirement::Preferred => Self::Preferred,
        }
    }
}
impl<'de> Deserialize<'de> for ResidentKeyRequirement {
    /// Deserializes [`prim@str`] based on
    /// [`ResidentKeyRequirement`](https://www.w3.org/TR/webauthn-3/#enumdef-residentkeyrequirement).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::ResidentKeyRequirement;
    /// assert!(
    ///     matches!(
    ///         serde_json::from_str(r#""required""#)?,
    ///         ResidentKeyRequirement::Required
    ///     )
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Requirement::deserialize(deserializer).map(Self::from)
    }
}
impl<'de> Deserialize<'de> for UserVerificationRequirement {
    /// Deserializes [`prim@str`] based on
    /// [`UserVerificationRequirement`](https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::UserVerificationRequirement;
    /// assert!(
    ///     matches!(
    ///         serde_json::from_str(r#""required""#)?,
    ///         UserVerificationRequirement::Required
    ///     )
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Requirement::deserialize(deserializer).map(Self::from)
    }
}
impl<'de> Deserialize<'de> for AuthenticatorAttachmentReq {
    /// Deserializes a [`prim@str`] according to
    /// [`AuthenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment).
    ///
    /// Note the contained hint will be none (e.g., [`PlatformHint::None`]).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{AuthenticatorAttachmentReq, PlatformHint};
    /// assert!(matches!(
    ///     serde_json::from_str(r#""platform""#)?,
    ///     AuthenticatorAttachmentReq::Platform(hint) if matches!(hint, PlatformHint::None)
    /// ));
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `AuthenticatorAttachmentReq`.
        struct AuthenticatorAttachmentReqVisitor;
        impl Visitor<'_> for AuthenticatorAttachmentReqVisitor {
            type Value = AuthenticatorAttachmentReq;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                write!(formatter, "'{PLATFORM}' or '{CROSS_PLATFORM}'")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match v {
                    PLATFORM => Ok(AuthenticatorAttachmentReq::Platform(PlatformHint::None)),
                    CROSS_PLATFORM => Ok(AuthenticatorAttachmentReq::CrossPlatform(
                        CrossPlatformHint::None,
                    )),
                    _ => Err(E::invalid_value(
                        Unexpected::Str(v),
                        &format!("'{PLATFORM}' or '{CROSS_PLATFORM}'").as_str(),
                    )),
                }
            }
        }
        deserializer.deserialize_str(AuthenticatorAttachmentReqVisitor)
    }
}
impl<'de> Deserialize<'de> for AuthenticatorSelectionCriteria {
    /// Deserializes a `struct` based on
    /// [`AuthenticatorSelectionCriteria`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorselectioncriteria).
    ///
    /// Note that none of the fields are required, and all are allowed to be `null`. Additionally
    /// [`residentKey`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-residentkey) and
    /// [`requireResidentKey`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-requireresidentkey)
    /// must be consistent (i.e., `requireResidentKey` iff `residentKey` is [`ResidentKeyRequirement::Required`]).
    ///
    /// `residentKey` defaults to [`ResidentKeyRequirement::Discouraged`] when it is `null` or does not exist
    /// unless `requireResidentKey` is `true` in which case it is `ResidentKeyRequirement::Required`.
    ///
    /// [`userVerification`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification)
    /// is [`UserVerificationRequirement::Preferred`] if it does not exist or is `null`.
    ///
    /// If
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-authenticatorattachment)
    /// does not exist or is `null`, then [`AuthenticatorAttachmentReq::None`] will be used containing
    /// [`Hint::None`].
    ///
    /// Unknown or duplicate fields lead to an error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{Hint, register::{AuthenticatorAttachmentReq, AuthenticatorSelectionCriteria}};
    /// assert!(
    ///     matches!(
    ///         serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"authenticatorAttachment":null,"residentKey":"required","requireResidentKey":true,"userVerification":"required"}"#)?.authenticator_attachment,
    ///         AuthenticatorAttachmentReq::None(hints) if matches!(hints, Hint::None)
    ///     )
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[expect(clippy::too_many_lines, reason = "144 isn't too bad")]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `AuthenticatorSelectionCriteria`.
        struct AuthenticatorSelectionCriteriaVisitor;
        impl<'de> Visitor<'de> for AuthenticatorSelectionCriteriaVisitor {
            type Value = AuthenticatorSelectionCriteria;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("AuthenticatorSelectionCriteria")
            }
            #[expect(clippy::too_many_lines, reason = "121 isn't too bad")]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                /// Field for `AuthenticatorSelectionCriteria`.
                enum Field {
                    /// `"authenticatorAttachment"`.
                    AuthenticatorAttachment,
                    /// `"residentKey"`.
                    ResidentKey,
                    /// `"requireResidentKey"`.
                    RequireResidentKey,
                    /// `"userVerification"`.
                    UserVerification,
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
                                    "'{AUTHENTICATOR_ATTACHMENT}', '{RESIDENT_KEY}', '{REQUIRE_RESIDENT_KEY}', or '{USER_VERIFICATION}'"
                                )
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    AUTHENTICATOR_ATTACHMENT => Ok(Field::AuthenticatorAttachment),
                                    RESIDENT_KEY => Ok(Field::ResidentKey),
                                    REQUIRE_RESIDENT_KEY => Ok(Field::RequireResidentKey),
                                    USER_VERIFICATION => Ok(Field::UserVerification),
                                    _ => Err(Error::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                let mut attach = None;
                let mut res_key = None;
                let mut res_req: Option<Option<bool>> = None;
                let mut uv = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::AuthenticatorAttachment => {
                            if attach.is_some() {
                                return Err(Error::duplicate_field(AUTHENTICATOR_ATTACHMENT));
                            }
                            attach = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::ResidentKey => {
                            if res_key.is_some() {
                                return Err(Error::duplicate_field(RESIDENT_KEY));
                            }
                            res_key = map.next_value::<Option<_>>().and_then(|opt| {
                                opt.map_or(Ok(Some(None)), |res| res_req.map_or(Ok(Some(opt)), |req_opt| req_opt.map_or(Ok(Some(opt)), |req| {
                                    match res {
                                        ResidentKeyRequirement::Required => {
                                            if req {
                                                Ok(Some(opt))
                                            } else {
                                                Err(Error::custom(format!("'{RESIDENT_KEY}' is '{REQUIRED}', but '{REQUIRE_RESIDENT_KEY}' is false")))
                                            }
                                        }
                                        ResidentKeyRequirement::Discouraged | ResidentKeyRequirement::Preferred => {
                                            if req {
                                                Err(Error::custom(format!("'{RESIDENT_KEY}' is not '{REQUIRED}', but '{REQUIRE_RESIDENT_KEY}' is true")))
                                            } else {
                                                Ok(Some(opt))
                                            }
                                        }
                                    }
                                })))
                            })?;
                        }
                        Field::RequireResidentKey => {
                            if res_req.is_some() {
                                return Err(Error::duplicate_field(REQUIRE_RESIDENT_KEY));
                            }
                            res_req = map.next_value::<Option<_>>().and_then(|opt| {
                                opt.map_or(Ok(Some(None)), |req| res_key.map_or(Ok(Some(opt)), |req_opt| req_opt.map_or(Ok(Some(opt)), |res| {
                                    match res {
                                        ResidentKeyRequirement::Required => {
                                            if req {
                                                Ok(Some(opt))
                                            } else {
                                                Err(Error::custom(format!("'{RESIDENT_KEY}' is '{REQUIRED}', but '{REQUIRE_RESIDENT_KEY}' is false")))
                                            }
                                        }
                                        ResidentKeyRequirement::Discouraged | ResidentKeyRequirement::Preferred => {
                                            if req {
                                                Err(Error::custom(format!("'{RESIDENT_KEY}' is not '{REQUIRED}', but '{REQUIRE_RESIDENT_KEY}' is true")))
                                            } else {
                                                Ok(Some(opt))
                                            }
                                        }
                                    }
                                })))
                            })?;
                        }
                        Field::UserVerification => {
                            if uv.is_some() {
                                return Err(Error::duplicate_field(USER_VERIFICATION));
                            }
                            uv = map.next_value::<Option<_>>().map(Some)?;
                        }
                    }
                }
                Ok(AuthenticatorSelectionCriteria {
                    authenticator_attachment: attach.flatten().unwrap_or_default(),
                    resident_key: res_key.flatten().unwrap_or_else(|| {
                        if res_req.flatten().is_some_and(convert::identity) {
                            ResidentKeyRequirement::Required
                        } else {
                            ResidentKeyRequirement::Discouraged
                        }
                    }),
                    user_verification: uv
                        .flatten()
                        .unwrap_or(UserVerificationRequirement::Preferred),
                })
            }
        }
        /// Fields for `AuthenticatorSelectionCriteria`.
        const FIELDS: &[&str; 4] = &[
            AUTHENTICATOR_ATTACHMENT,
            RESIDENT_KEY,
            REQUIRE_RESIDENT_KEY,
            USER_VERIFICATION,
        ];
        deserializer.deserialize_struct(
            "AuthenticatorSelectionCriteria",
            FIELDS,
            AuthenticatorSelectionCriteriaVisitor,
        )
    }
}
/// Helper for [`ClientCredentialCreationOptions::deserialize`].
struct Attestation;
impl<'de> Deserialize<'de> for Attestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `Attestation`.
        struct AttestationVisitor;
        impl Visitor<'_> for AttestationVisitor {
            type Value = Attestation;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(NONE)
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v == NONE {
                    Ok(Attestation)
                } else {
                    Err(E::invalid_value(Unexpected::Str(v), &NONE))
                }
            }
        }
        deserializer.deserialize_str(AttestationVisitor)
    }
}
/// Helper for [`ClientCredentialCreationOptions::deserialize`].
struct AttestationFormats;
impl<'de> Deserialize<'de> for AttestationFormats {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `AttestationFormats`.
        struct AttestationFormatsVisitor;
        impl<'d> Visitor<'d> for AttestationFormatsVisitor {
            type Value = AttestationFormats;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("AttestationFormats")
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'d>,
            {
                seq.next_element::<Attestation>().and_then(|opt| {
                    opt.map_or(Ok(AttestationFormats), |_f| {
                        seq.next_element::<Attestation>().and_then(|opt2| {
                            opt2.map_or(Ok(AttestationFormats), |_val| Err(Error::custom("attestationFormats must be an empty sequence or contain exactly one string whose value is 'none'")))
                        })
                    })
                })
            }
        }
        deserializer.deserialize_seq(AttestationFormatsVisitor)
    }
}
/// Similar to [`Extension`] except [`PrfInputOwned`] is used.
///
/// This is primarily useful to assist [`ClientCredentialCreationOptions::deserialize`].
#[derive(Debug, Default)]
pub struct ExtensionOwned {
    /// See [`Extension::cred_props`].
    pub cred_props: Option<ExtensionReq>,
    /// See [`Extension::cred_protect`].
    pub cred_protect: CredProtect,
    /// See [`Extension::min_pin_length`].
    pub min_pin_length: Option<(FourToSixtyThree, ExtensionInfo)>,
    /// See [`Extension::prf`].
    pub prf: Option<PrfInputOwned>,
}
impl<'a: 'prf_first + 'prf_second, 'prf_first, 'prf_second> From<&'a ExtensionOwned>
    for Extension<'prf_first, 'prf_second>
{
    #[inline]
    fn from(value: &'a ExtensionOwned) -> Self {
        Self {
            cred_props: value.cred_props,
            cred_protect: value.cred_protect,
            min_pin_length: value.min_pin_length,
            prf: value.prf.as_ref().map(|input| {
                (
                    PrfInput {
                        first: input.first.as_slice(),
                        second: input.second.as_deref(),
                    },
                    ExtensionInfo::AllowEnforceValue,
                )
            }),
        }
    }
}
impl<'de> Deserialize<'de> for ExtensionOwned {
    /// Deserializes a `struct` according to the following pseudo-schema:
    ///
    /// ```json
    /// {
    ///   "credProps": null | false | true,
    ///   "credentialProtectionPolicy": null | "userVerificationOptional" | "userVerificationOptionalWithCredentialIDList" | "userVerificationRequired",
    ///   "enforceCredentialProtectionPolicy": null | false | true,
    ///   "minPinLength": null | false | true,
    ///   "prf": null | PRFJSON
    /// }
    /// // PRFJSON:
    /// {
    ///   "eval": PRFInputs
    /// }
    /// // PRFInputs:
    /// {
    ///   "first": <base64url-encoded string>,
    ///   "second": null | <base64url-encoded string>
    /// }
    /// ```
    ///
    /// where the only required fields are `"eval"` and `"first"`. Additionally `"credentialProtectionPolicy"`
    /// must exist if `"enforceCredentialProtectionPolicy"` exists, and it must not be `null` if the latter
    /// is not `null`. If the former is defined and not `null` but the latter is not defined or is `null`, then
    /// `false` will be used for the latter. Unknown or duplicate fields lead to an error.
    ///
    /// All extensions are not required to have a response sent back; but _if_ a response is sent back, its value
    /// will be enforced. In the case of `"minPinLength"`, [`FourToSixtyThree::Four`] will be the minimum
    /// length enforced (i.e., any valid response is guaranteed to satisfy since it will have length at least
    /// as large).
    ///
    /// Unknown or duplicate fields lead to an error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{ExtensionInfo, ExtensionReq, register::{CredProtect, FourToSixtyThree, ser::ExtensionOwned}};
    /// let ext = serde_json::from_str::<ExtensionOwned>(
    ///     r#"{"credProps":true,"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"minPinLength":true,"prf":{"eval":{"first":"","second":null}}}"#,
    /// )?;
    /// assert!(
    ///     ext.cred_props
    ///         .map_or(false, |req| matches!(req, ExtensionReq::Allow))
    /// );
    /// assert!(
    ///     matches!(ext.cred_protect, CredProtect::UserVerificationRequired(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
    /// );
    /// assert!(ext.min_pin_length.map_or(false, |pin| pin.0 == FourToSixtyThree::Four
    ///     && matches!(pin.1, ExtensionInfo::AllowEnforceValue)));
    /// assert!(ext.prf.map_or(false, |prf| prf.first.is_empty()
    ///     && prf.second.is_none()
    ///     && matches!(prf.ext_req, ExtensionReq::Allow)));
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[expect(clippy::too_many_lines, reason = "want to keep logic internal")]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `ExtensionOwned`.
        struct ExtensionOwnedVisitor;
        impl<'d> Visitor<'d> for ExtensionOwnedVisitor {
            type Value = ExtensionOwned;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("ExtensionOwned")
            }
            #[expect(clippy::too_many_lines, reason = "want to keep logic internal")]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Field for `ExtensionOwned`.
                enum Field {
                    /// `credProps`.
                    CredProps,
                    /// `credentialProtectionPolicy`.
                    CredentialProtectionPolicy,
                    /// `enforceCredentialProtectionPolicy`.
                    EnforceCredentialProtectionPolicy,
                    /// `minPinLength`.
                    MinPinLength,
                    /// `prf`
                    Prf,
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
                                    "'{CRED_PROPS}', '{CREDENTIAL_PROTECTION_POLICY}', '{ENFORCE_CREDENTIAL_PROTECTION_POLICY}', '{MIN_PIN_LENGTH}', or '{PRF}'"
                                )
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    CRED_PROPS => Ok(Field::CredProps),
                                    CREDENTIAL_PROTECTION_POLICY => {
                                        Ok(Field::CredentialProtectionPolicy)
                                    }
                                    ENFORCE_CREDENTIAL_PROTECTION_POLICY => {
                                        Ok(Field::EnforceCredentialProtectionPolicy)
                                    }
                                    MIN_PIN_LENGTH => Ok(Field::MinPinLength),
                                    PRF => Ok(Field::Prf),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                /// Credential protection policy values.
                #[expect(clippy::enum_variant_names, reason = "consistent with ctap names")]
                enum Policy {
                    /// `userVerificationOptional`.
                    UserVerificationOptional,
                    /// `userVerificationOptionalWithCredentialIdList`.
                    UserVerificationOptionalWithCredentialIdLisit,
                    /// `userVerificationRequired`.
                    UserVerificationRequired,
                }
                impl<'e> Deserialize<'e> for Policy {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: Deserializer<'e>,
                    {
                        /// `Visitor` for `Policy`.
                        struct PolicyVisitor;
                        impl Visitor<'_> for PolicyVisitor {
                            type Value = Policy;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                write!(
                                    formatter,
                                    "'{USER_VERIFICATION_OPTIONAL}', '{USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST}', or '{USER_VERIFICATION_REQUIRED}'"
                                )
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    USER_VERIFICATION_OPTIONAL => Ok(Policy::UserVerificationOptional),
                                    USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST => Ok(Policy::UserVerificationOptionalWithCredentialIdLisit),
                                    USER_VERIFICATION_REQUIRED => Ok(Policy::UserVerificationRequired),
                                    _ => Err(E::invalid_value(Unexpected::Str(v), &format!("'{USER_VERIFICATION_OPTIONAL}', '{USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST}', or '{USER_VERIFICATION_REQUIRED}'").as_str())),
                                }
                            }
                        }
                        deserializer.deserialize_str(PolicyVisitor)
                    }
                }
                let mut props: Option<Option<bool>> = None;
                let mut policy = None;
                let mut enforce = None;
                let mut pin: Option<Option<bool>> = None;
                let mut prf_inputs = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::CredProps => {
                            if props.is_some() {
                                return Err(Error::duplicate_field(CRED_PROPS));
                            }
                            props = map.next_value().map(Some)?;
                        }
                        Field::CredentialProtectionPolicy => {
                            if policy.is_some() {
                                return Err(Error::duplicate_field(CREDENTIAL_PROTECTION_POLICY));
                            }
                            policy = map.next_value::<Option<Policy>>().map(Some)?;
                        }
                        Field::EnforceCredentialProtectionPolicy => {
                            if enforce.is_some() {
                                return Err(Error::duplicate_field(
                                    ENFORCE_CREDENTIAL_PROTECTION_POLICY,
                                ));
                            }
                            enforce = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::MinPinLength => {
                            if pin.is_some() {
                                return Err(Error::duplicate_field(MIN_PIN_LENGTH));
                            }
                            pin = map.next_value().map(Some)?;
                        }
                        Field::Prf => {
                            if prf_inputs.is_some() {
                                return Err(Error::duplicate_field(PRF));
                            }
                            prf_inputs = map
                                .next_value::<Option<PrfHelper>>()
                                .map(|opt| Some(opt.map(|p| p.0)))?;
                        }
                    }
                }
                policy.map_or_else(
                    || {
                        if enforce.is_some() {
                            Err(Error::custom(format!("'{ENFORCE_CREDENTIAL_PROTECTION_POLICY}' must not exist when '{CREDENTIAL_PROTECTION_POLICY}' does not exist")))
                        } else {
                            Ok(CredProtect::None)
                        }
                    },
                    |opt_policy| opt_policy.map_or_else(
                        || {
                            if enforce.is_some_and(|opt| opt.is_some()) {
                                Err(Error::custom(format!("'{ENFORCE_CREDENTIAL_PROTECTION_POLICY}' must be null or not exist when '{CREDENTIAL_PROTECTION_POLICY}' is null")))
                            } else {
                                Ok(CredProtect::None)
                            }
                        },
                        |cred_policy| {
                            match cred_policy {
                                Policy::UserVerificationOptional => Ok(CredProtect::UserVerificationOptional(enforce.flatten().unwrap_or_default(), ExtensionInfo::AllowEnforceValue)),
                                Policy::UserVerificationOptionalWithCredentialIdLisit => Ok(CredProtect::UserVerificationOptionalWithCredentialIdList(enforce.flatten().unwrap_or_default(), ExtensionInfo::AllowEnforceValue)),
                                Policy::UserVerificationRequired => Ok(CredProtect::UserVerificationRequired(enforce.flatten().unwrap_or_default(), ExtensionInfo::AllowEnforceValue)),
                            }
                        }
                    ),
                ).map(|cred_protect| {
                    ExtensionOwned { cred_props: props.flatten().and_then(|p| p.then_some(ExtensionReq::Allow)), cred_protect, min_pin_length: pin.flatten().and_then(|m| m.then_some((FourToSixtyThree::Four, ExtensionInfo::AllowEnforceValue))), prf: prf_inputs.flatten(), }
                })
            }
        }
        /// Fields for `ExtensionOwned`.
        const FIELDS: &[&str; 5] = &[
            CRED_PROPS,
            CREDENTIAL_PROTECTION_POLICY,
            ENFORCE_CREDENTIAL_PROTECTION_POLICY,
            MIN_PIN_LENGTH,
            PRF,
        ];
        deserializer.deserialize_struct("ExtensionOwned", FIELDS, ExtensionOwnedVisitor)
    }
}
/// Similar to [`PublicKeyCredentialCreationOptions`] except the fields are based on owned data.
///
/// This is primarily useful to assist [`ClientCredentialCreationOptions::deserialize`].
#[derive(Debug)]
pub struct PublicKeyCredentialCreationOptionsOwned<
    'user_name,
    'user_display_name,
    const USER_LEN: usize,
> {
    /// See [`PublicKeyCredentialCreationOptions::rp_id`].
    pub rp_id: RpId,
    /// See [`PublicKeyCredentialCreationOptions::user`].
    pub user: PublicKeyCredentialUserEntityOwned<'user_name, 'user_display_name, USER_LEN>,
    /// See [`PublicKeyCredentialCreationOptions::pub_key_cred_params`].
    pub pub_key_cred_params: CoseAlgorithmIdentifiers,
    /// See [`PublicKeyCredentialCreationOptions::timeout`].
    pub timeout: NonZeroU32,
    /// See [`PublicKeyCredentialCreationOptions::authenticator_selection`].
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    /// See [`PublicKeyCredentialCreationOptions::extensions`].
    pub extensions: ExtensionOwned,
}
impl<const USER_LEN: usize> PublicKeyCredentialCreationOptionsOwned<'_, '_, USER_LEN> {
    /// Creates a `PublicKeyCredentialCreationOptions` based on the contained data and randomly-generated
    /// [`Challenge`].
    #[inline]
    #[must_use]
    pub fn into_options(
        &self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Vec<u8>>>,
    ) -> PublicKeyCredentialCreationOptions<'_, '_, '_, '_, '_, '_, USER_LEN> {
        PublicKeyCredentialCreationOptions {
            rp_id: &self.rp_id,
            user: (&self.user).into(),
            challenge: Challenge::new(),
            pub_key_cred_params: self.pub_key_cred_params,
            timeout: self.timeout,
            exclude_credentials,
            authenticator_selection: self.authenticator_selection,
            extensions: (&self.extensions).into(),
        }
    }
}
impl<'user_name, 'user_display_name, const USER_LEN: usize> Default
    for PublicKeyCredentialCreationOptionsOwned<'user_name, 'user_display_name, USER_LEN>
where
    PublicKeyCredentialUserEntityOwned<'user_name, 'user_display_name, USER_LEN>: Default,
{
    #[inline]
    fn default() -> Self {
        Self {
            rp_id: DEFAULT_RP_ID,
            user: PublicKeyCredentialUserEntityOwned::default(),
            pub_key_cred_params: CoseAlgorithmIdentifiers::default(),
            timeout: FIVE_MINUTES,
            authenticator_selection: AuthenticatorSelectionCriteria {
                authenticator_attachment: AuthenticatorAttachmentReq::default(),
                resident_key: ResidentKeyRequirement::Discouraged,
                user_verification: UserVerificationRequirement::Preferred,
            },
            extensions: ExtensionOwned::default(),
        }
    }
}
impl<'de: 'user_name + 'user_display_name, 'user_name, 'user_display_name, const USER_LEN: usize>
    Deserialize<'de>
    for PublicKeyCredentialCreationOptionsOwned<'user_name, 'user_display_name, USER_LEN>
where
    UserHandle<USER_LEN>: Default,
    PublicKeyCredentialUserEntityOwned<'user_name, 'user_display_name, USER_LEN>: Default,
{
    /// Deserializes a `struct` based on
    /// [`PublicKeyCredentialCreationOptionsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptionsjson).
    ///
    /// Note that none of the fields are required, and all are allowed to be `null`.
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-authenticatorattachment)
    /// must be consistent with
    /// [`hints`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-hints)
    /// (e.g., if [`"platform"`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattachment-platform) is
    /// requested, then `hints` must either not exist, be `null`, be empty, or be `["client-device"]`).
    ///
    /// If [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-challenge)
    /// exists, it must be `null`. If
    /// [`excludeCredentials`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-excludecredentials)
    /// exists, it must be `null` or empty. If
    /// [`attestation`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-attestation)
    /// exists, it must be `null`or `"none"`. If
    /// [`attestationFormats`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-attestationformats)
    /// exists, it must be `null`, empty, or `["none"]`.
    ///
    /// If [`timeout`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptionsjson-timeout) exists,
    /// it must be `null` or positive.
    ///
    /// In the event there is no RP ID defined, the value `"example.invalid"` will be used.
    ///
    /// For any field that does not exist or is `null`, the corresponding [`Default`] `impl` will be used. For
    /// [`AuthenticatorSelectionCriteria`], `AuthenticatorAttachmentReq::None(Hint::None)`,
    /// [`ResidentKeyRequirement::Discouraged`], and [`UserVerificationRequirement::Preferred`] will be used.
    /// For `timeout`, [`FIVE_MINUTES`] will be used.
    ///
    /// Unknown or duplicate fields lead to an error.
    #[expect(clippy::too_many_lines, reason = "want to keep logic internal")]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `PublicKeyCredentialCreationOptionsOwned`.
        struct PublicKeyCredentialCreationOptionsOwnedVisitor<'a, 'b, const LEN: usize>(
            PhantomData<fn() -> (&'a (), &'b ())>,
        );
        impl<'d: 'a + 'b, 'a, 'b, const LEN: usize> Visitor<'d>
            for PublicKeyCredentialCreationOptionsOwnedVisitor<'a, 'b, LEN>
        where
            UserHandle<LEN>: Default,
            PublicKeyCredentialUserEntityOwned<'a, 'b, LEN>: Default,
        {
            type Value = PublicKeyCredentialCreationOptionsOwned<'a, 'b, LEN>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("PublicKeyCredentialCreationOptionsOwned")
            }
            #[expect(clippy::too_many_lines, reason = "want to keep logic internal")]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Field for `PublicKeyCredentialCreationOptionsOwned`.
                enum Field {
                    /// `rp`.
                    Rp,
                    /// `user`.
                    User,
                    /// `challenge`.
                    Challenge,
                    /// `pubKeyCredParams`.
                    PubKeyCredParams,
                    /// `timeout`.
                    Timeout,
                    /// `excludeCredentials`.
                    ExcludeCredentials,
                    /// `authenticatorSelection`.
                    AuthenticatorSelection,
                    /// `hints`.
                    Hints,
                    /// `extensions`.
                    Extensions,
                    /// `attestation`.
                    Attestation,
                    /// `attestationFormats`.
                    AttestationFormats,
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
                                    "'{RP}', '{USER}', '{CHALLENGE}', '{PUB_KEY_CRED_PARAMS}', '{TIMEOUT}', '{EXCLUDE_CREDENTIALS}', '{AUTHENTICATOR_SELECTION}', '{HINTS}', '{EXTENSIONS}', '{ATTESTATION}', or '{ATTESTATION_FORMATS}'"
                                )
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    RP => Ok(Field::Rp),
                                    USER => Ok(Field::User),
                                    CHALLENGE => Ok(Field::Challenge),
                                    PUB_KEY_CRED_PARAMS => Ok(Field::PubKeyCredParams),
                                    TIMEOUT => Ok(Field::Timeout),
                                    EXCLUDE_CREDENTIALS => Ok(Field::ExcludeCredentials),
                                    AUTHENTICATOR_SELECTION => Ok(Field::AuthenticatorSelection),
                                    HINTS => Ok(Field::Hints),
                                    EXTENSIONS => Ok(Field::Extensions),
                                    ATTESTATION => Ok(Field::Attestation),
                                    ATTESTATION_FORMATS => Ok(Field::AttestationFormats),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                let mut rp = None;
                let mut user_info = None;
                let mut chall = None;
                let mut params = None;
                let mut time = None;
                let mut exclude = None;
                let mut auth = None;
                let mut hint: Option<Hint> = None;
                let mut ext = None;
                let mut attest = None;
                let mut formats = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Rp => {
                            if rp.is_some() {
                                return Err(Error::duplicate_field(RP));
                            }
                            rp = map
                                .next_value::<Option<PublicKeyCredentialRpEntityHelper>>()
                                .map(|opt| Some(opt.map(|val| val.0)))?;
                        }
                        Field::User => {
                            if user_info.is_some() {
                                return Err(Error::duplicate_field(USER));
                            }
                            user_info = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::Challenge => {
                            if chall.is_some() {
                                return Err(Error::duplicate_field(CHALLENGE));
                            }
                            chall = map.next_value::<Null>().map(Some)?;
                        }
                        Field::PubKeyCredParams => {
                            if params.is_some() {
                                return Err(Error::duplicate_field(PUB_KEY_CRED_PARAMS));
                            }
                            params = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::Timeout => {
                            if time.is_some() {
                                return Err(Error::duplicate_field(TIMEOUT));
                            }
                            time = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::ExcludeCredentials => {
                            if exclude.is_some() {
                                return Err(Error::duplicate_field(EXCLUDE_CREDENTIALS));
                            }
                            exclude = map.next_value::<Option<[(); 0]>>().map(Some)?;
                        }
                        Field::AuthenticatorSelection => {
                            if auth.is_some() {
                                return Err(Error::duplicate_field(AUTHENTICATOR_SELECTION));
                            }
                            auth = map.next_value::<Option<AuthenticatorSelectionCriteria>>().and_then(|opt| {
                                opt.map_or(Ok(Some(AuthenticatorSelectionCriteria { authenticator_attachment: AuthenticatorAttachmentReq::default(), resident_key: ResidentKeyRequirement::Discouraged, user_verification: UserVerificationRequirement::Preferred, })), |mut crit| {
                                    let h = hint.unwrap_or_default();
                                    match crit.authenticator_attachment {
                                        AuthenticatorAttachmentReq::None(ref mut hi) => {
                                            *hi = h;
                                            Ok(Some(crit))
                                        }
                                        AuthenticatorAttachmentReq::Platform(ref mut hi) => {
                                            match h {
                                                Hint::None => Ok(Some(crit)),
                                                Hint::ClientDevice => {
                                                    *hi = PlatformHint::ClientDevice;
                                                    Ok(Some(crit))
                                                }
                                                Hint::SecurityKey | Hint::Hybrid | Hint::SecurityKeyClientDevice | Hint::ClientDeviceSecurityKey | Hint::SecurityKeyHybrid | Hint::HybridSecurityKey | Hint::ClientDeviceHybrid | Hint::HybridClientDevice | Hint::SecurityKeyClientDeviceHybrid | Hint::SecurityKeyHybridClientDevice | Hint::ClientDeviceSecurityKeyHybrid | Hint::ClientDeviceHybridSecurityKey | Hint::HybridSecurityKeyClientDevice | Hint::HybridClientDeviceSecurityKey => Err(Error::custom("'platform' authenticator attachment modality must coincide with no hints or 'client-device' hint")),
                                            }
                                        }
                                        AuthenticatorAttachmentReq::CrossPlatform(ref mut hi) => {
                                            match h {
                                                Hint::None => Ok(Some(crit)),
                                                Hint::SecurityKey => {
                                                    *hi = CrossPlatformHint::SecurityKey;
                                                    Ok(Some(crit))
                                                }
                                                Hint::Hybrid => {
                                                    *hi = CrossPlatformHint::Hybrid;
                                                    Ok(Some(crit))
                                                }
                                                Hint::SecurityKeyHybrid => {
                                                    *hi = CrossPlatformHint::SecurityKeyHybrid;
                                                    Ok(Some(crit))
                                                }
                                                Hint::HybridSecurityKey => {
                                                    *hi = CrossPlatformHint::HybridSecurityKey;
                                                    Ok(Some(crit))
                                                }
                                                Hint::ClientDevice | Hint::SecurityKeyClientDevice | Hint::ClientDeviceSecurityKey | Hint::ClientDeviceHybrid | Hint::HybridClientDevice | Hint::SecurityKeyClientDeviceHybrid | Hint::SecurityKeyHybridClientDevice | Hint::ClientDeviceSecurityKeyHybrid | Hint::ClientDeviceHybridSecurityKey | Hint::HybridSecurityKeyClientDevice | Hint::HybridClientDeviceSecurityKey => Err(Error::custom("'cross-platform' authenticator attachment modality must coincide with no hints or hints that lack 'client-device'")),
                                            }
                                        }
                                    }
                                })
                            })?;
                        }
                        Field::Hints => {
                            if hint.is_some() {
                                return Err(Error::duplicate_field(HINTS));
                            }
                            hint = map.next_value::<Option<Hint>>().and_then(|opt| {
                                opt.map_or(Ok(Some(Hint::None)), |h| {
                                    auth.as_mut().map_or(Ok(Some(h)), |crit| {
                                        match crit.authenticator_attachment {
                                            AuthenticatorAttachmentReq::None(ref mut hi) => {
                                                *hi = h;
                                                Ok(Some(h))
                                            }
                                            AuthenticatorAttachmentReq::Platform(ref mut hi) => {
                                                match h{
                                                    Hint::None => Ok(Some(h)),
                                                    Hint::ClientDevice => {
                                                        *hi = PlatformHint::ClientDevice;
                                                        Ok(Some(h))
                                                    }
                                                    Hint::SecurityKey | Hint::Hybrid | Hint::SecurityKeyClientDevice | Hint::ClientDeviceSecurityKey | Hint::SecurityKeyHybrid | Hint::HybridSecurityKey | Hint::ClientDeviceHybrid | Hint::HybridClientDevice | Hint::SecurityKeyClientDeviceHybrid | Hint::SecurityKeyHybridClientDevice | Hint::ClientDeviceSecurityKeyHybrid | Hint::ClientDeviceHybridSecurityKey | Hint::HybridSecurityKeyClientDevice | Hint::HybridClientDeviceSecurityKey => Err(Error::custom("'platform' authenticator attachment modality must coincide with no hints or 'client-device' hint")),
                                                }
                                            }
                                            AuthenticatorAttachmentReq::CrossPlatform(ref mut hi) => {
                                                match h {
                                                    Hint::None => Ok(Some(h)),
                                                    Hint::SecurityKey => {
                                                        *hi = CrossPlatformHint::SecurityKey;
                                                        Ok(Some(h))
                                                    }
                                                    Hint::Hybrid => {
                                                        *hi = CrossPlatformHint::Hybrid;
                                                        Ok(Some(h))
                                                    }
                                                    Hint::SecurityKeyHybrid => {
                                                        *hi = CrossPlatformHint::SecurityKeyHybrid;
                                                        Ok(Some(h))
                                                    }
                                                    Hint::HybridSecurityKey => {
                                                        *hi = CrossPlatformHint::HybridSecurityKey;
                                                        Ok(Some(h))
                                                    }
                                                    Hint::ClientDevice | Hint::SecurityKeyClientDevice | Hint::ClientDeviceSecurityKey | Hint::ClientDeviceHybrid | Hint::HybridClientDevice | Hint::SecurityKeyClientDeviceHybrid | Hint::SecurityKeyHybridClientDevice | Hint::ClientDeviceSecurityKeyHybrid | Hint::ClientDeviceHybridSecurityKey | Hint::HybridSecurityKeyClientDevice | Hint::HybridClientDeviceSecurityKey => Err(Error::custom("'cross-platform' authenticator attachment modality must coincide with no hints or hints that lack 'client-device'")),
                                                }
                                            }
                                        }
                                    })
                                })
                            })?;
                        }
                        Field::Extensions => {
                            if ext.is_some() {
                                return Err(Error::duplicate_field(EXTENSIONS));
                            }
                            ext = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::Attestation => {
                            if attest.is_some() {
                                return Err(Error::duplicate_field(ATTESTATION));
                            }
                            attest = map.next_value::<Option<Attestation>>().map(Some)?;
                        }
                        Field::AttestationFormats => {
                            if formats.is_some() {
                                return Err(Error::duplicate_field(ATTESTATION_FORMATS));
                            }
                            formats = map.next_value::<Option<AttestationFormats>>().map(Some)?;
                        }
                    }
                }
                Ok(PublicKeyCredentialCreationOptionsOwned {
                    rp_id: rp.flatten().unwrap_or(DEFAULT_RP_ID),
                    user: user_info.flatten().unwrap_or_default(),
                    pub_key_cred_params: params.flatten().unwrap_or_default(),
                    timeout: time.flatten().unwrap_or(FIVE_MINUTES),
                    authenticator_selection: auth.unwrap_or_else(|| {
                        AuthenticatorSelectionCriteria {
                            authenticator_attachment: AuthenticatorAttachmentReq::default(),
                            resident_key: ResidentKeyRequirement::Discouraged,
                            user_verification: UserVerificationRequirement::Preferred,
                        }
                    }),
                    extensions: ext.flatten().unwrap_or_default(),
                })
            }
        }
        /// Fields for `PublicKeyCredentialCreationOptionsOwned`.
        const FIELDS: &[&str; 11] = &[
            RP,
            USER,
            CHALLENGE,
            PUB_KEY_CRED_PARAMS,
            TIMEOUT,
            EXCLUDE_CREDENTIALS,
            AUTHENTICATOR_SELECTION,
            HINTS,
            EXTENSIONS,
            ATTESTATION,
            ATTESTATION_FORMATS,
        ];
        deserializer.deserialize_struct(
            "PublicKeyCredentialCreationOptionsOwned",
            FIELDS,
            PublicKeyCredentialCreationOptionsOwnedVisitor(PhantomData),
        )
    }
}
/// Deserializes client-supplied data to assist in the creation of [`CredentialCreationOptions`].
///
/// It's common to tailor a registration ceremony based on a user's environment. The options that should be
/// used are then sent to the server. For example, [`CredentialMediationRequirement::Conditional`] ceremonies
/// typically work best for [`AuthenticatorAttachment::Platform`] authenticators; a subset of which cannot
/// rely on [`UserVerificationRequirement::Required`]. Unfortunately one may not want to use
/// [`UserVerificationRequirement::Preferred`] unconditionally either since security keys may benefit from
/// [`CredProtect::UserVerificationRequired`] which can typically only be used when
/// [`UserVerificationRequirement::Required`] is requested since many user agents error otherwise.
///
/// To facilitate this, [`Self::deserialize`] can be used to deserialize the data sent from the client. Upon
/// successful deserialization, [`Self::into_options`] can then be used to construct the appropriate
/// [`CredentialCreationOptions`].
///
/// Note one may want to change some of the [`Extension`] data since [`ExtensionInfo::AllowEnforceValue`] and
/// [`ExtensionReq::Allow`] are unconditionally used. Read [`ExtensionOwned::deserialize`] for more information.
///
/// Additionally, one may want to change the value of [`PublicKeyCredentialCreationOptions::rp_id`] since
/// `"example.invalid"` is used in the event the RP ID was not supplied.
#[derive(Debug)]
pub struct ClientCredentialCreationOptions<'user_name, 'user_display_name, const USER_LEN: usize> {
    /// See [`CredentialCreationOptions::mediation`].
    pub mediation: CredentialMediationRequirement,
    /// See [`CredentialCreationOptions::public_key`].
    pub public_key:
        PublicKeyCredentialCreationOptionsOwned<'user_name, 'user_display_name, USER_LEN>,
}
impl<const USER_LEN: usize> ClientCredentialCreationOptions<'_, '_, USER_LEN> {
    /// Creates a `CredentialCreationOptions` based on the contained data where
    /// [`CredentialCreationOptions::public_key`] is constructed via
    /// [`PublicKeyCredentialCreationOptionsOwned::into_options`].
    #[inline]
    #[must_use]
    pub fn into_options(
        &self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Vec<u8>>>,
    ) -> CredentialCreationOptions<'_, '_, '_, '_, '_, '_, USER_LEN> {
        CredentialCreationOptions {
            mediation: self.mediation,
            public_key: self.public_key.into_options(exclude_credentials),
        }
    }
}
impl<'user_name, 'user_display_name, const USER_LEN: usize> Default
    for ClientCredentialCreationOptions<'user_name, 'user_display_name, USER_LEN>
where
    PublicKeyCredentialCreationOptionsOwned<'user_name, 'user_display_name, USER_LEN>: Default,
{
    #[inline]
    fn default() -> Self {
        Self {
            mediation: CredentialMediationRequirement::default(),
            public_key: PublicKeyCredentialCreationOptionsOwned::default(),
        }
    }
}
impl<'de: 'user_name + 'user_display_name, 'user_name, 'user_display_name, const USER_LEN: usize>
    Deserialize<'de> for ClientCredentialCreationOptions<'user_name, 'user_display_name, USER_LEN>
where
    UserHandle<USER_LEN>: Default,
    PublicKeyCredentialCreationOptionsOwned<'user_name, 'user_display_name, USER_LEN>: Default,
{
    /// Deserializes a `struct` according to the following pseudo-schema:
    ///
    /// ```json
    /// {
    ///   "mediation": null | "required" | "conditional",
    ///   "publicKey": null | <PublicKeyCredentialCreationOptionsOwned>
    /// }
    /// ```
    ///
    /// where none of the fields are required and `"publicKey"` is deserialized according to
    /// [`PublicKeyCredentialCreationOptionsOwned::deserialize`]. If any field is missing or is `null`, then
    /// the corresponding [`Default`] `impl` will be used.
    ///
    /// Unknown or duplicate fields lead to an error.
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `ClientCredentialCreationOptions`.
        struct ClientCredentialCreationOptionsVisitor<'a, 'b, const LEN: usize>(
            PhantomData<fn() -> (&'a (), &'b ())>,
        );
        impl<'d: 'a + 'b, 'a, 'b, const LEN: usize> Visitor<'d>
            for ClientCredentialCreationOptionsVisitor<'a, 'b, LEN>
        where
            UserHandle<LEN>: Default,
            PublicKeyCredentialCreationOptionsOwned<'a, 'b, LEN>: Default,
        {
            type Value = ClientCredentialCreationOptions<'a, 'b, LEN>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("ClientCredentialCreationOptions")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Field in `ClientCredentialCreationOptions`.
                enum Field {
                    /// `mediation`.
                    Mediation,
                    /// `publicKey`
                    PublicKey,
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
                                write!(formatter, "'{MEDIATION}' or '{PUBLIC_KEY_NO_HYPEN}'")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    MEDIATION => Ok(Field::Mediation),
                                    PUBLIC_KEY_NO_HYPEN => Ok(Field::PublicKey),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                let mut med = None;
                let mut key = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        Field::Mediation => {
                            if med.is_some() {
                                return Err(Error::duplicate_field(MEDIATION));
                            }
                            med = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::PublicKey => {
                            if key.is_some() {
                                return Err(Error::duplicate_field(PUBLIC_KEY_NO_HYPEN));
                            }
                            key = map.next_value::<Option<_>>().map(Some)?;
                        }
                    }
                }
                Ok(ClientCredentialCreationOptions {
                    mediation: med.flatten().unwrap_or_default(),
                    public_key: key.flatten().unwrap_or_default(),
                })
            }
        }
        /// Fields for `ClientCredentialCreationOptions`.
        const FIELDS: &[&str; 2] = &[MEDIATION, PUBLIC_KEY_NO_HYPEN];
        deserializer.deserialize_struct(
            "ClientCredentialCreationOptions",
            FIELDS,
            ClientCredentialCreationOptionsVisitor(PhantomData),
        )
    }
}
#[cfg(test)]
mod test {
    use super::{
        AuthenticatorAttachmentReq, AuthenticatorSelectionCriteria,
        ClientCredentialCreationOptions, CoseAlgorithmIdentifier, CoseAlgorithmIdentifiers,
        CredProtect, CredentialMediationRequirement, CrossPlatformHint, DEFAULT_RP_ID,
        ExtensionInfo, ExtensionOwned, ExtensionReq, FIVE_MINUTES, FourToSixtyThree, Hint,
        NonZeroU32, PlatformHint, PublicKeyCredentialCreationOptionsOwned,
        PublicKeyCredentialUserEntityOwned, ResidentKeyRequirement, UserVerificationRequirement,
    };
    use serde_json::Error;
    #[test]
    fn client_options() -> Result<(), Error> {
        let mut err =
            serde_json::from_str::<ClientCredentialCreationOptions<'_, '_, 16>>(r#"{"bob":true}"#)
                .unwrap_err();
        assert_eq!(
            err.to_string()[..56],
            *"unknown field `bob`, expected `mediation` or `publicKey`"
        );
        err = serde_json::from_str::<ClientCredentialCreationOptions<'_, '_, 1>>(
            r#"{"mediation":"required","mediation":"required"}"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string()[..27], *"duplicate field `mediation`");
        let mut options =
            serde_json::from_str::<ClientCredentialCreationOptions<'_, '_, 1>>(r#"{}"#)?;
        assert!(matches!(
            options.mediation,
            CredentialMediationRequirement::Required
        ));
        assert_eq!(options.public_key.rp_id, DEFAULT_RP_ID);
        assert_eq!(options.public_key.user.name.as_ref(), "blank");
        assert!(options.public_key.user.display_name.is_none());
        assert_eq!(
            options.public_key.pub_key_cred_params.0,
            CoseAlgorithmIdentifiers::ALL.0
        );
        assert_eq!(options.public_key.timeout, FIVE_MINUTES);
        assert!(
            matches!(options.public_key.authenticator_selection.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
        );
        assert!(matches!(
            options.public_key.authenticator_selection.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        assert!(matches!(
            options.public_key.authenticator_selection.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(options.public_key.extensions.cred_props.is_none());
        assert!(matches!(
            options.public_key.extensions.cred_protect,
            CredProtect::None
        ));
        assert!(options.public_key.extensions.min_pin_length.is_none());
        assert!(options.public_key.extensions.prf.is_none());
        options = serde_json::from_str::<ClientCredentialCreationOptions<'_, '_, 1>>(
            r#"{"mediation":null,"publicKey":null}"#,
        )?;
        assert!(matches!(
            options.mediation,
            CredentialMediationRequirement::Required
        ));
        assert_eq!(options.public_key.rp_id, DEFAULT_RP_ID);
        assert_eq!(options.public_key.user.name.as_ref(), "blank");
        assert!(options.public_key.user.display_name.is_none());
        assert_eq!(
            options.public_key.pub_key_cred_params.0,
            CoseAlgorithmIdentifiers::ALL.0
        );
        assert_eq!(options.public_key.timeout, FIVE_MINUTES);
        assert!(
            matches!(options.public_key.authenticator_selection.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
        );
        assert!(matches!(
            options.public_key.authenticator_selection.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        assert!(matches!(
            options.public_key.authenticator_selection.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(options.public_key.extensions.cred_props.is_none());
        assert!(matches!(
            options.public_key.extensions.cred_protect,
            CredProtect::None
        ));
        assert!(options.public_key.extensions.min_pin_length.is_none());
        assert!(options.public_key.extensions.prf.is_none());
        options = serde_json::from_str::<ClientCredentialCreationOptions<'_, '_, 1>>(
            r#"{"publicKey":{}}"#,
        )?;
        assert_eq!(options.public_key.rp_id, DEFAULT_RP_ID);
        assert_eq!(options.public_key.user.name.as_ref(), "blank");
        assert!(options.public_key.user.display_name.is_none());
        assert_eq!(
            options.public_key.pub_key_cred_params.0,
            CoseAlgorithmIdentifiers::ALL.0
        );
        assert_eq!(options.public_key.timeout, FIVE_MINUTES);
        assert!(
            matches!(options.public_key.authenticator_selection.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
        );
        assert!(matches!(
            options.public_key.authenticator_selection.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        assert!(matches!(
            options.public_key.authenticator_selection.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(options.public_key.extensions.cred_props.is_none());
        assert!(matches!(
            options.public_key.extensions.cred_protect,
            CredProtect::None
        ));
        assert!(options.public_key.extensions.min_pin_length.is_none());
        assert!(options.public_key.extensions.prf.is_none());
        options = serde_json::from_str::<ClientCredentialCreationOptions<'_, '_, 1>>(
            r#"{"mediation":"conditional","publicKey":{"rp":{"name":"Example.com","id":"example.com"},"user":{"name":"bob","displayName":"Bob","id":"AA"},"timeout":300000,"excludeCredentials":[],"attestation":"none","attestationFormats":["none"],"authenticatorSelection":{"authenticatorAttachment":"cross-platform","residentKey":"required","requireResidentKey":true,"userVerification":"required"},"extensions":{"credProps":true,"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"minPinLength":true,"prf":{"eval":{"first":"","second":""}}},"pubKeyCredParams":[{"type":"public-key","alg":-8}],"hints":["security-key"],"challenge":null}}"#,
        )?;
        assert!(matches!(
            options.mediation,
            CredentialMediationRequirement::Conditional
        ));
        assert_eq!(options.public_key.rp_id.as_ref(), "example.com");
        assert_eq!(options.public_key.user.name.as_ref(), "bob");
        assert!(
            options
                .public_key
                .user
                .display_name
                .map_or(false, |name| name.as_ref() == "Bob")
        );
        assert_eq!(
            options.public_key.pub_key_cred_params.0,
            CoseAlgorithmIdentifiers::ALL
                .remove(CoseAlgorithmIdentifier::Es256)
                .remove(CoseAlgorithmIdentifier::Es384)
                .remove(CoseAlgorithmIdentifier::Rs256)
                .0
        );
        assert_eq!(options.public_key.timeout, FIVE_MINUTES);
        assert!(
            matches!(options.public_key.authenticator_selection.authenticator_attachment, AuthenticatorAttachmentReq::CrossPlatform(hint) if matches!(hint, CrossPlatformHint::SecurityKey))
        );
        assert!(matches!(
            options.public_key.authenticator_selection.resident_key,
            ResidentKeyRequirement::Required
        ));
        assert!(matches!(
            options.public_key.authenticator_selection.user_verification,
            UserVerificationRequirement::Required
        ));
        assert!(
            options
                .public_key
                .extensions
                .cred_props
                .map_or(false, |req| matches!(req, ExtensionReq::Allow))
        );
        assert!(
            matches!(options.public_key.extensions.cred_protect, CredProtect::UserVerificationRequired(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
        );
        assert!(
            options
                .public_key
                .extensions
                .min_pin_length
                .map_or(false, |min| min.0 == FourToSixtyThree::Four
                    && matches!(min.1, ExtensionInfo::AllowEnforceValue))
        );
        assert!(
            options
                .public_key
                .extensions
                .prf
                .map_or(false, |prf| prf.first.is_empty()
                    && prf.second.is_some_and(|p| p.is_empty())
                    && matches!(prf.ext_req, ExtensionReq::Allow))
        );
        Ok(())
    }
    #[test]
    fn key_options() -> Result<(), Error> {
        let mut err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 16>>(
            r#"{"bob":true}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..201],
            *"unknown field `bob`, expected one of `rp`, `user`, `challenge`, `pubKeyCredParams`, `timeout`, `excludeCredentials`, `authenticatorSelection`, `hints`, `extensions`, `attestation`, `attestationFormats`"
        );
        err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"attestation":"none","attestation":"none"}"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string()[..29], *"duplicate field `attestation`");
        err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"authenticatorSelection":{"authenticatorAttachment":"platform"},"hints":["client-device", "security-key"]}"#,
        ).unwrap_err();
        assert_eq!(
            err.to_string()[..96],
            *"'platform' authenticator attachment modality must coincide with no hints or 'client-device' hint"
        );
        err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..41],
            *"invalid type: Option value, expected null"
        );
        err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"excludeCredentials":[{"type":"public-key","transports":["usb"],"id":"AAAAAAAAAAAAAAAAAAAAAA"}]}"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string()[..19], *"trailing characters");
        err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"attestation":"foo"}"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string()[..27], *"invalid value: string \"foo\"");
        err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"attestationFormats":["none","none"]}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..96],
            *"attestationFormats must be an empty sequence or contain exactly one string whose value is 'none'"
        );
        err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"attestationFormats":["foo"]}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..42],
            *"invalid value: string \"foo\", expected none"
        );
        err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"timeout":0}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..50],
            *"invalid value: integer `0`, expected a nonzero u32"
        );
        err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"timeout":4294967296}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..59],
            *"invalid value: integer `4294967296`, expected a nonzero u32"
        );
        let mut key =
            serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(r#"{}"#)?;
        assert_eq!(key.rp_id, DEFAULT_RP_ID);
        assert_eq!(key.user.name.as_ref(), "blank");
        assert!(key.user.display_name.is_none());
        assert_eq!(key.pub_key_cred_params.0, CoseAlgorithmIdentifiers::ALL.0);
        assert_eq!(key.timeout, FIVE_MINUTES);
        assert!(
            matches!(key.authenticator_selection.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
        );
        assert!(matches!(
            key.authenticator_selection.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        assert!(matches!(
            key.authenticator_selection.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(key.extensions.cred_props.is_none());
        assert!(matches!(key.extensions.cred_protect, CredProtect::None));
        assert!(key.extensions.min_pin_length.is_none());
        assert!(key.extensions.prf.is_none());
        key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"rp":null,"user":null,"timeout":null,"excludeCredentials":null,"attestation":null,"attestationFormats":null,"authenticatorSelection":null,"extensions":null,"pubKeyCredParams":null,"hints":null,"challenge":null}"#,
        )?;
        assert_eq!(key.rp_id, DEFAULT_RP_ID);
        assert_eq!(key.user.name.as_ref(), "blank");
        assert!(key.user.display_name.is_none());
        assert_eq!(key.pub_key_cred_params.0, CoseAlgorithmIdentifiers::ALL.0);
        assert_eq!(key.timeout, FIVE_MINUTES);
        assert!(
            matches!(key.authenticator_selection.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
        );
        assert!(matches!(
            key.authenticator_selection.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        assert!(matches!(
            key.authenticator_selection.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(key.extensions.cred_props.is_none());
        assert!(matches!(key.extensions.cred_protect, CredProtect::None));
        assert!(key.extensions.min_pin_length.is_none());
        assert!(key.extensions.prf.is_none());
        key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"rp":{},"user":{},"excludeCredentials":[],"attestationFormats":[],"authenticatorSelection":{},"extensions":{},"pubKeyCredParams":[],"hints":[]}"#,
        )?;
        assert_eq!(key.rp_id, DEFAULT_RP_ID);
        assert_eq!(key.user.name.as_ref(), "blank");
        assert!(key.user.display_name.is_none());
        assert_eq!(key.pub_key_cred_params.0, CoseAlgorithmIdentifiers::ALL.0);
        assert!(
            matches!(key.authenticator_selection.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
        );
        assert!(matches!(
            key.authenticator_selection.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        assert!(matches!(
            key.authenticator_selection.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(key.extensions.cred_props.is_none());
        assert!(matches!(key.extensions.cred_protect, CredProtect::None));
        assert!(key.extensions.min_pin_length.is_none());
        assert!(key.extensions.prf.is_none());
        key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"rp":{"name":null,"id":null},"user":{"name":null,"id":null,"displayName":null},"authenticatorSelection":{"residentKey":null,"requireResidentKey":null,"userVerification":null,"authenticatorAttachment":null},"extensions":{"credProps":null,"credentialProtectionPolicy":null,"enforceCredentialProtectionPolicy":null,"minPinLength":null,"prf":null}}"#,
        )?;
        assert_eq!(key.rp_id, DEFAULT_RP_ID);
        assert_eq!(key.user.name.as_ref(), "blank");
        assert!(key.user.display_name.is_none());
        assert_eq!(key.pub_key_cred_params.0, CoseAlgorithmIdentifiers::ALL.0);
        assert!(
            matches!(key.authenticator_selection.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
        );
        assert!(matches!(
            key.authenticator_selection.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        assert!(matches!(
            key.authenticator_selection.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(key.extensions.cred_props.is_none());
        assert!(matches!(key.extensions.cred_protect, CredProtect::None));
        assert!(key.extensions.min_pin_length.is_none());
        assert!(key.extensions.prf.is_none());
        key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"rp":{"name":"Example.com","id":"example.com"},"user":{"name":"bob","displayName":"Bob","id":"AA"},"timeout":300000,"excludeCredentials":[],"attestation":"none","attestationFormats":["none"],"authenticatorSelection":{"authenticatorAttachment":"cross-platform","residentKey":"required","requireResidentKey":true,"userVerification":"required"},"extensions":{"credProps":true,"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"minPinLength":true,"prf":{"eval":{"first":"","second":""}}},"pubKeyCredParams":[{"type":"public-key","alg":-8}],"hints":["security-key"],"challenge":null}"#,
        )?;
        assert_eq!(key.rp_id.as_ref(), "example.com");
        assert_eq!(key.user.name.as_ref(), "bob");
        assert!(
            key.user
                .display_name
                .map_or(false, |name| name.as_ref() == "Bob")
        );
        assert_eq!(
            key.pub_key_cred_params.0,
            CoseAlgorithmIdentifiers::ALL
                .remove(CoseAlgorithmIdentifier::Es256)
                .remove(CoseAlgorithmIdentifier::Es384)
                .remove(CoseAlgorithmIdentifier::Rs256)
                .0
        );
        assert_eq!(key.timeout, FIVE_MINUTES);
        assert!(
            matches!(key.authenticator_selection.authenticator_attachment, AuthenticatorAttachmentReq::CrossPlatform(hint) if matches!(hint, CrossPlatformHint::SecurityKey))
        );
        assert!(matches!(
            key.authenticator_selection.resident_key,
            ResidentKeyRequirement::Required
        ));
        assert!(matches!(
            key.authenticator_selection.user_verification,
            UserVerificationRequirement::Required
        ));
        assert!(
            key.extensions
                .cred_props
                .map_or(false, |req| matches!(req, ExtensionReq::Allow))
        );
        assert!(
            matches!(key.extensions.cred_protect, CredProtect::UserVerificationRequired(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
        );
        assert!(
            key.extensions
                .min_pin_length
                .map_or(false, |min| min.0 == FourToSixtyThree::Four
                    && matches!(min.1, ExtensionInfo::AllowEnforceValue))
        );
        assert!(key.extensions.prf.map_or(false, |prf| prf.first.is_empty()
            && prf.second.is_some_and(|p| p.is_empty())
            && matches!(prf.ext_req, ExtensionReq::Allow)));
        key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<'_, '_, 1>>(
            r#"{"timeout":4294967295}"#,
        )?;
        assert_eq!(key.timeout, NonZeroU32::MAX);
        Ok(())
    }
    #[test]
    fn extension() -> Result<(), Error> {
        let mut err = serde_json::from_str::<ExtensionOwned>(r#"{"bob":true}"#).unwrap_err();
        assert_eq!(
            err.to_string()[..138],
            *"unknown field `bob`, expected one of `credProps`, `credentialProtectionPolicy`, `enforceCredentialProtectionPolicy`, `minPinLength`, `prf`"
        );
        err = serde_json::from_str::<ExtensionOwned>(r#"{"credProps":true,"credProps":true}"#)
            .unwrap_err();
        assert_eq!(err.to_string()[..27], *"duplicate field `credProps`");
        err =
            serde_json::from_str::<ExtensionOwned>(r#"{"enforceCredentialProtectionPolicy":null}"#)
                .unwrap_err();
        assert_eq!(
            err.to_string()[..84],
            *"'enforceCredentialProtectionPolicy' must not exist when 'credentialProtectionPolicy'"
        );
        err = serde_json::from_str::<ExtensionOwned>(
            r#"{"enforceCredentialProtectionPolicy":false,"credentialProtectionPolicy":null}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..103],
            *"'enforceCredentialProtectionPolicy' must be null or not exist when 'credentialProtectionPolicy' is null"
        );
        let mut ext = serde_json::from_str::<ExtensionOwned>(
            r#"{"credProps":true,"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"minPinLength":true,"prf":{"eval":{"first":"","second":""}}}"#,
        )?;
        assert!(
            ext.cred_props
                .map_or(false, |props| matches!(props, ExtensionReq::Allow))
        );
        assert!(
            matches!(ext.cred_protect, CredProtect::UserVerificationRequired(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
        );
        assert!(
            ext.min_pin_length
                .map_or(false, |min| min.0 == FourToSixtyThree::Four
                    && matches!(min.1, ExtensionInfo::AllowEnforceValue))
        );
        assert!(ext.prf.map_or(false, |prf| prf.first.is_empty()
            && prf.second.is_some_and(|v| v.is_empty())
            && matches!(prf.ext_req, ExtensionReq::Allow)));
        ext = serde_json::from_str::<ExtensionOwned>(
            r#"{"credProps":null,"credentialProtectionPolicy":null,"enforceCredentialProtectionPolicy":null,"minPinLength":null,"prf":null}"#,
        )?;
        assert!(ext.cred_props.is_none());
        assert!(matches!(ext.cred_protect, CredProtect::None));
        assert!(ext.min_pin_length.is_none());
        assert!(ext.prf.is_none());
        ext = serde_json::from_str::<ExtensionOwned>(r#"{}"#)?;
        assert!(ext.cred_props.is_none());
        assert!(matches!(ext.cred_protect, CredProtect::None));
        assert!(ext.min_pin_length.is_none());
        assert!(ext.prf.is_none());
        ext = serde_json::from_str::<ExtensionOwned>(r#"{"credentialProtectionPolicy":null}"#)?;
        assert!(matches!(ext.cred_protect, CredProtect::None));
        ext = serde_json::from_str::<ExtensionOwned>(
            r#"{"credentialProtectionPolicy":"userVerificationOptional"}"#,
        )?;
        assert!(
            matches!(ext.cred_protect, CredProtect::UserVerificationOptional(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
        );
        ext = serde_json::from_str::<ExtensionOwned>(
            r#"{"credentialProtectionPolicy":"userVerificationOptionalWithCredentialIDList","enforceCredentialProtectionPolicy":null}"#,
        )?;
        assert!(
            matches!(ext.cred_protect, CredProtect::UserVerificationOptionalWithCredentialIdList(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
        );
        Ok(())
    }
    #[test]
    fn user_entity() -> Result<(), Error> {
        let mut err = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<'_, '_, 16>>(
            r#"{"bob":true}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..64],
            *"unknown field `bob`, expected one of `id`, `name`, `displayName`"
        );
        err = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<'_, '_, 1>>(
            r#"{"name":"bob","name":"bob"}"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string()[..22], *"duplicate field `name`");
        let mut user = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<'_, '_, 1>>(
            r#"{"id":"AA","name":"bob","displayName":"Bob"}"#,
        )?;
        assert_eq!(user.id.as_slice(), [0; 1].as_slice());
        assert_eq!(user.name.as_ref(), "bob");
        assert_eq!(user.display_name.as_ref().map(|v| v.as_ref()), Some("Bob"));
        user = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<'_, '_, 1>>(
            r#"{"id":null,"name":null,"displayName":null}"#,
        )?;
        assert_eq!(user.name.as_ref(), "blank");
        assert!(user.display_name.is_none());
        user = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<'_, '_, 1>>(r#"{}"#)?;
        assert_eq!(user.name.as_ref(), "blank");
        assert!(user.display_name.is_none());
        Ok(())
    }
    #[test]
    fn auth_crit() -> Result<(), Error> {
        let mut err =
            serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"null"#).unwrap_err();
        assert_eq!(
            err.to_string()[..59],
            *"invalid type: null, expected AuthenticatorSelectionCriteria"
        );
        err = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"residentKey":"required","requireResidentKey":false}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..62],
            *"'residentKey' is 'required', but 'requireResidentKey' is false"
        );
        err = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"residentKey":"preferred","requireResidentKey":true}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..65],
            *"'residentKey' is not 'required', but 'requireResidentKey' is true"
        );
        err =
            serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"residentKey":"prefered"}"#)
                .unwrap_err();
        assert_eq!(
            err.to_string()[..84],
            *"invalid value: string \"prefered\", expected 'required', 'discouraged', or 'preferred'"
        );
        err =
            serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"bob":true}"#).unwrap_err();
        assert_eq!(
            err.to_string()[..119],
            *"unknown field `bob`, expected one of `authenticatorAttachment`, `residentKey`, `requireResidentKey`, `userVerification`"
        );
        err = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"requireResidentKey":true,"requireResidentKey":true}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..36],
            *"duplicate field `requireResidentKey`"
        );
        let mut crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"authenticatorAttachment":"platform","residentKey":"required","requireResidentKey":true,"userVerification":"required"}"#,
        )?;
        assert!(
            matches!(crit.authenticator_attachment, AuthenticatorAttachmentReq::Platform(hint) if matches!(hint, PlatformHint::None))
        );
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Required
        ));
        assert!(matches!(
            crit.user_verification,
            UserVerificationRequirement::Required
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"authenticatorAttachment":null,"residentKey":null,"requireResidentKey":null,"userVerification":null}"#,
        )?;
        assert!(
            matches!(crit.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
        );
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        assert!(matches!(
            crit.user_verification,
            UserVerificationRequirement::Preferred
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{}"#)?;
        assert!(
            matches!(crit.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
        );
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        assert!(matches!(
            crit.user_verification,
            UserVerificationRequirement::Preferred
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"residentKey":"preferred","requireResidentKey":false}"#,
        )?;
        assert!(
            matches!(crit.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
        );
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Preferred
        ));
        assert!(matches!(
            crit.user_verification,
            UserVerificationRequirement::Preferred
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"residentKey":"preferred"}"#,
        )?;
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Preferred
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"requireResidentKey":true}"#,
        )?;
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Required
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"requireResidentKey":false}"#,
        )?;
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"residentKey":"required"}"#,
        )?;
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Required
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"residentKey":"discouraged"}"#,
        )?;
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"residentKey":"discouraged","requireResidentKey":null}"#,
        )?;
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"residentKey":"required","requireResidentKey":null}"#,
        )?;
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Required
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"residentKey":null,"requireResidentKey":true}"#,
        )?;
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Required
        ));
        crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
            r#"{"residentKey":null,"requireResidentKey":false}"#,
        )?;
        assert!(matches!(
            crit.resident_key,
            ResidentKeyRequirement::Discouraged
        ));
        Ok(())
    }
    #[test]
    fn cose_algs() -> Result<(), Error> {
        let mut err = serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"null"#).unwrap_err();
        assert_eq!(
            err.to_string()[..53],
            *"invalid type: null, expected CoseAlgorithmIdentifiers"
        );
        err = serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"[null]"#).unwrap_err();
        assert_eq!(
            err.to_string()[..37],
            *"invalid type: null, expected PubParam"
        );
        err = serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"[{}]"#).unwrap_err();
        assert_eq!(err.to_string()[..19], *"missing field `alg`");
        err = serde_json::from_str::<CoseAlgorithmIdentifiers>(
            r#"[{"type":"public-key","alg":-7,"foo":true}]"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..45],
            *"unknown field `foo`, expected `type` or `alg`"
        );
        err = serde_json::from_str::<CoseAlgorithmIdentifiers>(
            r#"[{"type":"public-key","alg":-7,"alg":-7}]"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string()[..21], *"duplicate field `alg`");
        err = serde_json::from_str::<CoseAlgorithmIdentifiers>(
            r#"[{"type":"public-key","alg":null}]"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..52],
            *"invalid type: null, expected CoseAlgorithmIdentifier"
        );
        err = serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"[{"type":null,"alg":-8}]"#)
            .unwrap_err();
        assert_eq!(
            err.to_string()[..39],
            *"invalid type: null, expected public-key"
        );
        err =
            serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"[{"type":"public-key","alg":-6}]"#)
                .unwrap_err();
        assert_eq!(
            err.to_string()[..58],
            *"invalid value: integer `-6`, expected -8, -7, -35, or -257"
        );
        err = serde_json::from_str::<CoseAlgorithmIdentifiers>(
            r#"[{"type":"public-key","alg":-7},{"type":"public-key","alg":-7}]"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..49],
            *"pubKeyCredParams contained duplicate Es256 values"
        );
        err = serde_json::from_str::<CoseAlgorithmIdentifiers>(
            r#"[{"type":"public-key","alg":-7},{"type":"public-key","alg":-8}]"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..63],
            *"pubKeyCredParams contained EdDSA, but it wasn't the first value"
        );
        let mut alg = serde_json::from_str::<CoseAlgorithmIdentifiers>(
            r#"[{"type":"public-key","alg":-8},{"alg":-7}]"#,
        )?;
        assert!(alg.contains(CoseAlgorithmIdentifier::Eddsa));
        assert!(alg.contains(CoseAlgorithmIdentifier::Es256));
        assert!(!alg.contains(CoseAlgorithmIdentifier::Es384));
        assert!(!alg.contains(CoseAlgorithmIdentifier::Rs256));
        alg = serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"[]"#)?;
        assert!(alg.contains(CoseAlgorithmIdentifier::Eddsa));
        assert!(alg.contains(CoseAlgorithmIdentifier::Es256));
        assert!(alg.contains(CoseAlgorithmIdentifier::Es384));
        assert!(alg.contains(CoseAlgorithmIdentifier::Rs256));
        Ok(())
    }
}
