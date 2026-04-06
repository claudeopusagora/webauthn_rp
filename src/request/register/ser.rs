#[cfg(test)]
mod tests;
use super::{
    super::{
        super::response::ser::{Null, Type},
        auth::PrfInputOwned,
        ser::PrfHelper,
    },
    AuthenticatorAttachment, AuthenticatorSelectionCriteria, Challenge, CoseAlgorithmIdentifier,
    CoseAlgorithmIdentifiers, CredProtect, CredentialCreationOptions,
    CredentialMediationRequirement, Extension, ExtensionInfo, ExtensionReq, FIVE_MINUTES,
    FourToSixtyThree, Hints, PrfInput, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity, RegistrationClientState,
    ResidentKeyRequirement, RpId, UserHandle, UserVerificationRequirement,
};
#[cfg(doc)]
use core::str::FromStr;
use core::{
    convert,
    error::Error as E,
    fmt::{self, Display, Formatter},
    num::NonZeroU32,
    str,
};
use serde::{
    de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Unexpected, Visitor},
    ser::{Serialize, SerializeSeq as _, SerializeStruct as _, Serializer},
};
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
/// [ML-DSA-44](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
const MLDSA44: i16 = -48i16;
/// [ML-DSA-65](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
const MLDSA65: i16 = -49i16;
/// [ML-DSA-87](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
const MLDSA87: i16 = -50i16;
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
                            Self::Mldsa87 => MLDSA87,
                            Self::Mldsa65 => MLDSA65,
                            Self::Mldsa44 => MLDSA44,
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
    ///     r#"[{"type":"public-key","alg":-50},{"type":"public-key","alg":-49},{"type":"public-key","alg":-48},{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-257}]"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&CoseAlgorithmIdentifiers::default().remove(CoseAlgorithmIdentifier::Es384))?,
    ///     r#"[{"type":"public-key","alg":-50},{"type":"public-key","alg":-49},{"type":"public-key","alg":-48},{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}]"#
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
        // At most we add `1` seven times which clearly cannot overflow or `usize`.
        serializer
            .serialize_seq(Some(
                usize::from(self.contains(CoseAlgorithmIdentifier::Mldsa87))
                    + usize::from(self.contains(CoseAlgorithmIdentifier::Mldsa65))
                    + usize::from(self.contains(CoseAlgorithmIdentifier::Mldsa44))
                    + usize::from(self.contains(CoseAlgorithmIdentifier::Eddsa))
                    + usize::from(self.contains(CoseAlgorithmIdentifier::Es256))
                    + usize::from(self.contains(CoseAlgorithmIdentifier::Es384))
                    + usize::from(self.contains(CoseAlgorithmIdentifier::Es384)),
            ))
            .and_then(|mut ser| {
                if self.contains(CoseAlgorithmIdentifier::Mldsa87) {
                    ser.serialize_element(&CoseAlgorithmIdentifier::Mldsa87)
                } else {
                    Ok(())
                }
                .and_then(|()| {
                    if self.contains(CoseAlgorithmIdentifier::Mldsa65) {
                        ser.serialize_element(&CoseAlgorithmIdentifier::Mldsa65)
                    } else {
                        Ok(())
                    }
                    .and_then(|()| {
                        if self.contains(CoseAlgorithmIdentifier::Mldsa44) {
                            ser.serialize_element(&CoseAlgorithmIdentifier::Mldsa44)
                        } else {
                            Ok(())
                        }
                        .and_then(|()| {
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
    ///         name: "georg.cantor",
    ///         id: &id,
    ///         display_name: "Гео́рг Ка́нтор",
    ///     }).unwrap(),
    ///     r#"{"name":"georg.cantor","id":"AA","displayName":"Гео́рг Ка́нтор"}"#
    /// );
    /// // The display name gets serialized as an empty string
    /// // iff `Self::display_name` is `None`.
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(
    ///     serde_json::to_string(&PublicKeyCredentialUserEntity {
    ///         name: "georg.cantor",
    ///         id: &id,
    ///         display_name: "",
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
                        ser.serialize_field(DISPLAY_NAME, &self.display_name)
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
    /// # use webauthn_rp::{request::register::AuthenticatorSelectionCriteria, response::AuthenticatorAttachment};
    /// assert_eq!(
    ///     serde_json::to_string(&AuthenticatorSelectionCriteria::passkey())?,
    ///     r#"{"residentKey":"required","requireResidentKey":true,"userVerification":"required"}"#
    /// );
    /// assert_eq!(
    ///     serde_json::to_string(&AuthenticatorSelectionCriteria::second_factor())?,
    ///     r#"{"residentKey":"discouraged","requireResidentKey":false,"userVerification":"discouraged"}"#
    /// );
    /// let mut crit = AuthenticatorSelectionCriteria::passkey();
    /// crit.authenticator_attachment = AuthenticatorAttachment::CrossPlatform;
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
        let count = if matches!(self.authenticator_attachment, AuthenticatorAttachment::None) {
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
                            AuthenticatorAttachment::Platform
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
                                        ser.serialize_field(TIMEOUT, &self.timeout).and_then(|()| {
                                            ser.serialize_field(
                                                EXCLUDE_CREDENTIALS,
                                                self.exclude_credentials.as_slice(),
                                            )
                                            .and_then(
                                                |()| {
                                                    ser.serialize_field(
                                                        AUTHENTICATOR_SELECTION,
                                                        &self.authenticator_selection,
                                                    )
                                                    .and_then(|()| {
                                                        ser.serialize_field(HINTS, &self.hints)
                                                            .and_then(|()| {
                                                                ser.serialize_field(
                                                                    ATTESTATION,
                                                                    NONE,
                                                                )
                                                                .and_then(|()| {
                                                                    ser.serialize_field(
                                                                        ATTESTATION_FORMATS,
                                                                        [NONE].as_slice(),
                                                                    )
                                                                    .and_then(|()| {
                                                                        ser.serialize_field(
                                                                            EXTENSIONS,
                                                                            &self.extensions,
                                                                        )
                                                                        .and_then(|()| ser.end())
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
    /// #             FourToSixtyThree, UserHandle64, CredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle
    /// #         },
    /// #         AsciiDomain, ExtensionInfo, Hints, PublicKeyCredentialHint, RpId, PublicKeyCredentialDescriptor, Credentials, UserVerificationRequirement,
    /// #     },
    /// #     response::{AuthTransports, AuthenticatorAttachment, CredentialId},
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
    /// let id = CredentialId::try_from(vec![0; 16].into_boxed_slice())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports = get_transports((&id).into())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// creds.push(PublicKeyCredentialDescriptor { id, transports });
    /// let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
    /// let user_handle = UserHandle64::new();
    /// let mut options = CredentialCreationOptions::passkey(&rp_id, PublicKeyCredentialUserEntity { name: "pierre.de.fermat", id: &user_handle, display_name: "Pierre de Fermat", }, creds);
    /// options.public_key.authenticator_selection.authenticator_attachment = AuthenticatorAttachment::None;
    /// options.public_key.hints = Hints::EMPTY.add(PublicKeyCredentialHint::SecurityKey);
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
    ///                 "alg":-50
    ///             },
    ///             {
    ///                 "type":"public-key",
    ///                 "alg":-49
    ///             },
    ///             {
    ///                 "type":"public-key",
    ///                 "alg":-48
    ///             },
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
                    RS256 => Ok(CoseAlgorithmIdentifier::Rs256),
                    MLDSA87 => Ok(CoseAlgorithmIdentifier::Mldsa87),
                    MLDSA65 => Ok(CoseAlgorithmIdentifier::Mldsa65),
                    MLDSA44 => Ok(CoseAlgorithmIdentifier::Mldsa44),
                    ES384 => Ok(CoseAlgorithmIdentifier::Es384),
                    EDDSA => Ok(CoseAlgorithmIdentifier::Eddsa),
                    ES256 => Ok(CoseAlgorithmIdentifier::Es256),
                    _ => Err(E::invalid_value(
                        Unexpected::Signed(i64::from(v)),
                        &format!(
                            "{MLDSA87}, {MLDSA65}, {MLDSA44}, {EDDSA}, {ES256}, {ES384}, or {RS256}"
                        )
                        .as_str(),
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
struct PublicKeyCredentialRpEntityHelper(Option<RpId>);
impl<'de> Deserialize<'de> for PublicKeyCredentialRpEntityHelper {
    /// Conforms to the following schema:
    ///
    /// ```json
    /// {
    ///   "id": null | <RpId>,
    ///   "name": null | <RpId> | <Nickname>
    /// }
    /// ```
    ///
    /// None of the fields are required, and missing fields are interpreted the same as fields
    /// with `null` values.
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
                            fn visit_str<E>(self, _: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                Ok(Name)
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
                Ok(PublicKeyCredentialRpEntityHelper(id.flatten()))
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
/// Similar to [`PublicKeyCredentialUserEntity`] except the [`UserHandle`] is owned, and all fields are
/// optional.
///
/// This is primarily useful to assist [`ClientCredentialCreationOptions::deserialize`].
#[derive(Debug, Default)]
pub struct PublicKeyCredentialUserEntityOwned<const LEN: usize> {
    /// See [`PublicKeyCredentialUserEntity::name`].
    pub name: Option<String>,
    /// See [`PublicKeyCredentialUserEntity::id`].
    pub id: Option<UserHandle<LEN>>,
    /// See [`PublicKeyCredentialUserEntity::display_name`].
    pub display_name: Option<String>,
}
/// Error returned when converting a [`PublicKeyCredentialUserEntityOwned`] into a
/// [`PublicKeyCredentialUserEntity`] (e.g., via [`PublicKeyCredentialUserEntityOwned::with_id`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicKeyCredentialUserEntityOwnedErr {
    /// Variant returned when [`PublicKeyCredentialUserEntityOwned::name`] is `None`.
    MissingName,
    /// Variant returned when [`PublicKeyCredentialUserEntityOwned::id`] is `None`.
    MissingId,
    /// Variant returned when [`PublicKeyCredentialUserEntityOwned::display_name`] is `None`.
    MissingDisplayName,
}
impl Display for PublicKeyCredentialUserEntityOwnedErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::MissingName => "user entity info did not have a username",
            Self::MissingId => "user entity info did not have a user handle",
            Self::MissingDisplayName => "user entity info did not have a user display name",
        })
    }
}
impl E for PublicKeyCredentialUserEntityOwnedErr {}
impl<const LEN: usize> PublicKeyCredentialUserEntityOwned<LEN> {
    /// Returns a `PublicKeyCredentialUserEntity` based on `self`.
    ///
    /// # Errors
    ///
    /// Errors iff any of the fields in `self` are `None`.
    #[inline]
    pub fn as_entity(
        &self,
    ) -> Result<PublicKeyCredentialUserEntity<'_, '_, '_, LEN>, PublicKeyCredentialUserEntityOwnedErr>
    {
        self.name
            .as_ref()
            .ok_or(PublicKeyCredentialUserEntityOwnedErr::MissingName)
            .and_then(|username| {
                self.id
                    .as_ref()
                    .ok_or(PublicKeyCredentialUserEntityOwnedErr::MissingId)
                    .and_then(|id| {
                        self.display_name
                            .as_ref()
                            .ok_or(PublicKeyCredentialUserEntityOwnedErr::MissingDisplayName)
                            .map(|display| PublicKeyCredentialUserEntity {
                                name: username,
                                id,
                                display_name: display,
                            })
                    })
            })
    }
    /// Returns a `PublicKeyCredentialUserEntity` based on `self` and `id`.
    ///
    /// Note `id` is used _unconditionally_ regardless if [`Self::id`] is `Some`.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::name`] or [`Self::display_name`] are `None`.
    #[inline]
    pub fn with_id<'id>(
        &self,
        id: &'id UserHandle<LEN>,
    ) -> Result<
        PublicKeyCredentialUserEntity<'_, '_, 'id, LEN>,
        PublicKeyCredentialUserEntityOwnedErr,
    > {
        self.name
            .as_ref()
            .ok_or(PublicKeyCredentialUserEntityOwnedErr::MissingName)
            .and_then(|username| {
                self.display_name
                    .as_ref()
                    .ok_or(PublicKeyCredentialUserEntityOwnedErr::MissingDisplayName)
                    .map(|display| PublicKeyCredentialUserEntity {
                        name: username,
                        id,
                        display_name: display,
                    })
            })
    }
    /// Returns a `PublicKeyCredentialUserEntity` based on `self`, `name`, and `display_name`.
    ///
    /// Note `name` and `display_name` are used _unconditionally_ regardless if [`Self::name`] or
    /// [`Self::display_name`] are `Some`.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::id`] is `None`.
    #[inline]
    pub fn with_name_and_display_name<'name, 'display_name>(
        &self,
        name: &'name str,
        display_name: &'display_name str,
    ) -> Result<
        PublicKeyCredentialUserEntity<'name, 'display_name, '_, LEN>,
        PublicKeyCredentialUserEntityOwnedErr,
    > {
        self.id
            .as_ref()
            .ok_or(PublicKeyCredentialUserEntityOwnedErr::MissingId)
            .map(|id| PublicKeyCredentialUserEntity {
                name,
                id,
                display_name,
            })
    }
}
impl<'de, const LEN: usize> Deserialize<'de> for PublicKeyCredentialUserEntityOwned<LEN>
where
    UserHandle<LEN>: Deserialize<'de>,
{
    /// Deserializes a `struct` according to
    /// [`PublicKeyCredentialUserEntityJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentityjson).
    ///
    /// Note none of the fields are required and all of them are allowed to be `null`.
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentityjson-id) is deserialized
    /// according to [`UserHandle::deserialize`],
    /// [`name`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentityjson-name) deserializes
    /// [`prim@str`].
    /// [`displayName`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentityjson-displayname)
    /// deserializes [`prim@str`].
    ///
    /// Unknown or duplicate fields lead to an error. Missing fields are interpreted the same as if the field
    /// were assigned `null`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::ser::PublicKeyCredentialUserEntityOwned;
    /// let val = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<16>>(r#"{"name":"paul.erdos","displayName":"Erdős Pál"}"#)?;
    /// assert!(val.name.is_some_and(|name| name == "paul.erdos"));
    /// assert!(val.display_name.is_some_and(|display| display == "Erdős Pál"));
    /// assert!(val.id.is_none());
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `PublicKeyCredentialUserEntityOwned`.
        struct PublicKeyCredentialUserEntityOwnedVisitor<const L: usize>;
        impl<'d, const L: usize> Visitor<'d> for PublicKeyCredentialUserEntityOwnedVisitor<L>
        where
            UserHandle<L>: Deserialize<'d>,
        {
            type Value = PublicKeyCredentialUserEntityOwned<L>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("PublicKeyCredentialUserEntityOwned")
            }
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
                            display = map.next_value::<Option<_>>().map(Some)?;
                        }
                    }
                }
                Ok(PublicKeyCredentialUserEntityOwned {
                    id: user_handle.flatten(),
                    name: username.flatten(),
                    display_name: display.flatten(),
                })
            }
        }
        /// Fields for `PublicKeyCredentialUserEntityOwned`.
        const FIELDS: &[&str; 3] = &[ID, NAME, DISPLAY_NAME];
        deserializer.deserialize_struct(
            "PublicKeyCredentialUserEntityOwned",
            FIELDS,
            PublicKeyCredentialUserEntityOwnedVisitor,
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
    /// error will occur (e.g., if [`CoseAlgorithmIdentifier::Mldsa87`] exists, then it must appear first).
    ///
    /// An empty sequence will be treated as [`Self::ALL`].
    ///
    /// Unknown or duplicate fields lead to an error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::CoseAlgorithmIdentifiers;
    /// assert!(serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"[{"type":"public-key","alg":-50},{"type":"public-key","alg":-49},{"type":"public-key","alg":-48},{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-257}]"#).is_ok());
    /// ```
    #[expect(clippy::too_many_lines, reason = "132 is fine")]
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
            #[expect(clippy::too_many_lines, reason = "118 is fine")]
            #[expect(clippy::else_if_without_else, reason = "prefer it this way")]
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'d>,
            {
                let mut mldsa87 = false;
                let mut mldsa65 = false;
                let mut mldsa44 = false;
                let mut eddsa = false;
                let mut es256 = false;
                let mut es384 = false;
                let mut rs256 = false;
                while let Some(elem) = seq.next_element::<PubParam>()? {
                    match elem.0 {
                        CoseAlgorithmIdentifier::Mldsa87 => {
                            if mldsa87 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained duplicate ML-DSA-87 values",
                                ));
                            } else if mldsa65 || mldsa44 || eddsa || es256 || es384 || rs256 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained ML-DSA-87, but it wasn't the first value",
                                ));
                            }
                            mldsa87 = true;
                        }
                        CoseAlgorithmIdentifier::Mldsa65 => {
                            if mldsa65 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained duplicate ML-DSA-65 values",
                                ));
                            } else if mldsa44 || eddsa || es256 || es384 || rs256 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained ML-DSA-65, but it was preceded by Mldsa44, Eddsa, Es256, Es384, or Rs256",
                                ));
                            }
                            mldsa65 = true;
                        }
                        CoseAlgorithmIdentifier::Mldsa44 => {
                            if mldsa44 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained duplicate ML-DSA-44 values",
                                ));
                            } else if eddsa || es256 || es384 || rs256 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained ML-DSA-44, but it was preceded by Eddsa, Es256, Es384, or Rs256",
                                ));
                            }
                            mldsa44 = true;
                        }
                        CoseAlgorithmIdentifier::Eddsa => {
                            if eddsa {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained duplicate EdDSA values",
                                ));
                            } else if es256 || es384 || rs256 {
                                return Err(Error::custom(
                                    "pubKeyCredParams contained Eddsa, but it was preceded by Es256, Es384, or Rs256",
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
                if mldsa87 {
                    algs = algs.add(CoseAlgorithmIdentifier::Mldsa87);
                }
                if mldsa65 {
                    algs = algs.add(CoseAlgorithmIdentifier::Mldsa65);
                }
                if mldsa44 {
                    algs = algs.add(CoseAlgorithmIdentifier::Mldsa44);
                }
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
impl<'de> Deserialize<'de> for AuthenticatorSelectionCriteria {
    /// Deserializes a `struct` based on
    /// [`AuthenticatorSelectionCriteria`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorselectioncriteria).
    ///
    /// Note that none of the fields are required, and all are allowed to be `null`. Additionally
    /// [`residentKey`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-residentkey) and
    /// [`requireResidentKey`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-requireresidentkey)
    /// must be consistent (i.e., `requireResidentKey` iff `residentKey` is [`ResidentKeyRequirement::Required`]).
    ///
    /// Missing and `null` fields default to the corresponding [`Default`] value. Unknown and duplicate fields
    /// lead to an error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::{request::register::AuthenticatorSelectionCriteria, response::AuthenticatorAttachment};
    /// assert_eq!(
    ///     serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"authenticatorAttachment":null,"residentKey":"required","requireResidentKey":true,"userVerification":"required"}"#)?.authenticator_attachment,
    ///     AuthenticatorAttachment::None,
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
impl<'de> Deserialize<'de> for FourToSixtyThree {
    /// Deserializes a `u8` based on [`Self::from_u8`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::FourToSixtyThree;
    /// # use serde_json::Error;
    /// assert_eq!(serde_json::from_str::<FourToSixtyThree>("4")?, FourToSixtyThree::Four);
    /// assert_eq!(serde_json::from_str::<FourToSixtyThree>("63")?, FourToSixtyThree::SixtyThree);
    /// assert!(serde_json::from_str::<FourToSixtyThree>("0").is_err());
    /// assert!(serde_json::from_str::<FourToSixtyThree>("3").is_err());
    /// assert!(serde_json::from_str::<FourToSixtyThree>("64").is_err());
    /// # Ok::<_, Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        u8::deserialize(deserializer).and_then(|val| {
            Self::from_u8(val).ok_or_else(|| {
                Error::invalid_value(
                    Unexpected::Unsigned(u64::from(val)),
                    &"integer inclusively between 4 and 63",
                )
            })
        })
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
impl ExtensionOwned {
    /// Returns an `Extension` based on `self`.
    ///
    /// Note [`PrfInputOwned::ext_req`] is converted into an [`ExtensionInfo`] such that the value is enforced.
    #[inline]
    #[must_use]
    pub fn as_extension(&self) -> Extension<'_, '_> {
        Extension {
            cred_props: self.cred_props,
            cred_protect: self.cred_protect,
            min_pin_length: self.min_pin_length,
            prf: self.prf.as_ref().map(|prf| {
                (
                    PrfInput {
                        first: &prf.first,
                        second: prf.second.as_deref(),
                    },
                    if matches!(prf.ext_req, ExtensionReq::Require) {
                        ExtensionInfo::RequireEnforceValue
                    } else {
                        ExtensionInfo::AllowEnforceValue
                    },
                )
            }),
        }
    }
    /// Returns an `Extension` based on `self` and `prf`.
    ///
    /// Note `prf` is used _unconditionally_ regardless if [`Self::prf`] is `Some`.
    #[inline]
    #[must_use]
    pub const fn with_prf<'prf_first, 'prf_second>(
        &self,
        prf: (PrfInput<'prf_first, 'prf_second>, ExtensionInfo),
    ) -> Extension<'prf_first, 'prf_second> {
        Extension {
            cred_props: self.cred_props,
            cred_protect: self.cred_protect,
            min_pin_length: self.min_pin_length,
            prf: Some(prf),
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
/// Similar to [`PublicKeyCredentialCreationOptions`] except the fields are based on owned data, and
/// [`Self::rp_id`] is optional.
///
/// This is primarily useful to assist [`ClientCredentialCreationOptions::deserialize`].
#[derive(Debug)]
pub struct PublicKeyCredentialCreationOptionsOwned<const USER_LEN: usize> {
    /// See [`PublicKeyCredentialCreationOptions::rp_id`].
    pub rp_id: Option<RpId>,
    /// See [`PublicKeyCredentialCreationOptions::user`].
    pub user: PublicKeyCredentialUserEntityOwned<USER_LEN>,
    /// See [`PublicKeyCredentialCreationOptions::pub_key_cred_params`].
    pub pub_key_cred_params: CoseAlgorithmIdentifiers,
    /// See [`PublicKeyCredentialCreationOptions::timeout`].
    pub timeout: NonZeroU32,
    /// See [`PublicKeyCredentialCreationOptions::authenticator_selection`].
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    /// See [`PublicKeyCredentialCreationOptions::hints`].
    pub hints: Hints,
    /// See [`PublicKeyCredentialCreationOptions::extensions`].
    pub extensions: ExtensionOwned,
}
/// Error returned when converting a [`PublicKeyCredentialCreationOptionsOwned`] into a
/// [`PublicKeyCredentialCreationOptions`] (e.g., via [`PublicKeyCredentialCreationOptionsOwned::with_rp_id`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicKeyCredentialCreationOptionsOwnedErr {
    /// Variant returned when [`PublicKeyCredentialCreationOptionsOwned::rp_id`] is `None`.
    MissingRpId,
    /// Variant returned when [`PublicKeyCredentialCreationOptionsOwned::user`] cannot be converted into a
    /// a [`PublicKeyCredentialCreationOptions`].
    UserEntity(PublicKeyCredentialUserEntityOwnedErr),
}
impl Display for PublicKeyCredentialCreationOptionsOwnedErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::MissingRpId => f.write_str("creation options did not have an RP ID"),
            Self::UserEntity(err) => err.fmt(f),
        }
    }
}
impl E for PublicKeyCredentialCreationOptionsOwnedErr {}
impl From<PublicKeyCredentialUserEntityOwnedErr> for PublicKeyCredentialCreationOptionsOwnedErr {
    #[inline]
    fn from(value: PublicKeyCredentialUserEntityOwnedErr) -> Self {
        Self::UserEntity(value)
    }
}
impl<const USER_LEN: usize> PublicKeyCredentialCreationOptionsOwned<USER_LEN> {
    /// Returns a `PublicKeyCredentialCreationOptions` based on `self` and `exclude_credentials`.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::rp_id`] is `None` or [`PublicKeyCredentialUserEntityOwned::as_entity`] errors.
    #[inline]
    pub fn as_options(
        &self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
    ) -> Result<
        PublicKeyCredentialCreationOptions<'_, '_, '_, '_, '_, '_, USER_LEN>,
        PublicKeyCredentialCreationOptionsOwnedErr,
    > {
        self.rp_id
            .as_ref()
            .ok_or(PublicKeyCredentialCreationOptionsOwnedErr::MissingRpId)
            .and_then(|rp_id| {
                self.user
                    .as_entity()
                    .map_err(PublicKeyCredentialCreationOptionsOwnedErr::UserEntity)
                    .map(|user| PublicKeyCredentialCreationOptions {
                        rp_id,
                        user,
                        challenge: Challenge::new(),
                        pub_key_cred_params: self.pub_key_cred_params,
                        timeout: self.timeout,
                        exclude_credentials,
                        authenticator_selection: self.authenticator_selection,
                        hints: self.hints,
                        extensions: self.extensions.as_extension(),
                    })
            })
    }
    /// Returns a `PublicKeyCredentialCreationOptions` based on `self`, `exclude_credentials`, and `rp_id`.
    ///
    /// Note `rp_id` is used _unconditionally_ regardless if [`Self::rp_id`] is `Some`.
    ///
    /// # Errors
    ///
    /// Errors iff [`PublicKeyCredentialUserEntityOwned::as_entity`] errors.
    #[inline]
    pub fn with_rp_id<'rp_id>(
        &self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
        rp_id: &'rp_id RpId,
    ) -> Result<
        PublicKeyCredentialCreationOptions<'rp_id, '_, '_, '_, '_, '_, USER_LEN>,
        PublicKeyCredentialCreationOptionsOwnedErr,
    > {
        self.user
            .as_entity()
            .map_err(PublicKeyCredentialCreationOptionsOwnedErr::UserEntity)
            .map(|user| PublicKeyCredentialCreationOptions {
                rp_id,
                user,
                challenge: Challenge::new(),
                pub_key_cred_params: self.pub_key_cred_params,
                timeout: self.timeout,
                exclude_credentials,
                authenticator_selection: self.authenticator_selection,
                hints: self.hints,
                extensions: self.extensions.as_extension(),
            })
    }
    /// Returns a `PublicKeyCredentialCreationOptions` based on `self`, `exclude_credentials`, and `user`.
    ///
    /// Note `user` is used _unconditionally_ regardless of what [`Self::user`] is.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::rp_id`] is `None`.
    #[inline]
    pub fn with_user<'user_name, 'user_display_name, 'user_id>(
        &self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
        user: PublicKeyCredentialUserEntity<'user_name, 'user_display_name, 'user_id, USER_LEN>,
    ) -> Result<
        PublicKeyCredentialCreationOptions<
            '_,
            'user_name,
            'user_display_name,
            'user_id,
            '_,
            '_,
            USER_LEN,
        >,
        PublicKeyCredentialCreationOptionsOwnedErr,
    > {
        self.rp_id
            .as_ref()
            .ok_or(PublicKeyCredentialCreationOptionsOwnedErr::MissingRpId)
            .map(|rp_id| PublicKeyCredentialCreationOptions {
                rp_id,
                user,
                challenge: Challenge::new(),
                pub_key_cred_params: self.pub_key_cred_params,
                timeout: self.timeout,
                exclude_credentials,
                authenticator_selection: self.authenticator_selection,
                hints: self.hints,
                extensions: self.extensions.as_extension(),
            })
    }
    /// Returns a `PublicKeyCredentialCreationOptions` based on `self`, `exclude_credentials`, and `extensions`.
    ///
    /// Note `extensions` is used _unconditionally_ regardless of what [`Self::extensions`] is.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::rp_id`] is `None` or [`PublicKeyCredentialUserEntityOwned::as_entity`] errors.
    #[inline]
    pub fn with_extensions<'prf_first, 'prf_second>(
        &self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
        extensions: Extension<'prf_first, 'prf_second>,
    ) -> Result<
        PublicKeyCredentialCreationOptions<'_, '_, '_, '_, 'prf_first, 'prf_second, USER_LEN>,
        PublicKeyCredentialCreationOptionsOwnedErr,
    > {
        self.rp_id
            .as_ref()
            .ok_or(PublicKeyCredentialCreationOptionsOwnedErr::MissingRpId)
            .and_then(|rp_id| {
                self.user
                    .as_entity()
                    .map_err(PublicKeyCredentialCreationOptionsOwnedErr::UserEntity)
                    .map(|user| PublicKeyCredentialCreationOptions {
                        rp_id,
                        user,
                        challenge: Challenge::new(),
                        pub_key_cred_params: self.pub_key_cred_params,
                        timeout: self.timeout,
                        exclude_credentials,
                        authenticator_selection: self.authenticator_selection,
                        hints: self.hints,
                        extensions,
                    })
            })
    }
    /// Returns a `PublicKeyCredentialCreationOptions` based on `self`, `exclude_credentials`, `rp_id`, and `user`.
    ///
    /// Note `rp_id` and `user` are used _unconditionally_ regardless if [`Self::rp_id`] is `Some` or what
    /// [`Self::user`] is.
    #[inline]
    #[must_use]
    pub fn with_rp_id_and_user<'rp_id, 'user_name, 'user_display_name, 'user_id>(
        &self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
        rp_id: &'rp_id RpId,
        user: PublicKeyCredentialUserEntity<'user_name, 'user_display_name, 'user_id, USER_LEN>,
    ) -> PublicKeyCredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        '_,
        '_,
        USER_LEN,
    > {
        PublicKeyCredentialCreationOptions {
            rp_id,
            user,
            challenge: Challenge::new(),
            pub_key_cred_params: self.pub_key_cred_params,
            timeout: self.timeout,
            exclude_credentials,
            authenticator_selection: self.authenticator_selection,
            hints: self.hints,
            extensions: self.extensions.as_extension(),
        }
    }
    /// Returns a `PublicKeyCredentialCreationOptions` based on `self`, `exclude_credentials`, `rp_id`, and
    /// `extensions`.
    ///
    /// Note `rp_id` and `extensions` are used _unconditionally_ regardless if [`Self::rp_id`] is `Some` or what
    /// [`Self::extensions`] is.
    ///
    /// # Errors
    ///
    /// Errors iff [`PublicKeyCredentialUserEntityOwned::as_entity`] errors.
    #[inline]
    pub fn with_rp_id_and_extensions<'rp_id, 'prf_first, 'prf_second>(
        &self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
        rp_id: &'rp_id RpId,
        extensions: Extension<'prf_first, 'prf_second>,
    ) -> Result<
        PublicKeyCredentialCreationOptions<'rp_id, '_, '_, '_, 'prf_first, 'prf_second, USER_LEN>,
        PublicKeyCredentialCreationOptionsOwnedErr,
    > {
        self.user
            .as_entity()
            .map_err(PublicKeyCredentialCreationOptionsOwnedErr::UserEntity)
            .map(|user| PublicKeyCredentialCreationOptions {
                rp_id,
                user,
                challenge: Challenge::new(),
                pub_key_cred_params: self.pub_key_cred_params,
                timeout: self.timeout,
                exclude_credentials,
                authenticator_selection: self.authenticator_selection,
                hints: self.hints,
                extensions,
            })
    }
    /// Returns a `PublicKeyCredentialCreationOptions` based on `self`, `exclude_credentials`, `user`, and
    /// `extensions`.
    ///
    /// Note `user` and `extensions` are used _unconditionally_ regardless of what the values of [`Self::user`]
    /// or [`Self::extensions`] are.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::rp_id`] is `None`.
    #[inline]
    pub fn with_user_and_extensions<
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
    >(
        &self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
        user: PublicKeyCredentialUserEntity<'user_name, 'user_display_name, 'user_id, USER_LEN>,
        extensions: Extension<'prf_first, 'prf_second>,
    ) -> Result<
        PublicKeyCredentialCreationOptions<
            '_,
            'user_name,
            'user_display_name,
            'user_id,
            'prf_first,
            'prf_second,
            USER_LEN,
        >,
        PublicKeyCredentialCreationOptionsOwnedErr,
    > {
        self.rp_id
            .as_ref()
            .ok_or(PublicKeyCredentialCreationOptionsOwnedErr::MissingRpId)
            .map(|rp_id| PublicKeyCredentialCreationOptions {
                rp_id,
                user,
                challenge: Challenge::new(),
                pub_key_cred_params: self.pub_key_cred_params,
                timeout: self.timeout,
                exclude_credentials,
                authenticator_selection: self.authenticator_selection,
                hints: self.hints,
                extensions,
            })
    }
    /// Returns a `PublicKeyCredentialCreationOptions` based on `self`, `exclude_credentials`, `rp_id`, `user`,
    /// and `extensions`.
    ///
    /// Note `rp_id`, `user`, and `extensions` are used _unconditionally_ regardless if [`Self::rp_id`] is `Some`
    /// or what the values of [`Self::user`] and [`Self::extensions`] are.
    #[inline]
    #[must_use]
    pub fn with_rp_id_user_and_extensions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
    >(
        &self,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
        rp_id: &'rp_id RpId,
        user: PublicKeyCredentialUserEntity<'user_name, 'user_display_name, 'user_id, USER_LEN>,
        extensions: Extension<'prf_first, 'prf_second>,
    ) -> PublicKeyCredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
        USER_LEN,
    > {
        PublicKeyCredentialCreationOptions {
            rp_id,
            user,
            challenge: Challenge::new(),
            pub_key_cred_params: self.pub_key_cred_params,
            timeout: self.timeout,
            exclude_credentials,
            authenticator_selection: self.authenticator_selection,
            hints: self.hints,
            extensions,
        }
    }
}
impl<const USER_LEN: usize> Default for PublicKeyCredentialCreationOptionsOwned<USER_LEN> {
    #[inline]
    fn default() -> Self {
        Self {
            rp_id: None,
            user: PublicKeyCredentialUserEntityOwned::default(),
            pub_key_cred_params: CoseAlgorithmIdentifiers::default(),
            timeout: FIVE_MINUTES,
            authenticator_selection: AuthenticatorSelectionCriteria {
                authenticator_attachment: AuthenticatorAttachment::default(),
                resident_key: ResidentKeyRequirement::Discouraged,
                user_verification: UserVerificationRequirement::Preferred,
            },
            hints: Hints::EMPTY,
            extensions: ExtensionOwned::default(),
        }
    }
}
impl<'de, const USER_LEN: usize> Deserialize<'de>
    for PublicKeyCredentialCreationOptionsOwned<USER_LEN>
where
    PublicKeyCredentialUserEntityOwned<USER_LEN>: Deserialize<'de>,
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
    /// it must be `null` or positive. When it does not exist or is `null`, [`FIVE_MINUTES`] will be used.
    ///
    /// Fields that are missing or `null` will be replaced with their corresponding [`Default`] value.
    ///
    /// Unknown or duplicate fields lead to an error.
    #[expect(clippy::too_many_lines, reason = "want to keep logic internal")]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `PublicKeyCredentialCreationOptionsOwned`.
        struct PublicKeyCredentialCreationOptionsOwnedVisitor<const LEN: usize>;
        impl<'d, const LEN: usize> Visitor<'d> for PublicKeyCredentialCreationOptionsOwnedVisitor<LEN>
        where
            PublicKeyCredentialUserEntityOwned<LEN>: Deserialize<'d>,
        {
            type Value = PublicKeyCredentialCreationOptionsOwned<LEN>;
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
                let mut hint = None;
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
                                .map(|opt| opt.map(|val| val.0))
                                .map(Some)?;
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
                            auth = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::Hints => {
                            if hint.is_some() {
                                return Err(Error::duplicate_field(HINTS));
                            }
                            hint = map.next_value::<Option<_>>().map(Some)?;
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
                    rp_id: rp.flatten().flatten(),
                    user: user_info.flatten().unwrap_or_default(),
                    pub_key_cred_params: params.flatten().unwrap_or_default(),
                    timeout: time.flatten().unwrap_or(FIVE_MINUTES),
                    authenticator_selection: auth.flatten().unwrap_or(
                        AuthenticatorSelectionCriteria {
                            authenticator_attachment: AuthenticatorAttachment::None,
                            resident_key: ResidentKeyRequirement::Discouraged,
                            user_verification: UserVerificationRequirement::Preferred,
                        },
                    ),
                    hints: hint.flatten().unwrap_or_default(),
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
            PublicKeyCredentialCreationOptionsOwnedVisitor,
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
/// To facilitate this, [`Self::deserialize`] can be used to deserialize the data sent from the client.
#[derive(Debug)]
pub struct ClientCredentialCreationOptions<const USER_LEN: usize> {
    /// See [`CredentialCreationOptions::mediation`].
    pub mediation: CredentialMediationRequirement,
    /// See [`CredentialCreationOptions::public_key`].
    pub public_key: PublicKeyCredentialCreationOptionsOwned<USER_LEN>,
}
impl<'de, const USER_LEN: usize> Deserialize<'de> for ClientCredentialCreationOptions<USER_LEN>
where
    PublicKeyCredentialCreationOptionsOwned<USER_LEN>: Deserialize<'de>,
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
        struct ClientCredentialCreationOptionsVisitor<const LEN: usize>;
        impl<'d, const LEN: usize> Visitor<'d> for ClientCredentialCreationOptionsVisitor<LEN>
        where
            PublicKeyCredentialCreationOptionsOwned<LEN>: Deserialize<'d>,
        {
            type Value = ClientCredentialCreationOptions<LEN>;
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
            ClientCredentialCreationOptionsVisitor,
        )
    }
}
