#[cfg(test)]
mod tests;
use super::{
    super::{
        DynamicState, Metadata, RegisteredCredential, StaticState,
        response::{
            AuthenticatorAttachment,
            register::{
                Attestation, AttestationFormat, AuthenticatorExtensionOutput,
                ClientExtensionsOutputs, CredentialProtectionPolicy, HmacSecret, Registration,
                UncompressedPubKey,
                error::{ExtensionErr, RegCeremonyErr},
            },
        },
    },
    Ceremony, Challenge, CredentialMediationRequirement, ExtensionInfo, ExtensionReq, FIVE_MINUTES,
    Hints, Origin, PrfInput, PublicKeyCredentialDescriptor, RpId, SentChallenge, TimedCeremony,
    UserVerificationRequirement,
    register::error::CreationOptionsErr,
};
#[cfg(doc)]
use crate::{
    request::{
        AsciiDomain, AsciiDomainStatic, DomainOrigin, Url,
        auth::{AuthenticationVerificationOptions, PublicKeyCredentialRequestOptions},
    },
    response::{AuthTransports, AuthenticatorTransport, Backup, CollectedClientData, Flag},
};
use core::{
    borrow::Borrow,
    cmp::Ordering,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    mem,
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};
#[cfg(any(doc, not(feature = "serializable_server_state")))]
use std::time::Instant;
#[cfg(any(doc, feature = "serializable_server_state"))]
use std::time::SystemTime;
/// Contains functionality to (de)serialize data to a data store.
#[cfg(feature = "bin")]
pub mod bin;
/// Contains functionality that needs to be accessible when `bin` or `serde` are not enabled.
#[cfg(feature = "custom")]
mod custom;
/// Contains error types.
pub mod error;
/// Contains functionality to (de)serialize data to a client.
#[cfg(feature = "serde")]
pub mod ser;
/// Contains functionality to (de)serialize [`RegistrationServerState`] to a data store.
#[cfg(feature = "serializable_server_state")]
pub mod ser_server_state;
/// Backup requirements for the credential.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BackupReq {
    /// No requirements (i.e., any [`Backup`] is allowed).
    #[default]
    None,
    /// Credential must not be eligible for backup.
    NotEligible,
    /// Credential must be eligible for backup.
    ///
    /// Note the existence of a backup is ignored. If a backup must exist, then use [`Self::Exists`]; if a
    /// backup must not exist, then use [`Self::EligibleNotExists`].
    Eligible,
    /// Credential must be eligible for backup, but a backup must not exist.
    EligibleNotExists,
    /// Credential must be backed up.
    Exists,
}
/// Used by [`Extension::cred_protect`] to enforce the [`CredentialProtectionPolicy`] sent by the client via
/// [`Registration`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CredProtect {
    /// No `credProtect` request.
    #[default]
    None,
    /// Request
    /// [`userVerificationOptional`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationoptional)
    /// but allow any.
    ///
    /// The `bool` corresponds to
    /// [`enforceCredentialProtectionPolicy`](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#dom-authenticationextensionsclientinputs-enforcecredentialprotectionpolicy).
    UserVerificationOptional(bool, ExtensionInfo),
    /// Request
    /// [`userVerificationOptionalWithCredentialIDList`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationoptionalwithcredentialidlist);
    /// and when enforcing the value, disallow [`CredentialProtectionPolicy::UserVerificationOptional`].
    ///
    /// The `bool` corresponds to
    /// [`enforceCredentialProtectionPolicy`](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#dom-authenticationextensionsclientinputs-enforcecredentialprotectionpolicy).
    UserVerificationOptionalWithCredentialIdList(bool, ExtensionInfo),
    /// Request
    /// [`userVerificationRequired`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationrequired);
    /// and when enforcing the value, only allow [`CredentialProtectionPolicy::UserVerificationRequired`].
    ///
    /// The `bool` corresponds to
    /// [`enforceCredentialProtectionPolicy`](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#dom-authenticationextensionsclientinputs-enforcecredentialprotectionpolicy).
    UserVerificationRequired(bool, ExtensionInfo),
}
impl CredProtect {
    /// Validates `other` is allowed based on `self`.
    ///
    /// # Errors
    ///
    /// Errors iff other is a less "secure" policy than `self` when enforcing the value or other does not exist
    /// despite requiring a value to be sent back.
    ///
    /// Note a missing response is OK when enforcing a value.
    const fn validate(self, other: CredentialProtectionPolicy) -> Result<(), ExtensionErr> {
        match self {
            Self::None => Ok(()),
            Self::UserVerificationOptional(_, info) => {
                if matches!(other, CredentialProtectionPolicy::None) {
                    if matches!(
                        info,
                        ExtensionInfo::RequireEnforceValue | ExtensionInfo::RequireDontEnforceValue
                    ) {
                        Err(ExtensionErr::MissingCredProtect)
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            }
            Self::UserVerificationOptionalWithCredentialIdList(_, info) => match info {
                ExtensionInfo::RequireEnforceValue => match other {
                    CredentialProtectionPolicy::None => Err(ExtensionErr::MissingCredProtect),
                    CredentialProtectionPolicy::UserVerificationOptional => {
                        Err(ExtensionErr::InvalidCredProtectValue(self, other))
                    }
                    CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList
                    | CredentialProtectionPolicy::UserVerificationRequired => Ok(()),
                },
                ExtensionInfo::RequireDontEnforceValue => {
                    if matches!(other, CredentialProtectionPolicy::None) {
                        Err(ExtensionErr::MissingCredProtect)
                    } else {
                        Ok(())
                    }
                }
                ExtensionInfo::AllowEnforceValue => {
                    if matches!(other, CredentialProtectionPolicy::UserVerificationOptional) {
                        Err(ExtensionErr::InvalidCredProtectValue(self, other))
                    } else {
                        Ok(())
                    }
                }
                ExtensionInfo::AllowDontEnforceValue => Ok(()),
            },
            Self::UserVerificationRequired(_, info) => match info {
                ExtensionInfo::RequireEnforceValue => match other {
                    CredentialProtectionPolicy::None => Err(ExtensionErr::MissingCredProtect),
                    CredentialProtectionPolicy::UserVerificationOptional
                    | CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList => {
                        Err(ExtensionErr::InvalidCredProtectValue(self, other))
                    }
                    CredentialProtectionPolicy::UserVerificationRequired => Ok(()),
                },
                ExtensionInfo::RequireDontEnforceValue => {
                    if matches!(other, CredentialProtectionPolicy::None) {
                        Err(ExtensionErr::MissingCredProtect)
                    } else {
                        Ok(())
                    }
                }
                ExtensionInfo::AllowEnforceValue => {
                    if matches!(
                        other,
                        CredentialProtectionPolicy::None
                            | CredentialProtectionPolicy::UserVerificationRequired
                    ) {
                        Ok(())
                    } else {
                        Err(ExtensionErr::InvalidCredProtectValue(self, other))
                    }
                }
                ExtensionInfo::AllowDontEnforceValue => Ok(()),
            },
        }
    }
}
impl Display for CredProtect {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::None => f.write_str("do not sent a credProtect request"),
            Self::UserVerificationOptional(enforce, info) => {
                write!(
                    f,
                    "request user verification optional with enforcement {enforce} and {info}"
                )
            }
            Self::UserVerificationOptionalWithCredentialIdList(enforce, info) => write!(
                f,
                "user verification optional with credential ID list with enforcement {enforce} and {info}"
            ),
            Self::UserVerificationRequired(enforce, info) => {
                write!(
                    f,
                    "user verification required with enforcement {enforce} and {info}"
                )
            }
        }
    }
}
/// [`COSEAlgorithmIdentifier`](https://www.w3.org/TR/webauthn-3/#typedefdef-cosealgorithmidentifier).
///
/// Note the order of variants is the following:
///
/// [`Self::Mldsa87`] `<` [`Self::Mldsa65`] `<` [`Self::Mldsa44`] `<` [`Self::Eddsa`] `<` [`Self::Es256`]
/// `<` [`Self::Es384`] `<` [`Self::Rs256`].
///
/// This is relevant for [`CoseAlgorithmIdentifiers`]. For example a `CoseAlgorithmIdentifiers`
/// that contains `Self::Mldsa87` will prioritize it over all others.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoseAlgorithmIdentifier {
    /// [ML-DSA-87](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
    Mldsa87,
    /// [ML-DSA-65](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
    Mldsa65,
    /// [ML-DSA-44](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
    Mldsa44,
    /// [EdDSA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
    ///
    /// Note that Ed25519 must be used for the `crv` parameter
    /// [per the spec](https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier).
    Eddsa,
    /// [ES256](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
    ///
    /// Note the uncompressed form must be used and P-256 must be used for the `crv` parameter
    /// [per the spec](https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier).
    Es256,
    /// [ES384](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
    ///
    /// Note the uncompressed form must be used and P-384 must be used for the `crv` parameter
    /// [per the spec](https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier).
    Es384,
    /// [RS256](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
    Rs256,
}
impl CoseAlgorithmIdentifier {
    /// Transforms `self` into a `u8`.
    const fn to_u8(self) -> u8 {
        match self {
            Self::Mldsa87 => 0x1,
            Self::Mldsa65 => 0x2,
            Self::Mldsa44 => 0x4,
            Self::Eddsa => 0x8,
            Self::Es256 => 0x10,
            Self::Es384 => 0x20,
            Self::Rs256 => 0x40,
        }
    }
}
impl PartialEq<&Self> for CoseAlgorithmIdentifier {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<CoseAlgorithmIdentifier> for &CoseAlgorithmIdentifier {
    #[inline]
    fn eq(&self, other: &CoseAlgorithmIdentifier) -> bool {
        **self == *other
    }
}
/// Non-empty ordered set of [`CoseAlgorithmIdentifier`]s.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoseAlgorithmIdentifiers(u8);
impl CoseAlgorithmIdentifiers {
    /// Contains all [`CoseAlgorithmIdentifier`]s.
    pub const ALL: Self = Self(0)
        .add(CoseAlgorithmIdentifier::Mldsa87)
        .add(CoseAlgorithmIdentifier::Mldsa65)
        .add(CoseAlgorithmIdentifier::Mldsa44)
        .add(CoseAlgorithmIdentifier::Eddsa)
        .add(CoseAlgorithmIdentifier::Es256)
        .add(CoseAlgorithmIdentifier::Es384)
        .add(CoseAlgorithmIdentifier::Rs256);
    /// Returns a `CoseAlgorithmIdentifiers` containing all `CoseAlgorithmIdentifier`s in `self` plus `alg`.
    const fn add(self, alg: CoseAlgorithmIdentifier) -> Self {
        Self(self.0 | alg.to_u8())
    }
    /// Returns a copy of `self` with `alg` removed if there would be at least one `CoseAlgorithmIdentifier`
    /// remaining; otherwise returns `self`.
    #[inline]
    #[must_use]
    pub const fn remove(self, alg: CoseAlgorithmIdentifier) -> Self {
        let val = alg.to_u8();
        if self.0 == val {
            self
        } else {
            Self(self.0 & !val)
        }
    }
    /// Returns `true` iff `self` contains `alg`.
    #[inline]
    #[must_use]
    pub const fn contains(self, alg: CoseAlgorithmIdentifier) -> bool {
        let val = alg.to_u8();
        self.0 & val == val
    }
    /// Validates `other` is allowed based on `self`.
    const fn validate(self, other: UncompressedPubKey<'_>) -> Result<(), RegCeremonyErr> {
        if match other {
            UncompressedPubKey::MlDsa87(_) => self.contains(CoseAlgorithmIdentifier::Mldsa87),
            UncompressedPubKey::MlDsa65(_) => self.contains(CoseAlgorithmIdentifier::Mldsa65),
            UncompressedPubKey::MlDsa44(_) => self.contains(CoseAlgorithmIdentifier::Mldsa44),
            UncompressedPubKey::Ed25519(_) => self.contains(CoseAlgorithmIdentifier::Eddsa),
            UncompressedPubKey::P256(_) => self.contains(CoseAlgorithmIdentifier::Es256),
            UncompressedPubKey::P384(_) => self.contains(CoseAlgorithmIdentifier::Es384),
            UncompressedPubKey::Rsa(_) => self.contains(CoseAlgorithmIdentifier::Rs256),
        } {
            Ok(())
        } else {
            Err(RegCeremonyErr::PublicKeyAlgorithmMismatch)
        }
    }
}
impl Default for CoseAlgorithmIdentifiers {
    /// Returns [`Self::ALL`].
    #[inline]
    fn default() -> Self {
        Self::ALL
    }
}
/// Four to sixty-three inclusively.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum FourToSixtyThree {
    /// 4.
    Four = 4,
    /// 5.
    Five,
    /// 6.
    Six,
    /// 7.
    Seven,
    /// 8.
    Eight,
    /// 9.
    Nine,
    /// 10.
    Ten,
    /// 11.
    Eleven,
    /// 12.
    Twelve,
    /// 13.
    Thirteen,
    /// 14.
    Fourteen,
    /// 15.
    Fifteen,
    /// 16.
    Sixteen,
    /// 17.
    Seventeen,
    /// 18.
    Eighteen,
    /// 19.
    Nineteen,
    /// 20.
    Twenty,
    /// 21.
    TwentyOne,
    /// 22.
    TwentyTwo,
    /// 23.
    TwentyThree,
    /// 24.
    TwentyFour,
    /// 25.
    TwentyFive,
    /// 26.
    TwentySix,
    /// 27.
    TwentySeven,
    /// 28.
    TwentyEight,
    /// 29.
    TwentyNine,
    /// 30.
    Thirty,
    /// 31.
    ThirtyOne,
    /// 32.
    ThirtyTwo,
    /// 33.
    ThirtyThree,
    /// 34.
    ThirtyFour,
    /// 35.
    ThirtyFive,
    /// 36.
    ThirtySix,
    /// 37.
    ThirtySeven,
    /// 38.
    ThirtyEight,
    /// 39.
    ThirtyNine,
    /// 40.
    Fourty,
    /// 41.
    FourtyOne,
    /// 42.
    FourtyTwo,
    /// 43.
    FourtyThree,
    /// 44.
    FourtyFour,
    /// 45.
    FourtyFive,
    /// 46.
    FourtySix,
    /// 47.
    FourtySeven,
    /// 48.
    FourtyEight,
    /// 49.
    FourtyNine,
    /// 50.
    Fifty,
    /// 51.
    FiftyOne,
    /// 52.
    FiftyTwo,
    /// 53.
    FiftyThree,
    /// 54.
    FiftyFour,
    /// 55.
    FiftyFive,
    /// 56.
    FiftySix,
    /// 57.
    FiftySeven,
    /// 58.
    FiftyEight,
    /// 59.
    FiftyNine,
    /// 60.
    Sixty,
    /// 61.
    SixtyOne,
    /// 62.
    SixtyTwo,
    /// 63.
    SixtyThree,
}
impl FourToSixtyThree {
    /// Returns the equivalent `u8`.
    #[expect(clippy::as_conversions, reason = "comment justifies correctness")]
    #[inline]
    #[must_use]
    pub const fn into_u8(self) -> u8 {
        // This is correct since `Self` is `repr(u8)`, and the initial discriminant has the value `4`
        // and subsequent discriminants are implicitly incremented by 1.
        self as u8
    }
    /// Returns `Some` representing `val` iff `val` is inclusively between 4 and 63.
    #[expect(unsafe_code, reason = "comment justifies correctness")]
    #[inline]
    #[must_use]
    pub const fn from_u8(val: u8) -> Option<Self> {
        match val {
            4..=63 => {
                // SAFETY:
                // `val` is inclusively between 4 and 63, and `Self` is `repr(u8)`; thus this
                // is safe and correct.
                Some(unsafe { mem::transmute::<u8, Self>(val) })
            }
            _ => None,
        }
    }
}
impl Display for FourToSixtyThree {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.into_u8().fmt(f)
    }
}
impl From<FourToSixtyThree> for u8 {
    #[inline]
    fn from(value: FourToSixtyThree) -> Self {
        value.into_u8()
    }
}
impl Default for FourToSixtyThree {
    #[inline]
    fn default() -> Self {
        Self::Four
    }
}
/// The [defined extensions](https://www.w3.org/TR/webauthn-3/#sctn-defined-extensions) to send to the client.
#[derive(Clone, Copy, Debug)]
pub struct Extension<'prf_first, 'prf_second> {
    /// [`credProps`](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension).
    ///
    /// The best one can do to ensure a server-side credential is created is by sending
    /// [`ResidentKeyRequirement::Discouraged`]; however authenticators are still allowed
    /// to create a client-side credential. To more definitively check that a server-side credential is
    /// created, send this extension. Note that it can be difficult to impossible for a client/user agent to
    /// know that a server-side credential is created; thus even when the response is
    /// `Some(CredentialPropertiesOutput { rk: Some(false) })`, a client-side/"resident" credential could still
    /// have been created. One may have better luck checking if [`AuthTransports::contains`]
    /// [`AuthenticatorTransport::Internal`] and using that as an indicator if a client-side credential was created.
    ///
    /// In the event [`ClientExtensionsOutputs::cred_props`] is `Some(CredentialPropertiesOutput { rk: Some(false) })`
    /// and [`ResidentKeyRequirement::Required`] was sent, an error will happen regardless of this value.
    pub cred_props: Option<ExtensionReq>,
    /// [`credProtect`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-credProtect-extension).
    pub cred_protect: CredProtect,
    /// [`minPinLength`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-minpinlength-extension).
    ///
    /// When the value is enforced, that corresponds to
    /// [`minPinLength`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-minpinlength-extension)
    /// in [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions) set to a value at least as large
    /// as the contained `FourToSixtyThree`.
    pub min_pin_length: Option<(FourToSixtyThree, ExtensionInfo)>,
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension).
    ///
    /// When the value is enforced, that corresponds to
    /// [`enabled`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-enabled) set to `true`.
    /// In contrast [`results`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-results)
    /// must not exist, be `null`, or be an
    /// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues)
    /// such that [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first) is `null`
    /// and [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second) does not
    /// exist or is `null`. This is to ensure the decrypted outputs stay on the client.
    ///
    /// Note some authenticators can only enable `prf` during registration (e.g., CTAP authenticators that only
    /// support
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-extension)
    /// and not
    /// [`hmac-secret-mc`](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-make-cred-extension));
    /// thus the value of `PrfInput` is ignored and only used as a signal to enable `prf`. For many such
    /// authenticators, not using this extension during registration will not preclude them from being used during
    /// authentication; however it is still encouraged to use the extension during registration since some
    /// authenticators actually require it.
    ///
    /// When the underlying credential is expected to be used during discoverable requests, it is likely that
    /// `'prf_first` will be `'static` and [`PrfInput::second`] is `None` since one will not be able to
    /// realistically rotate the underlying inputs and further the same input will likely be used for all credentials.
    /// For credentials intended to be used during non-discoverable requests, however, one is encouraged to rotate
    /// the inputs and have unique values for each credential.
    pub prf: Option<(PrfInput<'prf_first, 'prf_second>, ExtensionInfo)>,
}
impl<'prf_first, 'prf_second> Extension<'prf_first, 'prf_second> {
    /// Returns an empty `Extension`.
    #[inline]
    #[must_use]
    pub const fn none() -> Self {
        Self {
            cred_props: None,
            cred_protect: CredProtect::None,
            min_pin_length: None,
            prf: None,
        }
    }
    /// Same as [`Self::none`] except [`Self::cred_props`] is `Some` containing `req`.
    #[inline]
    #[must_use]
    pub const fn with_cred_props(req: ExtensionReq) -> Self {
        Self {
            cred_props: Some(req),
            ..Self::none()
        }
    }
    /// Same as [`Self::none`] except [`Self::cred_protect`] is `cred_protect`.
    #[inline]
    #[must_use]
    pub const fn with_cred_protect(cred_protect: CredProtect) -> Self {
        Self {
            cred_protect,
            ..Self::none()
        }
    }
    /// Same as [`Self::none`] except [`Self::min_pin_length`] is `Some` containing `min_len` and `info`.
    #[inline]
    #[must_use]
    pub const fn with_min_pin_length(min_len: FourToSixtyThree, info: ExtensionInfo) -> Self {
        Self {
            min_pin_length: Some((min_len, info)),
            ..Self::none()
        }
    }
    /// Same as [`Self::none`] except [`Self::prf`] is `Some` containing `input` and `info`.
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub const fn with_prf<'a: 'prf_first, 'b: 'prf_second>(
        input: PrfInput<'a, 'b>,
        info: ExtensionInfo,
    ) -> Self {
        Self {
            prf: Some((input, info)),
            ..Self::none()
        }
    }
}
impl Default for Extension<'_, '_> {
    /// Same as [`Self::none`].
    #[inline]
    fn default() -> Self {
        Self::none()
    }
}
#[cfg(test)]
impl PartialEq for Extension<'_, '_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.cred_props == other.cred_props
            && self.cred_protect == other.cred_protect
            && self.min_pin_length == other.min_pin_length
            && self.prf == other.prf
    }
}
/// The maximum number of bytes a [`UserHandle`] can be made of per
/// [WebAuthn](https://www.w3.org/TR/webauthn-3/#user-handle).
pub const USER_HANDLE_MAX_LEN: usize = 64;
/// The minimum number of bytes a [`UserHandle`] can be made of per
/// [WebAuthn](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id).
pub const USER_HANDLE_MIN_LEN: usize = 1;
/// A [user handle](https://www.w3.org/TR/webauthn-3/#user-handle) that is made up of
/// [`USER_HANDLE_MIN_LEN`]–[`USER_HANDLE_MAX_LEN`] bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UserHandle<const LEN: usize>([u8; LEN]);
impl<const LEN: usize> UserHandle<LEN> {
    /// Returns the contained data as a `slice`.
    #[inline]
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
    /// Returns the contained data as a shared reference to the array.
    #[inline]
    #[must_use]
    pub const fn as_array(&self) -> &[u8; LEN] {
        &self.0
    }
    /// Returns the contained data.
    #[inline]
    #[must_use]
    pub const fn into_array(self) -> [u8; LEN] {
        self.0
    }
}
/// Implements [`Default`] for [`UserHandle`] of array of length of the passed `usize` literal.
///
/// Only [`USER_HANDLE_MIN_LEN`]–[`USER_HANDLE_MAX_LEN`] inclusively are allowed to be passed.
macro_rules! user {
    ( $( $x:literal),* ) => {
        $(
impl Default for UserHandle<$x> {
    #[inline]
    fn default() -> Self {
        let mut data = [0; $x];
        rand::fill(data.as_mut_slice());
        Self(data)
    }
}
        )*
    };
}
// MUST only pass [`USER_HANDLE_MIN_LEN`]–[`USER_HANDLE_MAX_LEN`] inclusively.
user!(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64
);
impl<const LEN: usize> UserHandle<LEN>
where
    Self: Default,
{
    /// Returns a new `UserHandle` based on `LEN` randomly-generated [`u8`]s.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{UserHandle, UserHandle64, USER_HANDLE_MIN_LEN, USER_HANDLE_MAX_LEN};
    /// assert_eq!(
    ///     UserHandle::<USER_HANDLE_MIN_LEN>::new()
    ///         .as_ref()
    ///         .len(),
    ///     1
    /// );
    /// // The probability of an all-zero `UserHandle` being generated (assuming a good entropy
    /// // source) is 2^-512 ≈ 7.5 x 10^-155.
    /// assert_ne!(
    ///     UserHandle64::new().as_ref(),
    ///     [0; USER_HANDLE_MAX_LEN]
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
impl<const LEN: usize> AsRef<[u8]> for UserHandle<LEN> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl<const LEN: usize> Borrow<[u8]> for UserHandle<LEN> {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}
impl<const LEN: usize> PartialEq<&Self> for UserHandle<LEN> {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl<const LEN: usize> PartialEq<UserHandle<LEN>> for &UserHandle<LEN> {
    #[inline]
    fn eq(&self, other: &UserHandle<LEN>) -> bool {
        **self == *other
    }
}
impl<const LEN: usize> From<UserHandle<LEN>> for [u8; LEN] {
    #[inline]
    fn from(value: UserHandle<LEN>) -> Self {
        value.into_array()
    }
}
impl<'a: 'b, 'b, const LEN: usize> From<&'a UserHandle<LEN>> for &'b [u8; LEN] {
    #[inline]
    fn from(value: &'a UserHandle<LEN>) -> Self {
        value.as_array()
    }
}
/// `UserHandle` that is based on the [spec recommendation](https://www.w3.org/TR/webauthn-3/#user-handle).
pub type UserHandle64 = UserHandle<USER_HANDLE_MAX_LEN>;
/// `UserHandle` that is based on 16 bytes.
///
/// While not the recommended size like [`UserHandle64`], 16 bytes is common for many deployments since
/// it's the same size as [Universally Unique IDentifiers (UUIDs)](https://www.rfc-editor.org/rfc/rfc9562).
pub type UserHandle16 = UserHandle<16>;
impl UserHandle16 {
    /// Same as [`Self::new`] except 6 bits of metadata is encoded to conform with
    /// [UUID Version 4](https://www.rfc-editor.org/rfc/rfc9562#name-uuid-version-4).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::UserHandle16;
    /// assert!(UserHandle16::new_uuid_v4().is_uuid_v4());
    /// ```
    #[inline]
    #[must_use]
    pub fn new_uuid_v4() -> Self {
        let mut this = Self::new();
        // The first 4 bits of the 6th octet (0-based index) represents the UUID version (i.e., 4).
        // We first 0-out the version bits retaining the other 4 bits, then set the version bits to 4.
        this.0[6] = (this.0[6] & 0x0F) | 0x40;
        // The first 2 bits of the 8th octet (0-based index) represents the UUID variant (i.e., 8,9,A,B)
        // which is defined to be 2.
        // We first 0-out the variant bits retaining the other 6 bits, then set the variant bits to 2.
        this.0[8] = (this.0[8] & 0x3F) | 0x80;
        this
    }
    /// Returns `true` iff `self` is a valid
    /// [UUID Version 4](https://www.rfc-editor.org/rfc/rfc9562#name-uuid-version-4).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::UserHandle16;
    /// assert!(UserHandle16::new_uuid_v4().is_uuid_v4());
    /// let mut user = UserHandle16::new_uuid_v4().into_array();
    /// user[6] = 255;
    /// # #[cfg(feature = "custom")]
    /// assert!(!UserHandle16::from(user).is_uuid_v4());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_uuid_v4(&self) -> bool {
        // The first 4 bits of the 6th octet (0-based index) represents the UUID version (i.e., 4).
        // The first 2 bits of the 8th octet (0-based index) represents the UUID variant (i.e., 8,9,A,B) which
        // is defined to be 2.
        self.0[6] >> 4 == 0x4 && self.0[8] >> 6 == 0x2
    }
    /// Returns `Some` containing `uuid_v4` iff `uuid_v4` is a valid
    /// [UUID Version 4](https://www.rfc-editor.org/rfc/rfc9562#name-uuid-version-4).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::UserHandle16;
    /// let mut user = UserHandle16::new_uuid_v4().into_array();
    /// assert!(UserHandle16::from_uuid_v4(user).is_some());
    /// user[8] = 255;
    /// assert!(UserHandle16::from_uuid_v4(user).is_none());
    /// ```
    #[cfg(feature = "custom")]
    #[inline]
    #[must_use]
    pub fn from_uuid_v4(uuid_v4: [u8; 16]) -> Option<Self> {
        let this = Self(uuid_v4);
        this.is_uuid_v4().then_some(this)
    }
}
/// [The `PublicKeyCredentialUserEntity`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity)
/// sent to the client.
#[derive(Clone, Debug)]
pub struct PublicKeyCredentialUserEntity<'name, 'display_name, 'id, const LEN: usize> {
    /// [`name`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialentity-name).
    ///
    /// Note the spec recommends RPs enforce
    /// [RFC 8265 § 3.4.3](https://www.rfc-editor.org/rfc/rfc8265#section-3.4.3).
    pub name: &'name str,
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id).
    pub id: &'id UserHandle<LEN>,
    /// [`displayName`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-displayname).
    ///
    /// Note the spec recommends RPs enforce [RFC 8266 § 2.3](https://www.rfc-editor.org/rfc/rfc8266#section-2.3)
    /// when this isn't empty.
    pub display_name: &'display_name str,
}
/// `PublicKeyCredentialUserEntity` based on a [`UserHandle64`].
pub type PublicKeyCredentialUserEntity64<'name, 'display_name, 'id> =
    PublicKeyCredentialUserEntity<'name, 'display_name, 'id, USER_HANDLE_MAX_LEN>;
/// `PublicKeyCredentialUserEntity` based on a [`UserHandle16`].
pub type PublicKeyCredentialUserEntity16<'name, 'display_name, 'id> =
    PublicKeyCredentialUserEntity<'name, 'display_name, 'id, 16>;
/// [`ResidentKeyRequirement`](https://www.w3.org/TR/webauthn-3/#enumdef-residentkeyrequirement) sent to the client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentKeyRequirement {
    /// [`required`](https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-required).
    Required,
    /// [`discouraged`](https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-discouraged).
    Discouraged,
    /// [`preferred`](https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-preferred).
    Preferred,
}
impl AuthenticatorAttachment {
    /// Validates `self` against `other` based on `require_response`.
    const fn validate(self, require_response: bool, other: Self) -> Result<(), RegCeremonyErr> {
        match self {
            Self::None => {
                if require_response && matches!(other, Self::None) {
                    Err(RegCeremonyErr::MissingAuthenticatorAttachment)
                } else {
                    Ok(())
                }
            }
            Self::Platform => match other {
                Self::None => {
                    if require_response {
                        Err(RegCeremonyErr::MissingAuthenticatorAttachment)
                    } else {
                        Ok(())
                    }
                }
                Self::Platform => Ok(()),
                Self::CrossPlatform => Err(RegCeremonyErr::AuthenticatorAttachmentMismatch),
            },
            Self::CrossPlatform => match other {
                Self::None => {
                    if require_response {
                        Err(RegCeremonyErr::MissingAuthenticatorAttachment)
                    } else {
                        Ok(())
                    }
                }
                Self::CrossPlatform => Ok(()),
                Self::Platform => Err(RegCeremonyErr::AuthenticatorAttachmentMismatch),
            },
        }
    }
}
/// [`AuthenticatorSelectionCriteria`](https://www.w3.org/TR/webauthn-3/#dictionary-authenticatorSelection).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatorSelectionCriteria {
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-authenticatorattachment).
    pub authenticator_attachment: AuthenticatorAttachment,
    /// [`residentKey`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-residentkey).
    pub resident_key: ResidentKeyRequirement,
    /// [`userVerification`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-userverification).
    pub user_verification: UserVerificationRequirement,
}
impl AuthenticatorSelectionCriteria {
    /// Returns an `AuthenticatorSelectionCriteria` useful for passkeys (i.e., [`Self::resident_key`] is set to
    /// [`ResidentKeyRequirement::Required`] and [`Self::user_verification`] is set to
    /// [`UserVerificationRequirement::Required`]).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::{request::{
    /// #     register::{
    /// #         AuthenticatorSelectionCriteria, ResidentKeyRequirement,
    /// #     },
    /// #     UserVerificationRequirement,
    /// # }, response::AuthenticatorAttachment};
    /// let crit = AuthenticatorSelectionCriteria::passkey();
    /// assert_eq!(crit.authenticator_attachment, AuthenticatorAttachment::None);
    /// assert_eq!(crit.resident_key, ResidentKeyRequirement::Required);
    /// assert_eq!(crit.user_verification, UserVerificationRequirement::Required);
    /// ```
    #[inline]
    #[must_use]
    pub fn passkey() -> Self {
        Self {
            authenticator_attachment: AuthenticatorAttachment::default(),
            resident_key: ResidentKeyRequirement::Required,
            user_verification: UserVerificationRequirement::Required,
        }
    }
    /// Returns an `AuthenticatorSelectionCriteria` useful for second-factor flows (i.e., [`Self::resident_key`]
    /// is set to [`ResidentKeyRequirement::Discouraged`] and [`Self::user_verification`] is set to
    /// [`UserVerificationRequirement::Discouraged`]).
    ///
    /// Note some authenticators require user verification during credential registration (e.g.,
    /// [CTAP 2.0 authenticators](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorMakeCredential)).
    /// When an authenticator supports both CTAP 2.0 and
    /// [Universal 2nd Factor (U2F)](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html#registration-creating-a-key-pair)
    /// protocols, user agents will sometimes fall back to U2F when `UserVerificationRequirement::Discouraged`
    /// is requested since the latter allows for registration without user verification. If the user agent does not
    /// do this, then users will have an inconsistent experience when authenticating an already-registered
    /// credential. If this is undesirable, one can use [`UserVerificationRequirement::Required`] for this and
    /// [`PublicKeyCredentialRequestOptions::user_verification`] at the expense of requiring a user to verify
    /// themselves twice: once for the first factor and again here.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::{request::{
    /// #     register::{
    /// #         AuthenticatorSelectionCriteria, ResidentKeyRequirement,
    /// #     },
    /// #     UserVerificationRequirement,
    /// # }, response::AuthenticatorAttachment};
    /// let crit = AuthenticatorSelectionCriteria::second_factor();
    /// assert_eq!(crit.authenticator_attachment, AuthenticatorAttachment::None);
    /// assert_eq!(crit.resident_key, ResidentKeyRequirement::Discouraged);
    /// assert_eq!(crit.user_verification, UserVerificationRequirement::Discouraged);
    /// ```
    #[inline]
    #[must_use]
    pub fn second_factor() -> Self {
        Self {
            authenticator_attachment: AuthenticatorAttachment::default(),
            resident_key: ResidentKeyRequirement::Discouraged,
            user_verification: UserVerificationRequirement::Discouraged,
        }
    }
    /// Ensures a client-side credential was created when applicable. Also enforces `auth_attachment` when
    /// applicable.
    const fn validate(
        self,
        require_auth_attachment: bool,
        auth_attachment: AuthenticatorAttachment,
    ) -> Result<(), RegCeremonyErr> {
        self.authenticator_attachment
            .validate(require_auth_attachment, auth_attachment)
    }
}
/// Helper that verifies the overlap of [`CredentialCreationOptions::start_ceremony`] and
/// [`RegistrationServerState::decode`].
const fn validate_options_helper(
    auth_crit: AuthenticatorSelectionCriteria,
    extensions: ServerExtensionInfo,
) -> Result<(), CreationOptionsErr> {
    if matches!(
        auth_crit.user_verification,
        UserVerificationRequirement::Required
    ) {
        Ok(())
    } else if !matches!(extensions.prf, ServerPrfInfo::None) {
        Err(CreationOptionsErr::PrfWithoutUserVerification)
    } else if matches!(
        extensions.cred_protect,
        CredProtect::UserVerificationRequired(_, _)
    ) {
        Err(CreationOptionsErr::CredProtectRequiredWithoutUserVerification)
    } else {
        Ok(())
    }
}
/// The [`CredentialCreationOptions`](https://www.w3.org/TR/credential-management-1/#dictdef-credentialcreationoptions)
/// to send to the client when registering a new credential.
///
/// Upon saving the [`RegistrationServerState`] returned from [`Self::start_ceremony`], one MUST send
/// [`RegistrationClientState`] to the client ASAP. After receiving the newly created [`Registration`], it is
/// validated using [`RegistrationServerState::verify`].
#[derive(Debug)]
pub struct CredentialCreationOptions<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    const USER_LEN: usize,
> {
    /// [`mediation`](https://www.w3.org/TR/credential-management-1/#dom-credentialcreationoptions-mediation).
    ///
    /// Note if this is [`CredentialMediationRequirement::Conditional`], one may want to ensure
    /// [`AuthenticatorSelectionCriteria::user_verification`] is not [`UserVerificationRequirement::Required`]
    /// since some authenticators cannot enforce user verification during registration ceremonies when conditional
    /// mediation is used. Do note that in the event passkeys are to be created, one may want to set
    /// [`AuthenticationVerificationOptions::update_uv`] to `true` since [`Flag::user_verified`] will
    /// potentially be `false`.
    pub mediation: CredentialMediationRequirement,
    /// `public-key` [credential type](https://www.w3.org/TR/credential-management-1/#sctn-cred-type-registry).
    pub public_key: PublicKeyCredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
        USER_LEN,
    >,
}
impl<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    const USER_LEN: usize,
>
    CredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
        USER_LEN,
    >
{
    /// Sets [`Self::mediation`] to [`CredentialMediationRequirement::default`] and
    /// [`Self::public_key`] to [`PublicKeyCredentialCreationOptions::passkey`].
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub fn passkey<'a: 'rp_id, 'b: 'user_name, 'c: 'user_display_name, 'd: 'user_id>(
        rp_id: &'a RpId,
        user: PublicKeyCredentialUserEntity<'b, 'c, 'd, USER_LEN>,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
    ) -> Self {
        Self {
            mediation: CredentialMediationRequirement::default(),
            public_key: PublicKeyCredentialCreationOptions::passkey(
                rp_id,
                user,
                exclude_credentials,
            ),
        }
    }
    /// Sets [`Self::mediation`] to [`CredentialMediationRequirement::default`] and
    /// [`Self::public_key`] to [`PublicKeyCredentialCreationOptions::second_factor`].
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub fn second_factor<'a: 'rp_id, 'b: 'user_name, 'c: 'user_display_name, 'd: 'user_id>(
        rp_id: &'a RpId,
        user: PublicKeyCredentialUserEntity<'b, 'c, 'd, USER_LEN>,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
    ) -> Self {
        let mut opts = Self::passkey(rp_id, user, exclude_credentials);
        opts.public_key.authenticator_selection = AuthenticatorSelectionCriteria::second_factor();
        opts.public_key.extensions.cred_props = Some(ExtensionReq::Allow);
        opts.public_key.extensions.cred_protect =
            CredProtect::UserVerificationOptionalWithCredentialIdList(
                false,
                ExtensionInfo::AllowEnforceValue,
            );
        opts
    }
    /// Begins the [registration ceremony](https://www.w3.org/TR/webauthn-3/#registration-ceremony) consuming
    /// `self`. Note that the expiration [`Instant`]/[`SystemTime`] is saved, so `RegistrationClientState` MUST be
    /// sent ASAP. In order to complete registration, the returned `RegistrationServerState` MUST be saved so that
    /// it can later be used to verify the new credential with [`RegistrationServerState::verify`].
    ///
    /// # Errors
    ///
    /// Errors iff `self` contains incompatible configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(not(feature = "serializable_server_state"))]
    /// # use std::time::Instant;
    /// # #[cfg(not(feature = "serializable_server_state"))]
    /// # use webauthn_rp::request::TimedCeremony as _;
    /// # use webauthn_rp::request::{
    /// #     register::{CredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle64},
    /// #     AsciiDomain, RpId
    /// # };
    /// # #[cfg(not(feature = "serializable_server_state"))]
    /// assert!(
    ///     CredentialCreationOptions::passkey(
    ///         &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         PublicKeyCredentialUserEntity {
    ///             name: "bernard.riemann",
    ///             id: &UserHandle64::new(),
    ///             display_name: "Georg Friedrich Bernhard Riemann",
    ///         },
    ///         Vec::new()
    ///     ).start_ceremony()?.0.expiration() > Instant::now()
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    pub fn start_ceremony(
        mut self,
    ) -> Result<
        (
            RegistrationServerState<USER_LEN>,
            RegistrationClientState<
                'rp_id,
                'user_name,
                'user_display_name,
                'user_id,
                'prf_first,
                'prf_second,
                USER_LEN,
            >,
        ),
        CreationOptionsErr,
    > {
        let extensions = self.public_key.extensions.into();
        validate_options_helper(self.public_key.authenticator_selection, extensions).and_then(
            |()| {
                match self
                    .public_key
                    .authenticator_selection
                    .authenticator_attachment
                {
                    AuthenticatorAttachment::None => Ok(()),
                    AuthenticatorAttachment::Platform => {
                        if self.public_key.hints.contains_cross_platform_hints() {
                            Err(CreationOptionsErr::HintsIncompatibleWithAuthAttachment)
                        } else {
                            Ok(())
                        }
                    }
                    AuthenticatorAttachment::CrossPlatform => {
                        if self.public_key.hints.contains_platform_hints() {
                            Err(CreationOptionsErr::HintsIncompatibleWithAuthAttachment)
                        } else {
                            Ok(())
                        }
                    }
                }
                .and_then(|()| {
                    #[cfg(not(feature = "serializable_server_state"))]
                    let now = Instant::now();
                    #[cfg(feature = "serializable_server_state")]
                    let now = SystemTime::now();
                    now.checked_add(Duration::from_millis(
                        NonZeroU64::from(self.public_key.timeout).get(),
                    ))
                    .ok_or(CreationOptionsErr::InvalidTimeout)
                    .map(|expiration| {
                        // We remove duplicates. The order has no significance, so this is OK.
                        self.public_key
                            .exclude_credentials
                            .sort_unstable_by(|a, b| a.id.as_ref().cmp(b.id.as_ref()));
                        self.public_key
                            .exclude_credentials
                            .dedup_by(|a, b| a.id.as_ref() == b.id.as_ref());
                        (
                            RegistrationServerState {
                                mediation: self.mediation,
                                challenge: SentChallenge(self.public_key.challenge.0),
                                pub_key_cred_params: self.public_key.pub_key_cred_params,
                                authenticator_selection: self.public_key.authenticator_selection,
                                extensions,
                                expiration,
                                user_id: *self.public_key.user.id,
                            },
                            RegistrationClientState(self),
                        )
                    })
                })
            },
        )
    }
}
/// `CredentialCreationOptions` based on a [`UserHandle64`].
pub type CredentialCreationOptions64<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
> = CredentialCreationOptions<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    USER_HANDLE_MAX_LEN,
>;
/// `CredentialCreationOptions` based on a [`UserHandle16`].
pub type CredentialCreationOptions16<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
> = CredentialCreationOptions<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    16,
>;
/// The [`PublicKeyCredentialCreationOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions)
/// to send to the client when registering a new credential.
#[derive(Debug)]
pub struct PublicKeyCredentialCreationOptions<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    const USER_LEN: usize,
> {
    /// [`rp`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-rp).
    pub rp_id: &'rp_id RpId,
    /// [`user`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-user).
    pub user: PublicKeyCredentialUserEntity<'user_name, 'user_display_name, 'user_id, USER_LEN>,
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-challenge).
    pub challenge: Challenge,
    /// [`pubKeyCredParams`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-pubkeycredparams).
    pub pub_key_cred_params: CoseAlgorithmIdentifiers,
    /// [`timeout`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-timeout).
    ///
    /// Note we require a positive value despite the spec allowing an optional nonnegative value. This jives
    /// with the fact that in-memory storage is required when `serializable_server_state` is not enabled
    /// when attesting credentials as no timeout would make out-of-memory (OOM) conditions more likely.
    pub timeout: NonZeroU32,
    /// [`excludeCredentials`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-excludecredentials).
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
    /// [`authenticatorSelection`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-authenticatorselection).
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    /// [`hints`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-hints).
    pub hints: Hints,
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-extensions).
    pub extensions: Extension<'prf_first, 'prf_second>,
}
impl<'rp_id, 'user_name, 'user_display_name, 'user_id, const USER_LEN: usize>
    PublicKeyCredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        '_,
        '_,
        USER_LEN,
    >
{
    /// Most deployments of passkeys should use this function. Specifically deployments that are both userless and
    /// passwordless and desire multi-factor authentication (MFA) to be done entirely on the authenticator. It
    /// is important `exclude_credentials` contains the information for _all_ [`RegisteredCredential`]s registered to
    /// [`PublicKeyCredentialUserEntity::id`] to avoid accidentally overwriting existing credentials that
    /// have been previously registered.
    ///
    /// Creates a `PublicKeyCredentialCreationOptions` that requires the authenticator to create a client-side
    /// discoverable credential enforcing any form of user verification. [`Self::timeout`] is [`FIVE_MINUTES`].
    /// [`Extension::cred_protect`] with [`CredProtect::UserVerificationRequired`] with `false` and
    /// [`ExtensionInfo::AllowEnforceValue`] is used.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{
    /// #     register::{
    /// #         PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle64
    /// #     },
    /// #     AsciiDomain, RpId, UserVerificationRequirement
    /// # };
    /// assert!(matches!(
    ///     PublicKeyCredentialCreationOptions::passkey(
    ///         &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         PublicKeyCredentialUserEntity {
    ///             name: "archimedes.of.syracuse",
    ///             id: &UserHandle64::new(),
    ///             display_name: "Αρχιμήδης ο Συρακούσιος",
    ///         },
    ///         Vec::new()
    ///     )
    ///     .authenticator_selection.user_verification, UserVerificationRequirement::Required
    /// ));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub fn passkey<'a: 'rp_id, 'b: 'user_name, 'c: 'user_display_name, 'd: 'user_id>(
        rp_id: &'a RpId,
        user: PublicKeyCredentialUserEntity<'b, 'c, 'd, USER_LEN>,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
    ) -> Self {
        Self {
            rp_id,
            user,
            challenge: Challenge::new(),
            pub_key_cred_params: CoseAlgorithmIdentifiers::default(),
            timeout: FIVE_MINUTES,
            exclude_credentials,
            authenticator_selection: AuthenticatorSelectionCriteria::passkey(),
            hints: Hints::EMPTY,
            extensions: Extension {
                cred_props: None,
                cred_protect: CredProtect::UserVerificationRequired(
                    false,
                    ExtensionInfo::AllowEnforceValue,
                ),
                min_pin_length: None,
                prf: None,
            },
        }
    }
    /// Deployments that want to incorporate a "something a user has" factor into a larger multi-factor
    /// authentication (MFA) setup. Specifically deployments that are _not_ userless or passwordless. It
    /// is important `exclude_credentials` contains the information for _all_ [`RegisteredCredential`]s registered
    /// to [`PublicKeyCredentialUserEntity::id`] to avoid accidentally overwriting existing credentials that
    /// have been previously registered.
    ///
    /// Creates a `PublicKeyCredentialCreationOptions` that prefers the authenticator to create a server-side
    /// credential without requiring user verification. [`Self::timeout`] is [`FIVE_MINUTES`].
    /// [`Extension::cred_props`] is [`ExtensionReq::Allow`]. [`Extension::cred_protect`] is
    /// [`CredProtect::UserVerificationOptionalWithCredentialIdList`] with `false` and
    /// [`ExtensionInfo::AllowEnforceValue`].
    ///
    /// Note some authenticators require user verification during credential registration (e.g.,
    /// [CTAP 2.0 authenticators](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#authenticatorMakeCredential)).
    /// When an authenticator supports both CTAP 2.0 and
    /// [Universal 2nd Factor (U2F)](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html#registration-creating-a-key-pair)
    /// protocols, user agents will sometimes fall back to U2F when [`UserVerificationRequirement::Discouraged`]
    /// is requested since the latter allows for registration without user verification. If the user agent does not
    /// do this, then users will have an inconsistent experience when authenticating an already-registered
    /// credential. If this is undesirable, one can use [`UserVerificationRequirement::Required`] for this and
    /// [`PublicKeyCredentialRequestOptions::user_verification`] at the expense of requiring a user to verify
    /// themselves twice: once for the first factor and again here.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{register::{
    /// #     PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle64
    /// # }, AsciiDomain, RpId};
    /// assert_eq!(
    ///     PublicKeyCredentialCreationOptions::second_factor(
    ///         &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         PublicKeyCredentialUserEntity {
    ///             name: "carl.gauss",
    ///             id: &UserHandle64::new(),
    ///             display_name: "Johann Carl Friedrich Gauß",
    ///         },
    ///         Vec::new()
    ///     )
    ///     .timeout
    ///     .get(),
    ///     300_000
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub fn second_factor<'a: 'rp_id, 'b: 'user_name, 'c: 'user_display_name, 'd: 'user_id>(
        rp_id: &'a RpId,
        user: PublicKeyCredentialUserEntity<'b, 'c, 'd, USER_LEN>,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>,
    ) -> Self {
        let mut opts = Self::passkey(rp_id, user, exclude_credentials);
        opts.authenticator_selection = AuthenticatorSelectionCriteria::second_factor();
        opts.extensions.cred_props = Some(ExtensionReq::Allow);
        opts.extensions.cred_protect = CredProtect::UserVerificationOptionalWithCredentialIdList(
            false,
            ExtensionInfo::AllowEnforceValue,
        );
        opts
    }
}
/// `PublicKeyCredentialCreationOptions` based on a [`UserHandle64`].
pub type PublicKeyCredentialCreationOptions64<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
> = PublicKeyCredentialCreationOptions<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    USER_HANDLE_MAX_LEN,
>;
/// `PublicKeyCredentialCreationOptions` based on a [`UserHandle16`].
pub type PublicKeyCredentialCreationOptions16<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
> = PublicKeyCredentialCreationOptions<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    16,
>;
/// Container of a [`CredentialCreationOptions`] that has been used to start the registration ceremony.
/// This gets sent to the client ASAP.
#[derive(Debug)]
pub struct RegistrationClientState<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    const USER_LEN: usize,
>(
    CredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
        USER_LEN,
    >,
);
impl<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    const USER_LEN: usize,
>
    RegistrationClientState<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
        USER_LEN,
    >
{
    /// Returns the `CredentialCreationOptions` that was used to start a registration ceremony.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{register::{
    /// #     CoseAlgorithmIdentifiers, CredentialCreationOptions,
    /// #     PublicKeyCredentialUserEntity, UserHandle64,
    /// # }, AsciiDomain, RpId};
    /// assert_eq!(
    ///     CredentialCreationOptions::passkey(
    ///         &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         PublicKeyCredentialUserEntity {
    ///             name: "david.hilbert",
    ///             id: &UserHandle64::new(),
    ///             display_name: "David Hilbert",
    ///         },
    ///         Vec::new()
    ///     )
    ///     .start_ceremony()?
    ///     .1
    ///     .options()
    ///     .public_key
    ///     .rp_id.as_ref(),
    ///     "example.com"
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn options(
        &self,
    ) -> &CredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        'prf_first,
        'prf_second,
        USER_LEN,
    > {
        &self.0
    }
}
/// `RegistrationClientState` based on a [`UserHandle64`].
pub type RegistrationClientState64<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
> = RegistrationClientState<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    USER_HANDLE_MAX_LEN,
>;
/// `RegistrationClientState` based on a [`UserHandle16`].
pub type RegistrationClientState16<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
> = RegistrationClientState<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    'prf_first,
    'prf_second,
    16,
>;
/// Additional verification options to perform in [`RegistrationServerState::verify`].
#[derive(Clone, Copy, Debug)]
pub struct RegistrationVerificationOptions<'origins, 'top_origins, O, T> {
    /// Origins to use for [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin).
    ///
    /// When this is empty, the origin that will be used will be based on
    /// the [`RpId`] passed to [`RegistrationServerState::verify`]. If [`RpId::Domain`] or [`RpId::StaticDomain`],
    /// then the [`DomainOrigin`] returned from passing [`AsciiDomain::as_ref`] and [`AsciiDomainStatic::as_str`]
    /// to [`DomainOrigin::new`] respectively will be used; otherwise the [`Url`] in [`RpId::Url`] will be used.
    pub allowed_origins: &'origins [O],
    /// [Top-level origins](https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-top-level-origin)
    /// to use for [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin).
    ///
    /// When this is `Some`, [`CollectedClientData::cross_origin`] is allowed to be `true`. When the contained
    /// `slice` is empty, [`CollectedClientData::top_origin`] must be `None`. When this is `None`,
    /// `CollectedClientData::cross_origin` must be `false` and `CollectedClientData::top_origin` must be `None`.
    pub allowed_top_origins: Option<&'top_origins [T]>,
    /// The required [`Backup`] state of the credential.
    pub backup_requirement: BackupReq,
    /// Error when unsolicited extensions are sent back iff `true`.
    pub error_on_unsolicited_extensions: bool,
    /// [`AuthenticatorAttachment`] must be sent iff `true`.
    pub require_authenticator_attachment: bool,
    /// [`CollectedClientData::from_client_data_json_relaxed`] is used to extract [`CollectedClientData`] iff `true`.
    #[cfg(feature = "serde_relaxed")]
    pub client_data_json_relaxed: bool,
}
impl<O, T> RegistrationVerificationOptions<'_, '_, O, T> {
    /// Returns `Self` such that [`Self::allowed_origins`] is empty, [`Self::allowed_top_origins`] is `None`,
    /// [`Self::backup_requirement`] is [`BackupReq::None`], [`Self::error_on_unsolicited_extensions`] is `true`,
    /// [`Self::require_authenticator_attachment`] is `false`, and [`Self::client_data_json_relaxed`] is
    /// `true`.
    ///
    /// Note `O` and `T` should implement `PartialEq<Origin<'_>>` (e.g., `&str`).
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allowed_origins: [].as_slice(),
            allowed_top_origins: None,
            backup_requirement: BackupReq::None,
            error_on_unsolicited_extensions: true,
            require_authenticator_attachment: false,
            #[cfg(feature = "serde_relaxed")]
            client_data_json_relaxed: true,
        }
    }
}
impl<O, T> Default for RegistrationVerificationOptions<'_, '_, O, T> {
    /// Same as [`Self::new`].
    #[inline]
    fn default() -> Self {
        Self {
            allowed_origins: &[],
            allowed_top_origins: None,
            backup_requirement: BackupReq::default(),
            error_on_unsolicited_extensions: true,
            require_authenticator_attachment: false,
            #[cfg(feature = "serde_relaxed")]
            client_data_json_relaxed: true,
        }
    }
}
/// `PrfInput` without the actual data sent to reduce memory usage when storing [`RegistrationServerState`] in an
/// in-memory collection.
#[derive(Clone, Copy, Debug)]
enum ServerPrfInfo {
    /// No `PrfInput`.
    None,
    /// `PrfInput::second` was `None`.
    One(ExtensionInfo),
    /// `PrfInput::second` was `Some`.
    Two(ExtensionInfo),
}
#[cfg(test)]
impl PartialEq for ServerPrfInfo {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::None => matches!(*other, Self::None),
            Self::One(info) => matches!(*other, Self::One(info2) if info == info2),
            Self::Two(info) => matches!(*other, Self::Two(info2) if info == info2),
        }
    }
}
impl From<Option<(PrfInput<'_, '_>, ExtensionInfo)>> for ServerPrfInfo {
    fn from(value: Option<(PrfInput<'_, '_>, ExtensionInfo)>) -> Self {
        value.map_or(Self::None, |val| {
            val.0
                .second
                .map_or_else(|| Self::One(val.1), |_| Self::Two(val.1))
        })
    }
}
/// `Extension` without the actual data sent to reduce memory usage when storing [`AuthenticationServerState`]
/// in an in-memory collection.
#[derive(Clone, Copy, Debug)]
struct ServerExtensionInfo {
    /// `Extension::cred_props`.
    cred_props: Option<ExtensionReq>,
    /// `Extension::cred_protect`.
    cred_protect: CredProtect,
    /// `Extension::min_pin_length`.
    min_pin_length: Option<(FourToSixtyThree, ExtensionInfo)>,
    /// `Extension::prf`.
    prf: ServerPrfInfo,
}
impl ServerExtensionInfo {
    /// Validates the extensions.
    fn validate(
        self,
        client_ext: ClientExtensionsOutputs,
        auth_ext: AuthenticatorExtensionOutput,
        error_unsolicited: bool,
    ) -> Result<(), ExtensionErr> {
        if error_unsolicited {
            self.validate_unsolicited(client_ext, auth_ext)
        } else {
            Ok(())
        }
        .and_then(|()| {
            self.validate_required(client_ext, auth_ext)
                .and_then(|()| self.validate_value(client_ext, auth_ext))
        })
    }
    /// Validates if there are any unsolicited extensions.
    ///
    /// Note no distinction is made between an extension that is empty and one that is not (i.e., we are checking
    ///  purely for the existence of extension keys).
    fn validate_unsolicited(
        mut self,
        client_ext: ClientExtensionsOutputs,
        auth_ext: AuthenticatorExtensionOutput,
    ) -> Result<(), ExtensionErr> {
        // For simpler code, we artificially set non-requested extensions after verifying there was not an error
        // and recursively call this function. There are so few extensions and the checks are fast that there
        // should be no worry of stack overflow or performance overhead.
        if self.cred_props.is_some() {
            if !matches!(self.cred_protect, CredProtect::None) {
                if self.min_pin_length.is_some() {
                    // This is the last extension, so recursion stops here.
                    if !matches!(self.prf, ServerPrfInfo::None) {
                        Ok(())
                    } else if client_ext.prf.is_some() {
                        Err(ExtensionErr::ForbiddenPrf)
                    } else if !matches!(auth_ext.hmac_secret, HmacSecret::None) {
                        Err(ExtensionErr::ForbiddenHmacSecret)
                    } else {
                        Ok(())
                    }
                } else if auth_ext.min_pin_length.is_some() {
                    Err(ExtensionErr::ForbiddenMinPinLength)
                } else {
                    // Pretend to set `minPinLength`, so we can check `prf`.
                    self.min_pin_length =
                        Some((FourToSixtyThree::Four, ExtensionInfo::RequireEnforceValue));
                    self.validate_unsolicited(client_ext, auth_ext)
                }
            } else if !matches!(auth_ext.cred_protect, CredentialProtectionPolicy::None) {
                Err(ExtensionErr::ForbiddenCredProtect)
            } else {
                // Pretend to set `credProtect`, so we can check `minPinLength` and `prf` extensions.
                self.cred_protect = CredProtect::UserVerificationOptional(
                    false,
                    ExtensionInfo::RequireEnforceValue,
                );
                self.validate_unsolicited(client_ext, auth_ext)
            }
        } else if client_ext.cred_props.is_some() {
            Err(ExtensionErr::ForbiddenCredProps)
        } else {
            // Pretend to set `credProps`; so we can check `credProtect`, `minPinLength`, and `prf` extensions.
            self.cred_props = Some(ExtensionReq::Require);
            self.validate_unsolicited(client_ext, auth_ext)
        }
    }
    /// Validates if any required extensions don't have a corresponding response.
    ///
    /// Note empty extensions are treated as missing. For example when requiring the `credProps` extension,
    /// all of the following responses would lead to a failure:
    /// `{"clientExtensionResults":{}}`: no extensions.
    /// `{"clientExtensionResults":{"prf":true}}`: only the `prf` extension.
    /// `{"clientExtensionResults":{"credProps":{}}}`: empty `credProps` extension.
    /// `{"clientExtensionResults":{"credProps":{"foo":false}}}`: `credProps` extension doesn't contain at least one
    /// expected field (i.e., still "empty").
    fn validate_required(
        self,
        client_ext: ClientExtensionsOutputs,
        auth_ext: AuthenticatorExtensionOutput,
    ) -> Result<(), ExtensionErr> {
        // We don't check `self.cred_protect` since `CredProtect::validate` checks for both a required response
        // and value enforcement; thus it only needs to be checked once (which it is in `Self::validate_value`).
        self.cred_props
            .map_or(Ok(()), |info| {
                if matches!(info, ExtensionReq::Require) {
                    if client_ext
                        .cred_props
                        .is_some_and(|props| props.rk.is_some())
                    {
                        Ok(())
                    } else {
                        Err(ExtensionErr::MissingCredProps)
                    }
                } else {
                    Ok(())
                }
            })
            .and_then(|()| {
                self.min_pin_length
                    .map_or(Ok(()), |info| {
                        if matches!(
                            info.1,
                            ExtensionInfo::RequireEnforceValue
                                | ExtensionInfo::RequireDontEnforceValue
                        ) {
                            auth_ext
                                .min_pin_length
                                .ok_or(ExtensionErr::MissingMinPinLength)
                                .map(|_| ())
                        } else {
                            Ok(())
                        }
                    })
                    .and_then(|()| match self.prf {
                        ServerPrfInfo::None => Ok(()),
                        ServerPrfInfo::One(info) | ServerPrfInfo::Two(info) => {
                            if matches!(
                                info,
                                ExtensionInfo::RequireEnforceValue
                                    | ExtensionInfo::RequireDontEnforceValue
                            ) {
                                if client_ext.prf.is_some() {
                                    Ok(())
                                } else {
                                    Err(ExtensionErr::MissingPrf)
                                }
                            } else {
                                Ok(())
                            }
                        }
                    })
            })
    }
    /// Validates the value of any extensions sent from the client.
    ///
    /// Note missing and empty extensions are always OK.
    fn validate_value(
        self,
        client_ext: ClientExtensionsOutputs,
        auth_ext: AuthenticatorExtensionOutput,
    ) -> Result<(), ExtensionErr> {
        // This also checks for a missing response. Instead of duplicating that check, we only call
        // `self.cred_protect.validate` once here and not also in `Self::validate_required`.
        self.cred_protect
            .validate(auth_ext.cred_protect)
            .and_then(|()| {
                self.min_pin_length
                    .map_or(Ok(()), |info| {
                        if matches!(
                            info.1,
                            ExtensionInfo::RequireEnforceValue | ExtensionInfo::AllowEnforceValue
                        ) {
                            auth_ext.min_pin_length.map_or(Ok(()), |pin| {
                                if pin >= info.0 {
                                    Ok(())
                                } else {
                                    Err(ExtensionErr::InvalidMinPinLength(info.0, pin))
                                }
                            })
                        } else {
                            Ok(())
                        }
                    })
                    .and_then(|()| match self.prf {
                        ServerPrfInfo::None => Ok(()),
                        ServerPrfInfo::One(info) | ServerPrfInfo::Two(info) => {
                            if matches!(
                                info,
                                ExtensionInfo::RequireEnforceValue
                                    | ExtensionInfo::AllowEnforceValue
                            ) {
                                client_ext
                                    .prf
                                    .map_or(Ok(()), |prf| {
                                        if prf.enabled {
                                            Ok(())
                                        } else {
                                            Err(ExtensionErr::InvalidPrfValue)
                                        }
                                    })
                                    .and({
                                        if matches!(auth_ext.hmac_secret, HmacSecret::NotEnabled) {
                                            Err(ExtensionErr::InvalidHmacSecretValue)
                                        } else {
                                            Ok(())
                                        }
                                    })
                            } else {
                                Ok(())
                            }
                        }
                    })
            })
    }
}
impl From<Extension<'_, '_>> for ServerExtensionInfo {
    fn from(value: Extension<'_, '_>) -> Self {
        Self {
            cred_props: value.cred_props,
            cred_protect: value.cred_protect,
            min_pin_length: value.min_pin_length,
            prf: value.prf.into(),
        }
    }
}
#[cfg(test)]
impl PartialEq for ServerExtensionInfo {
    fn eq(&self, other: &Self) -> bool {
        self.prf == other.prf
    }
}
// This is essentially the `PublicKeyCredentialCreationOptions` used to create it; however to reduce
// memory usage, we remove all unnecessary data making an instance of this 48 bytes in size on
// `x86_64-unknown-linux-gnu` platforms when `USER_LEN` is `USER_HANDLE_MIN_LEN`.
/// State needed to be saved when beginning the registration ceremony.
///
/// Saves the necessary information associated with the [`CredentialCreationOptions`] used to create it
/// via [`CredentialCreationOptions::start_ceremony`] so that registration of a new credential can be
/// performed with [`Self::verify`].
///
/// `RegistrationServerState` implements [`Borrow`] of [`SentChallenge`]; thus to obtain the correct
/// `RegistrationServerState` associated with a [`Registration`], one should use its corresponding
/// [`Registration::challenge`].
#[derive(Debug)]
pub struct RegistrationServerState<const USER_LEN: usize> {
    /// [`mediation`](https://www.w3.org/TR/credential-management-1/#dom-credentialcreationoptions-mediation).
    mediation: CredentialMediationRequirement,
    // This is a `SentChallenge` since we need `RegistrationServerState` to be fetchable after receiving the
    // response from the client. This response must obviously be constructable; thus its challenge is a
    // `SentChallenge`.
    //
    // This must never be mutated since we want to ensure it is actually a `Challenge` (which
    // can only be constructed via `Challenge::new`). This is guaranteed to be true iff
    // `serializable_server_state` is not enabled. We avoid implementing `trait`s like `Hash` when that
    // is enabled.
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-challenge).
    challenge: SentChallenge,
    /// [`pubKeyCredParams`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-pubkeycredparams).
    pub_key_cred_params: CoseAlgorithmIdentifiers,
    /// [`authenticatorSelection`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-authenticatorselection).
    authenticator_selection: AuthenticatorSelectionCriteria,
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-extensions).
    extensions: ServerExtensionInfo,
    /// `Instant` the ceremony expires.
    #[cfg(not(feature = "serializable_server_state"))]
    expiration: Instant,
    /// `SystemTime` the ceremony expires.
    #[cfg(feature = "serializable_server_state")]
    expiration: SystemTime,
    /// User handle.
    user_id: UserHandle<USER_LEN>,
}
impl<const USER_LEN: usize> RegistrationServerState<USER_LEN> {
    #[cfg(all(test, feature = "custom", feature = "serializable_server_state"))]
    fn is_eq(&self, other: &Self) -> bool {
        self.mediation == other.mediation
            && self.challenge == other.challenge
            && self.pub_key_cred_params == other.pub_key_cred_params
            && self.authenticator_selection == other.authenticator_selection
            && self.extensions == other.extensions
            && self.expiration == other.expiration
            && self.user_id == other.user_id
    }
    /// Verifies `response` is valid based on `self` consuming `self` and returning a `RegisteredCredential` that
    /// borrows the necessary data from `response`.
    ///
    /// `rp_id` MUST be the same as the [`PublicKeyCredentialCreationOptions::rp_id`] used when starting the
    /// ceremony.
    ///
    /// It is _essential_ to ensure [`RegisteredCredential::id`] has not been previously registered; if
    /// so, the ceremony SHOULD be aborted and a failure reported. When saving `RegisteredCredential`, one may
    /// want to save the [`RpId`] and [`PublicKeyCredentialUserEntity`] information; however since [`RpId`] is
    /// likely static, that may not be necessary. User information is also likely static for a given [`UserHandle`]
    /// (which is saved in `RegisteredCredential`); so if such info is saved, one may want to save it once per
    /// `UserHandle` and not per `RegisteredCredential`.
    ///
    /// # Errors
    ///
    /// Errors iff `response` is not valid according to the
    /// [registration ceremony criteria](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)
    /// or violates any of the settings in `options`.
    #[inline]
    pub fn verify<'a, O: PartialEq<Origin<'a>>, T: PartialEq<Origin<'a>>>(
        self,
        rp_id: &RpId,
        response: &'a Registration,
        options: &RegistrationVerificationOptions<'_, '_, O, T>,
    ) -> Result<RegisteredCredential<'a, USER_LEN>, RegCeremonyErr> {
        // [Registration ceremony](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)
        // is handled by:
        //
        // 1. Calling code.
        // 2. Client code and the construction of `resp` (hopefully via [`Registration::deserialize`]).
        // 3. Client code and the construction of `resp` (hopefully via [`AuthenticatorAttestation::deserialize`]).
        // 4. Client code and the construction of `resp` (hopefully via [`ClientExtensionsOutputs::deserialize`]).
        // 5. [`Self::partial_validate`].
        // 6. [`Self::partial_validate`].
        // 7. [`Self::partial_validate`].
        // 8. [`Self::partial_validate`].
        // 9. [`Self::partial_validate`].
        // 10. [`Self::partial_validate`].
        // 11. [`Self::partial_validate`].
        // 12. [`Self::partial_validate`].
        // 13. [`Self::partial_validate`].
        // 14. [`Self::partial_validate`].
        // 15. Below.
        // 16. [`Self::partial_validate`].
        // 17. [`Self::partial_validate`].
        // 18. [`Self::partial_validate`].
        // 19. [`Self::partial_validate`].
        // 20. Below.
        // 21. [`Self::partial_validate`].
        // 22. [`Self::partial_validate`].
        // 23. N/A since only none and self attestations are supported.
        // 24. Always satisfied since only none and self attestations are supported (Item 3 is N/A).
        // 25. [`Self::partial_validate`].
        // 26. Calling code.
        // 27. Below.
        // 28. N/A since only none and self attestations are supported.
        // 29. Below.

        // Steps 5–14, 16–19, 21–22, and 25.
        self.partial_validate(rp_id, response, (), &options.into())
            .map_err(RegCeremonyErr::from)
            .and_then(|attestation_object| {
                let auth_data = attestation_object.auth_data();
                let flags = auth_data.flags();
                // Step 15.
                if matches!(self.mediation, CredentialMediationRequirement::Conditional)
                    || flags.user_present
                {
                    self.authenticator_selection
                        // Verify any required authenticator attachment modality.
                        .validate(
                            options.require_authenticator_attachment,
                            response.authenticator_attachment,
                        )
                        .and_then(|()| {
                            let attested_credential_data = auth_data.attested_credential_data();
                            self.pub_key_cred_params
                                // Step 20.
                                .validate(attested_credential_data.credential_public_key)
                                .and_then(|()| {
                                    let extensions = auth_data.extensions();
                                    // Step 27.
                                    self.extensions
                                        .validate(
                                            response.client_extension_results,
                                            extensions,
                                            options.error_on_unsolicited_extensions,
                                        )
                                        .map_err(RegCeremonyErr::Extension)
                                        .and_then(|()| {
                                            // Step 29.
                                            RegisteredCredential::new(
                                                attested_credential_data.credential_id,
                                                response.response.transports(),
                                                self.user_id,
                                                StaticState {
                                                    credential_public_key: attested_credential_data
                                                        .credential_public_key,
                                                    extensions: extensions.into(),
                                                    client_extension_results: response
                                                        .client_extension_results
                                                        .into(),
                                                },
                                                DynamicState {
                                                    user_verified: flags.user_verified,
                                                    backup: flags.backup,
                                                    sign_count: auth_data.sign_count(),
                                                    authenticator_attachment: response
                                                        .authenticator_attachment,
                                                },
                                                Metadata {
                                                    attestation: match attestation_object
                                                        .attestation()
                                                    {
                                                        AttestationFormat::None => {
                                                            Attestation::None
                                                        }
                                                        AttestationFormat::Packed(_) => {
                                                            Attestation::Surrogate
                                                        }
                                                    },
                                                    aaguid: attested_credential_data.aaguid,
                                                    extensions: extensions.into(),
                                                    client_extension_results: response
                                                        .client_extension_results
                                                        .into(),
                                                    resident_key: self
                                                        .authenticator_selection
                                                        .resident_key,
                                                },
                                            )
                                            .map_err(RegCeremonyErr::Credential)
                                        })
                                })
                        })
                } else {
                    Err(RegCeremonyErr::UserNotPresent)
                }
            })
    }
}
impl<const USER_LEN: usize> TimedCeremony for RegistrationServerState<USER_LEN> {
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    #[inline]
    fn expiration(&self) -> Instant {
        self.expiration
    }
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    #[inline]
    fn expiration(&self) -> SystemTime {
        self.expiration
    }
}
impl<const USER_LEN: usize> Ceremony<USER_LEN, false> for RegistrationServerState<USER_LEN> {
    type R = Registration;
    fn rand_challenge(&self) -> SentChallenge {
        self.challenge
    }
    #[cfg(not(feature = "serializable_server_state"))]
    fn expiry(&self) -> Instant {
        self.expiration
    }
    #[cfg(feature = "serializable_server_state")]
    fn expiry(&self) -> SystemTime {
        self.expiration
    }
    fn user_verification(&self) -> UserVerificationRequirement {
        self.authenticator_selection.user_verification
    }
}
impl<const USER_LEN: usize> Borrow<SentChallenge> for RegistrationServerState<USER_LEN> {
    #[inline]
    fn borrow(&self) -> &SentChallenge {
        &self.challenge
    }
}
impl<const USER_LEN: usize> PartialEq for RegistrationServerState<USER_LEN> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.challenge == other.challenge
    }
}
impl<const USER_LEN: usize> PartialEq<&Self> for RegistrationServerState<USER_LEN> {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl<const USER_LEN: usize> PartialEq<RegistrationServerState<USER_LEN>>
    for &RegistrationServerState<USER_LEN>
{
    #[inline]
    fn eq(&self, other: &RegistrationServerState<USER_LEN>) -> bool {
        **self == *other
    }
}
impl<const USER_LEN: usize> Eq for RegistrationServerState<USER_LEN> {}
impl<const USER_LEN: usize> Hash for RegistrationServerState<USER_LEN> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.challenge.hash(state);
    }
}
impl<const USER_LEN: usize> PartialOrd for RegistrationServerState<USER_LEN> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<const USER_LEN: usize> Ord for RegistrationServerState<USER_LEN> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.challenge.cmp(&other.challenge)
    }
}
/// `RegistrationServerState` based on a [`UserHandle64`].
pub type RegistrationServerState64 = RegistrationServerState<USER_HANDLE_MAX_LEN>;
/// `RegistrationServerState` based on a [`UserHandle16`].
pub type RegistrationServerState16 = RegistrationServerState<16>;
