extern crate alloc;
use super::{
    super::{
        DynamicState, Metadata, RegisteredCredential, StaticState,
        response::{
            AuthenticatorAttachment,
            register::{
                Attestation, AttestationFormat, AuthenticatorExtensionOutput,
                ClientExtensionsOutputs, CredentialProtectionPolicy, Registration,
                UncompressedPubKey,
                error::{ExtensionErr, RegCeremonyErr},
            },
        },
    },
    BackupReq, Ceremony, Challenge, CredentialMediationRequirement, ExtensionInfo, ExtensionReq,
    Hint, Origin, PublicKeyCredentialDescriptor, RpId, SentChallenge, THREE_HUNDRED_THOUSAND,
    TimedCeremony, UserVerificationRequirement,
    register::error::{CreationOptionsErr, NicknameErr, UsernameErr},
};
#[cfg(doc)]
use crate::{
    request::{AsciiDomain, DomainOrigin, Url, auth::PublicKeyCredentialRequestOptions},
    response::{AuthTransports, AuthenticatorTransport, Backup, CollectedClientData},
};
use alloc::borrow::Cow;
use core::{
    borrow::Borrow,
    cmp::Ordering,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};
use precis_profiles::{UsernameCasePreserved, precis_core::profile::Profile as _};
#[cfg(any(doc, not(feature = "serializable_server_state")))]
use std::time::Instant;
#[cfg(any(doc, feature = "serializable_server_state"))]
use std::time::SystemTime;
/// Contains functionality to (de)serialize data to a data store.
#[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
#[cfg(feature = "bin")]
pub mod bin;
/// Contains functionality that needs to be accessible when `bin` or `serde` are not enabled.
#[cfg_attr(docsrs, doc(cfg(feature = "custom")))]
#[cfg(feature = "custom")]
mod custom;
/// Contains error types.
pub mod error;
/// Contains functionality to serialize data to a client.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
pub(crate) mod ser;
/// Contains functionality to (de)serialize [`RegistrationServerState`] to a data store.
#[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
#[cfg(feature = "serializable_server_state")]
pub mod ser_server_state;
/// Used by [`Extension::cred_protect`] to enforce the [`CredentialProtectionPolicy`] sent by the client via
/// [`Registration`].
#[derive(Clone, Copy, Debug, Default)]
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
#[cfg(test)]
impl PartialEq for CredProtect {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::None => matches!(other, Self::None),
            Self::UserVerificationOptional(enforce, info) => {
                matches!(*other, Self::UserVerificationOptional(enforce2, info2) if enforce == enforce2 && info == info2)
            }
            Self::UserVerificationOptionalWithCredentialIdList(enforce, info) => {
                matches!(*other, Self::UserVerificationOptionalWithCredentialIdList(enforce2, info2) if enforce == enforce2 && info == info2)
            }
            Self::UserVerificationRequired(enforce, info) => {
                matches!(*other, Self::UserVerificationRequired(enforce2, info2) if enforce == enforce2 && info == info2)
            }
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
/// String returned from the [Nickname Enforcement rule](https://www.rfc-editor.org/rfc/rfc8266#section-2.3)
/// as defined in RFC 8266.
///
/// Note [string truncation](https://www.w3.org/TR/webauthn-3/#sctn-strings-truncation) is allowed, so one may
/// want to enforce [`Self::RECOMMENDED_MAX_LEN`].
#[derive(Clone, Debug)]
pub struct Nickname<'a>(Cow<'a, str>);
impl<'a> Nickname<'a> {
    /// The maximum allowed length.
    pub const MAX_LEN: usize = 1023;
    /// The recommended maximum length to allow.
    pub const RECOMMENDED_MAX_LEN: usize = 64;
    /// Returns a `Nickname` that consumes `self`. When `self` owns the data, the data is simply moved;
    /// when the data is borrowed, then it is cloned into an owned instance.
    #[inline]
    #[must_use]
    pub fn into_owned<'b>(self) -> Nickname<'b> {
        Nickname(Cow::Owned(self.0.into_owned()))
    }
    /// Same as [`Self::with_max_len`] except the length must not exceed [`Self::RECOMMENDED_MAX_LEN`] instead of
    /// [`Self::MAX_LEN`].
    ///
    /// # Errors
    ///
    /// Errors iff `value` violates [RFC 8266 § 2.3](https://www.rfc-editor.org/rfc/rfc8266.html#section-2.3)
    /// or the resulting length exceeds [`Self::RECOMMENDED_MAX_LEN`].
    #[inline]
    pub fn with_recommended_len<'b: 'a>(value: Cow<'b, str>) -> Result<Self, NicknameErr> {
        precis_profiles::Nickname::new()
            .enforce(value)
            .map_err(|_e| NicknameErr::Rfc8266)
            .and_then(|val| {
                if val.len() <= Self::RECOMMENDED_MAX_LEN {
                    Ok(Self(val))
                } else {
                    Err(NicknameErr::Len)
                }
            })
    }
    /// Same as [`Self::try_from`].
    /// # Errors
    ///
    /// Errors iff `value` violates [RFC 8266 § 2.3](https://www.rfc-editor.org/rfc/rfc8266.html#section-2.3)
    /// or the resulting length exceeds [`Self::MAX_LEN`].
    #[inline]
    pub fn with_max_len<'b: 'a>(value: Cow<'b, str>) -> Result<Self, NicknameErr> {
        Self::try_from(value)
    }
}
impl AsRef<str> for Nickname<'_> {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
impl Borrow<str> for Nickname<'_> {
    #[inline]
    fn borrow(&self) -> &str {
        self.0.as_ref()
    }
}
impl<'a: 'b, 'b> From<&'a Nickname<'_>> for Nickname<'b> {
    #[inline]
    fn from(value: &'a Nickname<'_>) -> Self {
        match value.0 {
            Cow::Borrowed(val) => Self(Cow::Borrowed(val)),
            Cow::Owned(ref val) => Self(Cow::Borrowed(val.as_str())),
        }
    }
}
impl<'a: 'b, 'b> From<Nickname<'a>> for Cow<'b, str> {
    #[inline]
    fn from(value: Nickname<'a>) -> Self {
        value.0
    }
}
impl<'a: 'b, 'b> TryFrom<Cow<'a, str>> for Nickname<'b> {
    type Error = NicknameErr;
    /// # Examples
    ///
    /// ```
    /// # use std::borrow::Cow;
    /// # use webauthn_rp::request::register::{error::NicknameErr, Nickname};
    /// assert_eq!(
    ///     Nickname::try_from(Cow::Borrowed("Srinivasa Ramanujan"))?.as_ref(),
    ///     "Srinivasa Ramanujan"
    /// );
    /// assert_eq!(
    ///     Nickname::try_from(Cow::Borrowed("श्रीनिवास रामानुजन्"))?.as_ref(),
    ///     "श्रीनिवास रामानुजन्"
    /// );
    /// // Empty strings are not valid.
    /// assert!(Nickname::try_from(Cow::Borrowed("")).map_or_else(
    ///     |e| matches!(e, NicknameErr::Rfc8266),
    ///     |_| false
    /// ));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn try_from(value: Cow<'a, str>) -> Result<Self, Self::Error> {
        precis_profiles::Nickname::new()
            .enforce(value)
            .map_err(|_e| NicknameErr::Rfc8266)
            .and_then(|val| {
                if val.len() <= Self::MAX_LEN {
                    Ok(Self(val))
                } else {
                    Err(NicknameErr::Len)
                }
            })
    }
}
impl<'a: 'b, 'b> TryFrom<&'a str> for Nickname<'b> {
    type Error = NicknameErr;
    /// Same as [`Nickname::try_from`] except the input is a `str`.
    #[inline]
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::try_from(Cow::Borrowed(value))
    }
}
impl TryFrom<String> for Nickname<'_> {
    type Error = NicknameErr;
    /// Same as [`Nickname::try_from`] except the input is a `String`.
    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(Cow::Owned(value))
    }
}
impl PartialEq<Nickname<'_>> for Nickname<'_> {
    #[inline]
    fn eq(&self, other: &Nickname<'_>) -> bool {
        self.0 == other.0
    }
}
impl PartialEq<&Nickname<'_>> for Nickname<'_> {
    #[inline]
    fn eq(&self, other: &&Nickname<'_>) -> bool {
        *self == **other
    }
}
impl PartialEq<Nickname<'_>> for &Nickname<'_> {
    #[inline]
    fn eq(&self, other: &Nickname<'_>) -> bool {
        **self == *other
    }
}
impl Eq for Nickname<'_> {}
impl Hash for Nickname<'_> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl PartialOrd<Nickname<'_>> for Nickname<'_> {
    #[inline]
    fn partial_cmp(&self, other: &Nickname<'_>) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
impl Ord for Nickname<'_> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
/// String returned from the
/// [UsernameCasePreserved Enforcement rule](https://www.rfc-editor.org/rfc/rfc8265#section-3.4.3) as defined in
/// RFC 8265.
///
/// Note [string truncation](https://www.w3.org/TR/webauthn-3/#sctn-strings-truncation) is allowed, so one may
/// want to enforce [`Self::RECOMMENDED_MAX_LEN`].
#[derive(Clone, Debug)]
pub struct Username<'a>(Cow<'a, str>);
impl<'a> Username<'a> {
    /// The maximum allowed length.
    pub const MAX_LEN: usize = 1023;
    /// The recommended maximum length to allow.
    pub const RECOMMENDED_MAX_LEN: usize = 64;
    /// Returns a `Username` that consumes `self`. When `self` owns the data, the data is simply moved;
    /// when the data is borrowed, then it is cloned into an owned instance.
    #[inline]
    #[must_use]
    pub fn into_owned<'b>(self) -> Username<'b> {
        Username(Cow::Owned(self.0.into_owned()))
    }
    /// Same as [`Self::with_max_len`] except the length must not exceed [`Self::RECOMMENDED_MAX_LEN`] instead of
    /// [`Self::MAX_LEN`].
    ///
    /// # Errors
    ///
    /// Errors iff `value` violates [RFC 8265 § 3.4.3](https://www.rfc-editor.org/rfc/rfc8265.html#section-3.4.3)
    /// or the resulting length exceeds [`Self::RECOMMENDED_MAX_LEN`].
    #[inline]
    pub fn with_recommended_len<'b: 'a>(value: Cow<'b, str>) -> Result<Self, UsernameErr> {
        UsernameCasePreserved::default()
            .enforce(value)
            .map_err(|_e| UsernameErr::Rfc8265)
            .and_then(|val| {
                if val.len() <= Self::RECOMMENDED_MAX_LEN {
                    Ok(Self(val))
                } else {
                    Err(UsernameErr::Len)
                }
            })
    }
    /// Same as [`Self::try_from`].
    /// # Errors
    ///
    /// Errors iff `value` violates [RFC 8265 § 3.4.3](https://www.rfc-editor.org/rfc/rfc8265.html#section-3.4.3)
    /// or the resulting length exceeds [`Self::MAX_LEN`].
    #[inline]
    pub fn with_max_len<'b: 'a>(value: Cow<'b, str>) -> Result<Self, UsernameErr> {
        Self::try_from(value)
    }
}
impl AsRef<str> for Username<'_> {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
impl Borrow<str> for Username<'_> {
    #[inline]
    fn borrow(&self) -> &str {
        self.0.as_ref()
    }
}
impl<'a: 'b, 'b> TryFrom<Cow<'a, str>> for Username<'b> {
    type Error = UsernameErr;
    /// # Examples
    ///
    /// ```
    /// # use std::borrow::Cow;
    /// # use webauthn_rp::request::register::{error::UsernameErr, Username};
    /// assert_eq!(
    ///     Username::try_from(Cow::Borrowed("leonhard.euler"))?.as_ref(),
    ///     "leonhard.euler"
    /// );
    /// // Empty strings are not valid.
    /// assert!(Username::try_from(Cow::Borrowed("")).map_or_else(
    ///     |e| matches!(e, UsernameErr::Rfc8265),
    ///     |_| false
    /// ));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn try_from(value: Cow<'a, str>) -> Result<Self, Self::Error> {
        UsernameCasePreserved::default()
            .enforce(value)
            .map_err(|_e| UsernameErr::Rfc8265)
            .and_then(|val| {
                if val.len() <= Self::MAX_LEN {
                    Ok(Self(val))
                } else {
                    Err(UsernameErr::Len)
                }
            })
    }
}
impl<'a: 'b, 'b> TryFrom<&'a str> for Username<'b> {
    type Error = UsernameErr;
    /// Same as [`Username::try_from`] except the input is a `str`.
    #[inline]
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Self::try_from(Cow::Borrowed(value))
    }
}
impl TryFrom<String> for Username<'_> {
    type Error = UsernameErr;
    /// Same as [`Username::try_from`] except the input is a `String`.
    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(Cow::Owned(value))
    }
}
impl<'a: 'b, 'b> From<Username<'a>> for Cow<'b, str> {
    #[inline]
    fn from(value: Username<'a>) -> Self {
        value.0
    }
}
impl<'a: 'b, 'b> From<&'a Username<'_>> for Username<'b> {
    #[inline]
    fn from(value: &'a Username<'_>) -> Self {
        match value.0 {
            Cow::Borrowed(val) => Self(Cow::Borrowed(val)),
            Cow::Owned(ref val) => Self(Cow::Borrowed(val.as_str())),
        }
    }
}
impl PartialEq<Username<'_>> for Username<'_> {
    #[inline]
    fn eq(&self, other: &Username<'_>) -> bool {
        self.0 == other.0
    }
}
impl PartialEq<&Username<'_>> for Username<'_> {
    #[inline]
    fn eq(&self, other: &&Username<'_>) -> bool {
        *self == **other
    }
}
impl PartialEq<Username<'_>> for &Username<'_> {
    #[inline]
    fn eq(&self, other: &Username<'_>) -> bool {
        **self == *other
    }
}
impl Eq for Username<'_> {}
impl Hash for Username<'_> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl PartialOrd<Username<'_>> for Username<'_> {
    #[inline]
    fn partial_cmp(&self, other: &Username<'_>) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
impl Ord for Username<'_> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
/// [`COSEAlgorithmIdentifier`](https://www.w3.org/TR/webauthn-3/#typedefdef-cosealgorithmidentifier).
///
/// Note the order of variants is the following:
///
/// [`Self::Eddsa`] `<` [`Self::Es256`] `<` [`Self::Es384`] `<` [`Self::Rs256`].
///
/// This is relevant for [`CoseAlgorithmIdentifiers`]. For example a `CoseAlgorithmIdentifiers`
/// that contains `Self::Eddsa` will prioritize it over all others.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoseAlgorithmIdentifier {
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
            Self::Eddsa => 1,
            Self::Es256 => 2,
            Self::Es384 => 4,
            Self::Rs256 => 8,
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
#[derive(Clone, Copy, Debug)]
pub struct CoseAlgorithmIdentifiers(u8);
impl CoseAlgorithmIdentifiers {
    /// Contains all [`CoseAlgorithmIdentifier`]s.
    pub const ALL: Self = Self(0)
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
#[cfg(test)]
impl PartialEq for CoseAlgorithmIdentifiers {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
/// `newtype` of `u8` bound inclusively between [`Self::MIN`] and [`Self::MAX`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FourToSixtyThree(u8);
impl FourToSixtyThree {
    /// Minimum inner value.
    const MIN_INNER: u8 = 4;
    /// Maximum inner value.
    const MAX_INNER: u8 = 63;
    /// Minimum value.
    pub const MIN: Self = Self(Self::MIN_INNER);
    /// Maximum value.
    pub const MAX: Self = Self(Self::MAX_INNER);
    /// Returns `Self` iff `val` is inclusively between [`Self::MIN`] and [`Self::MAX`].
    #[inline]
    #[must_use]
    pub const fn new(val: u8) -> Option<Self> {
        match val {
            Self::MIN_INNER..=Self::MAX_INNER => Some(Self(val)),
            _ => None,
        }
    }
    /// Returns the contained value.
    #[inline]
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}
impl Display for FourToSixtyThree {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl From<FourToSixtyThree> for u8 {
    #[inline]
    fn from(value: FourToSixtyThree) -> Self {
        value.0
    }
}
impl Default for FourToSixtyThree {
    /// Returns [`Self::MIN`].
    #[inline]
    fn default() -> Self {
        Self::MIN
    }
}
/// The [defined extensions](https://www.w3.org/TR/webauthn-3/#sctn-defined-extensions) to send to the client.
#[derive(Clone, Copy, Debug, Default)]
pub struct Extension {
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
    /// Note for
    /// [CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// this is only used to instruct the authenticator to create the necessary `hmac-secret` since it does not
    /// currently support PRF evaluation at creation time. This also requires
    /// [`UserVerificationRequirement::Required`].
    ///
    /// While many authenticators will be able to use the `prf` extension during authentication when this is not
    /// passed during registration, it is recommended to still pass this during registration in the event the
    /// authenticator does require it during registration.
    pub prf: Option<ExtensionInfo>,
}
impl Extension {
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
                    if self.prf.is_some() {
                        Ok(())
                    } else if client_ext.prf.is_some() {
                        Err(ExtensionErr::ForbiddenPrf)
                    } else if auth_ext.hmac_secret.is_some() {
                        Err(ExtensionErr::ForbiddenHmacSecret)
                    } else {
                        Ok(())
                    }
                } else if auth_ext.min_pin_length.is_some() {
                    Err(ExtensionErr::ForbiddenMinPinLength)
                } else {
                    // Pretend to set `minPinLength`, so we can check `prf`.
                    self.min_pin_length =
                        Some((FourToSixtyThree::MIN, ExtensionInfo::RequireEnforceValue));
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
                    .and_then(|()| {
                        self.prf.map_or(Ok(()), |info| {
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
                        })
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
                    .and_then(|()| {
                        self.prf.map_or(Ok(()), |info| {
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
                                    .and_then(|()| {
                                        auth_ext.hmac_secret.map_or(Ok(()), |hmac| {
                                            if hmac {
                                                Ok(())
                                            } else {
                                                Err(ExtensionErr::InvalidHmacSecretValue)
                                            }
                                        })
                                    })
                            } else {
                                Ok(())
                            }
                        })
                    })
            })
    }
}
#[cfg(test)]
impl PartialEq for Extension {
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
    #[cfg_attr(docsrs, doc(cfg(feature = "custom")))]
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
    pub name: Username<'name>,
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id).
    pub id: &'id UserHandle<LEN>,
    /// [`displayName`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-displayname).
    ///
    /// `None` iff the display name should be the empty string.
    pub display_name: Option<Nickname<'display_name>>,
}
impl<'a: 'b, 'b, const LEN: usize> From<&'a UserHandle<LEN>>
    for PublicKeyCredentialUserEntity<'_, '_, 'b, LEN>
{
    /// Returns a `PublicKeyCredentialUserEntity` with [`Self::name`] set to `"blank"`,
    /// [`Self::id`] set to `value`, and [`Self::display_name`] set to `None`.
    ///
    /// One should let users set their own user name and user display name; however this can technically happen
    /// _after_ successfully completing the registration ceremony since this information is not used during
    /// [`RegistrationServerState::verify`]. For example the client can send such information along with
    /// [`Registration`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{PublicKeyCredentialUserEntity, UserHandle64};
    /// let user_handle = UserHandle64::new();
    /// let entity = PublicKeyCredentialUserEntity::from(&user_handle);
    /// assert_eq!("blank", entity.name.as_ref());
    /// assert_eq!(user_handle, *entity.id);
    /// assert!(entity.display_name.is_none());
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    #[inline]
    fn from(value: &'a UserHandle<LEN>) -> Self {
        Self {
            name: Username::try_from("blank")
                .unwrap_or_else(|_e| unreachable!("'blank' is no longer a valid Username")),
            id: value,
            display_name: None,
        }
    }
}
/// `PublicKeyCredentialUserEntity` based on a [`UserHandle64`].
pub type PublicKeyCredentialUserEntity64<'name, 'display_name, 'id> =
    PublicKeyCredentialUserEntity<'name, 'display_name, 'id, USER_HANDLE_MAX_LEN>;
/// `PublicKeyCredentialUserEntity` based on a [`UserHandle16`].
pub type PublicKeyCredentialUserEntity16<'name, 'display_name, 'id> =
    PublicKeyCredentialUserEntity<'name, 'display_name, 'id, 16>;
/// [`ResidentKeyRequirement`](https://www.w3.org/TR/webauthn-3/#enumdef-residentkeyrequirement) sent to the client.
#[derive(Clone, Copy, Debug)]
pub enum ResidentKeyRequirement {
    /// [`required`](https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-required).
    Required,
    /// [`discouraged`](https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-discouraged).
    Discouraged,
    /// [`preferred`](https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-preferred).
    Preferred,
}
#[cfg(test)]
impl PartialEq for ResidentKeyRequirement {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::Required => matches!(other, Self::Required),
            Self::Discouraged => matches!(other, Self::Discouraged),
            Self::Preferred => matches!(other, Self::Preferred),
        }
    }
}
/// [`PublicKeyCredentialHints`](https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint)
/// for [`AuthenticatorAttachment::CrossPlatform`] authenticators.
#[derive(Clone, Copy, Debug, Default)]
pub enum CrossPlatformHint {
    /// No hints.
    #[default]
    None,
    /// [`security-key`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-security-key).
    SecurityKey,
    /// [`hybrid`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-hybrid).
    Hybrid,
    /// [`Self::SecurityKey`] and [`Self::Hybrid`].
    SecurityKeyHybrid,
    /// [`Self::Hybrid`] and [`Self::SecurityKey`].
    HybridSecurityKey,
}
impl From<CrossPlatformHint> for Hint {
    #[inline]
    fn from(value: CrossPlatformHint) -> Self {
        match value {
            CrossPlatformHint::None => Self::None,
            CrossPlatformHint::SecurityKey => Self::SecurityKey,
            CrossPlatformHint::Hybrid => Self::Hybrid,
            CrossPlatformHint::SecurityKeyHybrid => Self::SecurityKeyHybrid,
            CrossPlatformHint::HybridSecurityKey => Self::HybridSecurityKey,
        }
    }
}
#[cfg(test)]
impl PartialEq for CrossPlatformHint {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::None => matches!(other, Self::None),
            Self::SecurityKey => matches!(other, Self::SecurityKey),
            Self::Hybrid => matches!(other, Self::Hybrid),
            Self::SecurityKeyHybrid => matches!(other, Self::SecurityKeyHybrid),
            Self::HybridSecurityKey => matches!(other, Self::HybridSecurityKey),
        }
    }
}
/// [`PublicKeyCredentialHints`](https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint)
/// for [`AuthenticatorAttachment::Platform`] authenticators.
#[derive(Clone, Copy, Debug, Default)]
pub enum PlatformHint {
    /// No hints.
    #[default]
    None,
    /// [`client-device`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-client-device).
    ClientDevice,
}
impl From<PlatformHint> for Hint {
    #[inline]
    fn from(value: PlatformHint) -> Self {
        match value {
            PlatformHint::None => Self::None,
            PlatformHint::ClientDevice => Self::ClientDevice,
        }
    }
}
#[cfg(test)]
impl PartialEq for PlatformHint {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::None => matches!(other, Self::None),
            Self::ClientDevice => matches!(other, Self::ClientDevice),
        }
    }
}
/// [`AuthenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment)
/// requirement with associated hints for further refinement.
#[derive(Clone, Copy, Debug)]
pub enum AuthenticatorAttachmentReq {
    /// No attachment information (i.e., any [`AuthenticatorAttachment`]).
    None(Hint),
    /// [`platform`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattachment-platform) is required
    /// to be used.
    Platform(PlatformHint),
    /// [`cross-platform`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattachment-cross-platform) is
    /// required to be used.
    CrossPlatform(CrossPlatformHint),
}
impl Default for AuthenticatorAttachmentReq {
    #[inline]
    fn default() -> Self {
        Self::None(Hint::default())
    }
}
impl AuthenticatorAttachmentReq {
    /// Validates `self` against `other` ignoring [`Self::immutable_attachment`].
    const fn validate(
        self,
        require_response: bool,
        other: AuthenticatorAttachment,
    ) -> Result<(), RegCeremonyErr> {
        match self {
            Self::None(_) => {
                if require_response && matches!(other, AuthenticatorAttachment::None) {
                    Err(RegCeremonyErr::MissingAuthenticatorAttachment)
                } else {
                    Ok(())
                }
            }
            Self::Platform(_) => match other {
                AuthenticatorAttachment::None => {
                    if require_response {
                        Err(RegCeremonyErr::MissingAuthenticatorAttachment)
                    } else {
                        Ok(())
                    }
                }
                AuthenticatorAttachment::Platform => Ok(()),
                AuthenticatorAttachment::CrossPlatform => {
                    Err(RegCeremonyErr::AuthenticatorAttachmentMismatch)
                }
            },
            Self::CrossPlatform(_) => match other {
                AuthenticatorAttachment::None => {
                    if require_response {
                        Err(RegCeremonyErr::MissingAuthenticatorAttachment)
                    } else {
                        Ok(())
                    }
                }
                AuthenticatorAttachment::CrossPlatform => Ok(()),
                AuthenticatorAttachment::Platform => {
                    Err(RegCeremonyErr::AuthenticatorAttachmentMismatch)
                }
            },
        }
    }
}
#[cfg(test)]
impl PartialEq for AuthenticatorAttachmentReq {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::None(info) => matches!(*other, Self::None(info2) if info == info2),
            Self::Platform(info) => matches!(*other, Self::Platform(info2) if info == info2),
            Self::CrossPlatform(info) => {
                matches!(*other, Self::CrossPlatform(info2) if info == info2)
            }
        }
    }
}
/// [`AuthenticatorSelectionCriteria`](https://www.w3.org/TR/webauthn-3/#dictionary-authenticatorSelection).
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatorSelectionCriteria {
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorselectioncriteria-authenticatorattachment).
    pub authenticator_attachment: AuthenticatorAttachmentReq,
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
    /// # use webauthn_rp::request::{
    /// #     register::{
    /// #         AuthenticatorAttachmentReq, AuthenticatorSelectionCriteria, ResidentKeyRequirement,
    /// #     },
    /// #     Hint, UserVerificationRequirement,
    /// # };
    /// let crit = AuthenticatorSelectionCriteria::passkey();
    /// assert!(
    ///     matches!(crit.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
    /// );
    /// assert!(matches!(
    ///     crit.resident_key,
    ///     ResidentKeyRequirement::Required
    /// ));
    /// assert!(matches!(
    ///     crit.user_verification,
    ///     UserVerificationRequirement::Required
    /// ));
    /// ```
    #[inline]
    #[must_use]
    pub fn passkey() -> Self {
        Self {
            authenticator_attachment: AuthenticatorAttachmentReq::default(),
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
    /// # use webauthn_rp::request::{
    /// #     register::{
    /// #         AuthenticatorAttachmentReq, AuthenticatorSelectionCriteria, ResidentKeyRequirement,
    /// #     },
    /// #     Hint, UserVerificationRequirement,
    /// # };
    /// let crit = AuthenticatorSelectionCriteria::second_factor();
    /// assert!(
    ///     matches!(crit.authenticator_attachment, AuthenticatorAttachmentReq::None(hint) if matches!(hint, Hint::None))
    /// );
    /// assert!(matches!(
    ///     crit.resident_key,
    ///     ResidentKeyRequirement::Discouraged
    /// ));
    /// assert!(matches!(
    ///     crit.user_verification,
    ///     UserVerificationRequirement::Discouraged
    /// ));
    /// ```
    #[inline]
    #[must_use]
    pub fn second_factor() -> Self {
        Self {
            authenticator_attachment: AuthenticatorAttachmentReq::default(),
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
#[cfg(test)]
impl PartialEq for AuthenticatorSelectionCriteria {
    fn eq(&self, other: &Self) -> bool {
        self.authenticator_attachment == other.authenticator_attachment
            && self.resident_key == other.resident_key
            && self.user_verification == other.user_verification
    }
}
/// Helper that verifies the overlap of [`PublicKeyCredentialCreationOptions::start_ceremony`] and
/// [`RegistrationServerState::decode`].
const fn validate_options_helper(
    auth_crit: AuthenticatorSelectionCriteria,
    extensions: Extension,
) -> Result<(), CreationOptionsErr> {
    if matches!(
        auth_crit.user_verification,
        UserVerificationRequirement::Required
    ) {
        Ok(())
    } else if extensions.prf.is_some() {
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
/// The [`PublicKeyCredentialCreationOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialcreationoptions)
/// to send to the client when registering a new credential.
///
/// Upon saving the [`RegistrationServerState`] returned from [`Self::start_ceremony`], one MUST send
/// [`RegistrationClientState`] to the client ASAP. After receiving the newly created [`Registration`], it is
/// validated using [`RegistrationServerState::verify`].
#[derive(Debug)]
pub struct PublicKeyCredentialCreationOptions<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    const USER_LEN: usize,
> {
    /// [`mediation`](https://www.w3.org/TR/credential-management-1/#dom-credentialcreationoptions-mediation).
    pub mediation: CredentialMediationRequirement,
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
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor<Vec<u8>>>,
    /// [`authenticatorSelection`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-authenticatorselection).
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-extensions).
    pub extensions: Extension,
}
impl<'rp_id, 'user_name, 'user_display_name, 'user_id, const USER_LEN: usize>
    PublicKeyCredentialCreationOptions<'rp_id, 'user_name, 'user_display_name, 'user_id, USER_LEN>
{
    /// Most deployments of passkeys should use this function. Specifically deployments that are both userless and
    /// passwordless and desire multi-factor authentication (MFA) to be done entirely on the authenticator. It
    /// is important `exclude_credentials` contains the information for _all_ [`RegisteredCredential`]s registered to
    /// [`PublicKeyCredentialUserEntity::id`] to avoid accidentally overwriting existing credentials that
    /// have been previously registered.
    ///
    /// Creates a `PublicKeyCredentialCreationOptions` that requires the authenticator to create a client-side
    /// discoverable credential enforcing any form of user verification. A five-minute timeout is set.
    /// [`Extension::cred_protect`] with [`CredProtect::UserVerificationRequired`] with `false` and
    /// [`ExtensionInfo::AllowEnforceValue`] is used. [`Self::mediation`] is
    /// [`CredentialMediationRequirement::Optional`].
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
    ///             name: "archimedes.of.syracuse".try_into()?,
    ///             id: &UserHandle64::new(),
    ///             display_name: Some("Αρχιμήδης ο Συρακούσιος".try_into()?),
    ///         },
    ///         Vec::new()
    ///     )
    ///     .authenticator_selection.user_verification, UserVerificationRequirement::Required
    /// ));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn passkey<'a: 'rp_id, 'b: 'user_name, 'c: 'user_display_name, 'd: 'user_id>(
        rp_id: &'a RpId,
        user: PublicKeyCredentialUserEntity<'b, 'c, 'd, USER_LEN>,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Vec<u8>>>,
    ) -> Self {
        Self {
            mediation: CredentialMediationRequirement::Optional,
            rp_id,
            user,
            challenge: Challenge::new(),
            pub_key_cred_params: CoseAlgorithmIdentifiers::default(),
            timeout: THREE_HUNDRED_THOUSAND,
            exclude_credentials,
            authenticator_selection: AuthenticatorSelectionCriteria::passkey(),
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
    /// Convenience function for [`Self::passkey`] passing an empty `Vec`.
    ///
    /// This MUST only be used when this is the first credential for a user.
    #[inline]
    #[must_use]
    pub fn first_passkey<'a: 'rp_id, 'b: 'user_name, 'c: 'user_display_name, 'd: 'user_id>(
        rp_id: &'a RpId,
        user: PublicKeyCredentialUserEntity<'b, 'c, 'd, USER_LEN>,
    ) -> Self {
        Self::passkey(rp_id, user, Vec::new())
    }
    /// Convenience function for [`Self::first_passkey`] passing [`PublicKeyCredentialUserEntity::from`] applied
    /// to `user_id` for `user`.
    ///
    /// This MUST only be used when user information is provided _after_ registration (e.g., when the client
    /// sends user name and user display name along with [`Registration`]).
    ///
    /// Because user information is likely known for existing accounts, this will often only be called during
    /// greenfield deployments.
    #[inline]
    #[must_use]
    pub fn first_passkey_with_blank_user_info<'a: 'rp_id, 'b: 'user_id>(
        rp_id: &'a RpId,
        user_id: &'b UserHandle<USER_LEN>,
    ) -> Self {
        Self::first_passkey(rp_id, user_id.into())
    }
    /// Deployments that want to incorporate a "something a user has" factor into a larger multi-factor
    /// authentication (MFA) setup. Specifically deployments that are _not_ userless or passwordless. It
    /// is important `exclude_credentials` contains the information for _all_ [`RegisteredCredential`]s registered
    /// to [`PublicKeyCredentialUserEntity::id`] to avoid accidentally overwriting existing credentials that
    /// have been previously registered.
    ///
    /// Creates a `PublicKeyCredentialCreationOptions` that prefers the authenticator to create a server-side
    /// credential without requiring user verification. A five-minute timeout is set. [`Extension::cred_props`]
    /// is [`ExtensionReq::Allow`]. [`Extension::cred_protect`] is
    /// [`CredProtect::UserVerificationOptionalWithCredentialIdList`] with `false` and
    /// [`ExtensionInfo::AllowEnforceValue`]. [`Self::mediation`] is [`CredentialMediationRequirement::Optional`].
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
    ///             name: "carl.gauss".try_into()?,
    ///             id: &UserHandle64::new(),
    ///             display_name: Some("Johann Carl Friedrich Gauß".try_into()?),
    ///         },
    ///         Vec::new()
    ///     )
    ///     .timeout
    ///     .get(),
    ///     300_000
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn second_factor<'a: 'rp_id, 'b: 'user_name, 'c: 'user_display_name, 'd: 'user_id>(
        rp_id: &'a RpId,
        user: PublicKeyCredentialUserEntity<'b, 'c, 'd, USER_LEN>,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Vec<u8>>>,
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
    /// Convenience function for [`Self::second_factor`] passing an empty `Vec`.
    ///
    /// This MUST only be used when this is the first credential for a user.
    #[inline]
    #[must_use]
    pub fn first_second_factor<'a: 'rp_id, 'b: 'user_name, 'c: 'user_display_name, 'd: 'user_id>(
        rp_id: &'a RpId,
        user: PublicKeyCredentialUserEntity<'b, 'c, 'd, USER_LEN>,
    ) -> Self {
        Self::second_factor(rp_id, user, Vec::new())
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
    /// #     register::{PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle64},
    /// #     AsciiDomain, RpId
    /// # };
    /// # #[cfg(not(feature = "serializable_server_state"))]
    /// assert!(
    ///     PublicKeyCredentialCreationOptions::passkey(
    ///         &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         PublicKeyCredentialUserEntity {
    ///             name: "bernard.riemann".try_into()?,
    ///             id: &UserHandle64::new(),
    ///             display_name: Some("Georg Friedrich Bernhard Riemann".try_into()?)
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
            RegistrationClientState<'rp_id, 'user_name, 'user_display_name, 'user_id, USER_LEN>,
        ),
        CreationOptionsErr,
    > {
        validate_options_helper(self.authenticator_selection, self.extensions).and_then(|()| {
            #[cfg(not(feature = "serializable_server_state"))]
            let now = Instant::now();
            #[cfg(feature = "serializable_server_state")]
            let now = SystemTime::now();
            now.checked_add(Duration::from_millis(NonZeroU64::from(self.timeout).get()))
                .ok_or(CreationOptionsErr::InvalidTimeout)
                .map(|expiration| {
                    // We remove duplicates. The order has no significance, so this is OK.
                    self.exclude_credentials
                        .sort_unstable_by(|a, b| a.id.as_ref().cmp(b.id.as_ref()));
                    self.exclude_credentials
                        .dedup_by(|a, b| a.id.as_ref() == b.id.as_ref());
                    (
                        RegistrationServerState {
                            mediation: self.mediation,
                            challenge: SentChallenge(self.challenge.0),
                            pub_key_cred_params: self.pub_key_cred_params,
                            authenticator_selection: self.authenticator_selection,
                            extensions: self.extensions,
                            expiration,
                            user_id: *self.user.id,
                        },
                        RegistrationClientState(self),
                    )
                })
        })
    }
}
/// `PublicKeyCredentialCreationOptions` based on a [`UserHandle64`].
pub type PublicKeyCredentialCreationOptions64<'rp_id, 'user_name, 'user_display_name, 'user_id> =
    PublicKeyCredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        USER_HANDLE_MAX_LEN,
    >;
/// `PublicKeyCredentialCreationOptions` based on a [`UserHandle16`].
pub type PublicKeyCredentialCreationOptions16<'rp_id, 'user_name, 'user_display_name, 'user_id> =
    PublicKeyCredentialCreationOptions<'rp_id, 'user_name, 'user_display_name, 'user_id, 16>;
/// Container of a [`PublicKeyCredentialCreationOptions`] that has been used to start the registration ceremony.
/// This gets sent to the client ASAP.
#[derive(Debug)]
pub struct RegistrationClientState<
    'rp_id,
    'user_name,
    'user_display_name,
    'user_id,
    const USER_LEN: usize,
>(PublicKeyCredentialCreationOptions<'rp_id, 'user_name, 'user_display_name, 'user_id, USER_LEN>);
impl<'rp_id, 'user_name, 'user_display_name, 'user_id, const USER_LEN: usize>
    RegistrationClientState<'rp_id, 'user_name, 'user_display_name, 'user_id, USER_LEN>
{
    /// Returns the `PublicKeyCredentialCreationOptions` that was used to start a registration ceremony.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{register::{
    /// #     CoseAlgorithmIdentifiers, PublicKeyCredentialCreationOptions,
    /// #     PublicKeyCredentialUserEntity, UserHandle64,
    /// # }, AsciiDomain, RpId};
    /// assert_eq!(
    ///     PublicKeyCredentialCreationOptions::passkey(
    ///         &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         PublicKeyCredentialUserEntity {
    ///             name: "david.hilbert".try_into()?,
    ///             id: &UserHandle64::new(),
    ///             display_name: Some("David Hilbert".try_into()?)
    ///         },
    ///         Vec::new()
    ///     )
    ///     .start_ceremony()?
    ///     .1
    ///     .options()
    ///     .rp_id.as_ref(),
    ///     "example.com"
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn options(
        &self,
    ) -> &PublicKeyCredentialCreationOptions<
        'rp_id,
        'user_name,
        'user_display_name,
        'user_id,
        USER_LEN,
    > {
        &self.0
    }
}
/// `RegistrationClientState` based on a [`UserHandle64`].
pub type RegistrationClientState64<'rp_id, 'user_name, 'user_display_name, 'user_id> =
    RegistrationClientState<'rp_id, 'user_name, 'user_display_name, 'user_id, USER_HANDLE_MAX_LEN>;
/// `RegistrationClientState` based on a [`UserHandle16`].
pub type RegistrationClientState16<'rp_id, 'user_name, 'user_display_name, 'user_id> =
    RegistrationClientState<'rp_id, 'user_name, 'user_display_name, 'user_id, 16>;
/// Additional verification options to perform in [`RegistrationServerState::verify`].
#[derive(Clone, Copy, Debug)]
pub struct RegistrationVerificationOptions<'origins, 'top_origins, O, T> {
    /// Origins to use for [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin).
    ///
    /// When this is empty, the origin that will be used will be based on
    /// the [`RpId`] passed to [`RegistrationServerState::verify`]. If [`RpId::Domain`], then the [`DomainOrigin`] returned from
    /// passing [`AsciiDomain::as_ref`] to [`DomainOrigin::new`] will be used; otherwise the [`Url`] in
    /// [`RpId::Url`] will be used.
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
    #[cfg_attr(docsrs, doc(cfg(feature = "serde_relaxed")))]
    #[cfg(feature = "serde_relaxed")]
    pub client_data_json_relaxed: bool,
}
impl<O, T> Default for RegistrationVerificationOptions<'_, '_, O, T> {
    /// Returns `Self` such that [`Self::allowed_origins`] is empty, [`Self::allowed_top_origins`] is `None`,
    /// [`Self::backup_requirement`] is [`BackupReq::None`], [`Self::error_on_unsolicited_extensions`] is `true`,
    /// [`Self::require_authenticator_attachment`] is `false`, and [`Self::client_data_json_relaxed`] is
    /// `true`.
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
// This is essentially the `PublicKeyCredentialCreationOptions` used to create it; however to reduce
// memory usage, we remove all unnecessary data making an instance of this 48 bytes in size on
// `x86_64-unknown-linux-gnu` platforms.
/// State needed to be saved when beginning the registration ceremony.
///
/// Saves the necessary information associated with the [`PublicKeyCredentialCreationOptions`] used to create it
/// via [`PublicKeyCredentialCreationOptions::start_ceremony`] so that registration of a new credential can be
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
    extensions: Extension,
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
#[cfg(all(test, feature = "custom", feature = "serializable_server_state"))]
impl<const USER_LEN: usize> RegistrationServerState<USER_LEN> {
    fn is_eq(&self, other: &Self) -> bool {
        self.mediation == other.mediation
            && self.challenge == other.challenge
            && self.pub_key_cred_params == other.pub_key_cred_params
            && self.authenticator_selection == other.authenticator_selection
            && self.extensions == other.extensions
            && self.expiration == other.expiration
            && self.user_id == other.user_id
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
#[cfg(test)]
mod tests {
    #[cfg(all(
        feature = "custom",
        any(
            feature = "serializable_server_state",
            not(any(feature = "bin", feature = "serde"))
        )
    ))]
    use super::{
        super::{super::AggErr, ExtensionInfo},
        Challenge, CredProtect, FourToSixtyThree, PublicKeyCredentialCreationOptions, RpId,
        UserHandle,
    };
    #[cfg(all(feature = "custom", feature = "serializable_server_state"))]
    use super::{
        super::{
            super::bin::{Decode as _, Encode as _},
            AsciiDomain,
        },
        Extension, PublicKeyCredentialUserEntity, RegistrationServerState,
    };
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    use super::{
        super::{
            super::{
                CredentialErr,
                response::register::{
                    AuthenticationExtensionsPrfOutputs, AuthenticatorAttestation,
                    ClientExtensionsOutputs, CredentialPropertiesOutput,
                    CredentialProtectionPolicy,
                },
            },
            AuthTransports,
        },
        AuthenticatorAttachment, BackupReq, ExtensionErr, ExtensionReq, RegCeremonyErr,
        Registration, RegistrationVerificationOptions, UserVerificationRequirement,
    };
    #[cfg(all(feature = "custom", feature = "serializable_server_state"))]
    use ed25519_dalek::{Signer as _, SigningKey};
    #[cfg(all(
        feature = "custom",
        any(
            feature = "serializable_server_state",
            not(any(feature = "bin", feature = "serde"))
        )
    ))]
    use rsa::sha2::{Digest as _, Sha256};
    #[cfg(all(
        feature = "custom",
        any(
            feature = "serializable_server_state",
            not(any(feature = "bin", feature = "serde"))
        )
    ))]
    const CBOR_UINT: u8 = 0b000_00000;
    #[cfg(all(
        feature = "custom",
        any(
            feature = "serializable_server_state",
            not(any(feature = "bin", feature = "serde"))
        )
    ))]
    const CBOR_NEG: u8 = 0b001_00000;
    #[cfg(all(
        feature = "custom",
        any(
            feature = "serializable_server_state",
            not(any(feature = "bin", feature = "serde"))
        )
    ))]
    const CBOR_BYTES: u8 = 0b010_00000;
    #[cfg(all(
        feature = "custom",
        any(
            feature = "serializable_server_state",
            not(any(feature = "bin", feature = "serde"))
        )
    ))]
    const CBOR_TEXT: u8 = 0b011_00000;
    #[cfg(all(
        feature = "custom",
        any(
            feature = "serializable_server_state",
            not(any(feature = "bin", feature = "serde"))
        )
    ))]
    const CBOR_MAP: u8 = 0b101_00000;
    #[cfg(all(
        feature = "custom",
        any(
            feature = "serializable_server_state",
            not(any(feature = "bin", feature = "serde"))
        )
    ))]
    const CBOR_SIMPLE: u8 = 0b111_00000;
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    const CBOR_FALSE: u8 = CBOR_SIMPLE | 20;
    #[cfg(all(
        feature = "custom",
        any(
            feature = "serializable_server_state",
            not(any(feature = "bin", feature = "serde"))
        )
    ))]
    const CBOR_TRUE: u8 = CBOR_SIMPLE | 21;
    #[test]
    #[cfg(all(feature = "custom", feature = "serializable_server_state"))]
    fn eddsa_reg_ser() -> Result<(), AggErr> {
        let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
        let id = UserHandle::from([0; 1]);
        let mut opts = PublicKeyCredentialCreationOptions::passkey(
            &rp_id,
            PublicKeyCredentialUserEntity {
                name: "foo".try_into()?,
                id: &id,
                display_name: None,
            },
            Vec::new(),
        );
        opts.challenge = Challenge(0);
        opts.extensions = Extension {
            cred_props: None,
            cred_protect: CredProtect::UserVerificationRequired(
                false,
                ExtensionInfo::RequireEnforceValue,
            ),
            min_pin_length: Some((
                FourToSixtyThree::new(10)
                    .unwrap_or_else(|| unreachable!("bug in FourToSixtyThree::new")),
                ExtensionInfo::RequireEnforceValue,
            )),
            prf: Some(ExtensionInfo::RequireEnforceValue),
        };
        let client_data_json = br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.to_vec();
        // We over-allocate by 32 bytes. See [`AuthenticatorAttestation::new`] for more information.
        let mut attestation_object = Vec::new();
        attestation_object.extend_from_slice(
            [
                CBOR_MAP | 3,
                CBOR_TEXT | 3,
                b'f',
                b'm',
                b't',
                CBOR_TEXT | 6,
                b'p',
                b'a',
                b'c',
                b'k',
                b'e',
                b'd',
                CBOR_TEXT | 7,
                b'a',
                b't',
                b't',
                b'S',
                b't',
                b'm',
                b't',
                CBOR_MAP | 2,
                CBOR_TEXT | 3,
                b'a',
                b'l',
                b'g',
                // COSE EdDSA.
                CBOR_NEG | 7,
                CBOR_TEXT | 3,
                b's',
                b'i',
                b'g',
                CBOR_BYTES | 24,
                64,
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
                CBOR_TEXT | 8,
                b'a',
                b'u',
                b't',
                b'h',
                b'D',
                b'a',
                b't',
                b'a',
                CBOR_BYTES | 24,
                // Length is 154.
                154,
                // RP ID HASH.
                // This will be overwritten later.
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
                // FLAGS.
                // UP, UV, AT, and ED (right-to-left).
                0b1100_0101,
                // COUNTER.
                // 0 as 32-bit big endian.
                0,
                0,
                0,
                0,
                // AAGUID.
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
                // L.
                // CREDENTIAL ID length is 16 as 16-bit big endian.
                0,
                16,
                // CREDENTIAL ID.
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
                CBOR_MAP | 4,
                // COSE kty.
                CBOR_UINT | 1,
                // COSE OKP.
                CBOR_UINT | 1,
                // COSE alg.
                CBOR_UINT | 3,
                // COSE EdDSA.
                CBOR_NEG | 7,
                // COSE OKP crv.
                CBOR_NEG,
                // COSE Ed25519.
                CBOR_UINT | 6,
                // COSE OKP x.
                CBOR_NEG | 1,
                CBOR_BYTES | 24,
                // Length is 32.
                32,
                // Compressed-y coordinate.
                // This will be overwritten later.
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
                CBOR_MAP | 3,
                CBOR_TEXT | 11,
                b'c',
                b'r',
                b'e',
                b'd',
                b'P',
                b'r',
                b'o',
                b't',
                b'e',
                b'c',
                b't',
                // userVerificationRequired.
                CBOR_UINT | 3,
                // CBOR text of length 11.
                CBOR_TEXT | 11,
                b'h',
                b'm',
                b'a',
                b'c',
                b'-',
                b's',
                b'e',
                b'c',
                b'r',
                b'e',
                b't',
                CBOR_TRUE,
                CBOR_TEXT | 12,
                b'm',
                b'i',
                b'n',
                b'P',
                b'i',
                b'n',
                b'L',
                b'e',
                b'n',
                b'g',
                b't',
                b'h',
                CBOR_UINT | 16,
            ]
            .as_slice(),
        );
        attestation_object
            .extend_from_slice(Sha256::digest(client_data_json.as_slice()).as_slice());
        let sig_key = SigningKey::from_bytes(&[0; 32]);
        let ver_key = sig_key.verifying_key();
        let pub_key = ver_key.as_bytes();
        attestation_object[107..139]
            .copy_from_slice(Sha256::digest(rp_id.as_ref().as_bytes()).as_slice());
        attestation_object[188..220].copy_from_slice(pub_key);
        let sig = sig_key.sign(&attestation_object[107..]);
        attestation_object[32..96].copy_from_slice(sig.to_bytes().as_slice());
        attestation_object.truncate(261);
        let server = opts.start_ceremony()?.0;
        assert!(
            server.is_eq(&RegistrationServerState::decode(
                server
                    .encode()
                    .map_err(AggErr::EncodeRegistrationServerState)?
                    .as_slice()
            )?)
        );
        Ok(())
    }
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    #[derive(Clone, Copy)]
    struct TestResponseOptions {
        user_verified: bool,
        cred_protect: CredentialProtectionPolicy,
        prf: Option<bool>,
        hmac: Option<bool>,
        min_pin: Option<FourToSixtyThree>,
        cred_props: Option<Option<bool>>,
    }
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    #[derive(Clone, Copy)]
    enum PrfUvOptions {
        /// `true` iff `UserVerificationRequirement::Required` should be used; otherwise
        /// `UserVerificationRequirement::Preferred` is used.
        None(bool),
        Prf(ExtensionInfo),
    }
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    #[derive(Clone, Copy)]
    struct TestRequestOptions {
        error_unsolicited: bool,
        protect: CredProtect,
        prf_uv: PrfUvOptions,
        props: Option<ExtensionReq>,
        pin: Option<(FourToSixtyThree, ExtensionInfo)>,
    }
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    #[derive(Clone, Copy)]
    struct TestOptions {
        request: TestRequestOptions,
        response: TestResponseOptions,
    }
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    fn generate_client_data_json() -> Vec<u8> {
        let mut json = Vec::with_capacity(256);
        json.extend_from_slice(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice());
        json
    }
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    fn generate_attestation_object(options: TestResponseOptions) -> Vec<u8> {
        let mut attestation_object = Vec::with_capacity(256);
        attestation_object.extend_from_slice(
            [
                CBOR_MAP | 3,
                CBOR_TEXT | 3,
                b'f',
                b'm',
                b't',
                CBOR_TEXT | 4,
                b'n',
                b'o',
                b'n',
                b'e',
                CBOR_TEXT | 7,
                b'a',
                b't',
                b't',
                b'S',
                b't',
                b'm',
                b't',
                CBOR_MAP,
                CBOR_TEXT | 8,
                b'a',
                b'u',
                b't',
                b'h',
                b'D',
                b'a',
                b't',
                b'a',
                CBOR_BYTES | 24,
                // Length.
                113 + if matches!(options.cred_protect, CredentialProtectionPolicy::None) {
                    if options.hmac.is_some() {
                        14 + options.min_pin.map_or(0, |_| 14)
                    } else {
                        options.min_pin.map_or(0, |_| 15)
                    }
                } else {
                    14 + options.hmac.map_or(0, |_| 13) + options.min_pin.map_or(0, |_| 14)
                },
                // RP ID HASH.
                // This will be overwritten later.
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
                // FLAGS.
                // UP, UV, AT, and ED (right-to-left).
                0b0100_0001
                    | if options.user_verified {
                        0b0000_0100
                    } else {
                        0b0000_0000
                    }
                    | if matches!(options.cred_protect, CredentialProtectionPolicy::None)
                        && options.hmac.is_none()
                        && options.min_pin.is_none()
                    {
                        0
                    } else {
                        0b1000_0000
                    },
                // COUNTER.
                // 0 as 32-bit big endian.
                0,
                0,
                0,
                0,
                // AAGUID.
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
                // L.
                // CREDENTIAL ID length is 16 as 16-bit big endian.
                0,
                16,
                // CREDENTIAL ID.
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
                CBOR_MAP | 4,
                // COSE kty.
                CBOR_UINT | 1,
                // COSE OKP.
                CBOR_UINT | 1,
                // COSE alg.
                CBOR_UINT | 3,
                // COSE Eddsa.
                CBOR_NEG | 7,
                // COSE OKP crv.
                CBOR_NEG,
                // COSE Ed25519.
                CBOR_UINT | 6,
                // COSE OKP x.
                CBOR_NEG | 1,
                CBOR_BYTES | 24,
                // Length is 32.
                32,
                // Compressed-y coordinate.
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
            ]
            .as_slice(),
        );
        attestation_object[30..62]
            .copy_from_slice(Sha256::digest("example.com".as_bytes()).as_slice());
        if matches!(options.cred_protect, CredentialProtectionPolicy::None) {
            if options.hmac.is_some() {
                if options.min_pin.is_some() {
                    attestation_object.push(CBOR_MAP | 2);
                } else {
                    attestation_object.push(CBOR_MAP | 1);
                }
            } else if options.min_pin.is_some() {
                attestation_object.push(CBOR_MAP | 1);
            }
        } else {
            attestation_object.extend_from_slice(
                [
                    CBOR_MAP | 1 + u8::from(options.hmac.is_some()) + u8::from(options.min_pin.is_some()),
                    // CBOR text of length 11.
                    CBOR_TEXT | 11,
                    b'c',
                    b'r',
                    b'e',
                    b'd',
                    b'P',
                    b'r',
                    b'o',
                    b't',
                    b'e',
                    b'c',
                    b't',
                    match options.cred_protect { CredentialProtectionPolicy::None => unreachable!("bug"), CredentialProtectionPolicy::UserVerificationOptional => 1, CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList => 2, CredentialProtectionPolicy::UserVerificationRequired => 3, },
                ].as_slice()
            )
        }
        options.hmac.map(|h| {
            attestation_object.extend_from_slice(
                [
                    // CBOR text of length 11.
                    CBOR_TEXT | 11,
                    b'h',
                    b'm',
                    b'a',
                    b'c',
                    b'-',
                    b's',
                    b'e',
                    b'c',
                    b'r',
                    b'e',
                    b't',
                    if h { CBOR_TRUE } else { CBOR_FALSE },
                ]
                .as_slice(),
            );
        });
        options.min_pin.map(|p| {
            assert!(p.value() <= 23, "bug");
            attestation_object.extend_from_slice(
                [
                    // CBOR text of length 12.
                    CBOR_TEXT | 12,
                    b'm',
                    b'i',
                    b'n',
                    b'P',
                    b'i',
                    b'n',
                    b'L',
                    b'e',
                    b'n',
                    b'g',
                    b't',
                    b'h',
                    CBOR_UINT | p.value(),
                ]
                .as_slice(),
            );
        });
        attestation_object
    }
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    fn validate(options: TestOptions) -> Result<(), AggErr> {
        let rp_id = RpId::Domain("example.com".to_owned().try_into()?);
        let registration = Registration::new(
            AuthenticatorAttestation::new(
                generate_client_data_json(),
                generate_attestation_object(options.response),
                AuthTransports::NONE,
            ),
            AuthenticatorAttachment::None,
            ClientExtensionsOutputs {
                cred_props: options
                    .response
                    .cred_props
                    .map(|rk| CredentialPropertiesOutput { rk }),
                prf: options
                    .response
                    .prf
                    .map(|enabled| AuthenticationExtensionsPrfOutputs { enabled }),
            },
        );
        let reg_opts = RegistrationVerificationOptions::<'static, 'static, &str, &str> {
            allowed_origins: [].as_slice(),
            allowed_top_origins: None,
            backup_requirement: BackupReq::None,
            error_on_unsolicited_extensions: options.request.error_unsolicited,
            require_authenticator_attachment: false,
            #[cfg(feature = "serde_relaxed")]
            client_data_json_relaxed: false,
        };
        let user = UserHandle::from([0; 1]);
        let mut opts =
            PublicKeyCredentialCreationOptions::first_passkey_with_blank_user_info(&rp_id, &user);
        opts.challenge = Challenge(0);
        opts.authenticator_selection.user_verification = UserVerificationRequirement::Preferred;
        match options.request.prf_uv {
            PrfUvOptions::None(required) => {
                if required
                    || matches!(
                        options.request.protect,
                        CredProtect::UserVerificationRequired(_, _)
                    )
                {
                    opts.authenticator_selection.user_verification =
                        UserVerificationRequirement::Required;
                }
            }
            PrfUvOptions::Prf(info) => {
                opts.authenticator_selection.user_verification =
                    UserVerificationRequirement::Required;
                opts.extensions.prf = Some(info);
            }
        }
        opts.extensions.cred_protect = options.request.protect;
        opts.extensions.cred_props = options.request.props;
        opts.extensions.min_pin_length = options.request.pin;
        opts.start_ceremony()?
            .0
            .verify(&rp_id, &registration, &reg_opts)
            .map_err(AggErr::RegCeremony)
            .map(|_| ())
    }
    /// Test all, and only, possible `UserNotVerified` errors.
    /// 4 * 3 * 3 * 2 * 13 * 5 * 3 * 5 * 4 * 4 = 1,123,200 tests.
    /// We ignore this due to how long it takes (around 30 seconds or so).
    #[test]
    #[ignore]
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    fn test_uv_required_err() {
        const ALL_CRED_PROTECTION_OPTIONS: [CredentialProtectionPolicy; 4] = [
            CredentialProtectionPolicy::None,
            CredentialProtectionPolicy::UserVerificationOptional,
            CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
            CredentialProtectionPolicy::UserVerificationRequired,
        ];
        const ALL_PRF_OPTIONS: [Option<bool>; 3] = [None, Some(false), Some(true)];
        const ALL_HMAC_OPTIONS: [Option<bool>; 3] = [None, Some(false), Some(true)];
        const ALL_UNSOLICIT_OPTIONS: [bool; 2] = [false, true];
        const ALL_CRED_PROTECT_OPTIONS: [CredProtect; 13] = [
            CredProtect::None,
            CredProtect::UserVerificationOptional(false, ExtensionInfo::RequireEnforceValue),
            CredProtect::UserVerificationOptional(true, ExtensionInfo::RequireDontEnforceValue),
            CredProtect::UserVerificationOptional(false, ExtensionInfo::AllowEnforceValue),
            CredProtect::UserVerificationOptional(true, ExtensionInfo::AllowDontEnforceValue),
            CredProtect::UserVerificationOptionalWithCredentialIdList(
                false,
                ExtensionInfo::RequireEnforceValue,
            ),
            CredProtect::UserVerificationOptionalWithCredentialIdList(
                true,
                ExtensionInfo::RequireDontEnforceValue,
            ),
            CredProtect::UserVerificationOptionalWithCredentialIdList(
                false,
                ExtensionInfo::AllowEnforceValue,
            ),
            CredProtect::UserVerificationOptionalWithCredentialIdList(
                true,
                ExtensionInfo::AllowDontEnforceValue,
            ),
            CredProtect::UserVerificationRequired(false, ExtensionInfo::RequireEnforceValue),
            CredProtect::UserVerificationRequired(true, ExtensionInfo::RequireDontEnforceValue),
            CredProtect::UserVerificationRequired(false, ExtensionInfo::AllowEnforceValue),
            CredProtect::UserVerificationRequired(true, ExtensionInfo::AllowDontEnforceValue),
        ];
        const ALL_NOT_FALSE_PRF_UV_OPTIONS: [PrfUvOptions; 5] = [
            PrfUvOptions::None(true),
            PrfUvOptions::Prf(ExtensionInfo::RequireEnforceValue),
            PrfUvOptions::Prf(ExtensionInfo::RequireDontEnforceValue),
            PrfUvOptions::Prf(ExtensionInfo::AllowEnforceValue),
            PrfUvOptions::Prf(ExtensionInfo::AllowDontEnforceValue),
        ];
        const ALL_PROPS_OPTIONS: [Option<ExtensionReq>; 3] =
            [None, Some(ExtensionReq::Require), Some(ExtensionReq::Allow)];
        const ALL_PIN_OPTIONS: [Option<(FourToSixtyThree, ExtensionInfo)>; 5] = [
            None,
            Some((
                FourToSixtyThree::new(5).unwrap(),
                ExtensionInfo::RequireEnforceValue,
            )),
            Some((
                FourToSixtyThree::new(5).unwrap(),
                ExtensionInfo::RequireDontEnforceValue,
            )),
            Some((
                FourToSixtyThree::new(5).unwrap(),
                ExtensionInfo::AllowEnforceValue,
            )),
            Some((
                FourToSixtyThree::new(5).unwrap(),
                ExtensionInfo::AllowDontEnforceValue,
            )),
        ];
        const ALL_CRED_PROPS_OPTIONS: [Option<Option<bool>>; 4] =
            [None, Some(None), Some(Some(false)), Some(Some(true))];
        const ALL_MIN_PIN_OPTIONS: [Option<FourToSixtyThree>; 4] = [
            None,
            Some(FourToSixtyThree::MIN),
            Some(FourToSixtyThree::new(5).unwrap()),
            Some(FourToSixtyThree::new(6).unwrap()),
        ];
        for cred_protect in ALL_CRED_PROTECTION_OPTIONS {
            for prf in ALL_PRF_OPTIONS {
                for hmac in ALL_HMAC_OPTIONS {
                    for cred_props in ALL_CRED_PROPS_OPTIONS {
                        for min_pin in ALL_MIN_PIN_OPTIONS {
                            for error_unsolicited in ALL_UNSOLICIT_OPTIONS {
                                for protect in ALL_CRED_PROTECT_OPTIONS {
                                    for prf_uv in ALL_NOT_FALSE_PRF_UV_OPTIONS {
                                        for props in ALL_PROPS_OPTIONS {
                                            for pin in ALL_PIN_OPTIONS {
                                                assert!(validate(TestOptions {
                                                    request: TestRequestOptions {
                                                        error_unsolicited,
                                                        protect,
                                                        prf_uv,
                                                        props,
                                                        pin,
                                                    },
                                                    response: TestResponseOptions {
                                                        user_verified: false,
                                                        hmac,
                                                        cred_protect,
                                                        prf,
                                                        min_pin,
                                                        cred_props,
                                                    },
                                                }).map_or_else(|err| matches!(err, AggErr::RegCeremony(reg_err) if matches!(reg_err, RegCeremonyErr::UserNotVerified)), |_| false));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    /// Test all, and only, possible `ForbiddenCredProps` errors.
    /// 4 * 3 * 3 * 2 * 13 * 6 * 5 * 3 * 4 = 336,960
    /// -
    /// 4 * 3 * 3 * 4 * 6 * 5 * 3 * 4 = 51,840
    /// -
    /// 4 * 3 * 3 * 13 * 5 * 5 * 3 * 4 = 140,400
    /// +
    /// 4 * 3 * 3 * 4 * 5 * 5 * 3 * 4 = 43,200
    /// =
    /// 187,920 total tests.
    /// We ignore this due to how long it takes (around 6 seconds or so).
    #[test]
    #[ignore]
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    fn test_forbidden_cred_props() {
        const ALL_CRED_PROTECTION_OPTIONS: [CredentialProtectionPolicy; 4] = [
            CredentialProtectionPolicy::None,
            CredentialProtectionPolicy::UserVerificationOptional,
            CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
            CredentialProtectionPolicy::UserVerificationRequired,
        ];
        const ALL_PRF_OPTIONS: [Option<bool>; 3] = [None, Some(false), Some(true)];
        const ALL_HMAC_OPTIONS: [Option<bool>; 3] = [None, Some(false), Some(true)];
        const ALL_UV_OPTIONS: [bool; 2] = [false, true];
        const ALL_CRED_PROTECT_OPTIONS: [CredProtect; 13] = [
            CredProtect::None,
            CredProtect::UserVerificationOptional(false, ExtensionInfo::RequireEnforceValue),
            CredProtect::UserVerificationOptional(true, ExtensionInfo::RequireDontEnforceValue),
            CredProtect::UserVerificationOptional(false, ExtensionInfo::AllowEnforceValue),
            CredProtect::UserVerificationOptional(true, ExtensionInfo::AllowDontEnforceValue),
            CredProtect::UserVerificationOptionalWithCredentialIdList(
                false,
                ExtensionInfo::RequireEnforceValue,
            ),
            CredProtect::UserVerificationOptionalWithCredentialIdList(
                true,
                ExtensionInfo::RequireDontEnforceValue,
            ),
            CredProtect::UserVerificationOptionalWithCredentialIdList(
                false,
                ExtensionInfo::AllowEnforceValue,
            ),
            CredProtect::UserVerificationOptionalWithCredentialIdList(
                true,
                ExtensionInfo::AllowDontEnforceValue,
            ),
            CredProtect::UserVerificationRequired(false, ExtensionInfo::RequireEnforceValue),
            CredProtect::UserVerificationRequired(true, ExtensionInfo::RequireDontEnforceValue),
            CredProtect::UserVerificationRequired(false, ExtensionInfo::AllowEnforceValue),
            CredProtect::UserVerificationRequired(true, ExtensionInfo::AllowDontEnforceValue),
        ];
        const ALL_PRF_UV_OPTIONS: [PrfUvOptions; 6] = [
            PrfUvOptions::None(false),
            PrfUvOptions::None(true),
            PrfUvOptions::Prf(ExtensionInfo::RequireEnforceValue),
            PrfUvOptions::Prf(ExtensionInfo::RequireDontEnforceValue),
            PrfUvOptions::Prf(ExtensionInfo::AllowEnforceValue),
            PrfUvOptions::Prf(ExtensionInfo::AllowDontEnforceValue),
        ];
        const ALL_PIN_OPTIONS: [Option<(FourToSixtyThree, ExtensionInfo)>; 5] = [
            None,
            Some((
                FourToSixtyThree::new(5).unwrap(),
                ExtensionInfo::RequireEnforceValue,
            )),
            Some((
                FourToSixtyThree::new(5).unwrap(),
                ExtensionInfo::RequireDontEnforceValue,
            )),
            Some((
                FourToSixtyThree::new(5).unwrap(),
                ExtensionInfo::AllowEnforceValue,
            )),
            Some((
                FourToSixtyThree::new(5).unwrap(),
                ExtensionInfo::AllowDontEnforceValue,
            )),
        ];
        const ALL_NON_EMPTY_CRED_PROPS_OPTIONS: [Option<Option<bool>>; 3] =
            [Some(None), Some(Some(false)), Some(Some(true))];
        const ALL_MIN_PIN_OPTIONS: [Option<FourToSixtyThree>; 4] = [
            None,
            Some(FourToSixtyThree::MIN),
            Some(FourToSixtyThree::new(5).unwrap()),
            Some(FourToSixtyThree::new(6).unwrap()),
        ];
        for cred_protect in ALL_CRED_PROTECTION_OPTIONS {
            for prf in ALL_PRF_OPTIONS {
                for hmac in ALL_HMAC_OPTIONS {
                    for cred_props in ALL_NON_EMPTY_CRED_PROPS_OPTIONS {
                        for min_pin in ALL_MIN_PIN_OPTIONS {
                            for user_verified in ALL_UV_OPTIONS {
                                for protect in ALL_CRED_PROTECT_OPTIONS {
                                    for prf_uv in ALL_PRF_UV_OPTIONS {
                                        for pin in ALL_PIN_OPTIONS {
                                            if user_verified
                                                || (!matches!(
                                                    protect,
                                                    CredProtect::UserVerificationRequired(_, _)
                                                ) && matches!(prf_uv, PrfUvOptions::None(uv) if !uv))
                                            {
                                                assert!(validate(TestOptions {
                                                    request: TestRequestOptions {
                                                        error_unsolicited: true,
                                                        protect,
                                                        prf_uv,
                                                        props: None,
                                                        pin,
                                                    },
                                                    response: TestResponseOptions {
                                                        user_verified,
                                                        hmac,
                                                        cred_protect,
                                                        prf,
                                                        min_pin,
                                                        cred_props,
                                                    },
                                                }).map_or_else(|err| matches!(err, AggErr::RegCeremony(reg_err) if matches!(reg_err, RegCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::ForbiddenCredProps))), |_| false));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    fn test_prf() -> Result<(), AggErr> {
        let mut opts = TestOptions {
            request: TestRequestOptions {
                error_unsolicited: false,
                protect: CredProtect::None,
                prf_uv: PrfUvOptions::Prf(ExtensionInfo::RequireEnforceValue),
                props: None,
                pin: None,
            },
            response: TestResponseOptions {
                user_verified: true,
                hmac: None,
                cred_protect: CredentialProtectionPolicy::None,
                prf: Some(true),
                min_pin: None,
                cred_props: None,
            },
        };
        validate(opts)?;
        opts.response.prf = Some(false);
        assert!(validate(opts).map_or_else(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::InvalidPrfValue))), |_| false));
        opts.response.hmac = Some(false);
        opts.response.prf = Some(true);
        assert!(validate(opts).map_or_else(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::InvalidHmacSecretValue))), |_| false));
        opts.request.prf_uv = PrfUvOptions::Prf(ExtensionInfo::AllowDontEnforceValue);
        opts.response.hmac = Some(true);
        opts.response.prf = None;
        assert!(validate(opts).map_or_else(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Credential(cred_err) if matches!(cred_err, CredentialErr::HmacSecretWithoutPrf))), |_| false));
        opts.response.hmac = Some(false);
        assert!(validate(opts).map_or_else(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Credential(cred_err) if matches!(cred_err, CredentialErr::HmacSecretWithoutPrf))), |_| false));
        opts.response.prf = Some(true);
        assert!(validate(opts).map_or_else(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Credential(cred_err) if matches!(cred_err, CredentialErr::PrfWithoutHmacSecret))), |_| false));
        opts.response.prf = Some(false);
        validate(opts)?;
        opts.request.prf_uv = PrfUvOptions::None(false);
        opts.response.user_verified = false;
        opts.response.hmac = None;
        opts.response.prf = Some(true);
        assert!(validate(opts).map_or_else(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Credential(cred_err) if matches!(cred_err, CredentialErr::PrfWithoutUserVerified))), |_| false));
        opts.response.prf = None;
        validate(opts)?;
        Ok(())
    }
    #[test]
    #[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
    fn test_cred_protect() -> Result<(), AggErr> {
        let mut opts = TestOptions {
            request: TestRequestOptions {
                error_unsolicited: false,
                protect: CredProtect::UserVerificationRequired(
                    false,
                    ExtensionInfo::RequireEnforceValue,
                ),
                prf_uv: PrfUvOptions::None(false),
                props: None,
                pin: None,
            },
            response: TestResponseOptions {
                user_verified: true,
                hmac: None,
                cred_protect: CredentialProtectionPolicy::UserVerificationRequired,
                prf: None,
                min_pin: None,
                cred_props: None,
            },
        };
        validate(opts)?;
        opts.response.cred_protect =
            CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        assert!(validate(opts).map_or_else(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::InvalidCredProtectValue(CredProtect::UserVerificationRequired(false, ExtensionInfo::RequireEnforceValue), CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList)))), |_| false));
        opts.request.protect =
            CredProtect::UserVerificationOptional(true, ExtensionInfo::RequireEnforceValue);
        opts.response.user_verified = false;
        opts.response.cred_protect = CredentialProtectionPolicy::UserVerificationRequired;
        assert!(validate(opts).map_or_else(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Credential(cred_err) if matches!(cred_err, CredentialErr::CredProtectUserVerificationRequiredWithoutUserVerified))), |_| false));
        Ok(())
    }
}
