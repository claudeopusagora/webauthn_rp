extern crate alloc;
use super::{
    super::{
        response::{
            register::{
                error::{ExtensionErr, RegCeremonyErr},
                Attestation, AttestationFormat, AuthenticatorExtensionOutput,
                AuthenticatorExtensionOutputStaticState, ClientExtensionsOutputs,
                CredentialProtectionPolicy, Registration, UncompressedPubKey,
            },
            AuthenticatorAttachment,
        },
        DynamicState, Metadata, RegisteredCredential, StaticState,
    },
    register::error::{CreationOptionsErr, NicknameErr, UserHandleErr, UsernameErr},
    BackupReq, Ceremony, Challenge, CredentialMediationRequirement, ExtensionInfo, ExtensionReq,
    Hint, Origin, PublicKeyCredentialDescriptor, RpId, SentChallenge, ServerState,
    UserVerificationRequirement, THREE_HUNDRED_THOUSAND,
};
#[cfg(doc)]
use crate::{
    request::{auth::PublicKeyCredentialRequestOptions, AsciiDomain, DomainOrigin, Url},
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
use precis_profiles::{precis_core::profile::Profile as _, UsernameCasePreserved};
use rand::RngCore as _;
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
mod ser;
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
    UserVerificationOptional(ExtensionInfo),
    /// Request
    /// [`userVerificationOptionalWithCredentialIDList`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationoptionalwithcredentialidlist);
    /// and when enforcing the value, disallow [`CredentialProtectionPolicy::UserVerificationOptional`].
    UserVerificationOptionalWithCredentialIdList(ExtensionInfo),
    /// Request
    /// [`userVerificationRequired`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationrequired);
    /// and when enforcing the value, only allow [`CredentialProtectionPolicy::UserVerificationRequired`].
    UserVerificationRequired(ExtensionInfo),
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
            Self::UserVerificationOptional(info) => {
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
            Self::UserVerificationOptionalWithCredentialIdList(info) => match info {
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
            Self::UserVerificationRequired(info) => match info {
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
            Self::UserVerificationOptional(info) => {
                write!(f, "request user verification optional and {info}")
            }
            Self::UserVerificationOptionalWithCredentialIdList(info) => write!(
                f,
                "user verification optional with credential ID list and {info}"
            ),
            Self::UserVerificationRequired(info) => {
                write!(f, "user verification required and {info}")
            }
        }
    }
}
/// String returned from the [Nickname Enforcement rule](https://www.rfc-editor.org/rfc/rfc8266#section-2.3)
/// as defined in RFC 8266.
///
/// Note [string truncation](https://www.w3.org/TR/webauthn-3/#sctn-strings-truncation) is allowed, so one may
/// want to enforce their own length requirements in the event [`Self::MAX_LEN`] is too long.
#[derive(Clone, Debug)]
pub struct Nickname<'a>(Cow<'a, str>);
impl Nickname<'_> {
    /// The maximum allowed length.
    pub const MAX_LEN: usize = 1023;
    /// Returns a `Nickname` that consumes `self`. When `self` owns the data, the data is simply moved;
    /// when the data is borrowed, then it is cloned into an owned instance.
    #[inline]
    #[must_use]
    pub fn into_owned<'a>(self) -> Nickname<'a> {
        Nickname(Cow::Owned(self.0.into_owned()))
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
impl<'a: 'b, 'b> From<Nickname<'a>> for Cow<'b, str> {
    #[inline]
    fn from(value: Nickname<'a>) -> Self {
        value.0
    }
}
impl<'a: 'b, 'b> TryFrom<&'a str> for Nickname<'b> {
    type Error = NicknameErr;
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{error::NicknameErr, Nickname};
    /// assert_eq!(
    ///     Nickname::try_from("Srinivasa Ramanujan")?.as_ref(),
    ///     "Srinivasa Ramanujan"
    /// );
    /// assert_eq!(
    ///     Nickname::try_from("श्रीनिवास रामानुजन्")?.as_ref(),
    ///     "श्रीनिवास रामानुजन्"
    /// );
    /// // Empty strings are not valid.
    /// assert!(Nickname::try_from("").map_or_else(
    ///     |e| matches!(e, NicknameErr::Rfc8266),
    ///     |_| false
    /// ));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
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
/// String returned from the
/// [UsernameCasePreserved Enforcement rule](https://www.rfc-editor.org/rfc/rfc8265#section-3.4.3) as defined in
/// RFC 8265.
///
/// Note [string truncation](https://www.w3.org/TR/webauthn-3/#sctn-strings-truncation) is allowed, so one may
/// want to enforce their own length requirements in the event [`Self::MAX_LEN`] is too long.
#[derive(Clone, Debug)]
pub struct Username<'a>(Cow<'a, str>);
impl Username<'_> {
    /// The maximum allowed length.
    pub const MAX_LEN: usize = 1023;
    /// Returns a `Username` that consumes `self`. When `self` owns the data, the data is simply moved;
    /// when the data is borrowed, then it is cloned into an owned instance.
    #[inline]
    #[must_use]
    pub fn into_owned<'a>(self) -> Username<'a> {
        Username(Cow::Owned(self.0.into_owned()))
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
impl<'a: 'b, 'b> TryFrom<&'a str> for Username<'b> {
    type Error = UsernameErr;
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{error::UsernameErr, Username};
    /// assert_eq!(
    ///     Username::try_from("leonhard.euler")?.as_ref(),
    ///     "leonhard.euler"
    /// );
    /// // Empty strings are not valid.
    /// assert!(Username::try_from("").map_or_else(
    ///     |e| matches!(e, UsernameErr::Rfc8265),
    ///     |_| false
    /// ));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
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
impl<'a: 'b, 'b> From<Username<'a>> for Cow<'b, str> {
    #[inline]
    fn from(value: Username<'a>) -> Self {
        value.0
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
    /// [EdDSA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) with the added requirement that
    /// Ed25519 be used for `crv` parameter [per the spec](https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier).
    Eddsa,
    /// [ES256](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) with the added requirements that
    /// P-256 be used for `crv` parameter and the uncompressed form must be used
    /// [per the spec](https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier).
    Es256,
    /// [ES384](https://www.iana.org/assignments/cose/cose.xhtml#algorithms) with the added requirements that
    /// P-384 be used for `crv` parameter and the uncompressed form must be used
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
    /// Contains all [`CoseAlgorithmIdentifiers`].
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
    /// as the contained `u8`.
    pub min_pin_length: Option<(u8, ExtensionInfo)>,
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension).
    ///
    /// When the value is enforced, that corresponds to
    /// [`enabled`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-enabled) and
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// in [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions) set to `true`. In contrast
    /// [`results`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-results) must not exist,
    /// be `null`, or be an
    /// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues)
    /// such that [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first) is `null` and
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second) does not exist or is
    /// `null`. This is to ensure the decrypted outputs stay on the client.
    ///
    /// Note for
    /// [CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// this is only used to instruct the authenticator to create the necessary `hmac-secret` since it does not
    /// currently support PRF evaluation at creation time. This also requires [`UserVerificationRequirement::Required`].
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
                    self.min_pin_length = Some((0, ExtensionInfo::RequireEnforceValue));
                    self.validate_unsolicited(client_ext, auth_ext)
                }
            } else if !matches!(auth_ext.cred_protect, CredentialProtectionPolicy::None) {
                Err(ExtensionErr::ForbiddenCredProtect)
            } else {
                // Pretend to set `credProtect`, so we can check `minPinLength` and `prf` extensions.
                self.cred_protect =
                    CredProtect::UserVerificationOptional(ExtensionInfo::RequireEnforceValue);
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
                                    auth_ext
                                        .hmac_secret
                                        .ok_or(ExtensionErr::MissingHmacSecret)
                                        .map(|_| ())
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
/// The maximum number of bytes a [`UserHandle`] can be made of per
/// [WebAuthn](https://www.w3.org/TR/webauthn-3/#user-handle).
pub const USER_HANDLE_MAX_LEN: usize = 64;
/// The minimum number of bytes a [`UserHandle`] can be made of per
/// [WebAuthn](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id).
pub const USER_HANDLE_MIN_LEN: usize = 1;
#[derive(Clone, Copy, Debug)]
/// A [user handle](https://www.w3.org/TR/webauthn-3/#user-handle) that is made up of
/// [`USER_HANDLE_MIN_LEN`]–[`USER_HANDLE_MAX_LEN`] bytes.
pub struct UserHandle<T>(T);
impl<T> UserHandle<T> {
    /// Returns the contained data consuming `self`.
    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }
    /// Returns the contained data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.0
    }
}
#[cfg(any(feature = "bin", feature = "custom"))]
impl<'a> UserHandle<&'a [u8]> {
    /// Creates a `UserHandle` from a `slice`.
    fn from_slice<'b: 'a>(value: &'b [u8]) -> Result<Self, UserHandleErr> {
        if (USER_HANDLE_MIN_LEN..=USER_HANDLE_MAX_LEN).contains(&value.len()) {
            Ok(Self(value))
        } else {
            Err(UserHandleErr)
        }
    }
}
impl UserHandle<Vec<u8>> {
    /// Returns a new `UserHandle` based on `len` randomly-generated [`u8`]s.
    ///
    /// # Errors
    ///
    /// Errors iff `len` is not inclusively between [`USER_HANDLE_MIN_LEN`] and [`USER_HANDLE_MAX_LEN`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{UserHandle, USER_HANDLE_MIN_LEN, USER_HANDLE_MAX_LEN};
    /// assert_eq!(
    ///     UserHandle::rand(USER_HANDLE_MIN_LEN)
    ///         .unwrap_or_else(|_| unreachable!("there is a bug in UserHandle::rand"))
    ///         .as_ref()
    ///         .len(),
    ///     1
    /// );
    /// // The probability of an all-zero `UserHandle` being generated (assuming a good entropy
    /// // source) is 2^-512 ≈ 7.5 x 10^-155.
    /// assert_ne!(
    ///     UserHandle::rand(USER_HANDLE_MAX_LEN)
    ///         .unwrap_or_else(|_| unreachable!("there is a bug in UserHandle::rand"))
    ///         .as_ref(),
    ///     [0; USER_HANDLE_MAX_LEN]
    /// );
    /// assert!(UserHandle::rand(0).is_err());
    /// assert!(UserHandle::rand(65).is_err());
    /// ```
    #[inline]
    pub fn rand(len: usize) -> Result<Self, UserHandleErr> {
        if (USER_HANDLE_MIN_LEN..=USER_HANDLE_MAX_LEN).contains(&len) {
            let mut data = vec![0; len];
            // [`ThreadRng` is infallible](https://docs.rs/rand_core/latest/src/rand_core/block.rs.html#237);
            // thus there is no point in calling `try_fill_bytes`.
            rand::thread_rng().fill_bytes(data.as_mut_slice());
            Ok(Self(data))
        } else {
            Err(UserHandleErr)
        }
    }
    /// [Per WebAuthn](https://www.w3.org/TR/webauthn-3/#sctn-user-handle-privacy), user handles should be
    /// a random 64 bytes; thus this is the same as [`Self::rand`] with `len` set to [`USER_HANDLE_MAX_LEN`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::register::{UserHandle, USER_HANDLE_MAX_LEN};
    /// // The probability of an all-zero `UserHandle` being generated (assuming a good entropy
    /// // source) is 2^-512 ≈ 7.5 x 10^-155.
    /// assert_ne!(UserHandle::new().as_ref(), [0; USER_HANDLE_MAX_LEN]);
    /// ```
    #[expect(clippy::unreachable, reason = "when there is a bug, we want to crash")]
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::rand(64).unwrap_or_else(|_e| unreachable!("there is a bug in UserHandle::rand"))
    }
}
impl Default for UserHandle<Vec<u8>> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
impl<T: AsRef<[u8]>> AsRef<[u8]> for UserHandle<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<T: Borrow<[u8]>> Borrow<[u8]> for UserHandle<T> {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.0.borrow()
    }
}
impl<'a: 'b, 'b> From<&'a UserHandle<Vec<u8>>> for UserHandle<&'b Vec<u8>> {
    #[inline]
    fn from(value: &'a UserHandle<Vec<u8>>) -> Self {
        Self(&value.0)
    }
}
impl<'a: 'b, 'b> From<UserHandle<&'a Vec<u8>>> for UserHandle<&'b [u8]> {
    #[inline]
    fn from(value: UserHandle<&'a Vec<u8>>) -> Self {
        Self(value.0.as_slice())
    }
}
impl<'a: 'b, 'b> From<&'a UserHandle<Vec<u8>>> for UserHandle<&'b [u8]> {
    #[inline]
    fn from(value: &'a UserHandle<Vec<u8>>) -> Self {
        Self(value.0.as_slice())
    }
}
impl From<UserHandle<&[u8]>> for UserHandle<Vec<u8>> {
    #[inline]
    fn from(value: UserHandle<&[u8]>) -> Self {
        Self(value.0.to_owned())
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<UserHandle<T>> for UserHandle<T2> {
    #[inline]
    fn eq(&self, other: &UserHandle<T>) -> bool {
        self.0 == other.0
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<UserHandle<T>> for &UserHandle<T2> {
    #[inline]
    fn eq(&self, other: &UserHandle<T>) -> bool {
        **self == *other
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<&UserHandle<T>> for UserHandle<T2> {
    #[inline]
    fn eq(&self, other: &&UserHandle<T>) -> bool {
        *self == **other
    }
}
impl<T: Eq> Eq for UserHandle<T> {}
impl<T: Hash> Hash for UserHandle<T> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
/// [The `PublicKeyCredentialUserEntity`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity)
/// sent to the client.
#[derive(Clone, Debug)]
pub struct PublicKeyCredentialUserEntity<'name, 'display_name, T> {
    /// [`name`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialentity-name).
    pub name: Username<'name>,
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id).
    pub id: UserHandle<T>,
    /// [`displayName`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-displayname).
    ///
    /// `None` iff the display name should be the empty string.
    pub display_name: Option<Nickname<'display_name>>,
}
impl PublicKeyCredentialUserEntity<'_, '_, Vec<u8>> {
    /// Returns a `PublicKeyCredentialUserEntity` that consumes `self`. When `self` owns the data, the data is
    /// simply moved; when the data is borrowed, then it is cloned into an owned instance.
    #[inline]
    #[must_use]
    pub fn into_owned<'a, 'b>(self) -> PublicKeyCredentialUserEntity<'a, 'b, Vec<u8>> {
        PublicKeyCredentialUserEntity {
            name: self.name.into_owned(),
            id: self.id,
            display_name: self.display_name.map(Nickname::into_owned),
        }
    }
}
impl<'a: 'b, 'b, T: AsRef<[u8]>> From<&'a PublicKeyCredentialUserEntity<'_, '_, T>>
    for PublicKeyCredentialUserEntity<'b, 'b, &'b [u8]>
{
    #[inline]
    fn from(value: &'a PublicKeyCredentialUserEntity<'_, '_, T>) -> Self {
        Self {
            name: Username(Cow::Borrowed(&value.name.0)),
            id: UserHandle(value.id.0.as_ref()),
            display_name: value
                .display_name
                .as_ref()
                .map(|v| Nickname(Cow::Borrowed(&v.0))),
        }
    }
}
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
/// [`PublicKeyCredentialHints`](https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhints)
/// for [`AuthenticatorAttachment::CrossPlatform`] authenticators.
#[derive(Clone, Copy, Debug, Default)]
pub enum CrossPlatformHint {
    /// No hints.
    #[default]
    None,
    /// [`security-key`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhints-security-key).
    SecurityKey,
    /// [`hybrid`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhints-hybrid).
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
/// [`PublicKeyCredentialHints`](https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhints)
/// for [`AuthenticatorAttachment::Platform`] authenticators.
#[derive(Clone, Copy, Debug, Default)]
pub enum PlatformHint {
    /// No hints.
    #[default]
    None,
    /// [`client-device`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhints-client-device).
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
        CredProtect::UserVerificationRequired(_)
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
pub struct PublicKeyCredentialCreationOptions<'rp_id, 'user_name, 'user_display_name, 'user_handle>
{
    /// [`mediation`](https://www.w3.org/TR/credential-management-1/#dom-credentialcreationoptions-mediation).
    pub mediation: CredentialMediationRequirement,
    /// [`rp`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-rp).
    pub rp_id: &'rp_id RpId,
    /// [`user`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-user).
    pub user: PublicKeyCredentialUserEntity<'user_name, 'user_display_name, &'user_handle [u8]>,
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
impl<'rp_id, 'user_name, 'user_display_name, 'user_handle>
    PublicKeyCredentialCreationOptions<'rp_id, 'user_name, 'user_display_name, 'user_handle>
{
    /// Most deployments of passkeys should use this function. Specifically deployments that are both userless and
    /// passwordless and desire multi-factor authentication (MFA) to be done entirely on the authenticator. It
    /// is important `exclude_credentials` contains the information for _all_ [`RegisteredCredential`]s registered to
    /// [`PublicKeyCredentialUserEntity::id`] to avoid accidentally overwriting existing credentials that
    /// have been previously registered.
    ///
    /// Creates a `PublicKeyCredentialCreationOptions` that requires the authenticator to create a client-side
    /// discoverable credential enforcing any form of user verification. A five-minute timeout is set.
    /// [`Extension::cred_protect`] with [`CredProtect::UserVerificationRequired`] and
    /// [`ExtensionInfo::AllowEnforceValue`] is used. [`Self::mediation`] is
    /// [`CredentialMediationRequirement::Optional`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{
    /// #     register::{
    /// #         PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle
    /// #     },
    /// #     AsciiDomain, RpId, UserVerificationRequirement
    /// # };
    /// assert!(matches!(
    ///     PublicKeyCredentialCreationOptions::passkey(
    ///         &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         PublicKeyCredentialUserEntity {
    ///             name: "archimedes.of.syracuse".try_into()?,
    ///             id: (&UserHandle::new()).into(),
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
    pub fn passkey<'a: 'rp_id, 'b: 'user_name, 'c: 'user_display_name, 'd: 'user_handle>(
        rp_id: &'a RpId,
        user: PublicKeyCredentialUserEntity<'b, 'c, &'d [u8]>,
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
    /// credential without requiring user verification. A five-minute timeout is set. [`Extension::cred_props`]
    /// is [`ExtensionReq::Allow`]. [`Self::mediation`] is [`CredentialMediationRequirement::Optional`].
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
    /// #     PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle
    /// # }, AsciiDomain, RpId};
    /// assert_eq!(
    ///     PublicKeyCredentialCreationOptions::second_factor(
    ///         &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         PublicKeyCredentialUserEntity {
    ///             name: "carl.gauss".try_into()?,
    ///             id: (&UserHandle::new()).into(),
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
    pub fn second_factor<'a: 'rp_id, 'b: 'user_name, 'c: 'user_display_name, 'd: 'user_handle>(
        rp_id: &'a RpId,
        user: PublicKeyCredentialUserEntity<'b, 'c, &'d [u8]>,
        exclude_credentials: Vec<PublicKeyCredentialDescriptor<Vec<u8>>>,
    ) -> Self {
        let mut opts = Self::passkey(rp_id, user, exclude_credentials);
        opts.authenticator_selection = AuthenticatorSelectionCriteria::second_factor();
        opts.extensions.cred_props = Some(ExtensionReq::Allow);
        opts.extensions.cred_protect = CredProtect::None;
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
    /// # use webauthn_rp::request::ServerState;
    /// # use webauthn_rp::request::{
    /// #     register::{PublicKeyCredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle},
    /// #     AsciiDomain, RpId
    /// # };
    /// # #[cfg(not(feature = "serializable_server_state"))]
    /// assert!(
    ///     PublicKeyCredentialCreationOptions::passkey(
    ///         &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         PublicKeyCredentialUserEntity {
    ///             name: "bernard.riemann".try_into()?,
    ///             id: (&UserHandle::new()).into(),
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
            RegistrationServerState,
            RegistrationClientState<'rp_id, 'user_name, 'user_display_name, 'user_handle>,
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
                        },
                        RegistrationClientState(self),
                    )
                })
        })
    }
}
/// Container of a [`PublicKeyCredentialCreationOptions`] that has been used to start the registration ceremony.
/// This gets sent to the client ASAP.
#[derive(Debug)]
pub struct RegistrationClientState<'rp_id, 'user_name, 'user_display_name, 'user_handle>(
    PublicKeyCredentialCreationOptions<'rp_id, 'user_name, 'user_display_name, 'user_handle>,
);
impl RegistrationClientState<'_, '_, '_, '_> {
    /// Returns the `PublicKeyCredentialCreationOptions` that was used to start a registration ceremony.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{register::{
    /// #     CoseAlgorithmIdentifiers, PublicKeyCredentialCreationOptions,
    /// #     PublicKeyCredentialUserEntity, UserHandle
    /// # }, AsciiDomain, RpId};
    /// assert_eq!(
    ///     PublicKeyCredentialCreationOptions::passkey(
    ///         &RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?),
    ///         PublicKeyCredentialUserEntity {
    ///             name: "david.hilbert".try_into()?,
    ///             id: (&UserHandle::new()).into(),
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
    pub const fn options(&self) -> &PublicKeyCredentialCreationOptions<'_, '_, '_, '_> {
        &self.0
    }
}
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
pub struct RegistrationServerState {
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
}
impl RegistrationServerState {
    /// Verifies `response` is valid based on `self` consuming `self` and returning a `RegisteredCredential` that
    /// borrows the necessary data from `response` as well as borrowing `user_handle`.
    ///
    /// `rp_id` and `user_handle` MUST be the same as the [`PublicKeyCredentialCreationOptions::rp_id`] and
    /// [`PublicKeyCredentialUserEntity::id`] used when starting the ceremony.
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
    pub fn verify<'a, 'b, O: PartialEq<Origin<'b>>, T: PartialEq<Origin<'b>>>(
        self,
        rp_id: &RpId,
        user_handle: UserHandle<&'a [u8]>,
        response: &'b Registration,
        options: &RegistrationVerificationOptions<'_, '_, O, T>,
    ) -> Result<RegisteredCredential<'b, 'a>, RegCeremonyErr> {
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
                                                user_handle,
                                                StaticState {
                                                    credential_public_key: attested_credential_data
                                                        .credential_public_key,
                                                    extensions:
                                                        AuthenticatorExtensionOutputStaticState {
                                                            cred_protect: extensions.cred_protect,
                                                            hmac_secret: extensions.hmac_secret,
                                                        },
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
                                                        .client_extension_results,
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
impl ServerState for RegistrationServerState {
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
    #[inline]
    fn sent_challenge(&self) -> SentChallenge {
        self.challenge
    }
}
impl Ceremony for RegistrationServerState {
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
impl Borrow<SentChallenge> for RegistrationServerState {
    #[inline]
    fn borrow(&self) -> &SentChallenge {
        &self.challenge
    }
}
impl PartialEq for RegistrationServerState {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.challenge == other.challenge
    }
}
impl PartialEq<&Self> for RegistrationServerState {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<RegistrationServerState> for &RegistrationServerState {
    #[inline]
    fn eq(&self, other: &RegistrationServerState) -> bool {
        **self == *other
    }
}
impl Eq for RegistrationServerState {}
impl Hash for RegistrationServerState {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.challenge.hash(state);
    }
}
impl PartialOrd for RegistrationServerState {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for RegistrationServerState {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.challenge.cmp(&other.challenge)
    }
}
