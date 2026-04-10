#[cfg(feature = "serde_relaxed")]
use super::super::SerdeJsonErr;
use super::super::{
    super::CredentialId, AuthRespErr, AuthenticatorDataErr as AuthDataErr, CeremonyErr,
    CollectedClientDataErr, PubKeyErr, RpId,
};
#[cfg(doc)]
use super::{
    super::{
        super::{
            AuthenticatedCredential, DynamicState, StaticState,
            request::{
                UserVerificationRequirement,
                auth::{
                    AllowedCredential, AllowedCredentials, AuthenticationVerificationOptions,
                    BackupStateReq, CredentialSpecificExtension,
                    DiscoverableAuthenticationServerState, DiscoverableCredentialRequestOptions,
                    Extension, NonDiscoverableAuthenticationServerState,
                    PublicKeyCredentialRequestOptions,
                },
            },
        },
        Backup,
        register::CredentialProtectionPolicy,
    },
    Authentication, AuthenticatorAssertion, AuthenticatorAttachment, AuthenticatorData,
    AuthenticatorExtensionOutput, CollectedClientData, CompressedPubKeyBorrowed, Flag, HmacSecret,
    Signature, UserHandle,
};
use core::{
    convert::Infallible,
    error::Error,
    fmt::{self, Display, Formatter},
};
/// Error returned in [`AuthenticatorDataErr::AuthenticatorExtension`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorExtensionOutputErr {
    /// The `slice` had an invalid length.
    Len,
    /// The first byte did not represent a map of one key pair.
    CborHeader,
    /// `hmac-secret` was not a byte string with additional info 24.
    HmacSecretType,
    /// `hmac-secret` was not a byte string of length 48 or 80.
    HmacSecretValue,
    /// An unsupported extension existed.
    Unsupported,
    /// Fewer extensions existed than expected.
    Missing,
}
impl Display for AuthenticatorExtensionOutputErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Len => "CBOR authenticator extensions had an invalid length",
            Self::CborHeader => {
                "CBOR authenticator extensions did not represent a map of one key pair"
            }
            Self::HmacSecretType => "CBOR authenticator extension 'hmac-secret' was not a byte string with additional info 24",
            Self::HmacSecretValue => "CBOR authenticator extension 'hmac-secret' was not a byte string of length 48 or 80",
            Self::Unsupported => "CBOR authenticator extension had an unsupported extension",
            Self::Missing => "CBOR authenticator extensions had fewer extensions than expected",
        })
    }
}
impl Error for AuthenticatorExtensionOutputErr {}
/// Error returned from [`AuthenticatorData::try_from`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorDataErr {
    /// The `slice` had an invalid length.
    Len,
    /// [`Flag::user_present`] was `false`.
    UserNotPresent,
    /// Bit 1 in [`flags`](https://www.w3.org/TR/webauthn-3/#authdata-flags) is not 0.
    FlagsBit1Not0,
    /// Bit 5 in [`flags`](https://www.w3.org/TR/webauthn-3/#authdata-flags) is not 0.
    FlagsBit5Not0,
    /// [AT](https://www.w3.org/TR/webauthn-3/#authdata-flags-at) was 1.
    AttestedCredentialDataIncluded,
    /// [BE](https://www.w3.org/TR/webauthn-3/#authdata-flags-be) and
    /// [BS](https://www.w3.org/TR/webauthn-3/#authdata-flags-bs) bits were 0 and 1 respectively.
    BackupWithoutEligibility,
    /// Error returned when [`AuthenticatorExtensionOutput`] is malformed.
    AuthenticatorExtension(AuthenticatorExtensionOutputErr),
    /// [ED](https://www.w3.org/TR/webauthn-3/#authdata-flags-ed) bit was 0, but
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions) existed.
    NoExtensionBitWithData,
    /// [ED](https://www.w3.org/TR/webauthn-3/#authdata-flags-ed) bit was 1, but
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions) did not exist.
    ExtensionBitWithoutData,
    /// There was data remaining that could not be deserialized.
    TrailingData,
}
impl Display for AuthenticatorDataErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Len => AuthDataErr::<(), Infallible, AuthenticatorExtensionOutputErr>::Len.fmt(f),
            Self::UserNotPresent => f.write_str("the user was not present"),
            Self::FlagsBit1Not0 => {
                AuthDataErr::<(), Infallible, AuthenticatorExtensionOutputErr>::FlagsBit1Not0.fmt(f)
            }
            Self::FlagsBit5Not0 => {
                AuthDataErr::<(), Infallible, AuthenticatorExtensionOutputErr>::FlagsBit5Not0.fmt(f)
            }
            Self::AttestedCredentialDataIncluded => {
                f.write_str("attested credential data was included")
            }
            Self::BackupWithoutEligibility => AuthDataErr::<
                (),
                Infallible,
                AuthenticatorExtensionOutputErr,
            >::BackupWithoutEligibility
                .fmt(f),
            Self::AuthenticatorExtension(err) => err.fmt(f),
            Self::NoExtensionBitWithData => AuthDataErr::<
                (),
                Infallible,
                AuthenticatorExtensionOutputErr,
            >::NoExtensionBitWithData
                .fmt(f),
            Self::ExtensionBitWithoutData => AuthDataErr::<
                (),
                Infallible,
                AuthenticatorExtensionOutputErr,
            >::ExtensionBitWithoutData
                .fmt(f),
            Self::TrailingData => {
                AuthDataErr::<(), Infallible, AuthenticatorExtensionOutputErr>::TrailingData.fmt(f)
            }
        }
    }
}
impl Error for AuthenticatorDataErr {}
/// One or two.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OneOrTwo {
    /// One.
    One,
    /// Two.
    Two,
}
impl Display for OneOrTwo {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::One => "one",
            Self::Two => "two",
        })
    }
}
/// Error in [`AuthCeremonyErr::Extension`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionErr {
    /// [`AuthenticatorExtensionOutput::hmac_secret`] was sent from the client, but [`Flag::user_verified`]
    /// was `false`.
    ///
    /// Note this is only possible iff [`PublicKeyCredentialRequestOptions::user_verification`] is not
    /// [`UserVerificationRequirement::Required`], [`Extension::prf`] is `None`,
    /// [`CredentialSpecificExtension::prf`] is `None`, and
    /// [`AuthenticationVerificationOptions::error_on_unsolicited_extensions`] is `false`.
    UserNotVerifiedHmacSecret,
    /// [`AuthenticatorExtensionOutput::hmac_secret`] was sent from the client but was not supposed to be.
    ForbiddenHmacSecret,
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// was received for a credential that does not support it.
    HmacSecretForNonHmacSecretCredential,
    /// [`Extension::prf`] was requested for a PRF-capable credential that is based on the
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// extension, but the required response was not sent back.
    MissingHmacSecret,
    /// [`Extension::prf`] was requested with the first number of PRF inputs, but the second number of
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// outputs were sent for a PRF-capable credential that is based on the `hmac-secret` extension.
    InvalidHmacSecretValue(OneOrTwo, OneOrTwo),
}
impl Display for ExtensionErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::UserNotVerifiedHmacSecret => {
                f.write_str("user was not verified but hmac-secret info was sent from the client")
            }
            Self::ForbiddenHmacSecret => {
                f.write_str("hmac-secret info was sent from the client, but it is not allowed")
            }
            Self::HmacSecretForNonHmacSecretCredential => f.write_str(
                "hmac-secret info was sent from the client, but the credential does not support it",
            ),
            Self::MissingHmacSecret => f.write_str("hmac-secret was not sent from the client"),
            Self::InvalidHmacSecretValue(sent, recv) => write!(
                f,
                "{sent} PRF input(s) were sent, but {recv} hmac-secret output(s) were received"
            ),
        }
    }
}
impl Error for ExtensionErr {}
/// Error returned by [`DiscoverableAuthenticationServerState::verify`] and
/// [`NonDiscoverableAuthenticationServerState::verify`].
#[derive(Debug)]
pub enum AuthCeremonyErr {
    /// [`PublicKeyCredentialRequestOptions::timeout`] was exceeded.
    Timeout,
    /// [`AuthenticatorAssertion::client_data_json`] could not be parsed by
    /// [`CollectedClientData::from_client_data_json`].
    CollectedClientData(CollectedClientDataErr),
    /// [`AuthenticatorAssertion::client_data_json`] could not be parsed by
    /// [`CollectedClientData::from_client_data_json_relaxed`].
    #[cfg(feature = "serde_relaxed")]
    CollectedClientDataRelaxed(SerdeJsonErr),
    /// [`AuthenticatorAssertion::authenticator_data`] could not be parsed into an
    /// [`AuthenticatorData`].
    AuthenticatorData(AuthenticatorDataErr),
    /// [`CompressedPubKeyBorrowed`] was not valid.
    PubKey(PubKeyErr),
    /// [`CompressedPubKeyBorrowed`] was not able to verify [`AuthenticatorAssertion::signature`].
    AssertionSignature,
    /// [`CollectedClientData::origin`] does not match one of the values in
    /// [`AuthenticationVerificationOptions::allowed_origins`].
    OriginMismatch,
    /// [`CollectedClientData::cross_origin`] was `true`, but
    /// [`AuthenticationVerificationOptions::allowed_top_origins`] was `None`.
    CrossOrigin,
    /// [`CollectedClientData::top_origin`] does not match one of the values in
    /// [`AuthenticationVerificationOptions::allowed_top_origins`].
    TopOriginMismatch,
    /// [`PublicKeyCredentialRequestOptions::challenge`] and [`CollectedClientData::challenge`] don't match.
    ChallengeMismatch,
    /// The SHA-256 hash of the [`RpId`] does not match [`AuthenticatorData::rp_id_hash`].
    RpIdHashMismatch,
    /// [`PublicKeyCredentialRequestOptions::user_verification`] was set to
    /// [`UserVerificationRequirement::Required`], but [`Flag::user_verified`] was `false`.
    UserNotVerified,
    /// [`Backup::Eligible`] was sent back despite the credential not being eligible to be backed up.
    BackupEligible,
    /// [`Backup::NotEligible`] was sent back despite the credential being eligible to be backed up.
    BackupNotEligible,
    /// [`Backup::Exists`] was sent back despite [`BackupStateReq::DoesntExist`].
    BackupExists,
    /// [`Backup::Eligible`] was sent back despite [`BackupStateReq::Exists`].
    BackupDoesNotExist,
    /// [`AuthenticatorAttachment`] was not sent back despite being required.
    MissingAuthenticatorAttachment,
    /// [`AuthenticatorAttachment`] modality changed despite it being forbidden to do so.
    AuthenticatorAttachmentMismatch,
    /// Variant returned when there is an issue with [`Extension`]s.
    Extension(ExtensionErr),
    /// [`AuthenticatorData::sign_count`] was not strictly greater than [`DynamicState::sign_count`].
    SignatureCounter,
    /// [`AuthenticatorAssertion::user_handle`] did not match [`AuthenticatedCredential::user_id`].
    UserHandleMismatch,
    /// [`Authentication::raw_id`] did not match [`AuthenticatedCredential::id`].
    CredentialIdMismatch,
    /// [`AllowedCredentials`] did not have a matching [`CredentialId`] as
    /// [`Authentication::raw_id`].
    NoMatchingAllowedCredential,
    /// [`AllowedCredentials`] is empty (i.e., a discoverable request was issued), but
    /// [`AuthenticatorAssertion::user_handle`] was [`None`].
    MissingUserHandle,
    /// [`Flag::user_verified`] was `false`, but the credential has
    /// [`CredentialProtectionPolicy::UserVerificationRequired`].
    UserNotVerifiedCredProtectRequired,
    /// [`DiscoverableCredentialRequestOptions`] was sent but the credential has
    /// [`CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList`].
    DiscoverableCredProtectCredentialIdList,
}
impl Display for AuthCeremonyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Timeout => CeremonyErr::<AuthenticatorDataErr>::Timeout.fmt(f),
            Self::CollectedClientData(ref err) => write!(f, "clientDataJSON could not be parsed: {err}"),
            #[cfg(feature = "serde_relaxed")]
            Self::CollectedClientDataRelaxed(ref err) => write!(f, "clientDataJSON could not be parsed: {err}"),
            Self::AuthenticatorData(err) => err.fmt(f),
            Self::PubKey(err) => err.fmt(f),
            Self::AssertionSignature => AuthRespErr::<AuthenticatorDataErr>::Signature.fmt(f),
            Self::OriginMismatch => CeremonyErr::<AuthenticatorDataErr>::OriginMismatch.fmt(f),
            Self::CrossOrigin => CeremonyErr::<AuthenticatorDataErr>::CrossOrigin.fmt(f),
            Self::TopOriginMismatch => CeremonyErr::<AuthenticatorDataErr>::TopOriginMismatch.fmt(f),
            Self::BackupEligible => CeremonyErr::<AuthenticatorDataErr>::BackupEligible.fmt(f),
            Self::BackupNotEligible => CeremonyErr::<AuthenticatorDataErr>::BackupNotEligible.fmt(f),
            Self::BackupExists => CeremonyErr::<AuthenticatorDataErr>::BackupExists.fmt(f),
            Self::BackupDoesNotExist => CeremonyErr::<AuthenticatorDataErr>::BackupDoesNotExist.fmt(f),
            Self::ChallengeMismatch => CeremonyErr::<AuthenticatorDataErr>::ChallengeMismatch.fmt(f),
            Self::RpIdHashMismatch => CeremonyErr::<AuthenticatorDataErr>::RpIdHashMismatch.fmt(f),
            Self::UserNotVerified => CeremonyErr::<AuthenticatorDataErr>::UserNotVerified.fmt(f),
            Self::MissingAuthenticatorAttachment=> f.write_str(
                "authenticator attachment was not sent back despite being required",
            ),
            Self::AuthenticatorAttachmentMismatch => f.write_str(
                "authenticator attachment modality changed despite not being allowed to",
            ),
            Self::Extension(err) => err.fmt(f),
            Self::SignatureCounter => f.write_str(
                "the signature counter sent back is not strictly greater than the previous counter",
            ),
            Self::UserHandleMismatch => f.write_str("the user handle does not match"),
            Self::CredentialIdMismatch => f.write_str("the credential ID does not match"),
            Self::NoMatchingAllowedCredential => f.write_str("none of the credentials used to start the non-discoverable request have the same Credential ID as the credential used to finish the ceremony"),
            Self::MissingUserHandle => f.write_str("the credential used to finish the ceremony did not have a user handle despite a discoverable request being issued"),
            Self::UserNotVerifiedCredProtectRequired => f.write_str("the credential requires user verification, but the user was not verified"),
            Self::DiscoverableCredProtectCredentialIdList => f.write_str("the credential requires user verification or to be used for non-discoverable requests, but a discoverable request was used and the user was not verified"),
        }
    }
}
impl Error for AuthCeremonyErr {}
/// [`UnknownCredentialOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-unknowncredentialoptions).
///
/// This can be sent to the client when an authentication ceremony fails due to an unknown [`CredentialId`]. This
/// can be due to the user deleting a credential on the RP's side but not deleting it on the authenticator. This
/// response can be forwarded to the authenticator which can subsequently delete the credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownCredentialOptions<'rp, 'cred> {
    /// [`rpId`](https://www.w3.org/TR/webauthn-3/#dictdef-unknowncredentialoptions-rpid).
    pub rp_id: &'rp RpId,
    /// [`credentialId`](https://www.w3.org/TR/webauthn-3/#dictdef-unknowncredentialoptions-credentialid).
    pub credential_id: CredentialId<&'cred [u8]>,
}
/// Error when a [`UserHandle`] does not exist that is required to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MissingUserHandleErr;
impl Display for MissingUserHandleErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("user handle does not exist")
    }
}
impl Error for MissingUserHandleErr {}
