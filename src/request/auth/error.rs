#[cfg(doc)]
use super::{
    AllowedCredentials, CredentialMediationRequirement, CredentialSpecificExtension,
    DiscoverableCredentialRequestOptions, Extension, NonDiscoverableCredentialRequestOptions,
    PublicKeyCredentialRequestOptions, UserVerificationRequirement,
};
use core::{
    error::Error,
    fmt::{self, Display, Formatter},
};
#[cfg(doc)]
use std::time::{Instant, SystemTime};
/// Error returned by [`DiscoverableCredentialRequestOptions::start_ceremony`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoverableCredentialRequestOptionsErr {
    /// Error when [`Extension::prf`] is [`Some`] but [`PublicKeyCredentialRequestOptions::user_verification`] is
    /// not [`UserVerificationRequirement::Required`].
    PrfWithoutUserVerification,
    /// Variant when [`PublicKeyCredentialRequestOptions::timeout`] could not be added to [`Instant::now`] or
    /// [`SystemTime::now`].
    InvalidTimeout,
}
impl Display for DiscoverableCredentialRequestOptionsErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::PrfWithoutUserVerification => {
                "prf extension was requested without requiring user verification"
            }
            Self::InvalidTimeout => "the timeout could not be added to the current Instant",
        })
    }
}
impl Error for DiscoverableCredentialRequestOptionsErr {}
/// Error returned by [`NonDiscoverableCredentialRequestOptions::start_ceremony`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NonDiscoverableCredentialRequestOptionsErr {
    /// Variant when [`NonDiscoverableCredentialRequestOptions::allow_credentials`] is
    /// empty.
    EmptyAllowedCredentials,
    /// Variant when [`NonDiscoverableCredentialRequestOptions::mediation`] is
    /// [`CredentialMediationRequirement::Conditional`].
    ConditionalMediationRequested,
    /// Error when [`Extension::prf`] or [`CredentialSpecificExtension::prf`] is [`Some`] but
    /// [`PublicKeyCredentialRequestOptions::user_verification`] is not
    /// [`UserVerificationRequirement::Required`].
    PrfWithoutUserVerification,
    /// Variant when [`PublicKeyCredentialRequestOptions::timeout`] could not be added to [`Instant::now`] or
    /// [`SystemTime::now`].
    InvalidTimeout,
}
impl Display for NonDiscoverableCredentialRequestOptionsErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::EmptyAllowedCredentials => {
                "non-discoverable requests require a non-empty collection of allowed credentials"
            }
            Self::ConditionalMediationRequested => {
                "non-discoverable requests are not allowed to use conditional mediation"
            }
            Self::PrfWithoutUserVerification => {
                "prf extension was requested without requiring user verification"
            }
            Self::InvalidTimeout => "the timeout could not be added to the current Instant",
        })
    }
}
impl Error for NonDiscoverableCredentialRequestOptionsErr {}
