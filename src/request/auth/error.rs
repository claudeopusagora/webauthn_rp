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
///
/// This happens when [`PublicKeyCredentialRequestOptions::timeout`] could not be added to [`Instant::now`] or
/// [`SystemTime::now`].
#[derive(Clone, Copy, Debug)]
pub struct InvalidTimeout;
impl Display for InvalidTimeout {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("the timeout could not be added to the current Instant")
    }
}
impl Error for InvalidTimeout {}
/// Error returned by [`NonDiscoverableCredentialRequestOptions::start_ceremony`].
#[derive(Clone, Copy, Debug)]
pub enum NonDiscoverableCredentialRequestOptionsErr {
    /// Variant when [`NonDiscoverableCredentialRequestOptions::allow_credentials`] is
    /// empty.
    EmptyAllowedCredentials,
    /// Variant when [`NonDiscoverableCredentialRequestOptions::mediation`] is
    /// [`CredentialMediationRequirement::Conditional`].
    ConditionalMediationRequested,
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
            Self::InvalidTimeout => "the timeout could not be added to the current Instant",
        })
    }
}
impl Error for NonDiscoverableCredentialRequestOptionsErr {}
