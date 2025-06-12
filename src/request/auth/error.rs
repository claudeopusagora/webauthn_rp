#[cfg(doc)]
use super::{
    AllowedCredentials, CredentialSpecificExtension, DiscoverableCredentialRequestOptions,
    Extension, NonDiscoverableCredentialRequestOptions, PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
};
use core::{
    error::Error,
    fmt::{self, Display, Formatter},
};
#[cfg(doc)]
use std::time::{Instant, SystemTime};
/// Error returned from [`NonDiscoverableCredentialRequestOptions::second_factor`] when
/// [`AllowedCredentials`] is empty.
#[derive(Clone, Copy, Debug)]
pub struct SecondFactorErr;
impl Display for SecondFactorErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("allowed credentials was empty")
    }
}
impl Error for SecondFactorErr {}
/// Error returned by [`DiscoverableCredentialRequestOptions::start_ceremony`]
/// and [`NonDiscoverableCredentialRequestOptions::start_ceremony`].
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
