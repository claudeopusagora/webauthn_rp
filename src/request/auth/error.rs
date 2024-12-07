#[cfg(doc)]
use super::{
    AllowedCredentials, CredentialSpecificExtension, Extension, PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
};
use core::{
    error::Error,
    fmt::{self, Display, Formatter},
};
#[cfg(doc)]
use std::time::{Instant, SystemTime};
/// Error returned from [`PublicKeyCredentialRequestOptions::second_factor`] when
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
/// Error returned by [`PublicKeyCredentialRequestOptions::start_ceremony`].
#[derive(Clone, Copy, Debug)]
pub enum RequestOptionsErr {
    /// Error when [`Extension::prf`] or [`CredentialSpecificExtension::prf`] is [`Some`] but
    /// [`PublicKeyCredentialRequestOptions::user_verification`] is not
    /// [`UserVerificationRequirement::Required`].
    PrfWithoutUserVerification,
    /// [`PublicKeyCredentialRequestOptions::timeout`] could not be added to [`Instant::now`] or [`SystemTime::now`].
    InvalidTimeout,
}
impl Display for RequestOptionsErr {
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
impl Error for RequestOptionsErr {}
