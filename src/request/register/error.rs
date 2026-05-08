#[cfg(doc)]
use super::{
    AuthenticatorSelectionCriteria, CredProtect, CredentialCreationOptions, Extension,
    PublicKeyCredentialCreationOptions, USER_HANDLE_MAX_LEN, USER_HANDLE_MIN_LEN, UserHandle,
    UserVerificationRequirement,
};
use core::{
    error::Error,
    fmt::{self, Display, Formatter},
};
#[cfg(doc)]
use std::time::{Instant, SystemTime};
/// Error returned by [`CredentialCreationOptions::start_ceremony`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreationOptionsErr {
    /// Error when [`Extension::prf`] is [`Some`] but [`AuthenticatorSelectionCriteria::user_verification`] is not
    /// [`UserVerificationRequirement::Required`].
    PrfWithoutUserVerification,
    /// Error when [`Extension::cred_protect`] is [`CredProtect::UserVerificationRequired`] but [`AuthenticatorSelectionCriteria::user_verification`] is not
    /// [`UserVerificationRequirement::Required`].
    CredProtectRequiredWithoutUserVerification,
    /// Error when [`PublicKeyCredentialCreationOptions::hints`] is not compatible with
    /// [`AuthenticatorSelectionCriteria::authenticator_attachment`].
    HintsIncompatibleWithAuthAttachment,
    /// [`PublicKeyCredentialCreationOptions::timeout`] could not be added to [`Instant::now`] or [`SystemTime::now`].
    InvalidTimeout,
}
impl Display for CreationOptionsErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::PrfWithoutUserVerification => "prf extension was requested without requiring user verification",
            Self::CredProtectRequiredWithoutUserVerification => "credProtect extension with a value of user verification required was requested without requiring user verification",
            Self::HintsIncompatibleWithAuthAttachment => "hints are not compatible with the requested authenticator attachment modality",
            Self::InvalidTimeout => "the timeout could not be added to the current Instant",
        })
    }
}
impl Error for CreationOptionsErr {}
