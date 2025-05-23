#[cfg(doc)]
use super::{
    AuthenticatorSelectionCriteria, CredProtect, Extension, Nickname,
    PublicKeyCredentialCreationOptions, USER_HANDLE_MAX_LEN, USER_HANDLE_MIN_LEN, UserHandle,
    UserVerificationRequirement, Username,
};
use core::{
    error::Error,
    fmt::{self, Display, Formatter},
};
#[cfg(doc)]
use std::time::{Instant, SystemTime};
/// Error returned by [`Nickname::try_from`].
#[derive(Clone, Copy, Debug)]
pub enum NicknameErr {
    /// Error returned when the [Nickname Enforcement rule](https://www.rfc-editor.org/rfc/rfc8266#section-2.3)
    /// fails.
    Rfc8266,
    /// Error returned when the length of the transformed string would exceed [`Nickname::MAX_LEN`] or
    /// [`Nickname::RECOMMENDED_MAX_LEN`].
    Len,
}
impl Display for NicknameErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Rfc8266 => "nickname does not conform to RFC 8266",
            Self::Len => "length of nickname is too long",
        })
    }
}
impl Error for NicknameErr {}
/// Error returned by [`Username::try_from`].
#[derive(Clone, Copy, Debug)]
pub enum UsernameErr {
    /// Error returned when the
    /// [UsernameCasePreserved Enforcement rule](https://www.rfc-editor.org/rfc/rfc8265#section-3.4.3) fails.
    Rfc8265,
    /// Error returned when the length of the transformed string would exceed [`Username::MAX_LEN`] or
    /// [`Username::RECOMMENDED_MAX_LEN`].
    Len,
}
impl Display for UsernameErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Rfc8265 => "username does not conform to RFC 8265",
            Self::Len => "length of username is too long",
        })
    }
}
impl Error for UsernameErr {}
/// Error returned by [`PublicKeyCredentialCreationOptions::start_ceremony`].
#[derive(Clone, Copy, Debug)]
pub enum CreationOptionsErr {
    /// Error when [`Extension::prf`] is [`Some`] but [`AuthenticatorSelectionCriteria::user_verification`] is not
    /// [`UserVerificationRequirement::Required`].
    PrfWithoutUserVerification,
    /// Error when [`Extension::cred_protect`] is [`CredProtect::UserVerificationRequired`] but [`AuthenticatorSelectionCriteria::user_verification`] is not
    /// [`UserVerificationRequirement::Required`].
    CredProtectRequiredWithoutUserVerification,
    /// [`PublicKeyCredentialCreationOptions::timeout`] could not be added to [`Instant::now`] or [`SystemTime::now`].
    InvalidTimeout,
}
impl Display for CreationOptionsErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::PrfWithoutUserVerification => "prf extension was requested without requiring user verification",
            Self::CredProtectRequiredWithoutUserVerification => "credProtect extension with a value of user verification required was requested without requiring user verification",
            Self::InvalidTimeout => "the timeout could not be added to the current Instant",
        })
    }
}
impl Error for CreationOptionsErr {}
