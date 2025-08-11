extern crate alloc;
use super::{CRED_ID_MAX_LEN, CRED_ID_MIN_LEN};
#[cfg(doc)]
use super::{Challenge, CollectedClientData, CredentialId};
use alloc::string::FromUtf8Error;
use core::{
    error::Error,
    fmt::{self, Display, Formatter},
    str::Utf8Error,
};
/// Error returned when a [`CredentialId`] does not have length inclusively between [`CRED_ID_MIN_LEN`] and
/// [`CRED_ID_MAX_LEN`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialIdErr;
impl Display for CredentialIdErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CredentialId did not have length inclusively between {CRED_ID_MIN_LEN} and {CRED_ID_MAX_LEN}",
        )
    }
}
impl Error for CredentialIdErr {}
/// Error returned from [`CollectedClientData::from_client_data_json`].
#[derive(Debug, Eq, PartialEq)]
pub enum CollectedClientDataErr {
    /// The `slice` had invalid length.
    Len,
    /// The `slice` did not begin with `{"type":"webauthn.`.
    InvalidStart,
    /// [`type`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-type)
    /// was not `"webauthn.create"` during registration or `"webauthn.get"`
    /// during authentication.
    Type,
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge)
    /// without whitespace was not the second key in the object.
    ChallengeKey,
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge)
    /// was not a valid base64url-encoding of [`Challenge`].
    Challenge,
    /// [`origin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin)
    /// without whitespace was not the third key in the object.
    OriginKey,
    /// [`crossOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-crossorigin)
    /// without whitespace was not the fourth key in the object.
    CrossOriginKey,
    /// [`crossOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-crossorigin)
    /// was not `true` or `false`.
    CrossOrigin,
    /// The object was not a valid JSON object.
    InvalidObject,
    /// [`origin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin) or
    /// [`topOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin) was
    /// not escaped correctly (i.e., a Unicode scalar value in U+0000–U+001F was not escaped or another Unicode
    /// scalar value, sans `"` and `\`, was escaped).
    InvalidEscapedString,
    /// [`origin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin) or
    /// [`topOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin) was
    /// not valid UTF-8.
    Utf8(Utf8Error),
    /// [`origin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin) or
    /// [`topOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin) was
    /// not valid UTF-8.
    Utf8Owned(FromUtf8Error),
    /// [`topOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin) existed
    /// despite [`crossOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-crossorigin)
    /// being `false`.
    TopOriginWithoutCrossOrigin,
    /// [`topOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin) was the same value
    /// as [`origin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin).
    TopOriginSameAsOrigin,
}
impl Display for CollectedClientDataErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Len => f.write_str("clientDataJSON had an invalid length"),
            Self::InvalidStart => f.write_str(r#"clientDataJSON does not start with '{"type":"webauthn.'"#),
            Self::Type => f.write_str(r#"clientDataJSON 'type' did not have value '"webauthn.create"' during registration or '"webauthn.get"' during authentication"#),
            Self::ChallengeKey => f.write_str("clientDataJSON 'challenge' was not the second key in the object, or it had whitespace around it"),
            Self::Challenge => f.write_str("clientDataJSON 'challenge' was not a valid base64url encoding of 16 bytes"),
            Self::OriginKey => f.write_str("clientDataJSON 'origin' was not the third key in the object, or it had whitespace around it"),
            Self::CrossOriginKey => f.write_str("clientDataJSON 'crossOrigin' was not the fourth key in the object, or it had whitespace around it"),
            Self::CrossOrigin => f.write_str("clientDataJSON 'crossOrigin' was not false or true"),
            Self::InvalidObject => f.write_str("clientDataJSON was an invalid object"),
            Self::InvalidEscapedString => f.write_str("clientDataJSON 'origin' or 'topOrigin' was not escaped correctly"),
            Self::Utf8(err) => write!(f, "clientDataJSON 'origin' or 'topOrigin' was not valid UTF-8: {err}"),
            Self::Utf8Owned(ref err) => write!(f, "clientDataJSON 'origin' or 'topOrigin' was not valid UTF-8: {err}"),
            Self::TopOriginWithoutCrossOrigin => f.write_str("clientDataJSON 'topOrigin' existed despite 'crossOrigin' being false"),
            Self::TopOriginSameAsOrigin => f.write_str("clientDataJSON 'origin' and 'topOrigin' were the same"),
        }
    }
}
impl Error for CollectedClientDataErr {}
