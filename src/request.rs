#[cfg(doc)]
use super::{
    hash::hash_set::FixedCapHashSet,
    request::{
        auth::{
            AllowedCredential, AllowedCredentials, CredentialSpecificExtension,
            DiscoverableAuthenticationServerState, DiscoverableCredentialRequestOptions,
            NonDiscoverableAuthenticationServerState, NonDiscoverableCredentialRequestOptions,
            PublicKeyCredentialRequestOptions,
        },
        register::{CredentialCreationOptions, RegistrationServerState},
    },
    response::register::ClientExtensionsOutputs,
};
use crate::{
    request::{
        error::{AsciiDomainErr, DomainOriginParseErr, PortParseErr, SchemeParseErr, UrlErr},
        register::RegistrationVerificationOptions,
    },
    response::{
        AuthData as _, AuthDataContainer, AuthResponse, AuthTransports, Backup, CeremonyErr,
        CredentialId, Origin, Response, SentChallenge,
    },
};
use core::{
    borrow::Borrow,
    fmt::{self, Display, Formatter},
    num::NonZeroU32,
    str::FromStr,
};
use rsa::sha2::{Digest as _, Sha256};
#[cfg(any(doc, not(feature = "serializable_server_state")))]
use std::time::Instant;
#[cfg(feature = "serializable_server_state")]
use std::time::SystemTime;
use url::Url as Uri;
/// Contains functionality for beginning the
/// [authentication ceremony](https://www.w3.org/TR/webauthn-3/#authentication-ceremony).
///
/// # Examples
///
/// ```
/// # use core::convert;
/// # use webauthn_rp::{
/// #     hash::hash_set::FixedCapHashSet,
/// #     request::{
/// #         auth::{AllowedCredentials, DiscoverableCredentialRequestOptions, NonDiscoverableCredentialRequestOptions},
/// #         register::UserHandle64,
/// #         AsciiDomain, Credentials, PublicKeyCredentialDescriptor, RpId,
/// #     },
/// #     response::{AuthTransports, CredentialId, CRED_ID_MIN_LEN},
/// #     AggErr,
/// # };
/// let mut ceremonies = FixedCapHashSet::new(128);
/// let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
/// let (server, client) = DiscoverableCredentialRequestOptions::passkey(&rp_id).start_ceremony()?;
/// assert!(
///     ceremonies.insert_remove_all_expired(server).map_or(false, convert::identity)
/// );
/// # #[cfg(feature = "custom")]
/// let mut ceremonies_2 = FixedCapHashSet::new(128);
/// # #[cfg(feature = "serde")]
/// assert!(serde_json::to_string(&client).is_ok());
/// let user_handle = get_user_handle();
/// # #[cfg(feature = "custom")]
/// let creds = get_registered_credentials(&user_handle)?;
/// # #[cfg(feature = "custom")]
/// let (server_2, client_2) =
///     NonDiscoverableCredentialRequestOptions::second_factor(&rp_id, creds)?.start_ceremony()?;
/// # #[cfg(feature = "custom")]
/// assert!(
///     ceremonies_2.insert_remove_all_expired(server_2).map_or(false, convert::identity)
/// );
/// # #[cfg(all(feature = "custom", feature = "serde"))]
/// assert!(serde_json::to_string(&client_2).is_ok());
/// /// Extract `UserHandle` from session cookie.
/// fn get_user_handle() -> UserHandle64 {
///     // ⋮
/// #     UserHandle64::new()
/// }
/// # #[cfg(feature = "custom")]
/// /// Fetch the `AllowedCredentials` associated with `user`.
/// fn get_registered_credentials(user: &UserHandle64) -> Result<AllowedCredentials, AggErr> {
///     // ⋮
/// #     let mut creds = AllowedCredentials::new();
/// #     creds.push(
/// #         PublicKeyCredentialDescriptor {
/// #             id: CredentialId::try_from(vec![0; CRED_ID_MIN_LEN])?,
/// #             transports: AuthTransports::NONE,
/// #         }
/// #         .into(),
/// #     );
/// #     Ok(creds)
/// }
/// # Ok::<_, AggErr>(())
/// ```
pub mod auth;
/// Contains error types.
pub mod error;
/// Contains functionality for beginning the
/// [registration ceremony](https://www.w3.org/TR/webauthn-3/#registration-ceremony).
///
/// # Examples
///
/// ```
/// # use core::convert;
/// # use webauthn_rp::{
/// #     hash::hash_set::FixedCapHashSet,
/// #     request::{
/// #         register::{
/// #             CredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle, USER_HANDLE_MAX_LEN, UserHandle64,
/// #         },
/// #         AsciiDomain, PublicKeyCredentialDescriptor, RpId
/// #     },
/// #     response::{AuthTransports, CredentialId, CRED_ID_MIN_LEN},
/// #     AggErr,
/// # };
/// # #[cfg(feature = "custom")]
/// let mut ceremonies = FixedCapHashSet::new(128);
/// let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
/// # #[cfg(feature = "custom")]
/// let user_handle = get_user_handle();
/// # #[cfg(feature = "custom")]
/// let user = get_user_entity(&user_handle)?;
/// # #[cfg(feature = "custom")]
/// let creds = get_registered_credentials(&user_handle)?;
/// # #[cfg(feature = "custom")]
/// let (server, client) = CredentialCreationOptions::passkey(&rp_id, user.clone(), creds)
///     .start_ceremony()?;
/// # #[cfg(feature = "custom")]
/// assert!(
///     ceremonies.insert_remove_all_expired(server).map_or(false, convert::identity)
/// );
/// # #[cfg(all(feature = "serde", feature = "custom"))]
/// assert!(serde_json::to_string(&client).is_ok());
/// # #[cfg(feature = "custom")]
/// let creds_2 = get_registered_credentials(&user_handle)?;
/// # #[cfg(feature = "custom")]
/// let (server_2, client_2) =
///     CredentialCreationOptions::second_factor(&rp_id, user, creds_2).start_ceremony()?;
/// # #[cfg(feature = "custom")]
/// assert!(
///     ceremonies.insert_remove_all_expired(server_2).map_or(false, convert::identity)
/// );
/// # #[cfg(all(feature = "serde", feature = "custom"))]
/// assert!(serde_json::to_string(&client_2).is_ok());
/// /// Extract `UserHandle` from session cookie or storage if this is not the first credential registered.
/// # #[cfg(feature = "custom")]
/// fn get_user_handle() -> UserHandle64 {
///     // ⋮
/// #     [0; USER_HANDLE_MAX_LEN].into()
/// }
/// /// Fetch `PublicKeyCredentialUserEntity` info associated with `user`.
/// ///
/// /// If this is the first time a credential is being registered, then `PublicKeyCredentialUserEntity`
/// /// will need to be constructed with `name` and `display_name` passed from the client and `UserHandle::new`
/// /// used for `id`. Once created, this info can be stored such that the entity information
/// /// does not need to be requested for subsequent registrations.
/// # #[cfg(feature = "custom")]
/// fn get_user_entity(user: &UserHandle64) -> Result<PublicKeyCredentialUserEntity<'_, '_, '_, USER_HANDLE_MAX_LEN>, AggErr> {
///     // ⋮
/// #     Ok(PublicKeyCredentialUserEntity {
/// #         name: "foo".try_into()?,
/// #         id: user,
/// #         display_name: None,
/// #     })
/// }
/// /// Fetch the `PublicKeyCredentialDescriptor`s associated with `user`.
/// ///
/// /// This doesn't need to be called when this is the first credential registered for `user`; instead
/// /// an empty `Vec` should be passed.
/// fn get_registered_credentials(
///     user: &UserHandle64,
/// ) -> Result<Vec<PublicKeyCredentialDescriptor<Vec<u8>>>, AggErr> {
///     // ⋮
/// #     Ok(Vec::new())
/// }
/// # Ok::<_, AggErr>(())
/// ```
pub mod register;
/// Contains functionality to serialize data to a client.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
mod ser;
/// Contains functionality to (de)serialize data needed for [`RegistrationServerState`],
/// [`DiscoverableAuthenticationServerState`], and [`NonDiscoverableAuthenticationServerState`] to a data store.
#[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
#[cfg(feature = "serializable_server_state")]
pub(super) mod ser_server_state;
// `Challenge` must _never_ be constructable directly or indirectly; thus its tuple field must always be private,
// and it must never implement `trait`s (e.g., `Clone`) that would allow indirect creation. It must only ever
// be constructed via `Self::new` or `Self::default`. In contrast downstream code must be able to construct
// `SentChallenge` since it is used during ceremony validation; thus we must keep `Challenge` and `SentChallenge`
// as separate types.
/// [Cryptographic challenge](https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges).
#[derive(Debug)]
pub struct Challenge(u128);
impl Challenge {
    // This won't `panic` since 4/3 of 16 is less than `usize::MAX`.
    /// The number of bytes a `Challenge` takes to encode in base64url.
    pub(super) const BASE64_LEN: usize = super::base64url_nopad_len(16).unwrap();
    /// Generates a random `Challenge`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Challenge;
    /// // The probability of a `Challenge` being 0 (assuming a good entropy
    /// // source) is 2^-128 ≈ 2.9 x 10^-39.
    /// assert_ne!(Challenge::new().into_data(), 0);
    /// ```
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self(rand::random())
    }
    /// Returns the contained `u128` consuming `self`.
    #[inline]
    #[must_use]
    pub const fn into_data(self) -> u128 {
        self.0
    }
    /// Returns the contained `u128`.
    #[inline]
    #[must_use]
    pub const fn as_data(&self) -> u128 {
        self.0
    }
}
impl Default for Challenge {
    /// Same as [`Self::new`].
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
impl From<Challenge> for u128 {
    #[inline]
    fn from(value: Challenge) -> Self {
        value.0
    }
}
impl From<&Challenge> for u128 {
    #[inline]
    fn from(value: &Challenge) -> Self {
        value.0
    }
}
/// A [domain](https://url.spec.whatwg.org/#concept-domain) in representation format consisting of only and any
/// ASCII.
///
/// The only ASCII character disallowed in a label is `'.'` since it is used exclusively as a separator. Every
/// label must have length inclusively between 1 and 63, and the total length of the domain must be at most 253
/// when a trailing `'.'` does not exist; otherwise the max length is 254. The root domain (i.e., `'.'`) is not
/// allowed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsciiDomain(String);
impl AsciiDomain {
    /// Removes a trailing `'.'` if it exists.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{error::AsciiDomainErr, AsciiDomain};
    /// let mut dom = AsciiDomain::try_from("example.com.".to_owned())?;
    /// dom.remove_trailing_dot();
    /// assert_eq!(dom.as_ref(), "example.com");
    /// # Ok::<_, AsciiDomainErr>(())
    /// ```
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    #[inline]
    pub fn remove_trailing_dot(&mut self) {
        if *self
            .0
            .as_bytes()
            .last()
            .unwrap_or_else(|| unreachable!("there is a bug in AsciiDomain::try_from"))
            == b'.'
        {
            self.0.pop();
        }
    }
}
impl AsRef<str> for AsciiDomain {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}
impl Borrow<str> for AsciiDomain {
    #[inline]
    fn borrow(&self) -> &str {
        self.0.as_str()
    }
}
impl From<AsciiDomain> for String {
    #[inline]
    fn from(value: AsciiDomain) -> Self {
        value.0
    }
}
impl PartialEq<&Self> for AsciiDomain {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<AsciiDomain> for &AsciiDomain {
    #[inline]
    fn eq(&self, other: &AsciiDomain) -> bool {
        **self == *other
    }
}
impl TryFrom<String> for AsciiDomain {
    type Error = AsciiDomainErr;
    /// Verifies `value` is an ASCII domain in representation format converting any uppercase ASCII into
    /// lowercase.
    ///
    /// Note it is _strongly_ encouraged for `value` to only contain letters, numbers, hyphens, and underscores;
    /// otherwise certain applications may consider it not a domain. If the original domain contains non-ASCII, then
    /// one must encode it in Punycode _before_ calling this function. Domains that have a trailing `'.'` will be
    /// considered differently than domains without it; thus one will likely want to trim it if it does exist
    /// (e.g., [`AsciiDomain::remove_trailing_dot`]). Because this allows any ASCII, one may want to ensure `value`
    /// is not an IP address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{error::AsciiDomainErr, AsciiDomain};
    /// // Root `'.'` is not removed if it exists.
    /// assert_ne!("example.com", AsciiDomain::try_from("example.com.".to_owned())?.as_ref());
    /// // Root domain (i.e., `'.'`) is not allowed.
    /// assert!(AsciiDomain::try_from(".".to_owned()).is_err());
    /// // Uppercase is transformed into lowercase.
    /// assert_eq!("example.com", AsciiDomain::try_from("ExAmPle.CoM".to_owned())?.as_ref());
    /// // The only ASCII character not allowed in a domain label is `'.'` as it is used exclusively to delimit
    /// // labels.
    /// assert_eq!("\x00", AsciiDomain::try_from("\x00".to_owned())?.as_ref());
    /// // Empty labels are not allowed.
    /// assert!(AsciiDomain::try_from("example..com".to_owned()).is_err());
    /// // Labels cannot have length greater than 63.
    /// let mut long_label = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
    /// assert_eq!(long_label.len(), 64);
    /// assert!(AsciiDomain::try_from(long_label.clone()).is_err());
    /// long_label.pop();
    /// assert_eq!(long_label, AsciiDomain::try_from(long_label.clone())?.as_ref());
    /// // The maximum length of a domain is 254 if a trailing `'.'` exists; otherwise the max length is 253.
    /// let mut long_domain = format!("{long_label}.{long_label}.{long_label}.{long_label}");
    /// long_domain.pop();
    /// long_domain.push('.');
    /// assert_eq!(long_domain.len(), 255);
    /// assert!(AsciiDomain::try_from(long_domain.clone()).is_err());
    /// long_domain.pop();
    /// long_domain.pop();
    /// long_domain.push('.');
    /// assert_eq!(long_domain.len(), 254);
    /// assert_eq!(long_domain, AsciiDomain::try_from(long_domain.clone())?.as_ref());
    /// long_domain.pop();
    /// long_domain.push('a');
    /// assert_eq!(long_domain.len(), 254);
    /// assert!(AsciiDomain::try_from(long_domain.clone()).is_err());
    /// long_domain.pop();
    /// assert_eq!(long_domain.len(), 253);
    /// assert_eq!(long_domain, AsciiDomain::try_from(long_domain.clone())?.as_ref());
    /// // Only ASCII is allowed; thus if a domain needs to be Punycode-encoded, then it must be _before_ calling
    /// // this function.
    /// assert!(AsciiDomain::try_from("λ.com".to_owned()).is_err());
    /// assert_eq!("xn--wxa.com", AsciiDomain::try_from("xn--wxa.com".to_owned())?.as_ref());
    /// # Ok::<_, AsciiDomainErr>(())
    /// ```
    #[expect(
        unsafe_code,
        reason = "need to transform uppercase ASCII into lowercase"
    )]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment justifies its correctness"
    )]
    #[inline]
    fn try_from(mut value: String) -> Result<Self, Self::Error> {
        value
            .as_bytes()
            .last()
            .ok_or(AsciiDomainErr::Empty)
            .and_then(|b| {
                let len = value.len();
                if *b == b'.' {
                    if len == 1 {
                        Err(AsciiDomainErr::RootDomain)
                    } else if len > 254 {
                        Err(AsciiDomainErr::Len)
                    } else {
                        Ok(())
                    }
                } else if len > 253 {
                    Err(AsciiDomainErr::Len)
                } else {
                    Ok(())
                }
            })
            .and_then(|()| {
                // SAFETY:
                // The only possible mutation we perform is converting uppercase ASCII into lowercase which
                // is entirely safe since ASCII is a subset of UTF-8, and ASCII characters are always encoded
                // as a single UTF-8 code unit.
                let utf8 = unsafe { value.as_bytes_mut() };
                utf8.iter_mut()
                    .try_fold(0u8, |label_len, byt| {
                        let b = *byt;
                        if b == b'.' {
                            if label_len == 0 {
                                Err(AsciiDomainErr::EmptyLabel)
                            } else {
                                Ok(0)
                            }
                        } else if label_len == 63 {
                            Err(AsciiDomainErr::LabelLen)
                        } else if b.is_ascii() {
                            *byt = b.to_ascii_lowercase();
                            // This won't overflow since `label_len < 63`.
                            Ok(label_len + 1)
                        } else {
                            Err(AsciiDomainErr::NotAscii)
                        }
                    })
                    .map(|_| Self(value))
            })
    }
}
/// The output of the [URL serializer](https://url.spec.whatwg.org/#concept-url-serializer).
///
/// The returned URL must consist of a [scheme](https://url.spec.whatwg.org/#concept-url-scheme) and
/// optional [path](https://url.spec.whatwg.org/#url-path) but nothing else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Url(String);
impl AsRef<str> for Url {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}
impl Borrow<str> for Url {
    #[inline]
    fn borrow(&self) -> &str {
        self.0.as_str()
    }
}
impl From<Url> for String {
    #[inline]
    fn from(value: Url) -> Self {
        value.0
    }
}
impl PartialEq<&Self> for Url {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Url> for &Url {
    #[inline]
    fn eq(&self, other: &Url) -> bool {
        **self == *other
    }
}
impl FromStr for Url {
    type Err = UrlErr;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uri::from_str(s).map_err(|_e| UrlErr).and_then(|url| {
            if url.scheme().is_empty()
                || url.has_host()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                Err(UrlErr)
            } else {
                Ok(Self(url.into()))
            }
        })
    }
}
/// [RP ID](https://w3c.github.io/webauthn/#rp-id).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RpId {
    /// An ASCII domain.
    ///
    /// Note web platforms MUST use this variant; and if possible, non-web platforms should too. Also despite
    /// the spec currently requiring RP IDs to be
    /// [valid domain strings](https://url.spec.whatwg.org/#valid-domain-string), this is unnecessarily strict
    /// and will likely be relaxed in a [future version](https://github.com/w3c/webauthn/issues/2206); thus
    /// any ASCII domain is allowed.
    Domain(AsciiDomain),
    /// A URL with only scheme and path.
    Url(Url),
}
impl RpId {
    /// Validates `hash` is the same as the SHA-256 hash of `self`.
    fn validate_rp_id_hash<E>(&self, hash: &[u8]) -> Result<(), CeremonyErr<E>> {
        if hash == Sha256::digest(self.as_ref()).as_slice() {
            Ok(())
        } else {
            Err(CeremonyErr::RpIdHashMismatch)
        }
    }
}
impl AsRef<str> for RpId {
    #[inline]
    fn as_ref(&self) -> &str {
        match *self {
            Self::Domain(ref dom) => dom.as_ref(),
            Self::Url(ref url) => url.as_ref(),
        }
    }
}
impl Borrow<str> for RpId {
    #[inline]
    fn borrow(&self) -> &str {
        match *self {
            Self::Domain(ref dom) => dom.borrow(),
            Self::Url(ref url) => url.borrow(),
        }
    }
}
impl From<RpId> for String {
    #[inline]
    fn from(value: RpId) -> Self {
        match value {
            RpId::Domain(dom) => dom.into(),
            RpId::Url(url) => url.into(),
        }
    }
}
impl PartialEq<&Self> for RpId {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<RpId> for &RpId {
    #[inline]
    fn eq(&self, other: &RpId) -> bool {
        **self == *other
    }
}
/// A URI scheme. This can be used to make
/// [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin) more convenient.
#[derive(Clone, Copy, Debug, Default)]
pub enum Scheme<'a> {
    /// A scheme must not exist when validating the origin.
    None,
    /// Any scheme, or no scheme at all, is allowed to exist when validating the origin.
    Any,
    /// The HTTPS scheme must exist when validating the origin.
    #[default]
    Https,
    /// The SSH scheme must exist when validating the origin.
    Ssh,
    /// The contained `str` scheme must exist when validating the origin.
    Other(&'a str),
    /// [`Self::None`] or [`Self::Https`].
    NoneHttps,
    /// [`Self::None`] or [`Self::Ssh`].
    NoneSsh,
    /// [`Self::None`] or [`Self::Other`].
    NoneOther(&'a str),
}
impl Scheme<'_> {
    /// `self` is any `Scheme`; however `other` is assumed to only be a `Scheme` from a `DomainOrigin` returned
    /// from `DomainOrigin::try_from`. The latter implies that `other` is only `Scheme::None`, `Scheme::Https`,
    /// `Scheme::Ssh`, or `Scheme::Other`; furthermore when `Scheme::Other`, it won't contain a `str` that is
    /// empty or equal to "https" or "ssh".
    #[expect(clippy::unreachable, reason = "there is a bug, so we want to crash")]
    fn is_equal_to_origin_scheme(self, other: Self) -> bool {
        match self {
            Self::None => matches!(other, Self::None),
            Self::Any => true,
            Self::Https => matches!(other, Self::Https),
            Self::Ssh => matches!(other, Self::Ssh),
            Self::Other(scheme) => match other {
                Self::None => false,
                // We want to crash and burn since there is a bug in code.
                Self::Any | Self::NoneHttps | Self::NoneSsh | Self::NoneOther(_) => {
                    unreachable!("there is a bug in DomainOrigin::try_from")
                }
                Self::Https => scheme == "https",
                Self::Ssh => scheme == "ssh",
                Self::Other(scheme_other) => scheme == scheme_other,
            },
            Self::NoneHttps => match other {
                Self::None | Self::Https => true,
                Self::Ssh | Self::Other(_) => false,
                // We want to crash and burn since there is a bug in code.
                Self::Any | Self::NoneHttps | Self::NoneSsh | Self::NoneOther(_) => {
                    unreachable!("there is a bug in DomainOrigin::try_from")
                }
            },
            Self::NoneSsh => match other {
                Self::None | Self::Ssh => true,
                // We want to crash and burn since there is a bug in code.
                Self::Any | Self::NoneHttps | Self::NoneSsh | Self::NoneOther(_) => {
                    unreachable!("there is a bug in DomainOrigin::try_from")
                }
                Self::Https | Self::Other(_) => false,
            },
            Self::NoneOther(scheme) => match other {
                Self::None => true,
                // We want to crash and burn since there is a bug in code.
                Self::Any | Self::NoneHttps | Self::NoneSsh | Self::NoneOther(_) => {
                    unreachable!("there is a bug in DomainOrigin::try_from")
                }
                Self::Https => scheme == "https",
                Self::Ssh => scheme == "ssh",
                Self::Other(scheme_other) => scheme == scheme_other,
            },
        }
    }
}
impl<'a: 'b, 'b> TryFrom<&'a str> for Scheme<'b> {
    type Error = SchemeParseErr;
    /// `"https"` and `"ssh"` get mapped to [`Self::Https`] and [`Self::Ssh`] respectively. All other
    /// values get mapped to [`Self::Other`].
    ///
    /// # Errors
    ///
    /// Errors iff `s` is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Scheme;
    /// assert!(matches!(Scheme::try_from("https")?, Scheme::Https));
    /// assert!(matches!(Scheme::try_from("https ")?, Scheme::Other(scheme) if scheme == "https "));
    /// assert!(matches!(Scheme::try_from("ssh")?, Scheme::Ssh));
    /// assert!(matches!(Scheme::try_from("Ssh")?, Scheme::Other(scheme) if scheme == "Ssh"));
    /// // Even though one can construct an empty `Scheme` via `Scheme::Other` or `Scheme::NoneOther`,
    /// // one cannot parse one.
    /// assert!(Scheme::try_from("").is_err());
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match value {
            "" => Err(SchemeParseErr),
            "https" => Ok(Self::Https),
            "ssh" => Ok(Self::Ssh),
            _ => Ok(Self::Other(value)),
        }
    }
}
/// A TCP/UDP port. This can be used to make
/// [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin) more convenient.
#[derive(Clone, Copy, Debug, Default)]
pub enum Port {
    /// A port must not exist when validating the origin.
    #[default]
    None,
    /// Any port, or no port at all, is allowed to exist when validating the origin.
    Any,
    /// The contained `u16` port must exist when validating the origin.
    Val(u16),
    /// [`Self::None`] or [`Self::Val`].
    NoneVal(u16),
}
impl Port {
    /// `self` is any `Port`; however `other` is assumed to only be a `Port` from a `DomainOrigin` returned
    /// from `DomainOrigin::try_from`. The latter implies that `other` is only `Port::None` or `Port::Val`.
    #[expect(clippy::unreachable, reason = "there is a bug, so we want to crash")]
    fn is_equal_to_origin_port(self, other: Self) -> bool {
        match self {
            Self::None => matches!(other, Self::None),
            Self::Any => true,
            Self::Val(port) => match other {
                Self::None => false,
                // There is a bug in code so we want to crash and burn.
                Self::Any | Self::NoneVal(_) => {
                    unreachable!("there is a bug in DomainOrigin::try_from")
                }
                Self::Val(port_other) => port == port_other,
            },
            Self::NoneVal(port) => match other {
                Self::None => true,
                // There is a bug in code so we want to crash and burn.
                Self::Any | Self::NoneVal(_) => {
                    unreachable!("there is a bug in DomainOrigin::try_from")
                }
                Self::Val(port_other) => port == port_other,
            },
        }
    }
}
impl FromStr for Port {
    type Err = PortParseErr;
    /// Parses `s` as a 16-bit unsigned integer without leading 0s returning [`Self::Val`] with the contained
    /// `u16`.
    ///
    /// # Errors
    ///
    /// Errors iff `s` is not a valid 16-bit unsigned integer in decimal notation without leading 0s.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{error::PortParseErr, Port};
    /// assert!(matches!("443".parse()?, Port::Val(443)));
    /// // TCP/UDP ports have to be in canonical form:
    /// assert!("022"
    ///     .parse::<Port>()
    ///     .map_or_else(|err| matches!(err, PortParseErr::NotCanonical), |_| false));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map_err(PortParseErr::ParseInt).and_then(|port| {
            if s.len()
                == match port {
                    ..=9 => 1,
                    10..=99 => 2,
                    100..=999 => 3,
                    1_000..=9_999 => 4,
                    10_000.. => 5,
                }
            {
                Ok(Self::Val(port))
            } else {
                Err(PortParseErr::NotCanonical)
            }
        })
    }
}
/// A [`tuple origin`](https://html.spec.whatwg.org/multipage/browsers.html#concept-origin-tuple).
///
/// This can be used to make [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin)
/// more convenient.
#[derive(Clone, Copy, Debug)]
pub struct DomainOrigin<'a, 'b> {
    /// The scheme.
    pub scheme: Scheme<'a>,
    /// The host.
    pub host: &'b str,
    /// The TCP/UDP port.
    pub port: Port,
}
impl<'b> DomainOrigin<'_, 'b> {
    /// Returns a `DomainOrigin` with [`Self::scheme`] as [`Scheme::Https`], [`Self::host`] as `host`, and
    /// [`Self::port`] as [`Port::None`].
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate alloc;
    /// # use alloc::borrow::Cow;
    /// # use webauthn_rp::{request::DomainOrigin, response::Origin};
    /// assert_eq!(
    ///     DomainOrigin::new("www.example.com"),
    ///     Origin(Cow::Borrowed("https://www.example.com"))
    /// );
    /// // `DomainOrigin::new` does not allow _any_ port to exist.
    /// assert_ne!(
    ///     DomainOrigin::new("www.example.com"),
    ///     Origin(Cow::Borrowed("https://www.example.com:443"))
    /// );
    /// ```
    #[must_use]
    #[inline]
    pub const fn new<'c: 'b>(host: &'c str) -> Self {
        Self {
            scheme: Scheme::Https,
            host,
            port: Port::None,
        }
    }
    /// Returns a `DomainOrigin` with [`Self::scheme`] as [`Scheme::Https`], [`Self::host`] as `host`, and
    /// [`Self::port`] as [`Port::Any`].
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate alloc;
    /// # use alloc::borrow::Cow;
    /// # use webauthn_rp::{request::DomainOrigin, response::Origin};
    /// // Any port is allowed to exist.
    /// assert_eq!(
    ///     DomainOrigin::new_ignore_port("www.example.com"),
    ///     Origin(Cow::Borrowed("https://www.example.com:1234"))
    /// );
    /// // A port doesn't have to exist at all either.
    /// assert_eq!(
    ///     DomainOrigin::new_ignore_port("www.example.com"),
    ///     Origin(Cow::Borrowed("https://www.example.com"))
    /// );
    /// ```
    #[must_use]
    #[inline]
    pub const fn new_ignore_port<'c: 'b>(host: &'c str) -> Self {
        Self {
            scheme: Scheme::Https,
            host,
            port: Port::Any,
        }
    }
}
impl PartialEq<Origin<'_>> for DomainOrigin<'_, '_> {
    /// Returns `true` iff [`DomainOrigin::scheme`], [`DomainOrigin::host`], and [`DomainOrigin::port`] are the
    /// same after calling [`DomainOrigin::try_from`] on `other.0.as_str()`.
    ///
    /// Note that [`Scheme`] and [`Port`] need not be the same variant. For example [`Scheme::Https`] and
    /// [`Scheme::Other`] containing `"https"` will be treated the same.
    #[inline]
    fn eq(&self, other: &Origin<'_>) -> bool {
        DomainOrigin::try_from(other.0.as_ref()).is_ok_and(|dom| {
            self.scheme.is_equal_to_origin_scheme(dom.scheme)
                && self.host == dom.host
                && self.port.is_equal_to_origin_port(dom.port)
        })
    }
}
impl PartialEq<Origin<'_>> for &DomainOrigin<'_, '_> {
    #[inline]
    fn eq(&self, other: &Origin<'_>) -> bool {
        **self == *other
    }
}
impl PartialEq<&Origin<'_>> for DomainOrigin<'_, '_> {
    #[inline]
    fn eq(&self, other: &&Origin<'_>) -> bool {
        *self == **other
    }
}
impl PartialEq<DomainOrigin<'_, '_>> for Origin<'_> {
    #[inline]
    fn eq(&self, other: &DomainOrigin<'_, '_>) -> bool {
        *other == *self
    }
}
impl PartialEq<DomainOrigin<'_, '_>> for &Origin<'_> {
    #[inline]
    fn eq(&self, other: &DomainOrigin<'_, '_>) -> bool {
        *other == **self
    }
}
impl PartialEq<&DomainOrigin<'_, '_>> for Origin<'_> {
    #[inline]
    fn eq(&self, other: &&DomainOrigin<'_, '_>) -> bool {
        **other == *self
    }
}
impl<'a: 'b + 'c, 'b, 'c> TryFrom<&'a str> for DomainOrigin<'b, 'c> {
    type Error = DomainOriginParseErr;
    /// `value` is parsed according to the following extended regex:
    ///
    /// `^([^:]*:\/\/)?[^:]*(:.*)?$`
    ///
    /// where the `[^:]*` of the first capturing group is parsed according to [`Scheme::try_from`], and
    /// the `.*` of the second capturing group is parsed according to [`Port::from_str`].
    ///
    /// # Errors
    ///
    /// Errors iff `Scheme::try_from` or `Port::from_str` fail when applicable.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{DomainOrigin, Port, Scheme};
    /// assert!(
    ///     DomainOrigin::try_from("https://www.example.com:443").map_or(false, |dom| matches!(
    ///         dom.scheme,
    ///         Scheme::Https
    ///     ) && dom.host
    ///         == "www.example.com"
    ///         && matches!(dom.port, Port::Val(port) if port == 443))
    /// );
    /// // Parsing is done in a case sensitive way.
    /// assert!(DomainOrigin::try_from("Https://www.EXample.com").map_or(
    ///     false,
    ///     |dom| matches!(dom.scheme, Scheme::Other(scheme) if scheme == "Https")
    ///         && dom.host == "www.EXample.com"
    ///         && matches!(dom.port, Port::None)
    /// ));
    /// ```
    #[inline]
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        // Any string that contains `':'` is not a [valid domain](https://url.spec.whatwg.org/#valid-domain), and
        // and `"//"` never exists in a `Port`; thus if `"://"` exists, it's either invalid or delimits the scheme
        // from the rest of the origin.
        match value.split_once("://") {
            None => Ok((Scheme::None, value)),
            Some((poss_scheme, rem)) => Scheme::try_from(poss_scheme)
                .map_err(DomainOriginParseErr::Scheme)
                .map(|scheme| (scheme, rem)),
        }
        .and_then(|(scheme, rem)| {
            // `':'` never exists in a valid domain; thus if it exists, it's either invalid or
            // separates the domain from the port.
            rem.split_once(':')
                .map_or_else(
                    || Ok((rem, Port::None)),
                    |(rem2, poss_port)| {
                        Port::from_str(poss_port)
                            .map_err(DomainOriginParseErr::Port)
                            .map(|port| (rem2, port))
                    },
                )
                .map(|(host, port)| Self { scheme, host, port })
        })
    }
}
/// [`PublicKeyCredentialDescriptor`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptor)
/// associated with a registered credential.
#[derive(Clone, Debug)]
pub struct PublicKeyCredentialDescriptor<T> {
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialdescriptor-id).
    pub id: CredentialId<T>,
    /// [`transports`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialdescriptor-transports).
    pub transports: AuthTransports,
}
/// [`UserVerificationRequirement`](https://www.w3.org/TR/webauthn-3/#enumdef-userverificationrequirement).
#[derive(Clone, Copy, Debug)]
pub enum UserVerificationRequirement {
    /// [`required`](https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-required).
    Required,
    /// [`discouraged`](https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-discouraged).
    ///
    /// Note some authenticators always require user verification when registering a credential (e.g.,
    /// [CTAP 2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html)
    /// authenticators that have had a PIN enabled).
    Discouraged,
    /// [`preferred`](https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-preferred).
    Preferred,
}
#[cfg(test)]
impl PartialEq for UserVerificationRequirement {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::Required => matches!(other, Self::Required),
            Self::Discouraged => matches!(other, Self::Discouraged),
            Self::Preferred => matches!(other, Self::Preferred),
        }
    }
}
/// [`PublicKeyCredentialHints`](https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint).
#[derive(Clone, Copy, Debug, Default)]
pub enum Hint {
    /// No hints.
    #[default]
    None,
    /// [`security-key`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-security-key).
    SecurityKey,
    /// [`client-device`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-client-device).
    ClientDevice,
    /// [`hybrid`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-hybrid).
    Hybrid,
    /// [`Self::SecurityKey`] and [`Self::ClientDevice`].
    SecurityKeyClientDevice,
    /// [`Self::ClientDevice`] and [`Self::SecurityKey`].
    ClientDeviceSecurityKey,
    /// [`Self::SecurityKey`] and [`Self::Hybrid`].
    SecurityKeyHybrid,
    /// [`Self::Hybrid`] and [`Self::SecurityKey`].
    HybridSecurityKey,
    /// [`Self::ClientDevice`] and [`Self::Hybrid`].
    ClientDeviceHybrid,
    /// [`Self::Hybrid`] and [`Self::ClientDevice`].
    HybridClientDevice,
    /// [`Self::SecurityKeyClientDevice`] and [`Self::Hybrid`].
    SecurityKeyClientDeviceHybrid,
    /// [`Self::SecurityKeyHybrid`] and [`Self::ClientDevice`].
    SecurityKeyHybridClientDevice,
    /// [`Self::ClientDeviceSecurityKey`] and [`Self::Hybrid`].
    ClientDeviceSecurityKeyHybrid,
    /// [`Self::ClientDeviceHybrid`] and [`Self::SecurityKey`].
    ClientDeviceHybridSecurityKey,
    /// [`Self::HybridSecurityKey`] and [`Self::ClientDevice`].
    HybridSecurityKeyClientDevice,
    /// [`Self::HybridClientDevice`] and [`Self::SecurityKey`].
    HybridClientDeviceSecurityKey,
}
#[cfg(test)]
impl PartialEq for Hint {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::None => matches!(other, Self::None),
            Self::SecurityKey => matches!(other, Self::SecurityKey),
            Self::ClientDevice => matches!(other, Self::ClientDevice),
            Self::Hybrid => matches!(other, Self::Hybrid),
            Self::SecurityKeyClientDevice => matches!(other, Self::SecurityKeyClientDevice),
            Self::ClientDeviceSecurityKey => matches!(other, Self::ClientDeviceSecurityKey),
            Self::SecurityKeyHybrid => matches!(other, Self::SecurityKeyHybrid),
            Self::HybridSecurityKey => matches!(other, Self::HybridSecurityKey),
            Self::ClientDeviceHybrid => matches!(other, Self::ClientDeviceHybrid),
            Self::HybridClientDevice => matches!(other, Self::HybridClientDevice),
            Self::SecurityKeyClientDeviceHybrid => {
                matches!(other, Self::SecurityKeyClientDeviceHybrid)
            }
            Self::SecurityKeyHybridClientDevice => {
                matches!(other, Self::SecurityKeyHybridClientDevice)
            }
            Self::ClientDeviceSecurityKeyHybrid => {
                matches!(other, Self::ClientDeviceSecurityKeyHybrid)
            }
            Self::ClientDeviceHybridSecurityKey => {
                matches!(other, Self::ClientDeviceHybridSecurityKey)
            }
            Self::HybridSecurityKeyClientDevice => {
                matches!(other, Self::HybridSecurityKeyClientDevice)
            }
            Self::HybridClientDeviceSecurityKey => {
                matches!(other, Self::HybridClientDeviceSecurityKey)
            }
        }
    }
}
/// Controls if the response to a requested extension is required to be sent back.
///
/// Note when requiring an extension, the extension must not only be sent back but also
/// contain at least one expected field
/// (e.g., [`ClientExtensionsOutputs::cred_props`] must be
/// `Some(CredentialPropertiesOutput { rk: Some(_) })`.
///
/// If one wants to additionally control the values of an extension, use [`ExtensionInfo`].
#[derive(Clone, Copy, Debug)]
pub enum ExtensionReq {
    /// The response to a requested extension is required to be sent back.
    Require,
    /// The response to a requested extension is allowed, but not required, to be sent back.
    Allow,
}
#[cfg(test)]
impl PartialEq for ExtensionReq {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::Require => matches!(other, Self::Require),
            Self::Allow => matches!(other, Self::Allow),
        }
    }
}
/// Dictates how an extension should be processed.
///
/// If one wants to only control if the extension should be returned, use [`ExtensionReq`].
#[derive(Clone, Copy, Debug)]
pub enum ExtensionInfo {
    /// Require the associated extension and enforce its value.
    RequireEnforceValue,
    /// Require the associated extension but don't enforce its value.
    RequireDontEnforceValue,
    /// Allow the associated extension to exist and enforce its value when it does exist.
    AllowEnforceValue,
    /// Allow the associated extension to exist but don't enforce its value.
    AllowDontEnforceValue,
}
#[cfg(test)]
impl PartialEq for ExtensionInfo {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::RequireEnforceValue => matches!(other, Self::RequireEnforceValue),
            Self::RequireDontEnforceValue => matches!(other, Self::RequireDontEnforceValue),
            Self::AllowEnforceValue => matches!(other, Self::AllowEnforceValue),
            Self::AllowDontEnforceValue => matches!(other, Self::AllowDontEnforceValue),
        }
    }
}
impl Display for ExtensionInfo {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::RequireEnforceValue => "require the corresponding extension response and enforce its value",
            Self::RequireDontEnforceValue => "require the corresponding extension response but don't enforce its value",
            Self::AllowEnforceValue => "don't require the corresponding extension response; but if sent, enforce its value",
            Self::AllowDontEnforceValue => "don't require the corresponding extension response; and if sent, don't enforce its value",
        })
    }
}
/// [`CredentialMediationRequirement`](https://www.w3.org/TR/credential-management-1/#enumdef-credentialmediationrequirement).
#[derive(Clone, Copy, Debug, Default)]
pub enum CredentialMediationRequirement {
    /// [`silent`](https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-silent).
    Silent,
    /// [`optional`](https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-optional).
    #[default]
    Optional,
    /// [`conditional`](https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-conditional).
    ///
    /// Note that when registering a new credential with [`CredentialCreationOptions::mediation`] set to
    /// `Self::Conditional`, [`UserVerificationRequirement::Discouraged`] MUST be used unless user verification
    /// can be explicitly performed during the ceremony.
    Conditional,
    /// [`required`](https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-required).
    Required,
}
#[cfg(test)]
impl PartialEq for CredentialMediationRequirement {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::Silent => matches!(other, Self::Silent),
            Self::Optional => matches!(other, Self::Optional),
            Self::Conditional => matches!(other, Self::Conditional),
            Self::Required => matches!(other, Self::Required),
        }
    }
}
/// Backup requirements for the credential.
#[derive(Clone, Copy, Debug, Default)]
pub enum BackupReq {
    /// No requirements (i.e., any [`Backup`] is allowed).
    #[default]
    None,
    /// Credential must not be eligible for backup.
    NotEligible,
    /// Credential must be eligible for backup.
    ///
    /// Note the existence of a backup is ignored. If a backup must exist, then use [`Self::Exists`]; if a
    /// backup must not exist, then use [`Self::EligibleNotExists`].
    Eligible,
    /// Credential must be eligible for backup, but a backup must not exist.
    EligibleNotExists,
    /// Credential must be backed up.
    Exists,
}
impl From<Backup> for BackupReq {
    /// One may want to create `BackupReq` based on the previous `Backup` such that the subsequent `Backup` is
    /// essentially unchanged.
    ///
    /// Specifically this transforms [`Backup::NotEligible`] to [`Self::NotEligible`] and [`Backup::Eligible`] and
    /// [`Backup::Exists`] to [`Self::Eligible`]. Note this means that a credential that
    /// is eligible to be backed up but currently does not have a backup will be allowed to change such that it
    /// is backed up. Similarly, a credential that is backed up is allowed to change such that a backup no longer
    /// exists.
    #[inline]
    fn from(value: Backup) -> Self {
        if matches!(value, Backup::NotEligible) {
            Self::NotEligible
        } else {
            Self::Eligible
        }
    }
}
/// A container of "credentials".
///
/// This is mainly a way to unify [`Vec`] of [`PublicKeyCredentialDescriptor`]
/// and [`AllowedCredentials`]. This can be useful in situations when one only
/// deals with [`AllowedCredential`]s with empty [`CredentialSpecificExtension`]s
/// essentially making them the same as [`PublicKeyCredentialDescriptor`]s.
///
/// # Examples
///
/// ```
/// # use webauthn_rp::{
/// #     request::{
/// #         auth::AllowedCredentials, register::UserHandle, Credentials, PublicKeyCredentialDescriptor,
/// #     },
/// #     response::{AuthTransports, CredentialId},
/// # };
/// /// Fetches all credentials under `user_handle` to be allowed during authentication for non-discoverable
/// /// requests.
/// # #[cfg(feature = "custom")]
/// fn get_allowed_credentials<const LEN: usize>(user_handle: &UserHandle<LEN>) -> AllowedCredentials {
///     get_credentials(user_handle)
/// }
/// /// Fetches all credentials under `user_handle` to be excluded during registration.
/// # #[cfg(feature = "custom")]
/// fn get_excluded_credentials<const LEN: usize>(
///     user_handle: &UserHandle<LEN>,
/// ) -> Vec<PublicKeyCredentialDescriptor<Vec<u8>>> {
///     get_credentials(user_handle)
/// }
/// /// Used to fetch the excluded `PublicKeyCredentialDescriptor`s associated with `user_handle` during
/// /// registration as well as the `AllowedCredentials` containing `AllowedCredential`s with no credential-specific
/// /// extensions which is used for non-discoverable requests.
/// # #[cfg(feature = "custom")]
/// fn get_credentials<const LEN: usize, T>(user_handle: &UserHandle<LEN>) -> T
/// where
///     T: Credentials,
///     PublicKeyCredentialDescriptor<Vec<u8>>: Into<T::Credential>,
/// {
///     let iter = get_cred_parts(user_handle);
///     let len = iter.size_hint().0;
///     iter.fold(T::with_capacity(len), |mut creds, parts| {
///         creds.push(
///             PublicKeyCredentialDescriptor {
///                 id: parts.0,
///                 transports: parts.1,
///             }
///             .into(),
///         );
///         creds
///     })
/// }
/// /// Fetches all `CredentialId`s and associated `AuthTransports` under `user_handle`
/// /// from the database.
/// # #[cfg(feature = "custom")]
/// fn get_cred_parts<const LEN: usize>(
///     user_handle: &UserHandle<LEN>,
/// ) -> impl Iterator<Item = (CredentialId<Vec<u8>>, AuthTransports)> {
///     // ⋮
/// #     [(
/// #         CredentialId::try_from(vec![0; 16]).unwrap(),
/// #         AuthTransports::NONE,
/// #     )]
/// #     .into_iter()
/// }
/// ```
pub trait Credentials: Sized {
    /// The "credential"s that make up `Self`.
    type Credential;
    /// Returns `Self`.
    #[inline]
    #[must_use]
    fn new() -> Self {
        Self::with_capacity(0)
    }
    /// Returns `Self` with at least `capacity` allocated.
    fn with_capacity(capacity: usize) -> Self;
    /// Adds `cred` to `self`.
    ///
    /// Returns `true` iff `cred` was added.
    fn push(&mut self, cred: Self::Credential) -> bool;
    /// Returns the number of [`Self::Credential`]s in `Self`.
    fn len(&self) -> usize;
    /// Returns `true` iff [`Self::len`] is `0`.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T> Credentials for Vec<T> {
    type Credential = T;
    #[inline]
    fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
    #[inline]
    fn push(&mut self, cred: Self::Credential) -> bool {
        self.push(cred);
        true
    }
    #[inline]
    fn len(&self) -> usize {
        self.len()
    }
}
/// Additional options that control how [`Ceremony::partial_validate`] works.
struct CeremonyOptions<'origins, 'top_origins, O, T> {
    /// Origins to use for [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin).
    ///
    /// When this is empty, the origin that will be used will be based on
    /// the [`RpId`] passed to [`RegistrationServerState::verify`]. If [`RpId::Domain`], then the [`DomainOrigin`] returned from
    /// passing [`AsciiDomain::as_ref`] to [`DomainOrigin::new`] will be used; otherwise the [`Url`] in
    /// [`RpId::Url`] will be used.
    allowed_origins: &'origins [O],
    /// [Top-level origins](https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-top-level-origin)
    /// to use for [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin).
    ///
    /// When this is `Some`, [`CollectedClientData::cross_origin`] is allowed to be `true`. When the contained
    /// `slice` is empty, [`CollectedClientData::top_origin`] must be `None`. When this is `None`,
    /// `CollectedClientData::cross_origin` must be `false` and `CollectedClientData::top_origin` must be `None`.
    allowed_top_origins: Option<&'top_origins [T]>,
    /// The required [`Backup`] state of the credential.
    backup_requirement: BackupReq,
    /// [`CollectedClientData::from_client_data_json_relaxed`] is used to extract [`CollectedClientData`] iff `true`.
    #[cfg(feature = "serde_relaxed")]
    client_data_json_relaxed: bool,
}
impl<'o, 't, O, T> From<&RegistrationVerificationOptions<'o, 't, O, T>>
    for CeremonyOptions<'o, 't, O, T>
{
    fn from(value: &RegistrationVerificationOptions<'o, 't, O, T>) -> Self {
        Self {
            allowed_origins: value.allowed_origins,
            allowed_top_origins: value.allowed_top_origins,
            backup_requirement: value.backup_requirement,
            #[cfg(feature = "serde_relaxed")]
            client_data_json_relaxed: value.client_data_json_relaxed,
        }
    }
}
/// Functionality common to both registration and authentication ceremonies.
///
/// Designed to be implemented on the _request_ side.
trait Ceremony<const USER_LEN: usize, const DISCOVERABLE: bool> {
    /// The type of response that is associated with the ceremony.
    type R: Response;
    /// Challenge.
    fn rand_challenge(&self) -> SentChallenge;
    /// `Instant` the ceremony was expires.
    #[cfg(not(feature = "serializable_server_state"))]
    fn expiry(&self) -> Instant;
    /// `Instant` the ceremony was expires.
    #[cfg(feature = "serializable_server_state")]
    fn expiry(&self) -> SystemTime;
    /// User verification requirement.
    fn user_verification(&self) -> UserVerificationRequirement;
    /// Performs validation of ceremony criteria common to both ceremony types.
    #[expect(
        clippy::type_complexity,
        reason = "type aliases with bounds are even more problematic at least until lazy_type_alias is stable"
    )]
    #[expect(clippy::too_many_lines, reason = "102 lines is fine")]
    fn partial_validate<'a, O: PartialEq<Origin<'a>>, T: PartialEq<Origin<'a>>>(
        &self,
        rp_id: &RpId,
        resp: &'a Self::R,
        key: <<Self::R as Response>::Auth as AuthResponse>::CredKey<'_>,
        options: &CeremonyOptions<'_, '_, O, T>,
    ) -> Result<
        <<Self::R as Response>::Auth as AuthResponse>::Auth<'a>,
        CeremonyErr<
            <<<Self::R as Response>::Auth as AuthResponse>::Auth<'a> as AuthDataContainer<'a>>::Err,
        >,
    > {
        // [Registration ceremony](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)
        // is handled by:
        //
        // 1. Calling code.
        // 2. Client code and the construction of `resp` (hopefully via [`Registration::deserialize`]).
        // 3. Client code and the construction of `resp` (hopefully via [`AuthenticatorAttestation::deserialize`]).
        // 4. Client code and the construction of `resp` (hopefully via [`ClientExtensionsOutputs::deserialize`]).
        // 5. Below via [`CollectedClientData::from_client_data_json_relaxed`].
        // 6. Below via [`CollectedClientData::from_client_data_json_relaxed`] or [`CollectedClientData::from_client_data_json_relaxed`].
        // 7. Below via [`CollectedClientData::from_client_data_json_relaxed`] or [`CollectedClientData::from_client_data_json_relaxed`].
        // 8. Below.
        // 9. Below.
        // 10. Below.
        // 11. Below.
        // 12. Below via [`AuthenticatorAttestation::new`].
        // 13. Below via [`AttestationObject::parse_data`].
        // 14. Below.
        // 15. [`RegistrationServerState::verify`].
        // 16. Below.
        // 17. Below via [`AuthenticatorData::from_cbor`].
        // 18. Below.
        // 19. Below.
        // 20. [`RegistrationServerState::verify`].
        // 21. Below via [`AttestationObject::parse_data`].
        // 22. Below via [`AttestationObject::parse_data`].
        // 23. N/A since only none and self attestations are supported.
        // 24. Always satisfied since only none and self attestations are supported (Item 3 is N/A).
        // 25. Below via [`AttestedCredentialData::from_cbor`].
        // 26. Calling code.
        // 27. [`RegistrationServerState::verify`].
        // 28. N/A since only none and self attestations are supported.
        // 29. [`RegistrationServerState::verify`].
        //
        //
        // [Authentication ceremony](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)
        // is handled by:
        //
        // 1. Calling code.
        // 2. Client code and the construction of `resp` (hopefully via [`Authentication::deserialize`]).
        // 3. Client code and the construction of `resp` (hopefully via [`AuthenticatorAssertion::deserialize`]).
        // 4. Client code and the construction of `resp` (hopefully via [`ClientExtensionsOutputs::deserialize`]).
        // 5. [`AuthenticationServerState::verify`].
        // 6. [`AuthenticationServerState::verify`].
        // 7. Informative only in that it defines variables.
        // 8. Below via [`CollectedClientData::from_client_data_json_relaxed`].
        // 9. Below via [`CollectedClientData::from_client_data_json_relaxed`] or [`CollectedClientData::from_client_data_json_relaxed`].
        // 10. Below via [`CollectedClientData::from_client_data_json_relaxed`] or [`CollectedClientData::from_client_data_json_relaxed`].
        // 11. Below.
        // 12. Below.
        // 13. Below.
        // 14. Below.
        // 15. Below.
        // 16. Below via [`AuthenticatorData::from_cbor`].
        // 17. Below.
        // 18. Below via [`AuthenticatorData::from_cbor`].
        // 19. Below.
        // 20. Below via [`AuthenticatorAssertion::new`].
        // 21. Below.
        // 22. [`AuthenticationServerState::verify`].
        // 23. [`AuthenticationServerState::verify`].
        // 24. [`AuthenticationServerState::verify`].
        // 25. [`AuthenticationServerState::verify`].

        // Enforce timeout.
        #[cfg(not(feature = "serializable_server_state"))]
        let active = self.expiry() >= Instant::now();
        #[cfg(feature = "serializable_server_state")]
        let active = self.expiry() >= SystemTime::now();
        if active {
            #[cfg(feature = "serde_relaxed")]
            let relaxed = options.client_data_json_relaxed;
            #[cfg(not(feature = "serde_relaxed"))]
            let relaxed = false;
            resp.auth()
                // Steps 5–7, 12–13, 17, 21–22, and 25 of the registration ceremony.
                // Steps 8–10, 16, 18, and 20–21 of the authentication ceremony.
                .parse_data_and_verify_sig(key, relaxed)
                .map_err(CeremonyErr::AuthResp)
                .and_then(|(client_data_json, auth_response)| {
                    if options.allowed_origins.is_empty() {
                        if match *rp_id {
                            RpId::Domain(ref dom) => {
                                // Steps 9 and 12 of the registration and authentication ceremonies
                                // respectively.
                                DomainOrigin::new(dom.as_ref()) == client_data_json.origin
                            }
                            // Steps 9 and 12 of the registration and authentication ceremonies
                            // respectively.
                            RpId::Url(ref url) => url == client_data_json.origin,
                        } {
                            Ok(())
                        } else {
                            Err(CeremonyErr::OriginMismatch)
                        }
                    } else {
                        options
                            .allowed_origins
                            .iter()
                            // Steps 9 and 12 of the registration and authentication ceremonies
                            // respectively.
                            .find(|o| **o == client_data_json.origin)
                            .ok_or(CeremonyErr::OriginMismatch)
                            .map(|_| ())
                    }
                    .and_then(|()| {
                        // Steps 10–11 of the registration ceremony.
                        // Steps 13–14 of the authentication ceremony.
                        match options.allowed_top_origins {
                            None => {
                                if client_data_json.cross_origin {
                                    Err(CeremonyErr::CrossOrigin)
                                } else if client_data_json.top_origin.is_some() {
                                    Err(CeremonyErr::TopOriginMismatch)
                                } else {
                                    Ok(())
                                }
                            }
                            Some(top_origins) => client_data_json.top_origin.map_or(Ok(()), |t| {
                                top_origins
                                    .iter()
                                    .find(|top| **top == t)
                                    .ok_or(CeremonyErr::TopOriginMismatch)
                                    .map(|_| ())
                            }),
                        }
                        .and_then(|()| {
                            // Steps 8 and 11 of the registration and authentication ceremonies
                            // respectively.
                            if self.rand_challenge() == client_data_json.challenge {
                                let auth_data = auth_response.authenticator_data();
                                rp_id
                                    // Steps 14 and 15 of the registration and authentication ceremonies
                                    // respectively.
                                    .validate_rp_id_hash(auth_data.rp_hash())
                                    .and_then(|()| {
                                        let flag = auth_data.flag();
                                        // Steps 16 and 17 of the registration and authentication ceremonies
                                        // respectively.
                                        if flag.user_verified
                                            || !matches!(
                                                self.user_verification(),
                                                UserVerificationRequirement::Required
                                            )
                                        {
                                            // Steps 18–19 of the registration ceremony.
                                            // Step 19 of the authentication ceremony.
                                            match options.backup_requirement {
                                                BackupReq::None => Ok(()),
                                                BackupReq::NotEligible => {
                                                    if matches!(flag.backup, Backup::NotEligible) {
                                                        Ok(())
                                                    } else {
                                                        Err(CeremonyErr::BackupEligible)
                                                    }
                                                }
                                                BackupReq::Eligible => {
                                                    if matches!(flag.backup, Backup::NotEligible) {
                                                        Err(CeremonyErr::BackupNotEligible)
                                                    } else {
                                                        Ok(())
                                                    }
                                                }
                                                BackupReq::EligibleNotExists => {
                                                    if matches!(flag.backup, Backup::Eligible) {
                                                        Ok(())
                                                    } else {
                                                        Err(CeremonyErr::BackupExists)
                                                    }
                                                }
                                                BackupReq::Exists => {
                                                    if matches!(flag.backup, Backup::Exists) {
                                                        Ok(())
                                                    } else {
                                                        Err(CeremonyErr::BackupDoesNotExist)
                                                    }
                                                }
                                            }
                                        } else {
                                            Err(CeremonyErr::UserNotVerified)
                                        }
                                    })
                                    .map(|()| auth_response)
                            } else {
                                Err(CeremonyErr::ChallengeMismatch)
                            }
                        })
                    })
                })
        } else {
            Err(CeremonyErr::Timeout)
        }
    }
}
/// `300_000` milliseconds is equal to five minutes.
pub(super) const THREE_HUNDRED_THOUSAND: NonZeroU32 = NonZeroU32::new(300_000).unwrap();
/// "Ceremonies" stored on the server that expire after a certain duration.
///
/// Types like [`RegistrationServerState`] and [`DiscoverableAuthenticationServerState`] are based on [`Challenge`]s
/// that expire after a certain duration.
pub trait TimedCeremony {
    /// Returns the `Instant` the ceremony expires.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is returned instead.
    #[cfg_attr(docsrs, doc(cfg(not(feature = "serializable_server_state"))))]
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    fn expiration(&self) -> Instant;
    /// Returns the `SystemTime` the ceremony expires.
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    fn expiration(&self) -> SystemTime;
}
/// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues).
#[derive(Clone, Copy, Debug)]
pub struct PrfInput<'first, 'second> {
    /// [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first).
    pub first: &'first [u8],
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second).
    pub second: Option<&'second [u8]>,
}
#[cfg(test)]
impl PartialEq for PrfInput<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        self.first == other.first && self.second == other.second
    }
}
#[cfg(test)]
mod tests {
    #[cfg(feature = "custom")]
    use super::{
        super::{
            AggErr, AuthenticatedCredential,
            response::{
                AuthTransports, AuthenticatorAttachment, Backup, CredentialId,
                auth::{
                    DiscoverableAuthentication, DiscoverableAuthenticatorAssertion,
                    NonDiscoverableAuthentication, NonDiscoverableAuthenticatorAssertion,
                },
                register::{
                    AuthenticationExtensionsPrfOutputs, AuthenticatorAttestation,
                    AuthenticatorExtensionOutputStaticState, ClientExtensionsOutputs,
                    ClientExtensionsOutputsStaticState, CompressedP256PubKey, CompressedP384PubKey,
                    CompressedPubKey, CredentialProtectionPolicy, DynamicState, Ed25519PubKey,
                    Registration, RsaPubKey, StaticState, UncompressedPubKey,
                },
            },
        },
        AsciiDomain, Challenge, Credentials, ExtensionInfo, ExtensionReq, PrfInput,
        PublicKeyCredentialDescriptor, RpId, UserVerificationRequirement,
        auth::{
            AllowedCredential, AllowedCredentials, AuthenticationVerificationOptions,
            CredentialSpecificExtension, DiscoverableCredentialRequestOptions,
            Extension as AuthExt, NonDiscoverableCredentialRequestOptions, PrfInputOwned,
        },
        register::{
            CredProtect, CredentialCreationOptions, Extension as RegExt, FourToSixtyThree,
            PublicKeyCredentialUserEntity, RegistrationVerificationOptions, UserHandle,
        },
    };
    #[cfg(feature = "custom")]
    use ed25519_dalek::{Signer, SigningKey};
    #[cfg(feature = "custom")]
    use p256::{
        ecdsa::{DerSignature as P256DerSig, SigningKey as P256Key},
        elliptic_curve::sec1::Tag,
    };
    #[cfg(feature = "custom")]
    use p384::ecdsa::{DerSignature as P384DerSig, SigningKey as P384Key};
    #[cfg(feature = "custom")]
    use rsa::{
        BigUint, RsaPrivateKey,
        pkcs1v15::SigningKey as RsaKey,
        sha2::{Digest, Sha256},
        signature::{Keypair, SignatureEncoding},
        traits::PublicKeyParts,
    };
    #[cfg(feature = "custom")]
    const CBOR_UINT: u8 = 0b000_00000;
    #[cfg(feature = "custom")]
    const CBOR_NEG: u8 = 0b001_00000;
    #[cfg(feature = "custom")]
    const CBOR_BYTES: u8 = 0b010_00000;
    #[cfg(feature = "custom")]
    const CBOR_TEXT: u8 = 0b011_00000;
    #[cfg(feature = "custom")]
    const CBOR_MAP: u8 = 0b101_00000;
    #[cfg(feature = "custom")]
    const CBOR_SIMPLE: u8 = 0b111_00000;
    #[cfg(feature = "custom")]
    const CBOR_TRUE: u8 = CBOR_SIMPLE | 21;
    #[test]
    #[cfg(feature = "custom")]
    fn eddsa_reg() -> Result<(), AggErr> {
        let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
        let id = UserHandle::from([0]);
        let mut opts = CredentialCreationOptions::passkey(
            &rp_id,
            PublicKeyCredentialUserEntity {
                name: "foo".try_into()?,
                id: &id,
                display_name: None,
            },
            Vec::new(),
        );
        opts.public_key.challenge = Challenge(0);
        opts.public_key.extensions = RegExt {
            cred_props: None,
            cred_protect: CredProtect::UserVerificationRequired(
                false,
                ExtensionInfo::RequireEnforceValue,
            ),
            min_pin_length: Some((
                FourToSixtyThree::new(10)
                    .unwrap_or_else(|| unreachable!("bug in FourToSixyThree::new")),
                ExtensionInfo::RequireEnforceValue,
            )),
            prf: Some((
                PrfInput {
                    first: [0].as_slice(),
                    second: None,
                },
                ExtensionInfo::RequireEnforceValue,
            )),
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
        assert!(matches!(opts.start_ceremony()?.0.verify(
            &rp_id,
            &Registration {
                response: AuthenticatorAttestation::new(
                    client_data_json,
                    attestation_object,
                    AuthTransports::NONE,
                ),
                authenticator_attachment: AuthenticatorAttachment::None,
                client_extension_results: ClientExtensionsOutputs {
                    cred_props: None,
                    prf: Some(AuthenticationExtensionsPrfOutputs { enabled: true, }),
                },
            },
            &RegistrationVerificationOptions::<&str, &str>::default(),
        )?.static_state.credential_public_key, UncompressedPubKey::Ed25519(k) if k.into_inner() == pub_key));
        Ok(())
    }
    #[test]
    #[cfg(feature = "custom")]
    fn eddsa_auth() -> Result<(), AggErr> {
        let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
        let mut creds = AllowedCredentials::with_capacity(1);
        creds.push(AllowedCredential {
            credential: PublicKeyCredentialDescriptor {
                id: CredentialId::try_from(vec![0; 16])?,
                transports: AuthTransports::NONE,
            },
            extension: CredentialSpecificExtension {
                prf: Some(PrfInputOwned {
                    first: Vec::new(),
                    second: Some(Vec::new()),
                    ext_req: ExtensionReq::Require,
                }),
            },
        });
        let mut opts = NonDiscoverableCredentialRequestOptions::second_factor(&rp_id, creds)?;
        opts.options().user_verification = UserVerificationRequirement::Required;
        opts.options().challenge = Challenge(0);
        opts.options().extensions = AuthExt { prf: None };
        let client_data_json = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.to_vec();
        // We over-allocate by 32 bytes. See [`AuthenticatorAssertion::new`] for more information.
        let mut authenticator_data = Vec::with_capacity(164);
        authenticator_data.extend_from_slice(
            [
                // rpIdHash.
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
                // flags.
                // UP, UV, and ED (right-to-left).
                0b1000_0101,
                // signCount.
                // 0 as 32-bit big endian.
                0,
                0,
                0,
                0,
                CBOR_MAP | 1,
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
                CBOR_BYTES | 24,
                // Length is 80.
                80,
                // Two HMAC outputs concatenated and encrypted.
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
        authenticator_data[..32]
            .copy_from_slice(Sha256::digest(rp_id.as_ref().as_bytes()).as_slice());
        authenticator_data
            .extend_from_slice(Sha256::digest(client_data_json.as_slice()).as_slice());
        let ed_priv = SigningKey::from([0; 32]);
        let sig = ed_priv.sign(authenticator_data.as_slice()).to_vec();
        authenticator_data.truncate(132);
        assert!(!opts.start_ceremony()?.0.verify(
            &rp_id,
            &NonDiscoverableAuthentication {
                raw_id: CredentialId::try_from(vec![0; 16])?,
                response: NonDiscoverableAuthenticatorAssertion::with_user(
                    client_data_json,
                    authenticator_data,
                    sig,
                    UserHandle::from([0]),
                ),
                authenticator_attachment: AuthenticatorAttachment::None,
            },
            &mut AuthenticatedCredential::new(
                CredentialId::try_from([0; 16].as_slice())?,
                &UserHandle::from([0]),
                StaticState {
                    credential_public_key: CompressedPubKey::<_, &[u8], &[u8], &[u8]>::Ed25519(
                        Ed25519PubKey::from(ed_priv.verifying_key().to_bytes()),
                    ),
                    extensions: AuthenticatorExtensionOutputStaticState {
                        cred_protect: CredentialProtectionPolicy::None,
                        hmac_secret: Some(true),
                    },
                    client_extension_results: ClientExtensionsOutputsStaticState {
                        prf: Some(AuthenticationExtensionsPrfOutputs { enabled: true }),
                    }
                },
                DynamicState {
                    user_verified: true,
                    backup: Backup::NotEligible,
                    sign_count: 0,
                    authenticator_attachment: AuthenticatorAttachment::None,
                },
            )?,
            &AuthenticationVerificationOptions::<&str, &str>::default(),
        )?);
        Ok(())
    }
    #[test]
    #[cfg(feature = "custom")]
    fn es256_reg() -> Result<(), AggErr> {
        let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
        let id = UserHandle::from([0]);
        let mut opts = CredentialCreationOptions::passkey(
            &rp_id,
            PublicKeyCredentialUserEntity {
                name: "foo".try_into()?,
                id: &id,
                display_name: None,
            },
            Vec::new(),
        );
        opts.public_key.challenge = Challenge(0);
        let client_data_json = br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.to_vec();
        // We over-allocate by 32 bytes. See [`AuthenticatorAttestation::new`] for more information.
        let mut attestation_object = Vec::with_capacity(210);
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
                // Length is 148.
                148,
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
                // UP, UV, and AT (right-to-left).
                0b0100_0101,
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
                CBOR_MAP | 5,
                // COSE kty.
                CBOR_UINT | 1,
                // COSE EC2.
                CBOR_UINT | 2,
                // COSE alg.
                CBOR_UINT | 3,
                // COSE ES256.
                CBOR_NEG | 6,
                // COSE EC2 crv.
                CBOR_NEG,
                // COSE P-256.
                CBOR_UINT | 1,
                // COSE EC2 x.
                CBOR_NEG | 1,
                CBOR_BYTES | 24,
                // Length is 32.
                32,
                // X-coordinate. This will be overwritten later.
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
                // COSE EC2 y.
                CBOR_NEG | 2,
                CBOR_BYTES | 24,
                // Length is 32.
                32,
                // Y-coordinate. This will be overwritten later.
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
            .copy_from_slice(Sha256::digest(rp_id.as_ref().as_bytes()).as_slice());
        let p256_key = P256Key::from_bytes(
            &[
                137, 133, 36, 206, 163, 47, 255, 5, 76, 144, 163, 141, 40, 109, 108, 240, 246, 115,
                178, 237, 169, 68, 6, 129, 92, 21, 238, 127, 55, 158, 207, 95,
            ]
            .into(),
        )
        .unwrap()
        .verifying_key()
        .to_encoded_point(false);
        let x = p256_key.x().unwrap();
        let y = p256_key.y().unwrap();
        attestation_object[111..143].copy_from_slice(x);
        attestation_object[146..].copy_from_slice(y);
        assert!(matches!(opts.start_ceremony()?.0.verify(
            &rp_id,
            &Registration {
                response: AuthenticatorAttestation::new(
                    client_data_json,
                    attestation_object,
                    AuthTransports::NONE,
                ),
                authenticator_attachment: AuthenticatorAttachment::None,
                client_extension_results: ClientExtensionsOutputs {
                    cred_props: None,
                    prf: None,
                },
            },
            &RegistrationVerificationOptions::<&str, &str>::default(),
        )?.static_state.credential_public_key, UncompressedPubKey::P256(k) if k.x() == x.as_slice() && k.y() == y.as_slice()));
        Ok(())
    }
    #[test]
    #[cfg(feature = "custom")]
    fn es256_auth() -> Result<(), AggErr> {
        let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
        let mut opts = DiscoverableCredentialRequestOptions::passkey(&rp_id);
        opts.public_key.challenge = Challenge(0);
        let client_data_json = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.to_vec();
        // We over-allocate by 32 bytes. See [`AuthenticatorAssertion::new`] for more information.
        let mut authenticator_data = Vec::with_capacity(69);
        authenticator_data.extend_from_slice(
            [
                // rpIdHash.
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
                // flags.
                // UP and UV (right-to-left).
                0b0000_0101,
                // signCount.
                // 0 as 32-bit big endian.
                0,
                0,
                0,
                0,
            ]
            .as_slice(),
        );
        authenticator_data[..32]
            .copy_from_slice(Sha256::digest(rp_id.as_ref().as_bytes()).as_slice());
        authenticator_data
            .extend_from_slice(Sha256::digest(client_data_json.as_slice()).as_slice());
        let p256_key = P256Key::from_bytes(
            &[
                137, 133, 36, 206, 163, 47, 255, 5, 76, 144, 163, 141, 40, 109, 108, 240, 246, 115,
                178, 237, 169, 68, 6, 129, 92, 21, 238, 127, 55, 158, 207, 95,
            ]
            .into(),
        )
        .unwrap();
        let der_sig: P256DerSig = p256_key.sign(authenticator_data.as_slice());
        let pub_key = p256_key.verifying_key().to_encoded_point(true);
        authenticator_data.truncate(37);
        assert!(!opts.start_ceremony()?.0.verify(
            &rp_id,
            &DiscoverableAuthentication {
                raw_id: CredentialId::try_from(vec![0; 16])?,
                response: DiscoverableAuthenticatorAssertion::new(
                    client_data_json,
                    authenticator_data,
                    der_sig.as_bytes().into(),
                    UserHandle::from([0]),
                ),
                authenticator_attachment: AuthenticatorAttachment::None,
            },
            &mut AuthenticatedCredential::new(
                CredentialId::try_from([0; 16].as_slice())?,
                &UserHandle::from([0]),
                StaticState {
                    credential_public_key: CompressedPubKey::<&[u8], _, &[u8], &[u8]>::P256(
                        CompressedP256PubKey::from((
                            (*pub_key.x().unwrap()).into(),
                            pub_key.tag() == Tag::CompressedOddY
                        )),
                    ),
                    extensions: AuthenticatorExtensionOutputStaticState {
                        cred_protect: CredentialProtectionPolicy::None,
                        hmac_secret: None,
                    },
                    client_extension_results: ClientExtensionsOutputsStaticState { prf: None }
                },
                DynamicState {
                    user_verified: true,
                    backup: Backup::NotEligible,
                    sign_count: 0,
                    authenticator_attachment: AuthenticatorAttachment::None,
                },
            )?,
            &AuthenticationVerificationOptions::<&str, &str>::default(),
        )?);
        Ok(())
    }
    #[test]
    #[cfg(feature = "custom")]
    fn es384_reg() -> Result<(), AggErr> {
        let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
        let id = UserHandle::from([0]);
        let mut opts = CredentialCreationOptions::passkey(
            &rp_id,
            PublicKeyCredentialUserEntity {
                name: "foo".try_into()?,
                id: &id,
                display_name: None,
            },
            Vec::new(),
        );
        opts.public_key.challenge = Challenge(0);
        let client_data_json = br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.to_vec();
        // We over-allocate by 32 bytes. See [`AuthenticatorAttestation::new`] for more information.
        let mut attestation_object = Vec::with_capacity(243);
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
                // CBOR text of length 7.
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
                // Length is 181.
                181,
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
                // UP, UV, and AT (right-to-left).
                0b0100_0101,
                // COUNTER.
                // 0 as 32-bit big-endian.
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
                CBOR_MAP | 5,
                // COSE kty.
                CBOR_UINT | 1,
                // COSE EC2.
                CBOR_UINT | 2,
                // COSE alg.
                CBOR_UINT | 3,
                CBOR_NEG | 24,
                // COSE ES384.
                34,
                // COSE EC2 crv.
                CBOR_NEG,
                // COSE P-384.
                CBOR_UINT | 2,
                // COSE EC2 x.
                CBOR_NEG | 1,
                CBOR_BYTES | 24,
                // Length is 48.
                48,
                // X-coordinate. This will be overwritten later.
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
                // COSE EC2 y.
                CBOR_NEG | 2,
                CBOR_BYTES | 24,
                // Length is 48.
                48,
                // Y-coordinate. This will be overwritten later.
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
            ]
            .as_slice(),
        );
        attestation_object[30..62]
            .copy_from_slice(Sha256::digest(rp_id.as_ref().as_bytes()).as_slice());
        let p384_key = P384Key::from_bytes(
            &[
                158, 99, 156, 49, 190, 211, 85, 167, 28, 2, 80, 57, 31, 22, 17, 38, 85, 78, 232,
                42, 45, 199, 154, 243, 136, 251, 84, 34, 5, 120, 208, 91, 61, 248, 64, 144, 87, 1,
                32, 86, 220, 68, 182, 11, 105, 223, 75, 70,
            ]
            .into(),
        )
        .unwrap()
        .verifying_key()
        .to_encoded_point(false);
        let x = p384_key.x().unwrap();
        let y = p384_key.y().unwrap();
        attestation_object[112..160].copy_from_slice(x);
        attestation_object[163..].copy_from_slice(y);
        assert!(matches!(opts.start_ceremony()?.0.verify(
            &rp_id,
            &Registration {
                response: AuthenticatorAttestation::new(
                    client_data_json,
                    attestation_object,
                    AuthTransports::NONE,
                ),
                authenticator_attachment: AuthenticatorAttachment::None,
                client_extension_results: ClientExtensionsOutputs {
                    cred_props: None,
                    prf: None,
                },
            },
            &RegistrationVerificationOptions::<&str, &str>::default(),
        )?.static_state.credential_public_key, UncompressedPubKey::P384(k) if k.x() == x.as_slice() && k.y() == y.as_slice()));
        Ok(())
    }
    #[test]
    #[cfg(feature = "custom")]
    fn es384_auth() -> Result<(), AggErr> {
        let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
        let mut opts = DiscoverableCredentialRequestOptions::passkey(&rp_id);
        opts.public_key.challenge = Challenge(0);
        let client_data_json = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.to_vec();
        // We over-allocate by 32 bytes. See [`AuthenticatorAssertion::new`] for more information.
        let mut authenticator_data = Vec::with_capacity(69);
        authenticator_data.extend_from_slice(
            [
                // rpIdHash.
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
                // flags.
                // UP and UV (right-to-left).
                0b0000_0101,
                // signCount.
                // 0 as 32-bit big-endian.
                0,
                0,
                0,
                0,
            ]
            .as_slice(),
        );
        authenticator_data[..32]
            .copy_from_slice(Sha256::digest(rp_id.as_ref().as_bytes()).as_slice());
        authenticator_data
            .extend_from_slice(Sha256::digest(client_data_json.as_slice()).as_slice());
        let p384_key = P384Key::from_bytes(
            &[
                158, 99, 156, 49, 190, 211, 85, 167, 28, 2, 80, 57, 31, 22, 17, 38, 85, 78, 232,
                42, 45, 199, 154, 243, 136, 251, 84, 34, 5, 120, 208, 91, 61, 248, 64, 144, 87, 1,
                32, 86, 220, 68, 182, 11, 105, 223, 75, 70,
            ]
            .into(),
        )
        .unwrap();
        let der_sig: P384DerSig = p384_key.sign(authenticator_data.as_slice());
        let pub_key = p384_key.verifying_key().to_encoded_point(true);
        authenticator_data.truncate(37);
        assert!(!opts.start_ceremony()?.0.verify(
            &rp_id,
            &DiscoverableAuthentication {
                raw_id: CredentialId::try_from(vec![0; 16])?,
                response: DiscoverableAuthenticatorAssertion::new(
                    client_data_json,
                    authenticator_data,
                    der_sig.as_bytes().into(),
                    UserHandle::from([0]),
                ),
                authenticator_attachment: AuthenticatorAttachment::None,
            },
            &mut AuthenticatedCredential::new(
                CredentialId::try_from([0; 16].as_slice())?,
                &UserHandle::from([0]),
                StaticState {
                    credential_public_key: CompressedPubKey::<&[u8], &[u8], _, &[u8]>::P384(
                        CompressedP384PubKey::from((
                            (*pub_key.x().unwrap()).into(),
                            pub_key.tag() == Tag::CompressedOddY
                        )),
                    ),
                    extensions: AuthenticatorExtensionOutputStaticState {
                        cred_protect: CredentialProtectionPolicy::None,
                        hmac_secret: None,
                    },
                    client_extension_results: ClientExtensionsOutputsStaticState { prf: None }
                },
                DynamicState {
                    user_verified: true,
                    backup: Backup::NotEligible,
                    sign_count: 0,
                    authenticator_attachment: AuthenticatorAttachment::None,
                },
            )?,
            &AuthenticationVerificationOptions::<&str, &str>::default(),
        )?);
        Ok(())
    }
    #[test]
    #[cfg(feature = "custom")]
    fn rs256_reg() -> Result<(), AggErr> {
        let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
        let id = UserHandle::from([0]);
        let mut opts = CredentialCreationOptions::passkey(
            &rp_id,
            PublicKeyCredentialUserEntity {
                name: "foo".try_into()?,
                id: &id,
                display_name: None,
            },
            Vec::new(),
        );
        opts.public_key.challenge = Challenge(0);
        let client_data_json = br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.to_vec();
        // We over-allocate by 32 bytes. See [`AuthenticatorAttestation::new`] for more information.
        let mut attestation_object = Vec::with_capacity(406);
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
                CBOR_BYTES | 25,
                // Length is 343 as 16-bit big-endian.
                1,
                87,
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
                // UP, UV, and AT (right-to-left).
                0b0100_0101,
                // COUNTER.
                // 0 as 32-bit big-endian.
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
                // COSE RSA.
                CBOR_UINT | 3,
                // COSE alg.
                CBOR_UINT | 3,
                CBOR_NEG | 25,
                // COSE RS256.
                1,
                0,
                // COSE n.
                CBOR_NEG,
                CBOR_BYTES | 25,
                // Length is 256 as 16-bit big-endian.
                1,
                0,
                // N. This will be overwritten later.
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
                // COSE e.
                CBOR_NEG | 1,
                CBOR_BYTES | 3,
                // 65537 as 24-bit big-endian.
                1,
                0,
                1,
            ]
            .as_slice(),
        );
        attestation_object[31..63]
            .copy_from_slice(Sha256::digest(rp_id.as_ref().as_bytes()).as_slice());
        let n = [
            111, 183, 124, 133, 38, 167, 70, 148, 44, 50, 30, 60, 121, 14, 38, 37, 96, 114, 107,
            195, 248, 64, 79, 36, 237, 140, 43, 27, 94, 74, 102, 152, 135, 102, 184, 150, 186, 206,
            185, 19, 165, 209, 48, 98, 98, 9, 3, 205, 208, 82, 250, 105, 132, 201, 73, 62, 60, 165,
            100, 128, 153, 9, 41, 118, 66, 95, 236, 214, 73, 135, 197, 68, 184, 10, 27, 116, 204,
            145, 50, 174, 58, 42, 183, 181, 119, 232, 126, 252, 217, 96, 162, 190, 103, 122, 64,
            87, 145, 45, 32, 207, 17, 239, 223, 3, 35, 14, 112, 119, 124, 141, 123, 208, 239, 105,
            81, 217, 151, 162, 190, 17, 88, 182, 176, 158, 81, 200, 42, 166, 133, 48, 23, 236, 55,
            117, 248, 233, 151, 203, 122, 155, 231, 46, 177, 20, 20, 151, 64, 222, 239, 226, 7, 21,
            254, 81, 202, 64, 232, 161, 235, 22, 51, 246, 207, 213, 0, 229, 138, 46, 222, 205, 157,
            108, 139, 253, 230, 80, 50, 2, 122, 212, 163, 100, 180, 114, 12, 113, 52, 56, 99, 188,
            42, 198, 212, 23, 182, 222, 56, 221, 200, 79, 96, 239, 221, 135, 10, 17, 106, 183, 56,
            104, 68, 94, 198, 196, 35, 200, 83, 204, 26, 185, 204, 212, 31, 183, 19, 111, 233, 13,
            72, 93, 53, 65, 111, 59, 242, 122, 160, 244, 162, 126, 38, 235, 156, 47, 88, 39, 132,
            153, 79, 0, 133, 78, 7, 218, 165, 241,
        ];
        let e = 65537;
        let d = [
            145, 79, 21, 97, 233, 3, 192, 194, 177, 68, 181, 80, 120, 197, 23, 44, 185, 74, 144, 0,
            132, 149, 139, 11, 16, 224, 4, 112, 236, 94, 238, 97, 121, 124, 213, 145, 24, 253, 168,
            35, 190, 205, 132, 115, 33, 201, 38, 253, 246, 180, 66, 155, 165, 46, 3, 254, 68, 108,
            154, 247, 246, 45, 187, 0, 204, 96, 185, 157, 249, 174, 158, 38, 62, 244, 183, 76, 102,
            6, 219, 92, 212, 138, 59, 147, 163, 219, 111, 39, 105, 21, 236, 196, 38, 255, 114, 247,
            82, 104, 113, 204, 29, 152, 209, 219, 48, 239, 74, 129, 19, 247, 33, 239, 119, 166,
            216, 152, 94, 138, 238, 164, 242, 129, 50, 150, 57, 20, 53, 224, 56, 241, 138, 97, 111,
            215, 107, 212, 195, 146, 108, 143, 0, 229, 181, 171, 73, 152, 105, 146, 25, 243, 242,
            140, 252, 248, 162, 247, 63, 168, 180, 20, 153, 120, 10, 248, 211, 1, 71, 127, 212,
            249, 237, 203, 202, 48, 26, 216, 226, 228, 186, 13, 204, 70, 255, 240, 89, 255, 59, 83,
            31, 253, 55, 43, 158, 90, 248, 83, 32, 159, 105, 57, 134, 34, 96, 18, 255, 245, 153,
            162, 60, 91, 99, 220, 51, 44, 85, 114, 67, 125, 202, 65, 217, 245, 40, 8, 81, 165, 142,
            24, 245, 127, 122, 247, 152, 212, 75, 45, 59, 90, 184, 234, 31, 147, 36, 8, 212, 45,
            50, 23, 3, 25, 253, 87, 227, 79, 119, 161,
        ];
        let p = BigUint::from_slice(
            [
                352691927, 1294578443, 816143558, 690659917, 1161596366, 1544791087, 3999549486,
                3319149924, 2349250979, 1304689381, 3959753736, 3377900978, 866506027, 1671521644,
                3926847564, 898221388, 3448219846, 494454484, 3915534864, 2869735916, 2456511629,
                3397234721, 3012775852, 3472309790, 1923617705, 2993441050, 3210302569, 3605331368,
                3352563766, 688081007, 4104512503, 4145593376,
            ]
            .as_slice(),
        );
        let p_2 = BigUint::from_slice(
            [
                4039514409, 964284038, 3230008587, 3320139220, 3562360334, 3165876926, 212773653,
                2752465512, 2973674888, 1717425549, 2084262803, 3585031058, 4162394935, 1428626842,
                1015474994, 3283774155, 2840050110, 190639246, 147241978, 2994256073, 4081014755,
                3102401369, 3547397148, 1545029057, 895305733, 2689179461, 1593439337, 3960057302,
                193068804, 2835123424, 4054880057, 4200258364,
            ]
            .as_slice(),
        );
        let rsa_key = RsaKey::<Sha256>::new(
            RsaPrivateKey::from_components(
                BigUint::from_bytes_le(n.as_slice()),
                e.into(),
                BigUint::from_bytes_le(d.as_slice()),
                vec![p, p_2],
            )
            .unwrap(),
        )
        .verifying_key();
        let n = rsa_key.as_ref().n().to_bytes_be();
        attestation_object[113..369].copy_from_slice(n.as_slice());
        assert!(matches!(opts.start_ceremony()?.0.verify(
            &rp_id,
            &Registration {
                response: AuthenticatorAttestation::new(
                    client_data_json,
                    attestation_object,
                    AuthTransports::NONE,
                ),
                authenticator_attachment: AuthenticatorAttachment::None,
                client_extension_results: ClientExtensionsOutputs {
                    cred_props: None,
                    prf: None,
                },
            },
            &RegistrationVerificationOptions::<&str, &str>::default(),
        )?.static_state.credential_public_key, UncompressedPubKey::Rsa(k) if *k.n() == n.as_slice() && k.e() == e));
        Ok(())
    }
    #[test]
    #[cfg(feature = "custom")]
    fn rs256_auth() -> Result<(), AggErr> {
        let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
        let mut opts = DiscoverableCredentialRequestOptions::passkey(&rp_id);
        opts.public_key.challenge = Challenge(0);
        let client_data_json = br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.to_vec();
        // We over-allocate by 32 bytes. See [`AuthenticatorAssertion::new`] for more information.
        let mut authenticator_data = Vec::with_capacity(69);
        authenticator_data.extend_from_slice(
            [
                // rpIdHash.
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
                // flags.
                // UP and UV (right-to-left).
                0b0000_0101,
                // signCount.
                // 0 as 32-bit big-endian.
                0,
                0,
                0,
                0,
            ]
            .as_slice(),
        );
        authenticator_data[..32]
            .copy_from_slice(Sha256::digest(rp_id.as_ref().as_bytes()).as_slice());
        authenticator_data
            .extend_from_slice(Sha256::digest(client_data_json.as_slice()).as_slice());
        let n = [
            111, 183, 124, 133, 38, 167, 70, 148, 44, 50, 30, 60, 121, 14, 38, 37, 96, 114, 107,
            195, 248, 64, 79, 36, 237, 140, 43, 27, 94, 74, 102, 152, 135, 102, 184, 150, 186, 206,
            185, 19, 165, 209, 48, 98, 98, 9, 3, 205, 208, 82, 250, 105, 132, 201, 73, 62, 60, 165,
            100, 128, 153, 9, 41, 118, 66, 95, 236, 214, 73, 135, 197, 68, 184, 10, 27, 116, 204,
            145, 50, 174, 58, 42, 183, 181, 119, 232, 126, 252, 217, 96, 162, 190, 103, 122, 64,
            87, 145, 45, 32, 207, 17, 239, 223, 3, 35, 14, 112, 119, 124, 141, 123, 208, 239, 105,
            81, 217, 151, 162, 190, 17, 88, 182, 176, 158, 81, 200, 42, 166, 133, 48, 23, 236, 55,
            117, 248, 233, 151, 203, 122, 155, 231, 46, 177, 20, 20, 151, 64, 222, 239, 226, 7, 21,
            254, 81, 202, 64, 232, 161, 235, 22, 51, 246, 207, 213, 0, 229, 138, 46, 222, 205, 157,
            108, 139, 253, 230, 80, 50, 2, 122, 212, 163, 100, 180, 114, 12, 113, 52, 56, 99, 188,
            42, 198, 212, 23, 182, 222, 56, 221, 200, 79, 96, 239, 221, 135, 10, 17, 106, 183, 56,
            104, 68, 94, 198, 196, 35, 200, 83, 204, 26, 185, 204, 212, 31, 183, 19, 111, 233, 13,
            72, 93, 53, 65, 111, 59, 242, 122, 160, 244, 162, 126, 38, 235, 156, 47, 88, 39, 132,
            153, 79, 0, 133, 78, 7, 218, 165, 241,
        ];
        let e = 65537;
        let d = [
            145, 79, 21, 97, 233, 3, 192, 194, 177, 68, 181, 80, 120, 197, 23, 44, 185, 74, 144, 0,
            132, 149, 139, 11, 16, 224, 4, 112, 236, 94, 238, 97, 121, 124, 213, 145, 24, 253, 168,
            35, 190, 205, 132, 115, 33, 201, 38, 253, 246, 180, 66, 155, 165, 46, 3, 254, 68, 108,
            154, 247, 246, 45, 187, 0, 204, 96, 185, 157, 249, 174, 158, 38, 62, 244, 183, 76, 102,
            6, 219, 92, 212, 138, 59, 147, 163, 219, 111, 39, 105, 21, 236, 196, 38, 255, 114, 247,
            82, 104, 113, 204, 29, 152, 209, 219, 48, 239, 74, 129, 19, 247, 33, 239, 119, 166,
            216, 152, 94, 138, 238, 164, 242, 129, 50, 150, 57, 20, 53, 224, 56, 241, 138, 97, 111,
            215, 107, 212, 195, 146, 108, 143, 0, 229, 181, 171, 73, 152, 105, 146, 25, 243, 242,
            140, 252, 248, 162, 247, 63, 168, 180, 20, 153, 120, 10, 248, 211, 1, 71, 127, 212,
            249, 237, 203, 202, 48, 26, 216, 226, 228, 186, 13, 204, 70, 255, 240, 89, 255, 59, 83,
            31, 253, 55, 43, 158, 90, 248, 83, 32, 159, 105, 57, 134, 34, 96, 18, 255, 245, 153,
            162, 60, 91, 99, 220, 51, 44, 85, 114, 67, 125, 202, 65, 217, 245, 40, 8, 81, 165, 142,
            24, 245, 127, 122, 247, 152, 212, 75, 45, 59, 90, 184, 234, 31, 147, 36, 8, 212, 45,
            50, 23, 3, 25, 253, 87, 227, 79, 119, 161,
        ];
        let p = BigUint::from_slice(
            [
                352691927, 1294578443, 816143558, 690659917, 1161596366, 1544791087, 3999549486,
                3319149924, 2349250979, 1304689381, 3959753736, 3377900978, 866506027, 1671521644,
                3926847564, 898221388, 3448219846, 494454484, 3915534864, 2869735916, 2456511629,
                3397234721, 3012775852, 3472309790, 1923617705, 2993441050, 3210302569, 3605331368,
                3352563766, 688081007, 4104512503, 4145593376,
            ]
            .as_slice(),
        );
        let p_2 = BigUint::from_slice(
            [
                4039514409, 964284038, 3230008587, 3320139220, 3562360334, 3165876926, 212773653,
                2752465512, 2973674888, 1717425549, 2084262803, 3585031058, 4162394935, 1428626842,
                1015474994, 3283774155, 2840050110, 190639246, 147241978, 2994256073, 4081014755,
                3102401369, 3547397148, 1545029057, 895305733, 2689179461, 1593439337, 3960057302,
                193068804, 2835123424, 4054880057, 4200258364,
            ]
            .as_slice(),
        );
        let rsa_key = RsaKey::<Sha256>::new(
            RsaPrivateKey::from_components(
                BigUint::from_bytes_le(n.as_slice()),
                e.into(),
                BigUint::from_bytes_le(d.as_slice()),
                vec![p, p_2],
            )
            .unwrap(),
        );
        let rsa_pub = rsa_key.verifying_key();
        let sig = rsa_key.sign(authenticator_data.as_slice()).to_vec();
        authenticator_data.truncate(37);
        assert!(!opts.start_ceremony()?.0.verify(
            &rp_id,
            &DiscoverableAuthentication {
                raw_id: CredentialId::try_from(vec![0; 16])?,
                response: DiscoverableAuthenticatorAssertion::new(
                    client_data_json,
                    authenticator_data,
                    sig,
                    UserHandle::from([0]),
                ),
                authenticator_attachment: AuthenticatorAttachment::None,
            },
            &mut AuthenticatedCredential::new(
                CredentialId::try_from([0; 16].as_slice())?,
                &UserHandle::from([0]),
                StaticState {
                    credential_public_key: CompressedPubKey::<&[u8], &[u8], &[u8], _>::Rsa(
                        RsaPubKey::try_from((rsa_pub.as_ref().n().to_bytes_be(), e)).unwrap(),
                    ),
                    extensions: AuthenticatorExtensionOutputStaticState {
                        cred_protect: CredentialProtectionPolicy::None,
                        hmac_secret: None,
                    },
                    client_extension_results: ClientExtensionsOutputsStaticState { prf: None }
                },
                DynamicState {
                    user_verified: true,
                    backup: Backup::NotEligible,
                    sign_count: 0,
                    authenticator_attachment: AuthenticatorAttachment::None,
                },
            )?,
            &AuthenticationVerificationOptions::<&str, &str>::default(),
        )?);
        Ok(())
    }
}
