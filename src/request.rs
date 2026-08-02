#[cfg(test)]
mod tests;
#[cfg(doc)]
use super::{
    hash::hash_set::MaxLenHashSet,
    request::{
        auth::{
            AllowedCredential, AllowedCredentials, CredentialSpecificExtension,
            DiscoverableAuthenticationServerState, DiscoverableCredentialRequestOptions,
            NonDiscoverableAuthenticationServerState, NonDiscoverableCredentialRequestOptions,
            PublicKeyCredentialRequestOptions,
        },
        register::{CredentialCreationOptions, RegistrationServerState},
    },
    response::{AuthenticatorAttachment, register::ClientExtensionsOutputs},
};
use crate::{
    request::{
        error::{
            AsciiDomainErr, DomainOriginParseErr, PortParseErr, RpIdErr, SchemeParseErr, UrlErr,
        },
        register::{BackupReq, RegistrationVerificationOptions},
    },
    response::{
        AuthData as _, AuthDataContainer, AuthResponse, AuthTransports, Backup, CeremonyErr,
        CredentialId, Origin, Response, SentChallenge,
    },
};
use core::{
    borrow::Borrow,
    cell::Cell,
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
/// #     hash::hash_set::{InsertRemoveExpired, MaxLenHashSet},
/// #     request::{
/// #         auth::{AllowedCredentials, DiscoverableCredentialRequestOptions, NonDiscoverableCredentialRequestOptions},
/// #         register::UserHandle64,
/// #         Credentials, PublicKeyCredentialDescriptor, RpId,
/// #     },
/// #     response::{AuthTransports, CredentialId, CRED_ID_MIN_LEN},
/// #     AggErr,
/// # };
/// const RP_ID: &RpId = &RpId::from_static_domain("example.com").unwrap();
/// let mut ceremonies = MaxLenHashSet::new(128);
/// let (server, client) = DiscoverableCredentialRequestOptions::passkey(RP_ID).start_ceremony()?;
/// assert_eq!(ceremonies.insert_remove_all_expired(server), InsertRemoveExpired::Success);
/// # #[cfg(feature = "custom")]
/// let mut ceremonies_2 = MaxLenHashSet::new(128);
/// # #[cfg(feature = "serde")]
/// assert!(serde_json::to_string(&client).is_ok());
/// let user_handle = get_user_handle();
/// # #[cfg(feature = "custom")]
/// let creds = get_registered_credentials(&user_handle)?;
/// # #[cfg(feature = "custom")]
/// let (server_2, client_2) =
///     NonDiscoverableCredentialRequestOptions::second_factor(RP_ID, creds).start_ceremony()?;
/// # #[cfg(feature = "custom")]
/// assert_eq!(ceremonies_2.insert_remove_all_expired(server_2), InsertRemoveExpired::Success);
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
/// #             id: CredentialId::try_from(vec![0; CRED_ID_MIN_LEN].into_boxed_slice())?,
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
/// #     hash::hash_set::{InsertRemoveExpired, MaxLenHashSet},
/// #     request::{
/// #         register::{
/// #             CredentialCreationOptions, PublicKeyCredentialUserEntity, UserHandle, USER_HANDLE_MAX_LEN, UserHandle64,
/// #         },
/// #         PublicKeyCredentialDescriptor, RpId
/// #     },
/// #     response::{AuthTransports, CredentialId, CRED_ID_MIN_LEN},
/// #     AggErr,
/// # };
/// const RP_ID: &RpId = &RpId::from_static_domain("example.com").unwrap();
/// # #[cfg(feature = "custom")]
/// let mut ceremonies = MaxLenHashSet::new(128);
/// # #[cfg(feature = "custom")]
/// let user_handle = get_user_handle();
/// # #[cfg(feature = "custom")]
/// let user = get_user_entity(&user_handle)?;
/// # #[cfg(feature = "custom")]
/// let creds = get_registered_credentials(&user_handle)?;
/// # #[cfg(feature = "custom")]
/// let (server, client) = CredentialCreationOptions::passkey(RP_ID, user.clone(), creds)
///     .start_ceremony()?;
/// # #[cfg(feature = "custom")]
/// assert_eq!(ceremonies.insert_remove_all_expired(server), InsertRemoveExpired::Success);
/// # #[cfg(all(feature = "serde", feature = "custom"))]
/// assert!(serde_json::to_string(&client).is_ok());
/// # #[cfg(feature = "custom")]
/// let creds_2 = get_registered_credentials(&user_handle)?;
/// # #[cfg(feature = "custom")]
/// let (server_2, client_2) =
///     CredentialCreationOptions::second_factor(RP_ID, user, creds_2).start_ceremony()?;
/// # #[cfg(feature = "custom")]
/// assert_eq!(ceremonies.insert_remove_all_expired(server_2), InsertRemoveExpired::Success);
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
/// #         name: "foo",
/// #         id: user,
/// #         display_name: "",
/// #     })
/// }
/// /// Fetch the `PublicKeyCredentialDescriptor`s associated with `user`.
/// ///
/// /// This doesn't need to be called when this is the first credential registered for `user`; instead
/// /// an empty `Vec` should be passed.
/// fn get_registered_credentials(
///     user: &UserHandle64,
/// ) -> Result<Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>, AggErr> {
///     // ⋮
/// #     Ok(Vec::new())
/// }
/// # Ok::<_, AggErr>(())
/// ```
pub mod register;
/// Contains functionality to serialize data to a client.
#[cfg(feature = "serde")]
mod ser;
/// Contains functionality to (de)serialize data needed for [`RegistrationServerState`],
/// [`DiscoverableAuthenticationServerState`], and [`NonDiscoverableAuthenticationServerState`] to a data store.
#[cfg(feature = "serializable_server_state")]
pub(super) mod ser_server_state;
// `Challenge` must _never_ be constructable directly or indirectly; thus its tuple field must always be private,
// and it must never implement `trait`s (e.g., `Clone`) that would allow indirect creation. It must only ever
// be constructed via `Self::new` or `Self::default`. In contrast downstream code must be able to construct
// `SentChallenge` since it is used during ceremony validation; thus we must keep `Challenge` and `SentChallenge`
// as separate types.
/// [Cryptographic challenge](https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges).
#[expect(
    missing_copy_implementations,
    reason = "want to enforce randomly-generated challenges"
)]
#[derive(Debug)]
pub struct Challenge(u128);
impl Challenge {
    /// The number of bytes a `Challenge` takes to encode in base64url.
    pub(super) const BASE64_LEN: usize = base64url_nopad::encode_len(16);
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
    /// Returns the contained `u128` as a little-endian `array` consuming `self`.
    #[inline]
    #[must_use]
    pub const fn into_array(self) -> [u8; 16] {
        self.as_array()
    }
    /// Returns the contained `u128` as a little-endian `array`.
    #[expect(
        clippy::little_endian_bytes,
        reason = "Challenge and SentChallenge need to be compatible, and we need to ensure the data is sent and received in the same order"
    )]
    #[inline]
    #[must_use]
    pub const fn as_array(&self) -> [u8; 16] {
        self.0.to_le_bytes()
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
impl From<Challenge> for [u8; 16] {
    #[inline]
    fn from(value: Challenge) -> Self {
        value.into_array()
    }
}
impl From<&Challenge> for [u8; 16] {
    #[inline]
    fn from(value: &Challenge) -> Self {
        value.as_array()
    }
}
/// A [domain](https://url.spec.whatwg.org/#concept-domain) in representation format consisting of only and any
/// ASCII.
///
/// The only ASCII character disallowed in a label is `'.'` since it is used exclusively as a separator. Every
/// label must have length inclusively between 1 and 63, and the total length of the domain must be at most 253
/// when a trailing `'.'` does not exist; otherwise the max length is 254. The root domain (i.e., `'.'`) is not
/// allowed.
///
/// Note if the domain is a `&'static str`, then use [`AsciiDomainStatic`] instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsciiDomain(String);
impl AsciiDomain {
    /// Removes a trailing `'.'` if it exists.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{AsciiDomain, error::AsciiDomainErr};
    /// let mut dom = AsciiDomain::try_from("example.com.".to_owned())?;
    /// assert_eq!(dom.as_ref(), "example.com.");
    /// dom.remove_trailing_dot();
    /// assert_eq!(dom.as_ref(), "example.com");
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
            .unwrap_or_else(|| unreachable!("there is a bug in AsciiDomain::from_slice"))
            == b'.'
        {
            _ = self.0.pop();
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
impl TryFrom<Vec<u8>> for AsciiDomain {
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
    /// # Errors
    ///
    /// Errors iff `value` is not a valid ASCII domain.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{error::AsciiDomainErr, AsciiDomain};
    /// // Root `'.'` is not removed if it exists.
    /// assert_ne!("example.com", AsciiDomain::try_from(b"example.com.".to_vec())?.as_ref());
    /// // Root domain (i.e., `'.'`) is not allowed.
    /// assert!(AsciiDomain::try_from(vec![b'.']).is_err());
    /// // Uppercase is transformed into lowercase.
    /// assert_eq!("example.com", AsciiDomain::try_from(b"ExAmPle.CoM".to_vec())?.as_ref());
    /// // The only ASCII character not allowed in a domain label is `'.'` as it is used exclusively to delimit
    /// // labels.
    /// assert_eq!("\x00", AsciiDomain::try_from(b"\x00".to_vec())?.as_ref());
    /// // Empty labels are not allowed.
    /// assert!(AsciiDomain::try_from(b"example..com".to_vec()).is_err());
    /// // Labels cannot have length greater than 63.
    /// let mut long_label = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
    /// assert_eq!(long_label.len(), 64);
    /// assert!(AsciiDomain::try_from(long_label.clone().into_bytes()).is_err());
    /// long_label.pop();
    /// assert_eq!(long_label, AsciiDomain::try_from(long_label.clone().into_bytes())?.as_ref());
    /// // The maximum length of a domain is 254 if a trailing `'.'` exists; otherwise the max length is 253.
    /// let mut long_domain = format!("{long_label}.{long_label}.{long_label}.{long_label}");
    /// long_domain.pop();
    /// long_domain.push('.');
    /// assert_eq!(long_domain.len(), 255);
    /// assert!(AsciiDomain::try_from(long_domain.clone().into_bytes()).is_err());
    /// long_domain.pop();
    /// long_domain.pop();
    /// long_domain.push('.');
    /// assert_eq!(long_domain.len(), 254);
    /// assert_eq!(long_domain, AsciiDomain::try_from(long_domain.clone().into_bytes())?.as_ref());
    /// long_domain.pop();
    /// long_domain.push('a');
    /// assert_eq!(long_domain.len(), 254);
    /// assert!(AsciiDomain::try_from(long_domain.clone().into_bytes()).is_err());
    /// long_domain.pop();
    /// assert_eq!(long_domain.len(), 253);
    /// assert_eq!(long_domain, AsciiDomain::try_from(long_domain.clone().into_bytes())?.as_ref());
    /// // Only ASCII is allowed; thus if a domain needs to be Punycode-encoded, then it must be _before_ calling
    /// // this function.
    /// assert!(AsciiDomain::try_from("λ.com".to_owned().into_bytes()).is_err());
    /// assert_eq!("xn--wxa.com", AsciiDomain::try_from(b"xn--wxa.com".to_vec())?.as_ref());
    /// # Ok::<_, AsciiDomainErr>(())
    /// ```
    #[expect(unsafe_code, reason = "comment justifies correctness")]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comments justify correctness"
    )]
    #[inline]
    fn try_from(mut value: Vec<u8>) -> Result<Self, Self::Error> {
        /// Value to add to an uppercase ASCII `u8` to get the lowercase version.
        const DIFF: u8 = b'a' - b'A';
        let bytes = value.as_slice();
        bytes
            .as_ref()
            .last()
            .ok_or(AsciiDomainErr::Empty)
            .and_then(|b| {
                let len = bytes.len();
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
                value
                    .iter_mut()
                    .try_fold(0u8, |mut label_len, byt| {
                        let b = *byt;
                        if b == b'.' {
                            if label_len == 0 {
                                Err(AsciiDomainErr::EmptyLabel)
                            } else {
                                Ok(0)
                            }
                        } else if label_len == 63 {
                            Err(AsciiDomainErr::LabelLen)
                        } else {
                            // We know `label_len` is less than 63, thus this won't overflow.
                            label_len += 1;
                            match b {
                                // Non-uppercase ASCII is allowed and doesn't need to be converted.
                                ..b'A' | b'['..=0x7F => Ok(label_len),
                                // Uppercase ASCII is allowed but needs to be transformed into lowercase.
                                b'A'..=b'Z' => {
                                    // Lowercase ASCII is a contiguous block starting from `b'a'` as is uppercase
                                    // ASCII which starts from `b'A'` with uppercase ASCII coming before; thus we
                                    // simply need to shift by a fixed amount.
                                    *byt += DIFF;
                                    Ok(label_len)
                                }
                                // Non-ASCII is disallowed.
                                0x80.. => Err(AsciiDomainErr::NotAscii),
                            }
                        }
                    })
                    .map(|_| {
                        // SAFETY:
                        // We just verified `value` only contains ASCII; thus this is safe.
                        let utf8 = unsafe { String::from_utf8_unchecked(value) };
                        Self(utf8)
                    })
            })
    }
}
impl TryFrom<String> for AsciiDomain {
    type Error = AsciiDomainErr;
    /// Same as [`Self::try_from`] except `value` is a `String`.
    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.into_bytes())
    }
}
/// Similar to [`AsciiDomain`] except the contained data is a `&'static str`.
///
/// Since [`Self::new`] and [`Option::unwrap`] are `const fn`s, one can define a global `const` or `static`
/// variable that represents the RP ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsciiDomainStatic(&'static str);
impl AsciiDomainStatic {
    /// Returns the contained `str`.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
    /// Verifies `domain` is a valid lowercase ASCII domain returning `None` when not valid or when
    /// uppercase ASCII exists.
    ///
    /// Read [`AsciiDomain`] for more information about what constitutes a valid domain.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{AsciiDomainStatic, RpId};
    /// /// RP ID of our application.
    /// const RP_IP: &RpId = &RpId::StaticDomain(AsciiDomainStatic::new("example.com").unwrap());
    /// ```
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment justifies correctness"
    )]
    #[expect(
        clippy::else_if_without_else,
        reason = "part of if branch and else branch are the same"
    )]
    #[inline]
    #[must_use]
    pub const fn new(domain: &'static str) -> Option<Self> {
        let mut utf8 = domain.as_bytes();
        if let Some(lst) = utf8.last() {
            let len = utf8.len();
            if *lst == b'.' {
                if len == 1 || len > 254 {
                    return None;
                }
            } else if len > 253 {
                return None;
            }
            let mut label_len = 0;
            while let [first, ref rest @ ..] = *utf8 {
                if first == b'.' {
                    if label_len == 0 {
                        return None;
                    }
                    label_len = 0;
                } else if label_len == 63 {
                    return None;
                } else {
                    match first {
                        // Any non-uppercase ASCII is allowed.
                        // We know `label_len` is less than 63, so this won't overflow.
                        ..b'A' | b'['..=0x7F => label_len += 1,
                        // Uppercase ASCII and non-ASCII are disallowed.
                        b'A'..=b'Z' | 0x80.. => return None,
                    }
                }
                utf8 = rest;
            }
            Some(Self(domain))
        } else {
            None
        }
    }
}
impl AsRef<str> for AsciiDomainStatic {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
impl Borrow<str> for AsciiDomainStatic {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}
impl From<AsciiDomainStatic> for &'static str {
    #[inline]
    fn from(value: AsciiDomainStatic) -> Self {
        value.0
    }
}
impl From<AsciiDomainStatic> for String {
    #[inline]
    fn from(value: AsciiDomainStatic) -> Self {
        value.0.to_owned()
    }
}
impl From<AsciiDomainStatic> for AsciiDomain {
    #[inline]
    fn from(value: AsciiDomainStatic) -> Self {
        Self(value.0.to_owned())
    }
}
impl PartialEq<&Self> for AsciiDomainStatic {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<AsciiDomainStatic> for &AsciiDomainStatic {
    #[inline]
    fn eq(&self, other: &AsciiDomainStatic) -> bool {
        **self == *other
    }
}
/// The output of the [URL serializer](https://url.spec.whatwg.org/#concept-url-serializer).
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
        let violation = Cell::new(false);
        Uri::options()
            .syntax_violation_callback(Some(&|_| {
                violation.set(true);
            }))
            .parse(s)
            .map_err(|_e| UrlErr)
            .and_then(|url| {
                if violation.into_inner() {
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
    /// Similar to [`Self::Domain`] except the ASCII domain is static.
    ///
    /// Since [`AsciiDomainStatic::new`] is a `const fn`, one can define a `const` or `static` global variable
    /// the contains the RP ID.
    StaticDomain(AsciiDomainStatic),
    /// A URL.
    Url(Url),
}
impl RpId {
    /// Returns `Some` containing an [`AsciiDomainStatic`] iff [`AsciiDomainStatic::new`] does.
    #[inline]
    #[must_use]
    pub const fn from_static_domain(domain: &'static str) -> Option<Self> {
        if let Some(dom) = AsciiDomainStatic::new(domain) {
            Some(Self::StaticDomain(dom))
        } else {
            None
        }
    }
    /// Validates `hash` is the same as the SHA-256 hash of `self`.
    fn validate_rp_id_hash<E>(&self, hash: &[u8]) -> Result<(), CeremonyErr<E>> {
        if *hash == *Sha256::digest(self.as_ref()) {
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
            Self::StaticDomain(dom) => dom.as_str(),
            Self::Url(ref url) => url.as_ref(),
        }
    }
}
impl Borrow<str> for RpId {
    #[inline]
    fn borrow(&self) -> &str {
        match *self {
            Self::Domain(ref dom) => dom.borrow(),
            Self::StaticDomain(dom) => dom.as_str(),
            Self::Url(ref url) => url.borrow(),
        }
    }
}
impl From<RpId> for String {
    #[inline]
    fn from(value: RpId) -> Self {
        match value {
            RpId::Domain(dom) => dom.into(),
            RpId::StaticDomain(dom) => dom.into(),
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
impl From<AsciiDomain> for RpId {
    #[inline]
    fn from(value: AsciiDomain) -> Self {
        Self::Domain(value)
    }
}
impl From<AsciiDomainStatic> for RpId {
    #[inline]
    fn from(value: AsciiDomainStatic) -> Self {
        Self::StaticDomain(value)
    }
}
impl From<Url> for RpId {
    #[inline]
    fn from(value: Url) -> Self {
        Self::Url(value)
    }
}
impl TryFrom<String> for RpId {
    type Error = RpIdErr;
    /// Returns `Ok` iff `value` is a valid [`Url`] or [`AsciiDomain`].
    ///
    /// Note when `value` is a valid `Url` and `AsciiDomain`, it will be treated as a `Url`.
    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Url::from_str(value.as_str())
            .map(Self::Url)
            .or_else(|_err| {
                AsciiDomain::try_from(value)
                    .map(Self::Domain)
                    .map_err(|_e| RpIdErr)
            })
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
    #[expect(single_use_lifetimes, reason = "false positive")]
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
    #[expect(single_use_lifetimes, reason = "false positive")]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
/// [`PublicKeyCredentialHint`](https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialhint).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicKeyCredentialHint {
    /// [`security-key`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-security-key).
    SecurityKey,
    /// [`client-device`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-client-device).
    ClientDevice,
    /// [`hybrid`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-hybrid).
    Hybrid,
}
impl PublicKeyCredentialHint {
    /// Returns `true` iff `self` is the same as `other`.
    const fn is_eq(self, other: Self) -> bool {
        match self {
            Self::SecurityKey => matches!(other, Self::SecurityKey),
            Self::ClientDevice => matches!(other, Self::ClientDevice),
            Self::Hybrid => matches!(other, Self::Hybrid),
        }
    }
}
/// Unique sequence of [`PublicKeyCredentialHint`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Hints([Option<PublicKeyCredentialHint>; 3]);
impl Hints {
    /// Empty sequence of [`PublicKeyCredentialHint`]s.
    pub const EMPTY: Self = Self([None; 3]);
    /// Adds `hint` to `self` iff `self` doesn't already contain `hint`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{Hints, PublicKeyCredentialHint};
    /// assert_eq!(
    ///     Hints::EMPTY
    ///         .add(PublicKeyCredentialHint::SecurityKey)
    ///         .first(),
    ///     Some(PublicKeyCredentialHint::SecurityKey)
    /// );
    /// ```
    #[inline]
    #[must_use]
    pub const fn add(mut self, hint: PublicKeyCredentialHint) -> Self {
        let mut vals = self.0.as_mut_slice();
        while let [ref mut first, ref mut rem @ ..] = *vals {
            match *first {
                None => {
                    *first = Some(hint);
                    return self;
                }
                Some(h) => {
                    if h.is_eq(hint) {
                        return self;
                    }
                }
            }
            vals = rem;
        }
        self
    }
    /// Returns the first `PublicKeyCredentialHint`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Hints;
    /// assert!(Hints::EMPTY.first().is_none());
    /// ```
    #[inline]
    #[must_use]
    pub const fn first(self) -> Option<PublicKeyCredentialHint> {
        self.0[0]
    }
    /// Returns the second `PublicKeyCredentialHint`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Hints;
    /// assert!(Hints::EMPTY.second().is_none());
    /// ```
    #[inline]
    #[must_use]
    pub const fn second(self) -> Option<PublicKeyCredentialHint> {
        self.0[1]
    }
    /// Returns the third `PublicKeyCredentialHint`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Hints;
    /// assert!(Hints::EMPTY.third().is_none());
    /// ```
    #[inline]
    #[must_use]
    pub const fn third(self) -> Option<PublicKeyCredentialHint> {
        self.0[2]
    }
    /// Returns the number of [`PublicKeyCredentialHint`]s in `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Hints;
    /// assert_eq!(Hints::EMPTY.count(), 0);
    /// ```
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        reason = "comment justifies correctness"
    )]
    #[inline]
    #[must_use]
    pub const fn count(self) -> u8 {
        // `bool as u8` is well-defined. This maxes at 3, so overflow isn't possible.
        self.first().is_some() as u8 + self.second().is_some() as u8 + self.third().is_some() as u8
    }
    /// Returns `true` iff `self` is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Hints;
    /// assert!(Hints::EMPTY.is_empty());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.count() == 0
    }
    /// Returns `true` iff `self` contains `hint`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{Hints, PublicKeyCredentialHint};
    /// assert!(!Hints::EMPTY.contains(PublicKeyCredentialHint::Hybrid));
    /// ```
    #[inline]
    #[must_use]
    pub const fn contains(self, hint: PublicKeyCredentialHint) -> bool {
        let mut vals = self.0.as_slice();
        while let [ref first, ref rem @ ..] = *vals {
            match *first {
                None => return false,
                Some(h) => {
                    if h.is_eq(hint) {
                        return true;
                    }
                }
            }
            vals = rem;
        }
        false
    }
    /// Returns `true` iff `self` contains a `hint` that maps to [`AuthenticatorAttachment::CrossPlatform`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Hints;
    /// assert!(!Hints::EMPTY.contains_platform_hints());
    /// ```
    #[inline]
    #[must_use]
    pub const fn contains_cross_platform_hints(self) -> bool {
        let mut vals = self.0.as_slice();
        while let [ref first, ref rem @ ..] = *vals {
            match *first {
                None => return false,
                Some(h) => {
                    if matches!(
                        h,
                        PublicKeyCredentialHint::SecurityKey | PublicKeyCredentialHint::Hybrid
                    ) {
                        return true;
                    }
                }
            }
            vals = rem;
        }
        false
    }
    /// Returns `true` iff `self` contains a `hint` that maps to [`AuthenticatorAttachment::Platform`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::Hints;
    /// assert!(!Hints::EMPTY.contains_platform_hints());
    /// ```
    #[inline]
    #[must_use]
    pub const fn contains_platform_hints(self) -> bool {
        let mut vals = self.0.as_slice();
        while let [ref first, ref rem @ ..] = *vals {
            match *first {
                None => return false,
                Some(h) => {
                    if h.is_eq(PublicKeyCredentialHint::ClientDevice) {
                        return true;
                    }
                }
            }
            vals = rem;
        }
        false
    }
}
/// Controls if the response to a requested extension is required to be sent back.
///
/// Note when requiring an extension, the extension must not only be sent back but also
/// contain at least one expected field (e.g., [`ClientExtensionsOutputs::cred_props`] must be
/// `Some(CredentialPropertiesOutput { rk: Some(_) })`.
///
/// If one wants to additionally control the values of an extension, use [`ExtensionInfo`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionReq {
    /// The response to a requested extension is required to be sent back.
    Require,
    /// The response to a requested extension is allowed, but not required, to be sent back.
    Allow,
}
/// Dictates how an extension should be processed.
///
/// If one wants to only control if the extension should be returned, use [`ExtensionReq`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
///
/// Note [`silent`](https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-silent)
/// is not supported for WebAuthn credentials, and
/// [`optional`](https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-optional)
/// is just an alias for [`Self::Required`].
#[expect(clippy::doc_markdown, reason = "false positive")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CredentialMediationRequirement {
    /// [`required`](https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-required).
    ///
    /// This is the default mediation for ceremonies.
    #[default]
    Required,
    /// [`conditional`](https://www.w3.org/TR/credential-management-1/#dom-credentialmediationrequirement-conditional).
    ///
    /// Note that when registering a new credential with [`CredentialCreationOptions::mediation`] set to
    /// `Self::Conditional`, [`UserVerificationRequirement::Required`] MUST NOT be used unless user verification
    /// can be explicitly performed during the ceremony.
    Conditional,
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
/// ) -> Vec<PublicKeyCredentialDescriptor<Box<[u8]>>> {
///     get_credentials(user_handle)
/// }
/// /// Used to fetch the excluded `PublicKeyCredentialDescriptor`s associated with `user_handle` during
/// /// registration as well as the `AllowedCredentials` containing `AllowedCredential`s with no credential-specific
/// /// extensions which is used for non-discoverable requests.
/// # #[cfg(feature = "custom")]
/// fn get_credentials<const LEN: usize, T>(user_handle: &UserHandle<LEN>) -> T
/// where
///     T: Credentials,
///     PublicKeyCredentialDescriptor<Box<[u8]>>: Into<T::Credential>,
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
/// ) -> impl Iterator<Item = (CredentialId<Box<[u8]>>, AuthTransports)> {
///     // ⋮
/// #     [(
/// #         CredentialId::try_from(vec![0; 16].into_boxed_slice()).unwrap(),
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
                            RpId::StaticDomain(dom) => {
                                DomainOrigin::new(dom.0) == client_data_json.origin
                            }
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
/// "Ceremonies" stored on the server that expire after a certain duration.
///
/// Types like [`RegistrationServerState`] and [`DiscoverableAuthenticationServerState`] are based on [`Challenge`]s
/// that expire after a certain duration.
pub trait TimedCeremony {
    /// Returns the `Instant` the ceremony expires.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is returned instead.
    #[cfg_attr(docsrs, doc(auto_cfg = false))]
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    fn expiration(&self) -> Instant;
    /// Returns the `SystemTime` the ceremony expires.
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    fn expiration(&self) -> SystemTime;
}
/// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrfInput<'first, 'second> {
    /// [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first).
    pub first: &'first [u8],
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second).
    pub second: Option<&'second [u8]>,
}
impl<'first, 'second> PrfInput<'first, 'second> {
    /// Returns a `PrfInput` with [`Self::first`] set to `first` and [`Self::second`] set to `None`.
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub const fn with_first<'a: 'first>(first: &'a [u8]) -> Self {
        Self {
            first,
            second: None,
        }
    }
    /// Same as [`Self::with_first`] except [`Self::second`] is set to `Some` containing `second`.
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub const fn with_two<'a: 'first, 'b: 'second>(first: &'a [u8], second: &'b [u8]) -> Self {
        Self {
            first,
            second: Some(second),
        }
    }
}
/// The number of milliseconds in 5 minutes.
///
/// This is the recommended default timeout duration for ceremonies
/// [in the spec](https://www.w3.org/TR/webauthn-3/#sctn-timeout-recommended-range).
pub const FIVE_MINUTES: NonZeroU32 = NonZeroU32::new(300_000).unwrap();
