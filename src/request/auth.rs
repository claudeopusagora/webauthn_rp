#[cfg(doc)]
use super::{
    super::response::{
        Backup, CollectedClientData, Flag,
        auth::AuthenticatorData,
        register::{DynamicState, StaticState},
    },
    AsciiDomain, DomainOrigin, Url,
    register::{self, PublicKeyCredentialCreationOptions},
};
use super::{
    super::{
        AuthenticatedCredential,
        response::{
            AuthenticatorAttachment,
            auth::{
                Authentication, AuthenticatorExtensionOutput, HmacSecret,
                error::{AuthCeremonyErr, ExtensionErr, OneOrTwo},
            },
            register::CompressedPubKey,
        },
    },
    BackupReq, Ceremony, CeremonyOptions, Challenge, CredentialId, Credentials, ExtensionReq, Hint,
    Origin, PublicKeyCredentialDescriptor, RpId, SentChallenge, ServerState,
    THREE_HUNDRED_THOUSAND, UserVerificationRequirement,
    auth::error::{RequestOptionsErr, SecondFactorErr},
};
use core::{
    borrow::Borrow,
    cmp::Ordering,
    hash::{Hash, Hasher},
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};
#[cfg(any(doc, not(feature = "serializable_server_state")))]
use std::time::Instant;
#[cfg(any(doc, feature = "serializable_server_state"))]
use std::time::SystemTime;
/// Contains error types.
pub mod error;
/// Contains functionality to serialize data to a client.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
mod ser;
/// Contains functionality to (de)serialize [`AuthenticationServerState`] to a data store.
#[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
#[cfg(feature = "serializable_server_state")]
pub mod ser_server_state;
/// Controls how [signature counter](https://www.w3.org/TR/webauthn-3/#signature-counter) is enforced.
///
/// Note that if the previous signature counter is positive and the new counter is not strictly greater, then the
/// authenticator is likely a clone (i.e., there are at least two copies of the private key).
#[derive(Clone, Copy, Debug, Default)]
pub enum SignatureCounterEnforcement {
    /// Fail the authentication ceremony if the counter is less than or equal to the previous value when the
    /// previous value is positive.
    #[default]
    Fail,
    /// When the counter is less than the previous value, don't fail and update the value.
    ///
    /// Note in the special case that the new signature counter is 0, [`DynamicState::sign_count`] _won't_
    /// be updated since that would allow an attacker to permanently disable the counter.
    Update,
    /// When the counter is less than the previous value, don't fail but don't update the value.
    Ignore,
}
impl SignatureCounterEnforcement {
    /// Validates the signature counter based on `self`.
    const fn validate(self, prev: u32, cur: u32) -> Result<u32, AuthCeremonyErr> {
        if prev == 0 || cur > prev {
            Ok(cur)
        } else {
            match self {
                Self::Fail => Err(AuthCeremonyErr::SignatureCounter),
                // When the new counter is `0`, we use the previous counter to avoid an attacker from
                // being able to permanently disable it.
                Self::Update => Ok(if cur == 0 { prev } else { cur }),
                Self::Ignore => Ok(prev),
            }
        }
    }
}
/// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues).
///
/// This is only applicable if
/// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
/// is `true` when registering a new credential with [`register::Extension::prf`] and
/// [`PublicKeyCredentialRequestOptions::user_verification`] is [`UserVerificationRequirement::Required`].
///
/// Unlike the spec, it is forbidden for
/// [the decrypted outputs](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfoutputs) to be
/// passed back in an effort to ensure sensitive data remains client-side. This means
/// [`prf`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfoutputs) must not exist,
/// be `null`, or be an
/// [`AuthenticationExtensionsPRFOutputs`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfoutputs)
/// such that [`results`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-results) does not exist,
/// is `null`, or is an
/// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues) such
/// that [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first) is `null` and
/// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second) does not exist or is `null`.
///
/// For the owned analog, see [`PrfInputOwned`].
///
/// When relying on discoverable requests
/// (i.e., [`PublicKeyCredentialRequestOptions::allow_credentials`] is empty),
/// one will likely use a static PRF input for _all_ credentials since rolling over PRF inputs
/// is not feasible. One uses this type for such a thing. In other words, `'a` will likely
/// be `'static` and [`Self::second`] will likely be `None`.
#[derive(Clone, Copy, Debug)]
pub struct PrfInput<'a> {
    /// [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first).
    pub first: &'a [u8],
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second).
    pub second: Option<&'a [u8]>,
    /// Response requirements.
    pub ext_info: ExtensionReq,
}
/// Owned version of [`PrfInput`].
///
/// When relying on non-discoverable requests
/// (i.e., [`PublicKeyCredentialRequestOptions::allow_credentials`] is non-empty),
/// it's recommended to use credential-specific PRF inputs that are continuously rolled over.
/// One uses this type for such a thing.
#[derive(Debug)]
pub struct PrfInputOwned {
    /// [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first).
    pub first: Vec<u8>,
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second).
    pub second: Option<Vec<u8>>,
    /// Response requirements.
    pub ext_info: ExtensionReq,
}
/// The [defined extensions](https://www.w3.org/TR/webauthn-3/#sctn-defined-extensions) to send to the client.
#[derive(Clone, Copy, Debug, Default)]
pub struct Extension<'prf> {
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension).
    ///
    /// If both [`CredentialSpecificExtension::prf`] and this are [`Some`], then `CredentialSpecificExtension::prf`
    /// takes priority.
    pub prf: Option<PrfInput<'prf>>,
}
/// The [defined extensions](https://www.w3.org/TR/webauthn-3/#sctn-defined-extensions) to send to the client that
/// are credential-specific which among other things implies a non-discoverable request.
#[derive(Debug, Default)]
pub struct CredentialSpecificExtension {
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension).
    ///
    /// If both [`Extension::prf`] and this are [`Some`], then this take priority.
    pub prf: Option<PrfInputOwned>,
}
/// Registered credential used in
/// [`allowCredentials`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials).
#[derive(Debug)]
pub struct AllowedCredential {
    /// The registered credential.
    pub credential: PublicKeyCredentialDescriptor<Vec<u8>>,
    /// Credential-specific extensions.
    pub extension: CredentialSpecificExtension,
}
impl From<PublicKeyCredentialDescriptor<Vec<u8>>> for AllowedCredential {
    #[inline]
    fn from(credential: PublicKeyCredentialDescriptor<Vec<u8>>) -> Self {
        Self {
            credential,
            extension: CredentialSpecificExtension::default(),
        }
    }
}
/// Queue of unique [`AllowedCredential`]s.
#[derive(Debug, Default)]
pub struct AllowedCredentials {
    /// Allowed credentials.
    creds: Vec<AllowedCredential>,
    /// Number of `AllowedCredential`s that have PRF inputs.
    ///
    /// Useful to help serialization.
    prf_count: usize,
}
impl Credentials for AllowedCredentials {
    type Credential = AllowedCredential;
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{auth::AllowedCredentials, Credentials};
    /// assert!(AllowedCredentials::with_capacity(1).as_ref().is_empty());
    /// ```
    #[inline]
    fn with_capacity(capacity: usize) -> Self {
        Self {
            creds: Vec::with_capacity(capacity),
            prf_count: 0,
        }
    }
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// # use webauthn_rp::{bin::Decode, response::bin::DecodeAuthTransportsErr};
    /// # use webauthn_rp::{
    /// #     request::{auth::AllowedCredentials, PublicKeyCredentialDescriptor, Credentials},
    /// #     response::{AuthTransports, CredentialId},
    /// # };
    /// /// Retrieves the `AuthTransports` associated with the unique `cred_id`
    /// /// from the database.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// fn get_transports(cred_id: CredentialId<&[u8]>) -> Result<AuthTransports, DecodeAuthTransportsErr> {
    ///     // ⋮
    /// #     AuthTransports::decode(32)
    /// }
    /// let mut creds = AllowedCredentials::with_capacity(1);
    /// assert!(creds.as_ref().is_empty());
    /// // `CredentialId::try_from` only exists when `custom` is enabled; and even then, it is
    /// // likely never needed since the `CredentialId` was originally sent from the client and is likely
    /// // stored in a database which would be fetched by `UserHandle` or `Authentication::raw_id`.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let id = CredentialId::try_from(vec![0; 16])?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports = get_transports((&id).into())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert!(creds.push(PublicKeyCredentialDescriptor { id, transports }.into()));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let id_copy = CredentialId::try_from(vec![0; 16])?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports_2 = AuthTransports::NONE;
    /// // Duplicate `CredentialId`s don't get added.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert!(!creds.push(
    ///     PublicKeyCredentialDescriptor {
    ///         id: id_copy,
    ///         transports: transports_2
    ///     }
    ///     .into()
    /// ));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment explains how overflow is not possible"
    )]
    #[inline]
    fn push(&mut self, cred: Self::Credential) -> bool {
        self.creds
            .iter()
            .try_fold((), |(), c| {
                if c.credential.id == cred.credential.id {
                    Err(())
                } else {
                    Ok(())
                }
            })
            .is_ok_and(|()| {
                // This can't overflow since `self.creds.push` would `panic` since
                // `self.prf_count <= self.creds.len()`.
                self.prf_count += usize::from(cred.extension.prf.is_some());
                self.creds.push(cred);
                true
            })
    }
    #[inline]
    fn len(&self) -> usize {
        self.creds.len()
    }
}
impl AsRef<[AllowedCredential]> for AllowedCredentials {
    #[inline]
    fn as_ref(&self) -> &[AllowedCredential] {
        self.creds.as_slice()
    }
}
impl From<&AllowedCredentials> for Vec<CredInfo> {
    #[inline]
    fn from(value: &AllowedCredentials) -> Self {
        let len = value.creds.len();
        value
            .creds
            .iter()
            .fold(Self::with_capacity(len), |mut creds, cred| {
                creds.push(CredInfo {
                    id: cred.credential.id.clone(),
                    ext: (&cred.extension).into(),
                });
                creds
            })
    }
}
/// Helper that verifies the overlap of [`PublicKeyCredentialRequestOptions::start_ceremony`] and
/// [`AuthenticationServerState::decode`].
fn validate_options_helper(
    ext: ServerExtensionInfo,
    uv: UserVerificationRequirement,
    creds: &[CredInfo],
) -> Result<(), RequestOptionsErr> {
    // If PRF is set, the user has to verify themselves.
    ext.prf
        .as_ref()
        .map_or(Ok(()), |_| {
            if matches!(uv, UserVerificationRequirement::Required) {
                Ok(())
            } else {
                Err(RequestOptionsErr::PrfWithoutUserVerification)
            }
        })
        .and_then(|()| {
            creds.iter().try_fold((), |(), cred| {
                // If PRF is set, the user has to verify themselves.
                cred.ext.prf.as_ref().map_or(Ok(()), |_| {
                    if matches!(uv, UserVerificationRequirement::Required) {
                        Ok(())
                    } else {
                        Err(RequestOptionsErr::PrfWithoutUserVerification)
                    }
                })
            })
        })
}
/// The [`PublicKeyCredentialRequestOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions)
/// to send to the client when authenticating a credential.
///
/// Upon saving the [`AuthenticationServerState`] returned from [`Self::start_ceremony`], one MUST send
/// [`AuthenticationClientState`] to the client ASAP. After receiving the newly created [`Authentication`], it
/// is validated using [`AuthenticationServerState::verify`].
#[derive(Debug)]
pub struct PublicKeyCredentialRequestOptions<'rp_id, 'prf> {
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-challenge).
    pub challenge: Challenge,
    /// [`timeout`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-timeout).
    ///
    /// Note we require a positive value despite the spec allowing an optional nonnegative value. This jives
    /// with the fact that in-memory storage is required when `serializable_server_state` is not enabled
    /// when authenticating credentials as no timeout would make out-of-memory (OOM) conditions more likely.
    pub timeout: NonZeroU32,
    /// [`rpId`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-rpid).
    ///
    /// This MUST be the same as the [`PublicKeyCredentialCreationOptions::rp_id`] used when the credential was registered.
    pub rp_id: &'rp_id RpId,
    /// [`allowCredentials`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials).
    pub allow_credentials: AllowedCredentials,
    /// [`userVerification`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-userverification).
    pub user_verification: UserVerificationRequirement,
    /// [`hints`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-hints).
    pub hints: Hint,
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-extensions).
    pub extensions: Extension<'prf>,
}
impl<'rp_id, 'prf> PublicKeyCredentialRequestOptions<'rp_id, 'prf> {
    /// Creates a `PublicKeyCredentialRequestOptions` with [`Self::user_verification`] set to
    /// [`UserVerificationRequirement::Required`] and [`Self::timeout`] set to 5 minutes,
    ///
    /// Note `rp_id` _must_ be the same as the [`PublicKeyCredentialCreationOptions::rp_id`] when the
    /// credential was registered.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{auth::PublicKeyCredentialRequestOptions, AsciiDomain, RpId, UserVerificationRequirement};
    /// assert!(matches!(
    ///     PublicKeyCredentialRequestOptions::passkey(&RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?)).user_verification,
    ///     UserVerificationRequirement::Required
    /// ));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn passkey<'a: 'rp_id>(rp_id: &'a RpId) -> Self {
        Self {
            challenge: Challenge::new(),
            timeout: THREE_HUNDRED_THOUSAND,
            rp_id,
            allow_credentials: AllowedCredentials::new(),
            user_verification: UserVerificationRequirement::Required,
            hints: Hint::None,
            extensions: Extension::default(),
        }
    }
    /// Creates a `PublicKeyCredentialRequestOptions` with [`Self::user_verification`] set to
    /// [`UserVerificationRequirement::Discouraged`] and [`Self::timeout`] set to 5 minutes.
    ///
    /// Note `rp_id` _must_ be the same as the [`PublicKeyCredentialCreationOptions::rp_id`] when the
    /// [`AllowedCredential`]s were registered.
    ///
    /// # Errors
    ///
    /// Errors iff [`AllowedCredentials`] is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// # use webauthn_rp::{bin::Decode, response::bin::DecodeAuthTransportsErr};
    /// # use webauthn_rp::{
    /// #     request::{
    /// #         auth::{AllowedCredentials, PublicKeyCredentialRequestOptions},
    /// #         AsciiDomain, RpId, PublicKeyCredentialDescriptor, Credentials
    /// #     },
    /// #     response::{AuthTransports, CredentialId},
    /// # };
    /// /// Retrieves the `AuthTransports` associated with the unique `cred_id`
    /// /// from the database.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// fn get_transports(cred_id: CredentialId<&[u8]>) -> Result<AuthTransports, DecodeAuthTransportsErr> {
    ///     // ⋮
    /// #     AuthTransports::decode(32)
    /// }
    /// let mut creds = AllowedCredentials::with_capacity(1);
    /// assert!(creds.as_ref().is_empty());
    /// // `CredentialId::try_from` only exists when `custom` is enabled; and even then, it is
    /// // likely never needed since the `CredentialId` was originally sent from the client and is likely
    /// // stored in a database which would be fetched by `UserHandle` or `Authentication::raw_id`.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let id = CredentialId::try_from(vec![0; 16])?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports = get_transports((&id).into())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert!(creds.push(PublicKeyCredentialDescriptor { id, transports }.into()));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(
    ///     PublicKeyCredentialRequestOptions::second_factor(&RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?), creds)?
    ///         .allow_credentials
    ///         .as_ref()
    ///         .len(),
    ///     1
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    pub fn second_factor<'a: 'rp_id>(
        rp_id: &'a RpId,
        creds: AllowedCredentials,
    ) -> Result<Self, SecondFactorErr> {
        if creds.as_ref().is_empty() {
            Err(SecondFactorErr)
        } else {
            let mut opts = Self::passkey(rp_id);
            opts.allow_credentials = creds;
            opts.user_verification = UserVerificationRequirement::Discouraged;
            Ok(opts)
        }
    }
    /// Begins the [authentication ceremony](https://www.w3.org/TR/webauthn-3/#authentication-ceremony) consuming
    /// `self`. Note that the expiration [`Instant`]/[`SystemTime`] is saved, so `AuthenticationClientState` MUST be
    /// sent ASAP. In order to complete authentication, the returned `AuthenticationServerState` MUST be saved so
    /// that it can later be used to verify the credential assertion with [`AuthenticationServerState::verify`].
    ///
    /// # Errors
    ///
    /// Errors iff `self` contains incompatible configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(not(feature = "serializable_server_state"))]
    /// # use std::time::Instant;
    /// # #[cfg(not(feature = "serializable_server_state"))]
    /// # use webauthn_rp::request::ServerState;
    /// # use webauthn_rp::request::{auth::PublicKeyCredentialRequestOptions, AsciiDomain, RpId};
    /// # #[cfg(not(feature = "serializable_server_state"))]
    /// assert!(
    ///     PublicKeyCredentialRequestOptions::passkey(&RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?))
    ///         .start_ceremony()?
    ///         .0
    ///         .expiration() > Instant::now()
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    pub fn start_ceremony(
        self,
    ) -> Result<
        (
            AuthenticationServerState,
            AuthenticationClientState<'rp_id, 'prf>,
        ),
        RequestOptionsErr,
    > {
        let extensions = self.extensions.into();
        let allow_credentials = Vec::from(&self.allow_credentials);
        validate_options_helper(extensions, self.user_verification, &allow_credentials).and_then(
            |()| {
                #[cfg(not(feature = "serializable_server_state"))]
                let res = Instant::now();
                #[cfg(feature = "serializable_server_state")]
                let res = SystemTime::now();
                res.checked_add(Duration::from_millis(NonZeroU64::from(self.timeout).get()))
                    .ok_or(RequestOptionsErr::InvalidTimeout)
                    .map(|expiration| {
                        (
                            AuthenticationServerState {
                                challenge: SentChallenge(self.challenge.0),
                                allow_credentials,
                                user_verification: self.user_verification,
                                extensions,
                                expiration,
                            },
                            AuthenticationClientState(self),
                        )
                    })
            },
        )
    }
}
/// Container of a [`PublicKeyCredentialRequestOptions`] that has been used to start the authentication ceremony.
/// This gets sent to the client ASAP.
#[derive(Debug)]
pub struct AuthenticationClientState<'rp_id, 'prf>(PublicKeyCredentialRequestOptions<'rp_id, 'prf>);
impl<'rp_id, 'prf> AuthenticationClientState<'rp_id, 'prf> {
    /// Returns the `PublicKeyCredentialRequestOptions` that was used to start an authentication ceremony.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{auth::PublicKeyCredentialRequestOptions, AsciiDomain, RpId};
    /// assert!(
    ///     PublicKeyCredentialRequestOptions::passkey(&RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?))
    ///         .start_ceremony()?
    ///         .1
    ///         .options()
    ///         .allow_credentials
    ///         .as_ref()
    ///         .is_empty()
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    #[must_use]
    pub const fn options(&self) -> &PublicKeyCredentialRequestOptions<'rp_id, 'prf> {
        &self.0
    }
}
/// `PrfInput` and `PrfInputOwned` without the actual data sent to reduce memory usage when storing [`AuthenticationServerState`]
/// in an in-memory collection.
#[derive(Clone, Copy, Debug)]
enum ServerPrfInfo {
    /// `PrfInput::second` was `None`.
    One(ExtensionReq),
    /// `PrfInput::second` was `Some`.
    Two(ExtensionReq),
}
impl ServerPrfInfo {
    /// Returns the `ExtensionReq` sent to the client.
    const fn ext_info(self) -> ExtensionReq {
        match self {
            Self::One(info) | Self::Two(info) => info,
        }
    }
    /// Validates `val` based on the passed arguments.
    fn validate(
        val: Option<Self>,
        prf_capable: bool,
        hmac: HmacSecret,
        err_unsolicited: bool,
    ) -> Result<(), ExtensionErr> {
        match hmac {
            HmacSecret::None => {
                if prf_capable {
                    val.map_or(Ok(()), |input| {
                        if matches!(input.ext_info(), ExtensionReq::Allow) {
                            Ok(())
                        } else {
                            Err(ExtensionErr::MissingHmacSecret)
                        }
                    })
                } else {
                    // We check if the PRF extension was requested on an incapable credential;
                    // if so, we error.
                    val.map_or(Ok(()), |_| Err(ExtensionErr::HmacSecretForPrfIncapableCred))
                }
            }
            HmacSecret::One => {
                if prf_capable {
                    val.map_or_else(
                        || {
                            if err_unsolicited {
                                Err(ExtensionErr::ForbiddenHmacSecret)
                            } else {
                                Ok(())
                            }
                        },
                        |input| match input {
                            Self::One(_) => Ok(()),
                            Self::Two(_) => Err(ExtensionErr::InvalidHmacSecretValue(
                                OneOrTwo::Two,
                                OneOrTwo::One,
                            )),
                        },
                    )
                } else {
                    Err(ExtensionErr::HmacSecretForPrfIncapableCred)
                }
            }
            HmacSecret::Two => {
                if prf_capable {
                    val.map_or_else(
                        || {
                            if err_unsolicited {
                                Err(ExtensionErr::ForbiddenHmacSecret)
                            } else {
                                Ok(())
                            }
                        },
                        |input| match input {
                            Self::One(_) => Err(ExtensionErr::InvalidHmacSecretValue(
                                OneOrTwo::One,
                                OneOrTwo::Two,
                            )),
                            Self::Two(_) => Ok(()),
                        },
                    )
                } else {
                    Err(ExtensionErr::HmacSecretForPrfIncapableCred)
                }
            }
        }
    }
}
impl From<PrfInput<'_>> for ServerPrfInfo {
    fn from(value: PrfInput<'_>) -> Self {
        value
            .second
            .map_or_else(|| Self::One(value.ext_info), |_| Self::Two(value.ext_info))
    }
}
impl From<&PrfInputOwned> for ServerPrfInfo {
    fn from(value: &PrfInputOwned) -> Self {
        value
            .second
            .as_ref()
            .map_or_else(|| Self::One(value.ext_info), |_| Self::Two(value.ext_info))
    }
}
/// `Extension` without the actual data sent to reduce memory usage when storing [`AuthenticationServerState`]
/// in an in-memory collection.
#[derive(Clone, Copy, Debug)]
struct ServerExtensionInfo {
    /// `Extension::prf`.
    prf: Option<ServerPrfInfo>,
}
impl From<Extension<'_>> for ServerExtensionInfo {
    fn from(value: Extension<'_>) -> Self {
        Self {
            prf: value.prf.map(ServerPrfInfo::from),
        }
    }
}
/// `CredentialSpecificExtension` without the actual data sent to reduce memory usage when storing [`AuthenticationServerState`]
/// in an in-memory collection.
#[derive(Clone, Copy, Debug)]
struct ServerCredSpecificExtensionInfo {
    /// `CredentialSpecificExtension::prf`.
    prf: Option<ServerPrfInfo>,
}
impl From<&CredentialSpecificExtension> for ServerCredSpecificExtensionInfo {
    fn from(value: &CredentialSpecificExtension) -> Self {
        Self {
            prf: value.prf.as_ref().map(ServerPrfInfo::from),
        }
    }
}
impl ServerExtensionInfo {
    /// Validates the extensions.
    ///
    /// Note that this MUST only be called internally by `auth::validate_extensions`.
    fn validate_extensions(
        self,
        auth_ext: AuthenticatorExtensionOutput,
        error_unsolicited: bool,
        prf_capable: bool,
    ) -> Result<(), ExtensionErr> {
        ServerPrfInfo::validate(
            self.prf,
            prf_capable,
            auth_ext.hmac_secret,
            error_unsolicited,
        )
    }
}
/// Validates the extensions.
fn validate_extensions(
    ext: ServerExtensionInfo,
    cred_ext: Option<ServerCredSpecificExtensionInfo>,
    auth_ext: AuthenticatorExtensionOutput,
    error_unsolicited: bool,
    prf_capable: bool,
) -> Result<(), ExtensionErr> {
    cred_ext.map_or_else(
        || {
            // No client-specific extensions, so we can simply focus on `ext`.
            ext.validate_extensions(auth_ext, error_unsolicited, prf_capable)
        },
        |c_ext| {
            // Must carefully process each extension based on overlap and which gets priority over the other.
            c_ext.prf.as_ref().map_or_else(
                || {
                    ServerPrfInfo::validate(
                        ext.prf,
                        prf_capable,
                        auth_ext.hmac_secret,
                        error_unsolicited,
                    )
                },
                |_| {
                    ServerPrfInfo::validate(
                        c_ext.prf,
                        prf_capable,
                        auth_ext.hmac_secret,
                        error_unsolicited,
                    )
                },
            )
        },
    )
}
/// [`AllowedCredential`] with less data to reduce memory usage when storing [`AuthenticationServerState`]
/// in an in-memory collection.
#[derive(Debug)]
struct CredInfo {
    /// The Credential ID.
    id: CredentialId<Vec<u8>>,
    /// Any credential-specific extensions.
    ext: ServerCredSpecificExtensionInfo,
}
/// Controls how to handle a change in [`DynamicState::authenticator_attachment`].
///
/// Note when `DynamicState::authenticator_attachment` is [`AuthenticatorAttachment::None`], then it will
/// be updated regardless. Similarly when [`Authentication::authenticator_attachment`] is
/// `AuthenticatorAttachment::None`, it will never update `DynamicState::authenticator_attachment`.
#[derive(Clone, Copy, Debug)]
pub enum AuthenticatorAttachmentEnforcement {
    /// Fail the authentication ceremony if [`AuthenticatorAttachment`] is not the same.
    ///
    /// The contained `bool` represents if `AuthenticatorAttachment` must be sent.
    Fail(bool),
    /// Update [`DynamicState::authenticator_attachment`] to the sent [`AuthenticatorAttachment`].
    ///
    /// The contained `bool` represents if `AuthenticatorAttachment` must be sent.
    Update(bool),
    /// Do not update [`DynamicState::authenticator_attachment`] to the sent [`AuthenticatorAttachment`].
    ///
    /// The contained `bool` represents if `AuthenticatorAttachment` must be sent.
    Ignore(bool),
}
impl AuthenticatorAttachmentEnforcement {
    /// Validates `cur` based on `self` and `prev`.
    const fn validate(
        self,
        prev: AuthenticatorAttachment,
        cur: AuthenticatorAttachment,
    ) -> Result<AuthenticatorAttachment, AuthCeremonyErr> {
        match cur {
            AuthenticatorAttachment::None => match self {
                Self::Fail(require) | Self::Update(require) | Self::Ignore(require) => {
                    if require {
                        Err(AuthCeremonyErr::MissingAuthenticatorAttachment)
                    } else {
                        // We don't overwrite the previous one with [`AuthenticatorAttachment::None`].
                        Ok(prev)
                    }
                }
            },
            AuthenticatorAttachment::Platform => match self {
                Self::Fail(_) => {
                    if matches!(prev, AuthenticatorAttachment::CrossPlatform) {
                        Err(AuthCeremonyErr::AuthenticatorAttachmentMismatch)
                    } else {
                        // We don't fail when we previously had [`AuthenticatorAttachment::None`].
                        Ok(cur)
                    }
                }
                Self::Update(_) => Ok(cur),
                Self::Ignore(_) => {
                    if matches!(prev, AuthenticatorAttachment::None) {
                        // We overwrite the previous one when it is [`AuthenticatorAttachment::None`].
                        Ok(cur)
                    } else {
                        Ok(prev)
                    }
                }
            },
            AuthenticatorAttachment::CrossPlatform => match self {
                Self::Fail(_) => {
                    if matches!(prev, AuthenticatorAttachment::Platform) {
                        Err(AuthCeremonyErr::AuthenticatorAttachmentMismatch)
                    } else {
                        // We don't fail when we previously had [`AuthenticatorAttachment::None`].
                        Ok(cur)
                    }
                }
                Self::Update(_) => Ok(cur),
                Self::Ignore(_) => {
                    if matches!(prev, AuthenticatorAttachment::None) {
                        // We overwrite the previous one when it is [`AuthenticatorAttachment::None`].
                        Ok(cur)
                    } else {
                        Ok(prev)
                    }
                }
            },
        }
    }
}
impl Default for AuthenticatorAttachmentEnforcement {
    /// Returns [`Self::Ignore`] containing `false`.
    #[inline]
    fn default() -> Self {
        Self::Ignore(false)
    }
}
/// Additional verification options to perform in [`AuthenticationServerState::verify`].
#[derive(Clone, Copy, Debug)]
pub struct AuthenticationVerificationOptions<'origins, 'top_origins, O, T> {
    /// Origins to use for [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin).
    ///
    /// When this is empty, the origin that will be used will be based on
    /// the [`RpId`] passed to [`AuthenticationServerState::verify`]. If [`RpId::Domain`], then the [`DomainOrigin`] returned from
    /// passing [`AsciiDomain::as_ref`] to [`DomainOrigin::new`] will be used; otherwise the [`Url`] in
    /// [`RpId::Url`] will be used.
    pub allowed_origins: &'origins [O],
    /// [Top-level origins](https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-top-level-origin)
    /// to use for [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin).
    ///
    /// When this is `Some`, [`CollectedClientData::cross_origin`] is allowed to be `true`. When the contained
    /// `slice` is empty, [`CollectedClientData::top_origin`] must be `None`. When this is `None`,
    /// `CollectedClientData::cross_origin` must be `false` and `CollectedClientData::top_origin` must be `None`.
    pub allowed_top_origins: Option<&'top_origins [T]>,
    /// The required [`Backup`] state of the credential.
    ///
    /// Note that `None` is _not_ the same as `Some(BackupReq::None)` as the latter indicates that any [`Backup`]
    /// is allowed. This is rarely what you want; instead, `None` indicates that [`BackupReq::from`] applied to
    /// [`DynamicState::backup`] will be used in [`AuthenticationServerState::verify`].
    pub backup_requirement: Option<BackupReq>,
    /// Error when unsolicited extensions are sent back iff `true`.
    pub error_on_unsolicited_extensions: bool,
    /// Dictates what happens when [`Authentication::authenticator_attachment`] is not the same as
    /// [`DynamicState::authenticator_attachment`].
    pub auth_attachment_enforcement: AuthenticatorAttachmentEnforcement,
    /// [`DynamicState::user_verified`] will be set to `true` iff [`Flag::user_verified`] when `true`.
    pub update_uv: bool,
    /// Dictates what happens when [`AuthenticatorData::sign_count`] is not updated to a strictly greater value.
    pub sig_counter_enforcement: SignatureCounterEnforcement,
    /// [`CollectedClientData::from_client_data_json_relaxed`] is used to extract [`CollectedClientData`] iff `true`.
    #[cfg_attr(docsrs, doc(cfg(feature = "serde_relaxed")))]
    #[cfg(feature = "serde_relaxed")]
    pub client_data_json_relaxed: bool,
}
impl<O, T> Default for AuthenticationVerificationOptions<'_, '_, O, T> {
    /// Returns `Self` such that [`Self::allowed_origins`] is empty, [`Self::allowed_top_origins`] is `None`,
    /// [`Self::backup_requirement`] is `None`, [`Self::error_on_unsolicited_extensions`] is `true`,
    /// [`Self::auth_attachment_enforcement`] is [`AuthenticatorAttachmentEnforcement::default`],
    /// [`Self::update_uv`] is `false`, [`Self::sig_counter_enforcement`] is
    /// [`SignatureCounterEnforcement::Fail`], and [`Self::client_data_json_relaxed`] is `true`.
    #[inline]
    fn default() -> Self {
        Self {
            allowed_origins: &[],
            allowed_top_origins: None,
            backup_requirement: None,
            error_on_unsolicited_extensions: true,
            auth_attachment_enforcement: AuthenticatorAttachmentEnforcement::default(),
            update_uv: false,
            sig_counter_enforcement: SignatureCounterEnforcement::default(),
            #[cfg(feature = "serde_relaxed")]
            client_data_json_relaxed: true,
        }
    }
}
// This is essentially the `PublicKeyCredentialRequestOptions` used to create it; however to reduce
// memory usage, we remove all unnecessary data making an instance of this 64 bytes in size when
// `Self::allow_credentials` is empty on `x86_64-unknown-linux-gnu` platforms.
//
// The total memory used is dependent on the number of `AllowedCredential`s and the size of each `CredentialId`.
// To be exact, it is the following:
// 64 + i(32 + 56n + Σj_k from k=0 to k=m-1) where i is 0 iff `AllowedCredentials` has capacity 0; otherwise 1,
// n is `AllowedCredentials` capacity, j_k is the kth `CredentialId` in `AllowedCredentials` and `m` is
// `AllowedCredentials::len`.
/// State needed to be saved when beginning the authentication ceremony.
///
/// Saves the necessary information associated with the [`PublicKeyCredentialRequestOptions`] used to create it
/// via [`PublicKeyCredentialRequestOptions::start_ceremony`] so that authentication of a credential can be
/// performed with [`Self::verify`].
///
/// `AuthenticationServerState` implements [`Borrow`] of [`SentChallenge`]; thus to obtain the correct
/// `AuthenticationServerState` associated with an [`Authentication`], one should use its corresponding
/// [`Authentication::challenge`].
#[derive(Debug)]
pub struct AuthenticationServerState {
    // This is a `SentChallenge` since we need `AuthenticationServerState` to be fetchable after receiving the
    // response from the client. This response must obviously be constructable; thus its challenge is a
    // `SentChallenge`.
    //
    // This must never be mutated since we want to ensure it is actually a `Challenge` (which
    // can only be constructed via `Challenge::new`). This is guaranteed to be true iff
    // `serializable_server_state` is not enabled.
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-challenge).
    challenge: SentChallenge,
    /// [`allowCredentials`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials).
    allow_credentials: Vec<CredInfo>,
    /// [`userVerification`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-userverification).
    user_verification: UserVerificationRequirement,
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-extensions).
    extensions: ServerExtensionInfo,
    /// `Instant` the ceremony expires.
    #[cfg(not(feature = "serializable_server_state"))]
    expiration: Instant,
    /// `SystemTime` the ceremony expires.
    #[cfg(feature = "serializable_server_state")]
    expiration: SystemTime,
}
impl AuthenticationServerState {
    /// Verifies `response` is valid based on `self` consuming `self` and updating `cred`. Returns `true`
    /// iff `cred` was mutated.
    ///
    /// `rp_id` MUST be the same as the [`PublicKeyCredentialRequestOptions::rp_id`] used when starting the
    /// ceremony.
    ///
    /// It is _essential_ to save [`AuthenticatedCredential::dynamic_state`] overwriting the original value iff `Ok(true)`
    /// is returned.
    ///
    /// # Errors
    ///
    /// Errors iff `response` is not valid according to the
    /// [authentication ceremony](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion) or violates any
    /// of the settings in `options`.
    #[inline]
    pub fn verify<
        'a,
        'user,
        O: PartialEq<Origin<'a>>,
        T: PartialEq<Origin<'a>>,
        EdKey: AsRef<[u8]>,
        P256Key: AsRef<[u8]>,
        P384Key: AsRef<[u8]>,
        RsaKey: AsRef<[u8]>,
    >(
        self,
        rp_id: &RpId,
        response: &'a Authentication,
        cred: &mut AuthenticatedCredential<
            'a,
            'user,
            CompressedPubKey<EdKey, P256Key, P384Key, RsaKey>,
        >,
        options: &AuthenticationVerificationOptions<'_, '_, O, T>,
    ) -> Result<bool, AuthCeremonyErr> {
        // [Authentication ceremony](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)
        // is handled by:
        //
        // 1. Calling code.
        // 2. Client code and the construction of `resp` (hopefully via [`Authentication::deserialize`]).
        // 3. Client code and the construction of `resp` (hopefully via [`AuthenticatorAssertion::deserialize`]).
        // 4. Client code and the construction of `resp` (hopefully via [`ClientExtensionsOutputs::deserialize`]).
        // 5. Below.
        // 6. Below.
        // 7. Informative only in that it defines variables.
        // 8. [`Self::partial_validate`].
        // 9. [`Self::partial_validate`].
        // 10. [`Self::partial_validate`].
        // 11. [`Self::partial_validate`].
        // 12. [`Self::partial_validate`].
        // 13. [`Self::partial_validate`].
        // 14. [`Self::partial_validate`].
        // 15. [`Self::partial_validate`].
        // 16. [`Self::partial_validate`].
        // 17. [`Self::partial_validate`].
        // 18. [`Self::partial_validate`].
        // 19. [`Self::partial_validate`].
        // 20. [`Self::partial_validate`].
        // 21. [`Self::partial_validate`].
        // 22. Below.
        // 23. Below.
        // 24. Below.
        // 25. Below.

        if self.allow_credentials.is_empty() {
            // Step 6.
            response
                .response
                .user_handle()
                .as_ref()
                .ok_or(AuthCeremonyErr::MissingUserHandle)
                .and_then(|user| {
                    if cred.user_id() == user {
                        if cred.id == response.raw_id {
                            Ok(None)
                        } else {
                            Err(AuthCeremonyErr::CredentialIdMismatch)
                        }
                    } else {
                        Err(AuthCeremonyErr::UserHandleMismatch)
                    }
                })
        } else {
            // Steps 5–6.
            self.verify_nondiscoverable(response, cred)
        }
        .and_then(|ext| {
            // Steps 8–21.
            self.partial_validate(
                rp_id,
                response,
                (&cred.static_state.credential_public_key).into(),
                &CeremonyOptions {
                    allowed_origins: options.allowed_origins,
                    allowed_top_origins: options.allowed_top_origins,
                    backup_requirement: options
                        .backup_requirement
                        .unwrap_or_else(|| BackupReq::from(cred.dynamic_state.backup)),
                    #[cfg(feature = "serde_relaxed")]
                    client_data_json_relaxed: options.client_data_json_relaxed,
                },
            )
            .map_err(AuthCeremonyErr::from)
            .and_then(|auth_data| {
                options
                    .auth_attachment_enforcement
                    .validate(
                        cred.dynamic_state.authenticator_attachment,
                        response.authenticator_attachment,
                    )
                    .and_then(|auth_attachment| {
                        // Step 23.
                        validate_extensions(
                            self.extensions,
                            ext,
                            auth_data.extensions(),
                            options.error_on_unsolicited_extensions,
                            cred.static_state.extensions.hmac_secret.unwrap_or_default(),
                        )
                        .map_err(AuthCeremonyErr::Extension)
                        .and_then(|()| {
                            // Step 22.
                            options
                                .sig_counter_enforcement
                                .validate(cred.dynamic_state.sign_count, auth_data.sign_count())
                                .and_then(|sig_counter| {
                                    let flags = auth_data.flags();
                                    let prev_dyn_state = cred.dynamic_state;
                                    // Step 24 item 2.
                                    cred.dynamic_state.backup = flags.backup;
                                    if options.update_uv && flags.user_verified {
                                        // Step 24 item 3.
                                        cred.dynamic_state.user_verified = true;
                                    }
                                    // Step 24 item 1.
                                    cred.dynamic_state.sign_count = sig_counter;
                                    cred.dynamic_state.authenticator_attachment = auth_attachment;
                                    // Step 25.
                                    crate::verify_static_and_dynamic_state(
                                        &cred.static_state,
                                        cred.dynamic_state,
                                    )
                                    .map_err(|e| {
                                        cred.dynamic_state = prev_dyn_state;
                                        AuthCeremonyErr::Credential(e)
                                    })
                                    .map(|()| prev_dyn_state != cred.dynamic_state)
                                })
                        })
                    })
            })
        })
    }
    /// Retrieves the corresponding [`CredInfo`] used for a non-discoverable request that corresponds to
    /// `response`. Since this is a non-discoverable request, one must have an external way of identifying the
    /// `UserHandle`.
    ///
    /// This MUST be called iff a non-discoverable request was sent to the client (e.g.,
    /// [`PublicKeyCredentialRequestOptions::second_factor`]).
    ///
    /// # Errors
    ///
    /// Errors iff [`AuthenticatedCredential::user_handle`] does not match [`Authentication::user_handle`] or
    /// [`PublicKeyCredentialRequestOptions::allow_credentials`] does not have a [`CredInfo`] such that
    /// [`CredInfo::id`] matches [`Authentication::raw_id`].
    fn verify_nondiscoverable<'a, PublicKey>(
        &self,
        response: &'a Authentication,
        cred: &AuthenticatedCredential<'a, '_, PublicKey>,
    ) -> Result<Option<ServerCredSpecificExtensionInfo>, AuthCeremonyErr> {
        response
            .response
            .user_handle()
            .as_ref()
            .map_or(Ok(()), |user| {
                if user == cred.user_id() {
                    Ok(())
                } else {
                    Err(AuthCeremonyErr::UserHandleMismatch)
                }
            })
            .and_then(|()| {
                self.allow_credentials
                    .iter()
                    .find(|c| c.id == response.raw_id)
                    .ok_or(AuthCeremonyErr::NoMatchingAllowedCredential)
                    .map(|c| Some(c.ext))
            })
    }
}
impl ServerState for AuthenticationServerState {
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    #[inline]
    fn expiration(&self) -> Instant {
        self.expiration
    }
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    #[inline]
    fn expiration(&self) -> SystemTime {
        self.expiration
    }
    #[inline]
    fn sent_challenge(&self) -> SentChallenge {
        self.challenge
    }
}
impl Ceremony for AuthenticationServerState {
    type R = Authentication;
    fn rand_challenge(&self) -> SentChallenge {
        self.challenge
    }
    #[cfg(not(feature = "serializable_server_state"))]
    fn expiry(&self) -> Instant {
        self.expiration
    }
    #[cfg(feature = "serializable_server_state")]
    fn expiry(&self) -> SystemTime {
        self.expiration
    }
    fn user_verification(&self) -> UserVerificationRequirement {
        self.user_verification
    }
}
impl Borrow<SentChallenge> for AuthenticationServerState {
    #[inline]
    fn borrow(&self) -> &SentChallenge {
        &self.challenge
    }
}
impl PartialEq for AuthenticationServerState {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.challenge == other.challenge
    }
}
impl PartialEq<&Self> for AuthenticationServerState {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<AuthenticationServerState> for &AuthenticationServerState {
    #[inline]
    fn eq(&self, other: &AuthenticationServerState) -> bool {
        **self == *other
    }
}
impl Eq for AuthenticationServerState {}
impl Hash for AuthenticationServerState {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.challenge.hash(state);
    }
}
impl PartialOrd for AuthenticationServerState {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for AuthenticationServerState {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.challenge.cmp(&other.challenge)
    }
}
