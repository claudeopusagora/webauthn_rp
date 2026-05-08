#[cfg(test)]
mod tests;
#[cfg(doc)]
use super::{
    super::response::{
        CollectedClientData, Flag,
        auth::AuthenticatorData,
        register::{
            AuthenticatorExtensionOutputStaticState, ClientExtensionsOutputsStaticState,
            DynamicState, StaticState,
        },
    },
    AsciiDomain, AsciiDomainStatic, DomainOrigin, Url,
    register::{self, PublicKeyCredentialCreationOptions},
};
use super::{
    super::{
        AuthenticatedCredential,
        response::{
            AuthenticatorAttachment,
            auth::{
                Authentication, AuthenticatorExtensionOutput, DiscoverableAuthentication,
                HmacSecret, NonDiscoverableAuthentication,
                error::{AuthCeremonyErr, ExtensionErr, OneOrTwo},
            },
            register::{CompressedPubKey, CredentialProtectionPolicy},
        },
    },
    Backup, BackupReq, Ceremony, CeremonyOptions, Challenge, CredentialId,
    CredentialMediationRequirement, Credentials, ExtensionReq, FIVE_MINUTES, Hints, Origin,
    PrfInput, PublicKeyCredentialDescriptor, RpId, SentChallenge, TimedCeremony,
    UserVerificationRequirement,
    auth::error::{
        DiscoverableCredentialRequestOptionsErr, NonDiscoverableCredentialRequestOptionsErr,
    },
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
#[cfg(feature = "serde")]
pub mod ser;
/// Contains functionality to (de)serialize [`DiscoverableAuthenticationServerState`] and
/// [`NonDiscoverableAuthenticationServerState`] to a data store.
#[cfg(feature = "serializable_server_state")]
pub mod ser_server_state;
/// Controls how [signature counter](https://www.w3.org/TR/webauthn-3/#signature-counter) is enforced.
///
/// Note that if the previous signature counter is positive and the new counter is not strictly greater, then the
/// authenticator is likely a clone (i.e., there are at least two copies of the private key).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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
/// Owned version of [`PrfInput`].
///
/// When relying on [`NonDiscoverableCredentialRequestOptions`], it's recommended to use credential-specific PRF
/// inputs that are continuously rolled over. One uses this type for such a thing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrfInputOwned {
    /// [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first).
    pub first: Vec<u8>,
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second).
    pub second: Option<Vec<u8>>,
    /// Note this is only applicable for authenticators that implement the
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension) extension on top of the
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-extension)
    /// extension since the data is encrypted and is part of the [`AuthenticatorData`].
    pub ext_req: ExtensionReq,
}
/// The [defined extensions](https://www.w3.org/TR/webauthn-3/#sctn-defined-extensions) to send to the client.
#[derive(Clone, Copy, Debug)]
pub struct Extension<'prf_first, 'prf_second> {
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension).
    ///
    /// If both [`CredentialSpecificExtension::prf`] and this are [`Some`], then `CredentialSpecificExtension::prf`
    /// takes priority.
    ///
    /// Note `ExtensionReq` is only applicable for authenticators that implement the
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension) extension on top of the
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-extension)
    /// extension since the data is encrypted and is part of the [`AuthenticatorData`].
    pub prf: Option<(PrfInput<'prf_first, 'prf_second>, ExtensionReq)>,
}
impl<'prf_first, 'prf_second> Extension<'prf_first, 'prf_second> {
    /// Returns an `Extension` with [`Self::prf`] set to `None`.
    #[inline]
    #[must_use]
    pub const fn none() -> Self {
        Self { prf: None }
    }
    /// Returns an `Extension` with [`Self::prf`] set to `None`.
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub const fn with_prf<'a: 'prf_first, 'b: 'prf_second>(
        input: PrfInput<'a, 'b>,
        req: ExtensionReq,
    ) -> Self {
        Self {
            prf: Some((input, req)),
        }
    }
}
impl Default for Extension<'_, '_> {
    /// Same as [`Self::none`].
    #[inline]
    fn default() -> Self {
        Self::none()
    }
}
/// The [defined extensions](https://www.w3.org/TR/webauthn-3/#sctn-defined-extensions) to send to the client that
/// are credential-specific which among other things implies a non-discoverable request.
#[derive(Clone, Debug, Default)]
pub struct CredentialSpecificExtension {
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension).
    ///
    /// If both [`Extension::prf`] and this are [`Some`], then this take priority.
    pub prf: Option<PrfInputOwned>,
}
/// Registered credential used in
/// [`allowCredentials`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials).
#[derive(Clone, Debug)]
pub struct AllowedCredential {
    /// The registered credential.
    pub credential: PublicKeyCredentialDescriptor<Box<[u8]>>,
    /// Credential-specific extensions.
    pub extension: CredentialSpecificExtension,
}
impl From<PublicKeyCredentialDescriptor<Box<[u8]>>> for AllowedCredential {
    #[inline]
    fn from(credential: PublicKeyCredentialDescriptor<Box<[u8]>>) -> Self {
        Self {
            credential,
            extension: CredentialSpecificExtension::default(),
        }
    }
}
impl From<AllowedCredential> for PublicKeyCredentialDescriptor<Box<[u8]>> {
    #[inline]
    fn from(credential: AllowedCredential) -> Self {
        credential.credential
    }
}
/// Queue of unique [`AllowedCredential`]s.
#[derive(Clone, Debug, Default)]
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
    /// let id = CredentialId::try_from(vec![0; 16].into_boxed_slice())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports = get_transports((&id).into())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert!(creds.push(PublicKeyCredentialDescriptor { id, transports }.into()));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let id_copy = CredentialId::try_from(vec![0; 16].into_boxed_slice())?;
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
impl From<&AllowedCredentials> for Box<[CredInfo]> {
    #[inline]
    fn from(value: &AllowedCredentials) -> Self {
        let len = value.creds.len();
        value
            .creds
            .iter()
            .fold(Vec::with_capacity(len), |mut creds, cred| {
                creds.push(CredInfo {
                    id: cred.credential.id.clone(),
                    ext: (&cred.extension).into(),
                });
                creds
            })
            .into_boxed_slice()
    }
}
impl From<AllowedCredentials> for Vec<PublicKeyCredentialDescriptor<Box<[u8]>>> {
    #[inline]
    fn from(value: AllowedCredentials) -> Self {
        let mut creds = Self::with_capacity(value.creds.len());
        value.creds.into_iter().fold((), |(), cred| {
            creds.push(cred.credential);
        });
        creds
    }
}
impl From<Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>> for AllowedCredentials {
    #[inline]
    fn from(value: Vec<PublicKeyCredentialDescriptor<Box<[u8]>>>) -> Self {
        let mut creds = Self::with_capacity(value.len());
        value.into_iter().fold((), |(), credential| {
            _ = creds.push(AllowedCredential {
                credential,
                extension: CredentialSpecificExtension { prf: None },
            });
        });
        creds
    }
}
/// Helper that verifies the overlap of [`DiscoverableCredentialRequestOptions::start_ceremony`] and
/// [`DiscoverableAuthenticationServerState::decode`].
///
/// Returns `true` iff the options are valid.
const fn validate_discoverable_options_helper(
    ext: ServerExtensionInfo,
    uv: UserVerificationRequirement,
) -> bool {
    // If PRF is set, the user has to verify themselves.
    matches!(ext.prf, ServerPrfInfo::None) || matches!(uv, UserVerificationRequirement::Required)
}
/// Helper that verifies the overlap of [`NonDiscoverableCredentialRequestOptions::start_ceremony`] and
/// [`NonDiscoverableAuthenticationServerState::decode`].
fn validate_non_discoverable_options_helper(
    uv: UserVerificationRequirement,
    creds: &[CredInfo],
) -> Result<(), NonDiscoverableCredentialRequestOptionsErr> {
    creds.iter().try_fold((), |(), cred| {
        // If PRF is set, the user has to verify themselves.
        if matches!(cred.ext.prf, ServerPrfInfo::None)
            || matches!(uv, UserVerificationRequirement::Required)
        {
            Ok(())
        } else {
            Err(NonDiscoverableCredentialRequestOptionsErr::PrfWithoutUserVerification)
        }
    })
}
/// [`CredentialUiMode`](https://www.w3.org/TR/credential-management-1/#enumdef-credentialuimode)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialUiMode {
    /// [`immediate`](https://www.w3.org/TR/credential-management-1/#dom-credentialuimode-immediate).
    Immediate,
}
/// The [`CredentialRequestOptions`](https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions)
/// to send to the client when authenticating a discoverable credential.
///
/// Upon saving the [`DiscoverableAuthenticationServerState`] returned from [`Self::start_ceremony`], one MUST send
/// [`DiscoverableAuthenticationClientState`] to the client ASAP. After receiving the newly created
/// [`DiscoverableAuthentication`], it is validated using [`DiscoverableAuthenticationServerState::verify`].
#[derive(Debug)]
pub struct DiscoverableCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second> {
    /// [`mediation`](https://www.w3.org/TR/credential-management-1/#dom-credentialrequestoptions-mediation).
    ///
    /// Note if this is [`CredentialMediationRequirement::Conditional`], user agents are instructed to not
    /// enforce any timeout; as result, one may want to set [`PublicKeyCredentialRequestOptions::timeout`] to
    /// [`NonZeroU32::MAX`].
    pub mediation: CredentialMediationRequirement,
    /// [`uiMode`](https://www.w3.org/TR/credential-management-1/#dom-credentialrequestoptions-uimode).
    pub ui_mode: Option<CredentialUiMode>,
    /// `public-key` [credential type](https://www.w3.org/TR/credential-management-1/#sctn-cred-type-registry).
    pub public_key: PublicKeyCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second>,
}
impl<'rp_id, 'prf_first, 'prf_second>
    DiscoverableCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second>
{
    /// Creates a `DiscoverableCredentialRequestOptions` containing [`CredentialMediationRequirement::default`] and
    /// [`PublicKeyCredentialRequestOptions::passkey`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{auth::DiscoverableCredentialRequestOptions, AsciiDomain, RpId, UserVerificationRequirement};
    /// assert!(matches!(
    ///     DiscoverableCredentialRequestOptions::passkey(&RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?)).public_key.user_verification,
    ///     UserVerificationRequirement::Required
    /// ));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub fn passkey<'a: 'rp_id>(rp_id: &'a RpId) -> Self {
        Self {
            mediation: CredentialMediationRequirement::default(),
            ui_mode: None,
            public_key: PublicKeyCredentialRequestOptions::passkey(rp_id),
        }
    }
    /// Begins the [authentication ceremony](https://www.w3.org/TR/webauthn-3/#authentication-ceremony) consuming
    /// `self`. Note that the expiration [`Instant`]/[`SystemTime`] is saved, so
    /// `DiscoverableAuthenticationClientState` MUST be sent ASAP. In order to complete authentication, the returned
    /// `DiscoverableAuthenticationServerState` MUST be saved so that it can later be used to verify the credential
    /// assertion with [`DiscoverableAuthenticationServerState::verify`].
    ///
    /// # Errors
    ///
    /// Errors iff `self` contains incompatible configuration.
    #[inline]
    pub fn start_ceremony(
        self,
    ) -> Result<
        (
            DiscoverableAuthenticationServerState,
            DiscoverableAuthenticationClientState<'rp_id, 'prf_first, 'prf_second>,
        ),
        DiscoverableCredentialRequestOptionsErr,
    > {
        let extensions = self.public_key.extensions.into();
        if validate_discoverable_options_helper(extensions, self.public_key.user_verification) {
            #[cfg(not(feature = "serializable_server_state"))]
            let res = Instant::now();
            #[cfg(feature = "serializable_server_state")]
            let res = SystemTime::now();
            res.checked_add(Duration::from_millis(
                NonZeroU64::from(self.public_key.timeout).get(),
            ))
            .ok_or(DiscoverableCredentialRequestOptionsErr::InvalidTimeout)
            .map(|expiration| {
                (
                    DiscoverableAuthenticationServerState(AuthenticationServerState {
                        challenge: SentChallenge(self.public_key.challenge.0),
                        user_verification: self.public_key.user_verification,
                        extensions,
                        expiration,
                    }),
                    DiscoverableAuthenticationClientState(self),
                )
            })
        } else {
            Err(DiscoverableCredentialRequestOptionsErr::PrfWithoutUserVerification)
        }
    }
    /// Same as [`Self::start_ceremony`] except the raw challenge is returned instead of
    /// [`DiscoverableAuthenticationClientState`].
    ///
    /// Note this is useful when one configures the authentication ceremony client-side and only needs the
    /// server-generated challenge. It's of course essential that `self` is configured exactly the same as
    /// how it is configured client-side. See
    /// [`challengeURL`](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-challengeURL) for more
    /// information.
    ///
    /// # Errors
    ///
    /// Read [`Self::start_ceremony`].
    #[inline]
    pub fn start_ceremony_challenge_only(
        self,
    ) -> Result<
        (DiscoverableAuthenticationServerState, [u8; 16]),
        DiscoverableCredentialRequestOptionsErr,
    > {
        self.start_ceremony()
            .map(|(server, client)| (server, client.0.public_key.challenge.into_array()))
    }
}
/// The [`CredentialRequestOptions`](https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions)
/// to send to the client when authenticating non-discoverable credentials.
///
/// Upon saving the [`NonDiscoverableAuthenticationServerState`] returned from [`Self::start_ceremony`], one MUST send
/// [`NonDiscoverableAuthenticationClientState`] to the client ASAP. After receiving the newly created
/// [`NonDiscoverableAuthentication`], it is validated using [`NonDiscoverableAuthenticationServerState::verify`].
#[derive(Debug)]
pub struct NonDiscoverableCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second> {
    /// [`mediation`](https://www.w3.org/TR/credential-management-1/#dom-credentialrequestoptions-mediation).
    pub mediation: CredentialMediationRequirement,
    /// [`PublicKeyCredentialRequestOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions).
    pub options: PublicKeyCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second>,
    /// [`allowCredentials`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials).
    pub allow_credentials: AllowedCredentials,
}
impl<'rp_id, 'prf_first, 'prf_second>
    NonDiscoverableCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second>
{
    /// Creates a `NonDiscoverableCredentialRequestOptions` containing
    /// [`CredentialMediationRequirement::default`],
    /// [`PublicKeyCredentialRequestOptions::second_factor`], and the passed [`AllowedCredentials`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// # use webauthn_rp::{bin::Decode, response::bin::DecodeAuthTransportsErr};
    /// # use webauthn_rp::{
    /// #     request::{
    /// #         auth::{AllowedCredentials, NonDiscoverableCredentialRequestOptions},
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
    /// let id = CredentialId::try_from(vec![0; 16].into_boxed_slice())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports = get_transports((&id).into())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert!(creds.push(PublicKeyCredentialDescriptor { id, transports }.into()));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(
    ///     NonDiscoverableCredentialRequestOptions::second_factor(&RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?), creds)
    ///         .allow_credentials
    ///         .len(),
    ///     1
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub fn second_factor<'a: 'rp_id>(
        rp_id: &'a RpId,
        allow_credentials: AllowedCredentials,
    ) -> Self {
        Self {
            mediation: CredentialMediationRequirement::default(),
            options: PublicKeyCredentialRequestOptions::second_factor(rp_id),
            allow_credentials,
        }
    }
    /// Begins the [authentication ceremony](https://www.w3.org/TR/webauthn-3/#authentication-ceremony) consuming
    /// `self`. Note that the expiration [`Instant`]/[`SystemTime`] is saved, so `NonDiscoverableAuthenticationClientState`
    /// MUST be sent ASAP. In order to complete authentication, the returned `NonDiscoverableAuthenticationServerState`
    /// MUST be saved so that it can later be used to verify the credential assertion with
    /// [`NonDiscoverableAuthenticationServerState::verify`].
    ///
    /// # Errors
    ///
    /// Errors iff `self` contains incompatible configuration.
    #[inline]
    pub fn start_ceremony(
        self,
    ) -> Result<
        (
            NonDiscoverableAuthenticationServerState,
            NonDiscoverableAuthenticationClientState<'rp_id, 'prf_first, 'prf_second>,
        ),
        NonDiscoverableCredentialRequestOptionsErr,
    > {
        if self.allow_credentials.is_empty() {
            Err(NonDiscoverableCredentialRequestOptionsErr::EmptyAllowedCredentials)
        } else if matches!(self.mediation, CredentialMediationRequirement::Conditional) {
            Err(NonDiscoverableCredentialRequestOptionsErr::ConditionalMediationRequested)
        } else {
            let extensions = self.options.extensions.into();
            if validate_discoverable_options_helper(extensions, self.options.user_verification) {
                let allow_credentials = Box::from(&self.allow_credentials);
                validate_non_discoverable_options_helper(
                    self.options.user_verification,
                    &allow_credentials,
                )
                .and_then(|()| {
                    #[cfg(not(feature = "serializable_server_state"))]
                    let res = Instant::now();
                    #[cfg(feature = "serializable_server_state")]
                    let res = SystemTime::now();
                    res.checked_add(Duration::from_millis(
                        NonZeroU64::from(self.options.timeout).get(),
                    ))
                    .ok_or(NonDiscoverableCredentialRequestOptionsErr::InvalidTimeout)
                    .map(|expiration| {
                        (
                            NonDiscoverableAuthenticationServerState {
                                state: AuthenticationServerState {
                                    challenge: SentChallenge(self.options.challenge.0),
                                    user_verification: self.options.user_verification,
                                    extensions,
                                    expiration,
                                },
                                allow_credentials,
                            },
                            NonDiscoverableAuthenticationClientState(self),
                        )
                    })
                })
            } else {
                Err(NonDiscoverableCredentialRequestOptionsErr::PrfWithoutUserVerification)
            }
        }
    }
}
/// The [`PublicKeyCredentialRequestOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptions)
/// to send to the client when authenticating a credential.
///
/// This does _not_ contain [`allowCredentials`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-allowcredentials).
#[derive(Debug)]
pub struct PublicKeyCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second> {
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
    /// [`userVerification`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-userverification).
    pub user_verification: UserVerificationRequirement,
    /// [`hints`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-hints).
    pub hints: Hints,
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-extensions).
    pub extensions: Extension<'prf_first, 'prf_second>,
}
impl<'rp_id> PublicKeyCredentialRequestOptions<'rp_id, '_, '_> {
    /// Creates a `PublicKeyCredentialRequestOptions` with [`Self::user_verification`] set to
    /// [`UserVerificationRequirement::Required`] and [`Self::timeout`] set to [`FIVE_MINUTES`].
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
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub fn passkey<'a: 'rp_id>(rp_id: &'a RpId) -> Self {
        Self {
            challenge: Challenge::new(),
            timeout: FIVE_MINUTES,
            rp_id,
            user_verification: UserVerificationRequirement::Required,
            hints: Hints::EMPTY,
            extensions: Extension::default(),
        }
    }
    /// Creates a `PublicKeyCredentialRequestOptions` with [`Self::user_verification`] set to
    /// [`UserVerificationRequirement::Discouraged`] and [`Self::timeout`] set to [`FIVE_MINUTES`].
    ///
    /// Note `rp_id` _must_ be the same as the [`PublicKeyCredentialCreationOptions::rp_id`] when the
    /// credentials were registered.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{auth::PublicKeyCredentialRequestOptions, AsciiDomain, RpId, UserVerificationRequirement};
    /// assert!(matches!(
    ///     PublicKeyCredentialRequestOptions::second_factor(&RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?)).user_verification,
    ///     UserVerificationRequirement::Discouraged
    /// ));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    #[must_use]
    pub fn second_factor<'a: 'rp_id>(rp_id: &'a RpId) -> Self {
        let mut opts = Self::passkey(rp_id);
        opts.user_verification = UserVerificationRequirement::Discouraged;
        opts
    }
}
/// Container of a [`DiscoverableCredentialRequestOptions`] that has been used to start the authentication ceremony.
/// This gets sent to the client ASAP.
#[derive(Debug)]
pub struct DiscoverableAuthenticationClientState<'rp_id, 'prf_first, 'prf_second>(
    DiscoverableCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second>,
);
impl<'rp_id, 'prf_first, 'prf_second>
    DiscoverableAuthenticationClientState<'rp_id, 'prf_first, 'prf_second>
{
    /// Returns the `DiscoverableCredentialRequestOptions` that was used to start an authentication ceremony.
    #[inline]
    #[must_use]
    pub const fn options(
        &self,
    ) -> &DiscoverableCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second> {
        &self.0
    }
}
/// Container of a [`NonDiscoverableCredentialRequestOptions`] that has been used to start the authentication
/// ceremony. This gets sent to the client ASAP.
#[derive(Debug)]
pub struct NonDiscoverableAuthenticationClientState<'rp_id, 'prf_first, 'prf_second>(
    NonDiscoverableCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second>,
);
impl<'rp_id, 'prf_first, 'prf_second>
    NonDiscoverableAuthenticationClientState<'rp_id, 'prf_first, 'prf_second>
{
    /// Returns the `NonDiscoverableCredentialRequestOptions` that was used to start an authentication ceremony.
    #[inline]
    #[must_use]
    pub const fn options(
        &self,
    ) -> &NonDiscoverableCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second> {
        &self.0
    }
}
/// The possible combinations of an [`AuthenticatedCredential`]'s [`StaticState`]'s
/// `extensions.hmac_secret` and `client_extension_results.prf`.
///
/// Note we ensure in `crate::verify_static_and_dynamic_state` that `hmac_secret` does not exist when
/// `prf` does not exist, `hmac_secret` does not exist or is `false` when `prf` is `false`, or
/// `hmac_secret` does not exist or is `true` when `prf` is `true`.
#[derive(Clone, Copy)]
enum CredPrf {
    /// No `prf` or `hmac_secret`.
    None,
    /// `prf.enabled` is `false` but there is no `hmac_secret`.
    FalseNoHmac,
    /// `prf.enabled` and `hmac_secret` are `false`.
    FalseFalseHmac,
    /// `prf.enabled` is `true` but there is no `hmac_secret`.
    TrueNoHmac,
    /// `prf.enabled` and `hmac_secret` are `true`.
    TrueTrueHmac,
}
/// `PrfInput` and `PrfInputOwned` without the actual data sent to reduce memory usage when storing
/// [`DiscoverableAuthenticationServerState`] in an in-memory collection.
#[derive(Clone, Copy, Debug)]
enum ServerPrfInfo {
    /// No `PrfInput`.
    None,
    /// `PrfInput::second` was `None`.
    One(ExtensionReq),
    /// `PrfInput::second` was `Some`.
    Two(ExtensionReq),
}
impl ServerPrfInfo {
    /// Validates `val` based on the passed arguments.
    ///
    /// It's not possible to request the PRF extension without sending `UserVerificationRequirement::Required`;
    /// thus `user_verified` will always be `true` when sending PRF; otherwise ceremony validation will error.
    /// However when we _don't_ send the PRF extension _and_ we don't error on an unsolicited response, it's
    /// possible to receive an `HmacSecret` without the user having been verified; thus we only ensure
    /// `user_verified` is true when we don't error on unsolicted responses _and_ we didn't send the PRF extension.
    const fn validate(
        self,
        user_verified: bool,
        cred_prf: CredPrf,
        hmac: HmacSecret,
        err_unsolicited: bool,
    ) -> Result<(), ExtensionErr> {
        match hmac {
            HmacSecret::None => match self {
                Self::None => Ok(()),
                Self::One(req) | Self::Two(req) => {
                    if matches!(req, ExtensionReq::Allow)
                        || !matches!(cred_prf, CredPrf::TrueTrueHmac)
                    {
                        Ok(())
                    } else {
                        Err(ExtensionErr::MissingHmacSecret)
                    }
                }
            },
            HmacSecret::One => match self {
                Self::None => {
                    if err_unsolicited {
                        Err(ExtensionErr::ForbiddenHmacSecret)
                    } else if matches!(cred_prf, CredPrf::None | CredPrf::TrueTrueHmac) {
                        if user_verified {
                            Ok(())
                        } else {
                            Err(ExtensionErr::UserNotVerifiedHmacSecret)
                        }
                    } else {
                        Err(ExtensionErr::HmacSecretForNonHmacSecretCredential)
                    }
                }
                Self::One(_) => {
                    if matches!(cred_prf, CredPrf::None | CredPrf::TrueTrueHmac) {
                        Ok(())
                    } else {
                        Err(ExtensionErr::HmacSecretForNonHmacSecretCredential)
                    }
                }
                Self::Two(_) => Err(ExtensionErr::InvalidHmacSecretValue(
                    OneOrTwo::Two,
                    OneOrTwo::One,
                )),
            },
            HmacSecret::Two => match self {
                Self::None => {
                    if err_unsolicited {
                        Err(ExtensionErr::ForbiddenHmacSecret)
                    } else if matches!(cred_prf, CredPrf::None | CredPrf::TrueTrueHmac) {
                        if user_verified {
                            Ok(())
                        } else {
                            Err(ExtensionErr::UserNotVerifiedHmacSecret)
                        }
                    } else {
                        Err(ExtensionErr::HmacSecretForNonHmacSecretCredential)
                    }
                }
                Self::One(_) => Err(ExtensionErr::InvalidHmacSecretValue(
                    OneOrTwo::One,
                    OneOrTwo::Two,
                )),
                Self::Two(_) => {
                    if matches!(cred_prf, CredPrf::None | CredPrf::TrueTrueHmac) {
                        Ok(())
                    } else {
                        Err(ExtensionErr::HmacSecretForNonHmacSecretCredential)
                    }
                }
            },
        }
    }
}
#[cfg(test)]
impl PartialEq for ServerPrfInfo {
    fn eq(&self, other: &Self) -> bool {
        match *self {
            Self::None => matches!(*other, Self::None),
            Self::One(req) => matches!(*other, Self::One(req2) if req == req2),
            Self::Two(req) => matches!(*other, Self::Two(req2) if req == req2),
        }
    }
}
impl From<Option<(PrfInput<'_, '_>, ExtensionReq)>> for ServerPrfInfo {
    fn from(value: Option<(PrfInput<'_, '_>, ExtensionReq)>) -> Self {
        value.map_or(Self::None, |val| {
            val.0
                .second
                .map_or_else(|| Self::One(val.1), |_| Self::Two(val.1))
        })
    }
}
impl From<&PrfInputOwned> for ServerPrfInfo {
    fn from(value: &PrfInputOwned) -> Self {
        value
            .second
            .as_ref()
            .map_or_else(|| Self::One(value.ext_req), |_| Self::Two(value.ext_req))
    }
}
/// `Extension` without the actual data sent to reduce memory usage when storing [`AuthenticationServerState`]
/// in an in-memory collection.
#[derive(Clone, Copy, Debug)]
struct ServerExtensionInfo {
    /// `Extension::prf`.
    prf: ServerPrfInfo,
}
impl From<Extension<'_, '_>> for ServerExtensionInfo {
    fn from(value: Extension<'_, '_>) -> Self {
        Self {
            prf: value.prf.into(),
        }
    }
}
#[cfg(test)]
impl PartialEq for ServerExtensionInfo {
    fn eq(&self, other: &Self) -> bool {
        self.prf == other.prf
    }
}
/// `CredentialSpecificExtension` without the actual data sent to reduce memory usage when storing [`AuthenticationServerState`]
/// in an in-memory collection.
#[derive(Clone, Copy, Debug)]
struct ServerCredSpecificExtensionInfo {
    /// `CredentialSpecificExtension::prf`.
    prf: ServerPrfInfo,
}
#[cfg(test)]
impl PartialEq for ServerCredSpecificExtensionInfo {
    fn eq(&self, other: &Self) -> bool {
        self.prf == other.prf
    }
}
impl From<&CredentialSpecificExtension> for ServerCredSpecificExtensionInfo {
    fn from(value: &CredentialSpecificExtension) -> Self {
        Self {
            prf: value
                .prf
                .as_ref()
                .map_or(ServerPrfInfo::None, ServerPrfInfo::from),
        }
    }
}
impl ServerExtensionInfo {
    /// Validates the extensions.
    ///
    /// Note that this MUST only be called internally by `auth::validate_extensions`.
    const fn validate_extensions(
        self,
        user_verified: bool,
        auth_ext: AuthenticatorExtensionOutput,
        error_unsolicited: bool,
        cred_prf: CredPrf,
    ) -> Result<(), ExtensionErr> {
        ServerPrfInfo::validate(
            self.prf,
            user_verified,
            cred_prf,
            auth_ext.hmac_secret,
            error_unsolicited,
        )
    }
}
/// Validates the extensions.
fn validate_extensions(
    ext: ServerExtensionInfo,
    user_verified: bool,
    cred_ext: Option<ServerCredSpecificExtensionInfo>,
    auth_ext: AuthenticatorExtensionOutput,
    error_unsolicited: bool,
    cred_prf: CredPrf,
) -> Result<(), ExtensionErr> {
    cred_ext.map_or_else(
        || {
            // No credental-specific extensions, so we can simply focus on `ext`.
            ext.validate_extensions(user_verified, auth_ext, error_unsolicited, cred_prf)
        },
        |c_ext| {
            // Must carefully process each extension based on overlap and which gets priority over the other.
            if matches!(c_ext.prf, ServerPrfInfo::None) {
                ext.prf.validate(
                    user_verified,
                    cred_prf,
                    auth_ext.hmac_secret,
                    error_unsolicited,
                )
            } else {
                c_ext.prf.validate(
                    user_verified,
                    cred_prf,
                    auth_ext.hmac_secret,
                    error_unsolicited,
                )
            }
        },
    )
}
/// [`AllowedCredential`] with less data to reduce memory usage when storing [`AuthenticationServerState`]
/// in an in-memory collection.
#[derive(Debug)]
struct CredInfo {
    /// The Credential ID.
    id: CredentialId<Box<[u8]>>,
    /// Any credential-specific extensions.
    ext: ServerCredSpecificExtensionInfo,
}
#[cfg(test)]
impl PartialEq for CredInfo {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.ext == other.ext
    }
}
/// Controls how to handle a change in [`DynamicState::authenticator_attachment`].
///
/// Note when `DynamicState::authenticator_attachment` is [`AuthenticatorAttachment::None`], then it will
/// be updated regardless. Similarly when [`Authentication::authenticator_attachment`] is
/// `AuthenticatorAttachment::None`, it will never update `DynamicState::authenticator_attachment`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
/// Backup state requirements for the credential.
///
/// Note the backup eligibility of a credential is not allowed to change. This is only used to allow one to
/// require the existence or lack of existence of a backup.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BackupStateReq {
    /// No requirements on the backup state.
    ///
    /// The backup eligibility of the credential must be the same as required by the spec, but the existence
    /// of a backup doesn't matter.
    #[default]
    None,
    /// Credential must be backed up.
    Exists,
    /// Credential must not be backed up.
    DoesntExist,
}
/// Additional verification options to perform in [`DiscoverableAuthenticationServerState::verify`] and
/// [`NonDiscoverableAuthenticationServerState::verify`].
#[derive(Clone, Copy, Debug)]
pub struct AuthenticationVerificationOptions<'origins, 'top_origins, O, T> {
    /// Origins to use for [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin).
    ///
    /// When this is empty, the origin that will be used will be based on the [`RpId`] passed to
    /// [`DiscoverableAuthenticationServerState::verify`] or [`NonDiscoverableAuthenticationServerState::verify`].
    /// If [`RpId::Domain`] or [`RpId::StaticDomain`], then the [`DomainOrigin`] returned from passing
    /// [`AsciiDomain::as_ref`] and [`AsciiDomainStatic::as_str`] to [`DomainOrigin::new`] respectively will be
    /// used; otherwise the [`Url`] in [`RpId::Url`] will be used.
    pub allowed_origins: &'origins [O],
    /// [Top-level origins](https://html.spec.whatwg.org/multipage/webappapis.html#concept-environment-top-level-origin)
    /// to use for [origin validation](https://www.w3.org/TR/webauthn-3/#sctn-validating-origin).
    ///
    /// When this is `Some`, [`CollectedClientData::cross_origin`] is allowed to be `true`. When the contained
    /// `slice` is empty, [`CollectedClientData::top_origin`] must be `None`. When this is `None`,
    /// `CollectedClientData::cross_origin` must be `false` and `CollectedClientData::top_origin` must be `None`.
    pub allowed_top_origins: Option<&'top_origins [T]>,
    /// The required [`Backup`] state of the credential.
    pub backup_state_requirement: BackupStateReq,
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
    #[cfg(feature = "serde_relaxed")]
    pub client_data_json_relaxed: bool,
}
impl<O, T> AuthenticationVerificationOptions<'_, '_, O, T> {
    /// Returns `Self` such that [`Self::allowed_origins`] is empty, [`Self::allowed_top_origins`] is `None`,
    /// [`Self::backup_state_requirement`] is [`BackupStateReq::None`], [`Self::error_on_unsolicited_extensions`] is
    /// `true`, [`Self::auth_attachment_enforcement`] is [`AuthenticatorAttachmentEnforcement::default`],
    /// [`Self::update_uv`] is `false`, [`Self::sig_counter_enforcement`] is
    /// [`SignatureCounterEnforcement::default`], and [`Self::client_data_json_relaxed`] is `true`.
    ///
    /// Note `O` and `T` should implement `PartialEq<Origin<'_>>` (e.g., `&str`).
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allowed_origins: [].as_slice(),
            allowed_top_origins: None,
            backup_state_requirement: BackupStateReq::None,
            error_on_unsolicited_extensions: true,
            auth_attachment_enforcement: AuthenticatorAttachmentEnforcement::Ignore(false),
            update_uv: false,
            sig_counter_enforcement: SignatureCounterEnforcement::Fail,
            #[cfg(feature = "serde_relaxed")]
            client_data_json_relaxed: true,
        }
    }
}
impl<O, T> Default for AuthenticationVerificationOptions<'_, '_, O, T> {
    /// Same as [`Self::new`].
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
// This is essentially the `DiscoverableCredentialRequestOptions` used to create it; however to reduce
// memory usage, we remove all unnecessary data making an instance of this 48 bytes in size
// `x86_64-unknown-linux-gnu` platforms.
//
/// State needed to be saved when beginning the authentication ceremony.
///
/// Saves the necessary information associated with the [`DiscoverableCredentialRequestOptions`] used to create it
/// via [`DiscoverableCredentialRequestOptions::start_ceremony`] so that authentication of a credential can be
/// performed with [`Self::verify`].
///
/// `DiscoverableAuthenticationServerState` implements [`Borrow`] of [`SentChallenge`]; thus to obtain the correct
/// `DiscoverableAuthenticationServerState` associated with a [`DiscoverableAuthentication`], one should use its
/// corresponding [`DiscoverableAuthentication::challenge`].
#[derive(Debug)]
pub struct DiscoverableAuthenticationServerState(AuthenticationServerState);
impl DiscoverableAuthenticationServerState {
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
        const USER_LEN: usize,
        O: PartialEq<Origin<'a>>,
        T: PartialEq<Origin<'a>>,
        MlDsa87Key: AsRef<[u8]>,
        MlDsa65Key: AsRef<[u8]>,
        MlDsa44Key: AsRef<[u8]>,
        EdKey: AsRef<[u8]>,
        P256Key: AsRef<[u8]>,
        P384Key: AsRef<[u8]>,
        RsaKey: AsRef<[u8]>,
    >(
        self,
        rp_id: &RpId,
        response: &'a DiscoverableAuthentication<USER_LEN>,
        cred: &mut AuthenticatedCredential<
            '_,
            '_,
            USER_LEN,
            CompressedPubKey<MlDsa87Key, MlDsa65Key, MlDsa44Key, EdKey, P256Key, P384Key, RsaKey>,
        >,
        options: &AuthenticationVerificationOptions<'_, '_, O, T>,
    ) -> Result<bool, AuthCeremonyErr> {
        // Step 6 item 2.
        if cred.user_id == response.response.user_handle() {
            // Step 6 item 2.
            if cred.id.as_ref() == response.raw_id.as_ref() {
                self.0.verify(rp_id, response, cred, options, None)
            } else {
                Err(AuthCeremonyErr::CredentialIdMismatch)
            }
        } else {
            Err(AuthCeremonyErr::UserHandleMismatch)
        }
    }
    #[cfg(all(test, feature = "custom", feature = "serializable_server_state"))]
    fn is_eq(&self, other: &Self) -> bool {
        self.0.is_eq(&other.0)
    }
}
// This is essentially the `NonDiscoverableCredentialRequestOptions` used to create it; however to reduce
// memory usage, we remove all unnecessary data making an instance of this as small as 64 bytes in size on
// `x86_64-unknown-linux-gnu` platforms. This does not include the size of each `CredInfo` which should exist
// elsewhere on the heap but obviously contributes memory overall.
/// State needed to be saved when beginning the authentication ceremony.
///
/// Saves the necessary information associated with the [`NonDiscoverableCredentialRequestOptions`] used to create
/// it via [`NonDiscoverableCredentialRequestOptions::start_ceremony`] so that authentication of a credential can be
/// performed with [`Self::verify`].
///
/// `NonDiscoverableAuthenticationServerState` implements [`Borrow`] of [`SentChallenge`]; thus to obtain the
/// correct `NonDiscoverableAuthenticationServerState` associated with a [`NonDiscoverableAuthentication`], one
/// should use its corresponding [`NonDiscoverableAuthentication::challenge`].
#[derive(Debug)]
pub struct NonDiscoverableAuthenticationServerState {
    /// Most server state.
    state: AuthenticationServerState,
    /// The set of credentials that are allowed.
    allow_credentials: Box<[CredInfo]>,
}
impl NonDiscoverableAuthenticationServerState {
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
        const USER_LEN: usize,
        O: PartialEq<Origin<'a>>,
        T: PartialEq<Origin<'a>>,
        MlDsa87Key: AsRef<[u8]>,
        MlDsa65Key: AsRef<[u8]>,
        MlDsa44Key: AsRef<[u8]>,
        EdKey: AsRef<[u8]>,
        P256Key: AsRef<[u8]>,
        P384Key: AsRef<[u8]>,
        RsaKey: AsRef<[u8]>,
    >(
        self,
        rp_id: &RpId,
        response: &'a NonDiscoverableAuthentication<USER_LEN>,
        cred: &mut AuthenticatedCredential<
            '_,
            '_,
            USER_LEN,
            CompressedPubKey<MlDsa87Key, MlDsa65Key, MlDsa44Key, EdKey, P256Key, P384Key, RsaKey>,
        >,
        options: &AuthenticationVerificationOptions<'_, '_, O, T>,
    ) -> Result<bool, AuthCeremonyErr> {
        response
            .response
            .user_handle()
            .as_ref()
            .map_or(Ok(()), |user| {
                // Step 6 item 1.
                if *user == cred.user_id() {
                    Ok(())
                } else {
                    Err(AuthCeremonyErr::UserHandleMismatch)
                }
            })
            .and_then(|()| {
                self.allow_credentials
                    .iter()
                    // Step 5.
                    .find(|c| c.id == response.raw_id)
                    .ok_or(AuthCeremonyErr::NoMatchingAllowedCredential)
                    .and_then(|c| {
                        // Step 6 item 1.
                        if c.id.as_ref() == cred.id.as_ref() {
                            self.state
                                .verify(rp_id, response, cred, options, Some(c.ext))
                        } else {
                            Err(AuthCeremonyErr::CredentialIdMismatch)
                        }
                    })
            })
    }
    #[cfg(all(test, feature = "custom", feature = "serializable_server_state"))]
    fn is_eq(&self, other: &Self) -> bool {
        self.state.is_eq(&other.state) && self.allow_credentials == other.allow_credentials
    }
}
// This is essentially the `PublicKeyCredentialRequestOptions` used to create it; however to reduce
// memory usage, we remove all unnecessary data making an instance of this 48 bytes in size on
// `x86_64-unknown-linux-gnu` platforms.
/// Shared state used by [`DiscoverableAuthenticationServerState`] and [`NonDiscoverableAuthenticationServerState`].
#[derive(Debug)]
struct AuthenticationServerState {
    // This is a `SentChallenge` since we need `AuthenticationServerState` to be fetchable after receiving the
    // response from the client. This response must obviously be constructable; thus its challenge is a
    // `SentChallenge`.
    //
    // This must never be mutated since we want to ensure it is actually a `Challenge` (which
    // can only be constructed via `Challenge::new`). This is guaranteed to be true iff
    // `serializable_server_state` is not enabled.
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-challenge).
    challenge: SentChallenge,
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
    fn verify<
        'a,
        const USER_LEN: usize,
        const DISCOVERABLE: bool,
        O: PartialEq<Origin<'a>>,
        T: PartialEq<Origin<'a>>,
        MlDsa87Key: AsRef<[u8]>,
        MlDsa65Key: AsRef<[u8]>,
        MlDsa44Key: AsRef<[u8]>,
        EdKey: AsRef<[u8]>,
        P256Key: AsRef<[u8]>,
        P384Key: AsRef<[u8]>,
        RsaKey: AsRef<[u8]>,
    >(
        self,
        rp_id: &RpId,
        response: &'a Authentication<USER_LEN, DISCOVERABLE>,
        cred: &mut AuthenticatedCredential<
            '_,
            '_,
            USER_LEN,
            CompressedPubKey<MlDsa87Key, MlDsa65Key, MlDsa44Key, EdKey, P256Key, P384Key, RsaKey>,
        >,
        options: &AuthenticationVerificationOptions<'_, '_, O, T>,
        cred_ext: Option<ServerCredSpecificExtensionInfo>,
    ) -> Result<bool, AuthCeremonyErr> {
        // [Authentication ceremony](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)
        // is handled by:
        //
        // 1. Calling code.
        // 2. Client code and the construction of `resp` (hopefully via [`Authentication::deserialize`]).
        // 3. Client code and the construction of `resp` (hopefully via [`AuthenticatorAssertion::deserialize`]).
        // 4. Client code and the construction of `resp` (hopefully via [`ClientExtensionsOutputs::deserialize`]).
        // 5. [`NonDiscoverableAuthenticationServerState::verify`].
        // 6. [`DiscoverableAuthenticationServerState::verify`] and [`NonDiscoverableAuthenticationServerState::verify`].
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

        // Steps 8–21.
        self.partial_validate(
            rp_id,
            response,
            (&cred.static_state.credential_public_key).into(),
            &CeremonyOptions {
                allowed_origins: options.allowed_origins,
                allowed_top_origins: options.allowed_top_origins,
                backup_requirement: if cred.dynamic_state.backup == Backup::NotEligible {
                    BackupReq::NotEligible
                } else {
                    match options.backup_state_requirement {
                        BackupStateReq::None => BackupReq::Eligible,
                        BackupStateReq::Exists => BackupReq::Exists,
                        BackupStateReq::DoesntExist => BackupReq::EligibleNotExists,
                    }
                },
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
                    let flags = auth_data.flags();
                    // Step 23.
                    validate_extensions(
                        self.extensions,
                        flags.user_verified,
                        cred_ext,
                        auth_data.extensions(),
                        options.error_on_unsolicited_extensions,
                        cred.static_state.client_extension_results.prf.map_or(
                            CredPrf::None,
                            |prf| {
                                if prf.enabled {
                                    cred.static_state
                                        .extensions
                                        .hmac_secret
                                        .map_or(CredPrf::TrueNoHmac, |_| CredPrf::TrueTrueHmac)
                                } else {
                                    cred.static_state
                                        .extensions
                                        .hmac_secret
                                        .map_or(CredPrf::FalseNoHmac, |_| CredPrf::FalseFalseHmac)
                                }
                            },
                        ),
                    )
                    .map_err(AuthCeremonyErr::Extension)
                    .and_then(|()| {
                        // Step 22.
                        options
                            .sig_counter_enforcement
                            .validate(cred.dynamic_state.sign_count, auth_data.sign_count())
                            .and_then(|sig_counter| {
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
                                if flags.user_verified {
                                    Ok(())
                                } else {
                                    match cred.static_state.extensions.cred_protect {
                                        CredentialProtectionPolicy::None | CredentialProtectionPolicy::UserVerificationOptional => Ok(()),
                                        CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList => {
                                            if DISCOVERABLE {
                                                Err(AuthCeremonyErr::DiscoverableCredProtectCredentialIdList)
                                            } else {
                                                Ok(())
                                            }
                                        }
                                        CredentialProtectionPolicy::UserVerificationRequired => {
                                            Err(AuthCeremonyErr::UserNotVerifiedCredProtectRequired)
                                        }
                                    }
                                }.inspect_err(|_| {
                                    cred.dynamic_state = prev_dyn_state;
                                }).map(|()| {
                                    prev_dyn_state != cred.dynamic_state
                                })
                            })
                    })
                })
        })
    }
    #[cfg(all(test, feature = "custom", feature = "serializable_server_state"))]
    fn is_eq(&self, other: &Self) -> bool {
        self.challenge == other.challenge
            && self.user_verification == other.user_verification
            && self.extensions == other.extensions
            && self.expiration == other.expiration
    }
}
impl TimedCeremony for AuthenticationServerState {
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
}
impl TimedCeremony for DiscoverableAuthenticationServerState {
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    #[inline]
    fn expiration(&self) -> Instant {
        self.0.expiration()
    }
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    #[inline]
    fn expiration(&self) -> SystemTime {
        self.0.expiration()
    }
}
impl TimedCeremony for NonDiscoverableAuthenticationServerState {
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    #[inline]
    fn expiration(&self) -> Instant {
        self.state.expiration()
    }
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    #[inline]
    fn expiration(&self) -> SystemTime {
        self.state.expiration()
    }
}
impl<const USER_LEN: usize, const DISCOVERABLE: bool> Ceremony<USER_LEN, DISCOVERABLE>
    for AuthenticationServerState
{
    type R = Authentication<USER_LEN, DISCOVERABLE>;
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
impl Borrow<SentChallenge> for DiscoverableAuthenticationServerState {
    #[inline]
    fn borrow(&self) -> &SentChallenge {
        self.0.borrow()
    }
}
impl PartialEq for DiscoverableAuthenticationServerState {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl PartialEq<&Self> for DiscoverableAuthenticationServerState {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        self.0 == other.0
    }
}
impl PartialEq<DiscoverableAuthenticationServerState> for &DiscoverableAuthenticationServerState {
    #[inline]
    fn eq(&self, other: &DiscoverableAuthenticationServerState) -> bool {
        self.0 == other.0
    }
}
impl Eq for DiscoverableAuthenticationServerState {}
impl Hash for DiscoverableAuthenticationServerState {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl PartialOrd for DiscoverableAuthenticationServerState {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for DiscoverableAuthenticationServerState {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
impl Borrow<SentChallenge> for NonDiscoverableAuthenticationServerState {
    #[inline]
    fn borrow(&self) -> &SentChallenge {
        self.state.borrow()
    }
}
impl PartialEq for NonDiscoverableAuthenticationServerState {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}
impl PartialEq<&Self> for NonDiscoverableAuthenticationServerState {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        self.state == other.state
    }
}
impl PartialEq<NonDiscoverableAuthenticationServerState>
    for &NonDiscoverableAuthenticationServerState
{
    #[inline]
    fn eq(&self, other: &NonDiscoverableAuthenticationServerState) -> bool {
        self.state == other.state
    }
}
impl Eq for NonDiscoverableAuthenticationServerState {}
impl Hash for NonDiscoverableAuthenticationServerState {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.state.hash(state);
    }
}
impl PartialOrd for NonDiscoverableAuthenticationServerState {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for NonDiscoverableAuthenticationServerState {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.state.cmp(&other.state)
    }
}
