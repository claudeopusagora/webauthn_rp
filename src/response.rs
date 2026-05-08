extern crate alloc;
#[cfg(test)]
mod tests;
use crate::{
    request::{register::{PublicKeyCredentialUserEntity, UserHandle}, Challenge, RpId, Url},
    response::{
        auth::error::{
            AuthCeremonyErr, AuthenticatorDataErr as AuthAuthDataErr,
            AuthenticatorExtensionOutputErr as AuthAuthExtErr,
        },
        error::{CollectedClientDataErr, CredentialIdErr},
        register::error::{AttestationObjectErr, AttestedCredentialDataErr, AuthenticatorDataErr as RegAuthDataErr, AuthenticatorExtensionOutputErr as RegAuthExtErr, PubKeyErr, RegCeremonyErr},
    },
};
use alloc::borrow::Cow;
use core::{
    borrow::Borrow,
    cmp::Ordering,
    convert::Infallible,
    fmt::{self, Display, Formatter},
    hash::{Hash, Hasher},
    str,
};
use rsa::sha2::{digest::OutputSizeUser as _, Sha256};
#[cfg(feature = "serde_relaxed")]
use ser_relaxed::SerdeJsonErr;
/// Contains functionality for completing the
/// [authentication ceremony](https://www.w3.org/TR/webauthn-3/#authentication-ceremony).
///
/// # Examples
///
/// ```no_run
/// # use core::convert;
/// # use webauthn_rp::{
/// #     hash::hash_set::{InsertRemoveExpired, MaxLenHashSet},
/// #     request::{auth::{error::DiscoverableCredentialRequestOptionsErr, DiscoverableAuthenticationClientState, DiscoverableCredentialRequestOptions, AuthenticationVerificationOptions}, register::{BackupReq, UserHandle, USER_HANDLE_MAX_LEN, UserHandle64}, RpId},
/// #     response::{auth::{error::AuthCeremonyErr, DiscoverableAuthentication64}, error::CollectedClientDataErr, register::{AuthenticatorExtensionOutputStaticState, ClientExtensionsOutputsStaticState, CredentialProtectionPolicy, DynamicState, Ed25519PubKey, CompressedPubKeyOwned, StaticState}, AuthenticatorAttachment, Backup, CollectedClientData, CredentialId},
/// #     AuthenticatedCredential, CredentialErr
/// # };
/// # #[derive(Debug)]
/// # enum E {
/// #     CollectedClientData(CollectedClientDataErr),
/// #     DiscoverableCredentialRequestOptions(DiscoverableCredentialRequestOptionsErr),
/// #     SerdeJson(serde_json::Error),
/// #     MissingUserHandle,
/// #     MissingCeremony,
/// #     UnknownCredential,
/// #     Credential(CredentialErr),
/// #     AuthCeremony(AuthCeremonyErr),
/// # }
/// # impl From<CollectedClientDataErr> for E {
/// #     fn from(value: CollectedClientDataErr) -> Self {
/// #         Self::CollectedClientData(value)
/// #     }
/// # }
/// # impl From<DiscoverableCredentialRequestOptionsErr> for E {
/// #     fn from(value: DiscoverableCredentialRequestOptionsErr) -> Self {
/// #         Self::DiscoverableCredentialRequestOptions(value)
/// #     }
/// # }
/// # impl From<serde_json::Error> for E {
/// #     fn from(value: serde_json::Error) -> Self {
/// #         Self::SerdeJson(value)
/// #     }
/// # }
/// # impl From<CredentialErr> for E {
/// #     fn from(value: CredentialErr) -> Self {
/// #         Self::Credential(value)
/// #     }
/// # }
/// # impl From<AuthCeremonyErr> for E {
/// #     fn from(value: AuthCeremonyErr) -> Self {
/// #         Self::AuthCeremony(value)
/// #     }
/// # }
/// const RP_ID: &RpId = &RpId::from_static_domain("example.com").unwrap();
/// let mut ceremonies = MaxLenHashSet::new(128);
/// let (server, client) = DiscoverableCredentialRequestOptions::passkey(RP_ID).start_ceremony()?;
/// assert_eq!(ceremonies.insert_remove_all_expired(server), InsertRemoveExpired::Success);
/// # #[cfg(feature = "serde")]
/// let authentication = serde_json::from_str::<DiscoverableAuthentication64>(get_authentication_json(client).as_str())?;
/// # #[cfg(feature = "serde")]
/// let user_handle = authentication.response().user_handle();
/// # #[cfg(feature = "serde")]
/// let (static_state, dynamic_state) = get_credential(authentication.raw_id(), &user_handle).ok_or(E::UnknownCredential)?;
/// # #[cfg(all(feature = "custom", feature = "serde"))]
/// let mut cred = AuthenticatedCredential::new(authentication.raw_id(), &user_handle, static_state, dynamic_state)?;
/// # #[cfg(all(feature = "custom", feature = "serde"))]
/// if ceremonies.take(&authentication.challenge()?).ok_or(E::MissingCeremony)?.verify(RP_ID, &authentication, &mut cred, &AuthenticationVerificationOptions::<&str, &str>::default())? {
///     update_cred(authentication.raw_id(), cred.dynamic_state());
/// }
/// /// Send `DiscoverableAuthenticationClientState` and receive `DiscoverableAuthentication64` JSON from client.
/// # #[cfg(feature = "serde")]
/// fn get_authentication_json(client: DiscoverableAuthenticationClientState<'_, '_, '_>) -> String {
///     // ⋮
/// #     let client_data_json = base64url_nopad::encode(serde_json::json!({
/// #         "type": "webauthn.get",
/// #         "challenge": client.options().public_key.challenge,
/// #         "origin": format!("https://{}", client.options().public_key.rp_id.as_ref()),
/// #         "crossOrigin": false
/// #     }).to_string().as_bytes());
/// #     serde_json::json!({
/// #         "id": "AAAAAAAAAAAAAAAAAAAAAA",
/// #         "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
/// #         "response": {
/// #             "clientDataJSON": client_data_json,
/// #             "authenticatorData": "",
/// #             "signature": "",
/// #             "userHandle": "AA"
/// #         },
/// #         "clientExtensionResults": {},
/// #         "type": "public-key"
/// #     }).to_string()
/// }
/// /// Gets the `AuthenticatedCredential` parts associated with `id` and `user_handle` from the database.
/// fn get_credential(id: CredentialId<&[u8]>, user_handle: &UserHandle64) -> Option<(StaticState<CompressedPubKeyOwned>, DynamicState)> {
///     // ⋮
/// #     Some((StaticState { credential_public_key: CompressedPubKeyOwned::Ed25519(Ed25519PubKey::from([0; 32])), extensions: AuthenticatorExtensionOutputStaticState { cred_protect: CredentialProtectionPolicy::UserVerificationRequired, hmac_secret: None, }, client_extension_results: ClientExtensionsOutputsStaticState { prf: None, }, }, DynamicState { user_verified: true, backup: Backup::NotEligible, sign_count: 1, authenticator_attachment: AuthenticatorAttachment::None }))
/// }
/// /// Updates the current `DynamicState` associated with `id` in the database to
/// /// `dyn_state`.
/// fn update_cred(id: CredentialId<&[u8]>, dyn_state: DynamicState) {
///     // ⋮
/// }
/// # Ok::<_, E>(())
/// ```
pub mod auth;
/// Contains functionality to (de)serialize data to a data store.
#[cfg(feature = "bin")]
pub mod bin;
/// Contains constants useful for
/// [CTAP2 canonical CBOR encoding form](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#ctap2-canonical-cbor-encoding-form).
mod cbor;
/// Contains functionality that needs to be accessible when `bin` or `serde` are not enabled.
#[cfg(feature = "custom")]
pub mod custom;
/// Contains error types.
pub mod error;
/// Contains functionality for completing the
/// [registration ceremony](https://www.w3.org/TR/webauthn-3/#registration-ceremony).
///
/// # Examples
///
/// ```no_run
/// # use core::convert;
/// # use webauthn_rp::{
/// #     hash::hash_set::{InsertRemoveExpired, MaxLenHashSet},
/// #     request::{register::{error::CreationOptionsErr, CredentialCreationOptions, PublicKeyCredentialUserEntity, RegistrationClientState, UserHandle, UserHandle64, USER_HANDLE_MAX_LEN, RegistrationVerificationOptions}, PublicKeyCredentialDescriptor, RpId},
/// #     response::{register::{error::RegCeremonyErr, Registration}, error::CollectedClientDataErr, CollectedClientData},
/// #     RegisteredCredential
/// # };
/// # #[derive(Debug)]
/// # enum E {
/// #     CollectedClientData(CollectedClientDataErr),
/// #     CreationOptions(CreationOptionsErr),
/// #     SerdeJson(serde_json::Error),
/// #     MissingCeremony,
/// #     RegCeremony(RegCeremonyErr),
/// # }
/// # impl From<CollectedClientDataErr> for E {
/// #     fn from(value: CollectedClientDataErr) -> Self {
/// #         Self::CollectedClientData(value)
/// #     }
/// # }
/// # impl From<CreationOptionsErr> for E {
/// #     fn from(value: CreationOptionsErr) -> Self {
/// #         Self::CreationOptions(value)
/// #     }
/// # }
/// # impl From<serde_json::Error> for E {
/// #     fn from(value: serde_json::Error) -> Self {
/// #         Self::SerdeJson(value)
/// #     }
/// # }
/// # impl From<RegCeremonyErr> for E {
/// #     fn from(value: RegCeremonyErr) -> Self {
/// #         Self::RegCeremony(value)
/// #     }
/// # }
/// const RP_ID: &RpId = &RpId::from_static_domain("example.com").unwrap();
/// # #[cfg(feature = "custom")]
/// let mut ceremonies = MaxLenHashSet::new(128);
/// # #[cfg(feature = "custom")]
/// let user_handle = get_user_handle();
/// # #[cfg(feature = "custom")]
/// let user = get_user_entity(&user_handle);
/// # #[cfg(feature = "custom")]
/// let creds = get_registered_credentials(user_handle);
/// # #[cfg(feature = "custom")]
/// let (server, client) = CredentialCreationOptions::passkey(RP_ID, user, creds).start_ceremony()?;
/// # #[cfg(feature = "custom")]
/// assert_eq!(ceremonies.insert_remove_all_expired(server), InsertRemoveExpired::Success);
/// # #[cfg(all(feature = "serde_relaxed", feature = "custom"))]
/// let registration = serde_json::from_str::<Registration>(get_registration_json(client).as_str())?;
/// let ver_opts = RegistrationVerificationOptions::<&str, &str>::default();
/// # #[cfg(all(feature = "custom", feature = "serde_relaxed"))]
/// insert_cred(ceremonies.take(&registration.challenge()?).ok_or(E::MissingCeremony)?.verify(RP_ID, &registration, &ver_opts)?);
/// /// Extract `UserHandle` from session cookie if this is not the first credential registered.
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
/// fn get_user_entity(user: &UserHandle<USER_HANDLE_MAX_LEN>) -> PublicKeyCredentialUserEntity<'_, '_, '_, USER_HANDLE_MAX_LEN> {
///     // ⋮
/// #     PublicKeyCredentialUserEntity {
/// #         name: "foo",
/// #         id: user,
/// #         display_name: "",
/// #     }
/// }
/// /// Send `RegistrationClientState` and receive `Registration` JSON from client.
/// # #[cfg(feature = "serde")]
/// fn get_registration_json(client: RegistrationClientState<'_, '_, '_, '_, '_, '_, USER_HANDLE_MAX_LEN>) -> String {
///     // ⋮
/// #     let client_data_json = base64url_nopad::encode(serde_json::json!({
/// #         "type": "webauthn.create",
/// #         "challenge": client.options().public_key.challenge,
/// #         "origin": format!("https://{}", client.options().public_key.rp_id.as_ref()),
/// #         "crossOrigin": false
/// #     }).to_string().as_bytes());
/// #     serde_json::json!({
/// #         "response": {
/// #             "clientDataJSON": client_data_json,
/// #             "attestationObject": ""
/// #         }
/// #     }).to_string()
/// }
/// /// Fetch the `PublicKeyCredentialDescriptor`s associated with `user`.
/// ///
/// /// This doesn't need to be called when this is the first credential registered for `user`; instead
/// /// an empty `Vec` should be passed.
/// fn get_registered_credentials(
///     user: UserHandle<USER_HANDLE_MAX_LEN>,
/// ) -> Vec<PublicKeyCredentialDescriptor<Box<[u8]>>> {
///     // ⋮
/// #     Vec::new()
/// }
/// /// Inserts `RegisteredCredential::into_parts` into the database.
/// fn insert_cred(cred: RegisteredCredential<'_, USER_HANDLE_MAX_LEN>) {
///     // ⋮
/// }
/// # Ok::<_, E>(())
/// ```
pub mod register;
/// Contains functionality to (de)serialize data to/from a client.
#[cfg(feature = "serde")]
pub(crate) mod ser;
/// Contains functionality to deserialize data from a client in a "relaxed" way.
#[cfg(feature = "serde_relaxed")]
pub mod ser_relaxed;
/// [Backup eligibility](https://www.w3.org/TR/webauthn-3/#backup-eligibility) and
/// [backup state](https://www.w3.org/TR/webauthn-3/#backup-state).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backup {
    /// [BE and BS](https://www.w3.org/TR/webauthn-3/#authdata-flags) flags are `0`.
    NotEligible,
    /// [BE and BS](https://www.w3.org/TR/webauthn-3/#authdata-flags) flags are `1` and `0` respectively.
    Eligible,
    /// [BE and BS](https://www.w3.org/TR/webauthn-3/#authdata-flags) flags are `1`.
    Exists,
}
impl PartialEq<&Self> for Backup {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<Backup> for &Backup {
    #[inline]
    fn eq(&self, other: &Backup) -> bool {
        **self == *other
    }
}
/// [`AuthenticatorTransport`](https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorTransport {
    /// [`ble`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-ble).
    Ble,
    /// [`hybrid`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-hybrid).
    Hybrid,
    /// [`internal`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-internal).
    Internal,
    /// [`nfc`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-nfc).
    Nfc,
    /// [`smart-card`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-smart-card).
    SmartCard,
    /// [`usb`](https://www.w3.org/TR/webauthn-3/#dom-authenticatortransport-usb).
    Usb,
}
impl AuthenticatorTransport {
    /// Returns the encoded [`u8`] that `self` represents.
    const fn to_u8(self) -> u8 {
        match self {
            Self::Ble => 0x1,
            Self::Hybrid => 0x2,
            Self::Internal => 0x4,
            Self::Nfc => 0x8,
            Self::SmartCard => 0x10,
            Self::Usb => 0x20,
        }
    }
}
/// Set of [`AuthenticatorTransport`]s.
#[derive(Clone, Copy, Debug)]
pub struct AuthTransports(u8);
impl AuthTransports {
    /// An empty `AuthTransports`.
    #[cfg(feature = "custom")]
    pub const NONE: Self = Self::new();
    /// An `AuthTransports` containing all possible [`AuthenticatorTransport`]s.
    #[cfg(feature = "custom")]
    pub const ALL: Self = Self::all();
    /// Construct an empty `AuthTransports`.
    #[cfg(any(feature = "bin", feature = "custom", feature = "serde"))]
    pub(super) const fn new() -> Self {
        Self(0)
    }
    #[cfg(any(feature = "bin", feature = "custom"))]
    /// Construct an `AuthTransports` containing all `AuthenticatorTransport`s.
    const fn all() -> Self {
        Self::new()
            .add_transport(AuthenticatorTransport::Ble)
            .add_transport(AuthenticatorTransport::Hybrid)
            .add_transport(AuthenticatorTransport::Internal)
            .add_transport(AuthenticatorTransport::Nfc)
            .add_transport(AuthenticatorTransport::SmartCard)
            .add_transport(AuthenticatorTransport::Usb)
    }
    /// Returns the number of [`AuthenticatorTransport`]s in `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::AuthTransports;
    /// # #[cfg(feature = "custom")]
    /// assert_eq!(AuthTransports::ALL.count(), 6);
    /// ```
    #[inline]
    #[must_use]
    pub const fn count(self) -> u32 {
        self.0.count_ones()
    }
    /// Returns `true` iff there are no [`AuthenticatorTransport`]s in `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::AuthTransports;
    /// # #[cfg(feature = "custom")]
    /// assert!(AuthTransports::NONE.is_empty());
    /// ```
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    /// Returns `true` iff `self` contains `transport`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::{AuthTransports, AuthenticatorTransport};
    /// # #[cfg(feature = "custom")]
    /// assert!(AuthTransports::ALL.contains(AuthenticatorTransport::Ble));
    /// ```
    #[inline]
    #[must_use]
    pub const fn contains(self, transport: AuthenticatorTransport) -> bool {
        let val = transport.to_u8();
        self.0 & val == val
    }
    /// Returns a copy of `self` with `transport` added.
    ///
    /// `self` is returned iff `transport` already exists.
    #[cfg(any(feature = "bin", feature = "custom", feature = "serde"))]
    const fn add_transport(self, transport: AuthenticatorTransport) -> Self {
        Self(self.0 | transport.to_u8())
    }
    /// Returns a copy of `self` with `transport` added.
    ///
    /// `self` is returned iff `transport` already exists.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::{AuthTransports, AuthenticatorTransport};
    /// assert_eq!(
    ///     AuthTransports::NONE
    ///         .add(AuthenticatorTransport::Usb)
    ///         .count(),
    ///     1
    /// );
    /// assert_eq!(
    ///     AuthTransports::ALL.add(AuthenticatorTransport::Usb).count(),
    ///     6
    /// );
    /// ```
    #[cfg(feature = "custom")]
    #[inline]
    #[must_use]
    pub const fn add(self, transport: AuthenticatorTransport) -> Self {
        self.add_transport(transport)
    }
    /// Returns a copy of `self` with `transport` removed.
    ///
    /// `self` is returned iff `transport` did not exist.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::{AuthTransports, AuthenticatorTransport};
    /// assert_eq!(
    ///     AuthTransports::ALL
    ///         .remove(AuthenticatorTransport::Internal)
    ///         .count(),
    ///     5
    /// );
    /// assert_eq!(
    ///     AuthTransports::NONE.remove(AuthenticatorTransport::Usb).count(),
    ///     0
    /// );
    /// ```
    #[cfg(feature = "custom")]
    #[inline]
    #[must_use]
    pub const fn remove(self, transport: AuthenticatorTransport) -> Self {
        Self(self.0 & !transport.to_u8())
    }
}
/// [`AuthenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#enumdef-authenticatorattachment).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AuthenticatorAttachment {
    /// No attachment information.
    #[default]
    None,
    /// [`platform`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattachment-platform).
    Platform,
    /// [`cross-platform`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattachment-cross-platform).
    CrossPlatform,
}
impl PartialEq<&Self> for AuthenticatorAttachment {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<AuthenticatorAttachment> for &AuthenticatorAttachment {
    #[inline]
    fn eq(&self, other: &AuthenticatorAttachment) -> bool {
        **self == *other
    }
}
/// The maximum number of bytes that can make up a Credential ID
/// [per WebAuthn](https://www.w3.org/TR/webauthn-3/#credential-id).
pub const CRED_ID_MAX_LEN: usize = 1023;
/// The minimum number of bytes that can make up a Credential ID
/// [per WebAuthn](https://www.w3.org/TR/webauthn-3/#credential-id).
///
/// The spec does not call out this value directly instead it states the following:
///
/// > Credential IDs are generated by authenticators in two forms:
/// >
/// > * At least 16 bytes that include at least 100 bits of entropy, or
/// > * The [public key credential source](https://www.w3.org/TR/webauthn-3/#public-key-credential-source),
/// >   without its Credential ID or mutable items, encrypted so only its managing
/// >   authenticator can decrypt it. This form allows the authenticator to be nearly
/// >   stateless, by having the Relying Party store any necessary state.
///
/// One of the immutable items of the public key credential source is the private key
/// which for any real-world signature algorithm will always be at least 16 bytes.
pub const CRED_ID_MIN_LEN: usize = 16;
/// A [Credential ID](https://www.w3.org/TR/webauthn-3/#credential-id) that is made up of
/// [`CRED_ID_MIN_LEN`]–[`CRED_ID_MAX_LEN`] bytes.
#[derive(Clone, Copy, Debug)]
pub struct CredentialId<T>(T);
impl<T> CredentialId<T> {
    /// Returns the contained data consuming `self`.
    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }
    /// Returns the contained data.
    #[inline]
    pub const fn inner(&self) -> &T {
        &self.0
    }
}
impl<'a> CredentialId<&'a [u8]> {
    /// Creates a `CredentialId` from a `slice`.
    #[expect(single_use_lifetimes, reason = "false positive")]
    fn from_slice<'b: 'a>(value: &'b [u8]) -> Result<Self, CredentialIdErr> {
        if (CRED_ID_MIN_LEN..=CRED_ID_MAX_LEN).contains(&value.len()) {
            Ok(Self(value))
        } else {
            Err(CredentialIdErr)
        }
    }
}
impl<T: AsRef<[u8]>> AsRef<[u8]> for CredentialId<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<T: Borrow<[u8]>> Borrow<[u8]> for CredentialId<T> {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.0.borrow()
    }
}
impl<'a: 'b, 'b> From<&'a CredentialId<Box<[u8]>>> for CredentialId<&'b Box<[u8]>> {
    #[inline]
    fn from(value: &'a CredentialId<Box<[u8]>>) -> Self {
        Self(&value.0)
    }
}
impl<'a: 'b, 'b> From<CredentialId<&'a Box<[u8]>>> for CredentialId<&'b [u8]> {
    #[inline]
    fn from(value: CredentialId<&'a Box<[u8]>>) -> Self {
        Self(value.0)
    }
}
impl<'a: 'b, 'b> From<&'a CredentialId<Box<[u8]>>> for CredentialId<&'b [u8]> {
    #[inline]
    fn from(value: &'a CredentialId<Box<[u8]>>) -> Self {
        Self(&value.0)
    }
}
impl From<CredentialId<&[u8]>> for CredentialId<Box<[u8]>> {
    #[inline]
    fn from(value: CredentialId<&[u8]>) -> Self {
        Self(value.0.into())
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<CredentialId<T>> for CredentialId<T2> {
    #[inline]
    fn eq(&self, other: &CredentialId<T>) -> bool {
        self.0 == other.0
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<CredentialId<T>> for &CredentialId<T2> {
    #[inline]
    fn eq(&self, other: &CredentialId<T>) -> bool {
        **self == *other
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<&CredentialId<T>> for CredentialId<T2> {
    #[inline]
    fn eq(&self, other: &&CredentialId<T>) -> bool {
        *self == **other
    }
}
impl<T: Eq> Eq for CredentialId<T> {}
impl<T: Hash> Hash for CredentialId<T> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}
impl<T: PartialOrd<T2>, T2: PartialOrd<T>> PartialOrd<CredentialId<T>> for CredentialId<T2> {
    #[inline]
    fn partial_cmp(&self, other: &CredentialId<T>) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
impl<T: Ord> Ord for CredentialId<T> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
// We define a separate type to ensure challenges sent to the client are always randomly generated;
// otherwise one could deserialize arbitrary data into a `Challenge`.
/// Copy of [`Challenge`] sent back from the client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SentChallenge(pub u128);
impl SentChallenge {
    /// Transforms `value` into a `SentChallenge` by interpreting `value` as a
    /// little-endian `u128`.
    #[expect(clippy::little_endian_bytes, reason = "Challenge and SentChallenge need to be compatible, and we need to ensure the data is sent and received in the same order")]
    #[inline]
    #[must_use]
    pub const fn from_array(value: [u8; 16]) -> Self {
        Self(u128::from_le_bytes(value))
    }
    /// Transforms `value` into a `SentChallenge`.
    #[inline]
    #[must_use]
    pub const fn from_challenge(value: Challenge) -> Self {
        Self(value.into_data())
    }
}
impl From<Challenge> for SentChallenge {
    #[inline]
    fn from(value: Challenge) -> Self {
        Self::from_challenge(value)
    }
}
impl From<[u8; 16]> for SentChallenge {
    #[inline]
    fn from(value: [u8; 16]) -> Self {
        Self::from_array(value)
    }
}
impl PartialEq<&Self> for SentChallenge {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<SentChallenge> for &SentChallenge {
    #[inline]
    fn eq(&self, other: &SentChallenge) -> bool {
        **self == *other
    }
}
impl PartialOrd for SentChallenge {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SentChallenge {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}
impl Hash for SentChallenge {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u128(self.0);
    }
}
/// An [`origin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin) or
/// [`topOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin).
#[derive(Debug, Eq)]
pub struct Origin<'a>(pub Cow<'a, str>);
impl PartialEq<Origin<'_>> for Origin<'_> {
    #[inline]
    fn eq(&self, other: &Origin<'_>) -> bool {
        self.0 == other.0
    }
}
impl PartialEq<&Origin<'_>> for Origin<'_> {
    #[inline]
    fn eq(&self, other: &&Origin<'_>) -> bool {
        *self == **other
    }
}
impl PartialEq<Origin<'_>> for &Origin<'_> {
    #[inline]
    fn eq(&self, other: &Origin<'_>) -> bool {
        **self == *other
    }
}
impl PartialEq<str> for Origin<'_> {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.0.as_ref() == other
    }
}
impl PartialEq<Origin<'_>> for str {
    #[inline]
    fn eq(&self, other: &Origin<'_>) -> bool {
        *other == *self
    }
}
impl PartialEq<&str> for Origin<'_> {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        *self == **other
    }
}
impl PartialEq<Origin<'_>> for &str {
    #[inline]
    fn eq(&self, other: &Origin<'_>) -> bool {
        **self == *other
    }
}
impl PartialEq<String> for Origin<'_> {
    #[inline]
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}
impl PartialEq<Origin<'_>> for String {
    #[inline]
    fn eq(&self, other: &Origin<'_>) -> bool {
        *other == *self
    }
}
impl PartialEq<Url> for Origin<'_> {
    #[inline]
    fn eq(&self, other: &Url) -> bool {
        self.0.as_ref() == other.as_ref()
    }
}
impl PartialEq<Origin<'_>> for Url {
    #[inline]
    fn eq(&self, other: &Origin<'_>) -> bool {
        *other == *self
    }
}
impl PartialEq<&Url> for Origin<'_> {
    #[inline]
    fn eq(&self, other: &&Url) -> bool {
        *self == **other
    }
}
impl PartialEq<Origin<'_>> for &Url {
    #[inline]
    fn eq(&self, other: &Origin<'_>) -> bool {
        **self == *other
    }
}
/// [Authenticator data flags](https://www.w3.org/TR/webauthn-3/#authdata-flags).
#[derive(Clone, Copy, Debug)]
pub struct Flag {
    /// [`UP` flag](https://www.w3.org/TR/webauthn-3/#authdata-flags-up).
    ///
    /// Note this is always `true` when part of [`auth::AuthenticatorData::flags`].
    pub user_present: bool,
    /// [`UV` flag](https://www.w3.org/TR/webauthn-3/#concept-user-verified).
    pub user_verified: bool,
    /// [`BE`](https://www.w3.org/TR/webauthn-3/#backup-eligibility) and
    /// [`BS`](https://www.w3.org/TR/webauthn-3/#backup-state) flags.
    pub backup: Backup,
}
/// [Authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data).
pub(super) trait AuthData<'a>: Sized {
    /// Error returned by [`Self::user_is_not_present`].
    ///
    /// This should be [`Infallible`] in the event user must not always be present.
    type UpBitErr;
    /// [`attestedCredentialData`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata).
    type CredData;
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions).
    type Ext: AuthExtOutput + Copy;
    /// Errors iff the user must always be present.
    fn user_is_not_present() -> Result<(), Self::UpBitErr>;
    /// `true` iff `AT` bit (i.e., bit 6) in [`Self::flag_data`] can and must be set to 1.
    fn contains_at_bit() -> bool;
    /// Constructor.
    fn new(rp_id_hash: &'a [u8], flags: Flag, sign_count: u32, attested_credential_data: Self::CredData, extensions: Self::Ext) -> Self;
    /// [`rpIdHash`](https://www.w3.org/TR/webauthn-3/#authdata-rpidhash).
    fn rp_hash(&self) -> &'a [u8];
    /// [`flags`](https://www.w3.org/TR/webauthn-3/#authdata-flags).
    fn flag(&self) -> Flag;
}
/// [`CollectedClientData`](https://www.w3.org/TR/webauthn-3/#dictdef-collectedclientdata).
#[derive(Debug)]
pub struct CollectedClientData<'a> {
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge).
    pub challenge: SentChallenge,
    /// [`origin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin).
    pub origin: Origin<'a>,
    /// [`crossOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-crossorigin).
    pub cross_origin: bool,
    /// [`topOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin).
    ///
    /// When `CollectedClientData` is constructed via [`Self::from_client_data_json`], this can only be
    /// `Some` if [`Self::cross_origin`]; and if `Some`, it will be different than [`Self::origin`].
    pub top_origin: Option<Origin<'a>>,
}
impl<'a> CollectedClientData<'a> {
    /// Parses `json` based on the
    /// [limited verification algorithm](https://www.w3.org/TR/webauthn-3/#clientdatajson-verification).
    ///
    /// Additionally, [`topOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-toporigin) is only
    /// allowed to exist if it has a different value than
    /// [`origin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin) and
    /// [`crossOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-crossorigin) is `true`.
    ///
    /// `REGISTRATION` iff [`type`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-type) must be
    /// `"webauthn.create"`; otherwise it must be `"webauthn.get"`.
    ///
    /// # Errors
    ///
    /// Errors iff `json` cannot be parsed based on the aforementioned requirements.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::{error::CollectedClientDataErr, CollectedClientData};
    /// assert!(!CollectedClientData::from_client_data_json::<true>(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice())?.cross_origin);
    /// assert!(!CollectedClientData::from_client_data_json::<false>(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice())?.cross_origin);
    /// # Ok::<_, CollectedClientDataErr>(())
    /// ```
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[inline]
    pub fn from_client_data_json<'b: 'a, const REGISTRATION: bool>(json: &'b [u8]) -> Result<Self, CollectedClientDataErr> {
        LimitedVerificationParser::<REGISTRATION>::parse(json)
    }
    /// Parses `json` in a "relaxed" way.
    ///
    /// Unlike [`Self::from_client_data_json`] which requires `json` to be an output from the
    /// [JSON-compatible serialization of client data](https://www.w3.org/TR/webauthn-3/#clientdatajson-serialization),
    /// this parses `json` based entirely on the
    /// [`CollectedClientData`](https://www.w3.org/TR/webauthn-3/#dictdef-collectedclientdata) Web IDL `dictionary`.
    ///
    /// L1 clients predate the JSON-compatible serialization of client data; additionally there are L2 and L3
    /// clients that don't adhere to the JSON-compatible serialization of client data despite being required to.
    /// These clients serialize `CollectedClientData` so that it's valid JSON and conforms to the Web IDL `dictionary`
    /// and nothing more. Furthermore, when not relying on the
    /// [limited verification algorithm](https://www.w3.org/TR/webauthn-3/#clientdatajson-verification), the spec
    /// requires the data to be decoded in a way equivalent to
    /// [UTF-8 decode](https://encoding.spec.whatwg.org/#utf-8-decode) which both interprets a leading zero
    /// width no-breaking space (i.e., U+FEFF) as a byte-order mark (BOM) as well as replaces any sequences of
    /// invalid UTF-8 code units with the replacement character (i.e., U+FFFD). That is precisely what this
    /// function does.
    ///
    /// # Errors
    ///
    /// Errors iff any of the following is true:
    /// * The payload is not valid JSON _after_ ignoring a leading U+FEFF and replacing any sequences of invalid
    ///   UTF-8 code units with U+FFFD.
    /// * The JSON does not conform to the Web IDL `dictionary`.
    /// * [`type`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-type) is not `"webauthn.create"`
    ///   or `"webauthn.get"` when `REGISTRATION` and `!REGISTRATION` respectively.
    /// * [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge) is not a
    ///   base64url-encoded [`Challenge`].
    /// * Existence of duplicate keys for the keys that are expected.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::{ser_relaxed::SerdeJsonErr, CollectedClientData};
    /// assert!(!CollectedClientData::from_client_data_json_relaxed::<true>(b"\xef\xbb\xbf{
    ///   \"type\": \"webauthn.create\",
    ///   \"origin\": \"https://example.com\",
    ///   \"f\xffo\": 123,
    ///   \"topOrigin\": \"https://example.com\",
    ///   \"challenge\": \"AAAAAAAAAAAAAAAAAAAAAA\"
    /// }")?.cross_origin);
    /// # Ok::<_, SerdeJsonErr>(())
    /// ```
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[cfg(feature = "serde_relaxed")]
    #[inline]
    pub fn from_client_data_json_relaxed<'b: 'a, const REGISTRATION: bool>(json: &'b [u8]) -> Result<Self, SerdeJsonErr> {
        ser_relaxed::RelaxedClientDataJsonParser::<REGISTRATION>::parse(json)
    }
}
/// Parser of 
/// [`JSON-compatible serialization of client data`](https://www.w3.org/TR/webauthn-3/#collectedclientdata-json-compatible-serialization-of-client-data).
trait ClientDataJsonParser {
    /// Error returned by [`Self::parse`].
    type Err;
    /// Parses `json` into `CollectedClientData` based on the value of
    /// [`type`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-type).
    ///
    /// # Errors
    ///
    /// Errors iff `json` cannot be parsed into a `CollectedClientData`.
    fn parse(json: &[u8]) -> Result<CollectedClientData<'_>, Self::Err>;
    /// Extracts [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge)
    /// from `json`.
    ///
    /// Note `json` should be minimally parsed such that only `challenge` is extracted; thus
    /// `Ok` being returned does _not_ mean `json` is in fact valid.
    fn get_sent_challenge(json: &[u8]) -> Result<SentChallenge, Self::Err>;
}
/// [`ClientDataJsonParser`] based on the
/// [limited verification algorithm](https://www.w3.org/TR/webauthn-3/#clientdatajson-verification)
/// with the following additional requirements:
/// * Unknown keys are not allowed.
/// * The entire payload is parsed; thus the payload is guaranteed to be valid UTF-8 and JSON.
/// * [`CollectedClientData::top_origin`] can only be `Some` if
///   [`crossOrigin`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-crossorigin).
/// * If `CollectedClientData::top_origin` is `Some`, then it does not equal [`CollectedClientData::origin`].
///
/// `REGISTRATION` iff [`ClientDataJsonParser::parse`] requires
/// [`type`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-type) to be `"webauthn.create"`;
/// otherwise it must be `"webauthn.get"`.
struct LimitedVerificationParser<const REGISTRATION: bool>;
impl<const R: bool> LimitedVerificationParser<R> {
    /// Parses `val` as a JSON string with possibly trailing data. `val` MUST NOT begin with an opening quote. Upon
    /// encountering the first non-escaped quote, the parsed value is returned in addition to the remaining
    /// portion of `val` _after_ the closing quote. The limited verification algorithm is adhered to; thus the
    /// _only_ Unicode scalar values that are allowed (and must) be hex-escaped are U+0000 to U+001F inclusively.
    /// Similarly only `b'\\'` and `b'"'` are allowed (and must) be escaped with `b'\\'`.
    #[expect(unsafe_code, reason = "comment justifies its correctness")] 
    #[expect(clippy::arithmetic_side_effects, clippy::indexing_slicing, reason = "comments justify their correctness")]
    fn parse_string(val: &[u8]) -> Result<(Cow<'_, str>, &'_ [u8]), CollectedClientDataErr> {
        /// Tracks the state of the current Unicode scalar value that is being parsed.
        enum State {
            /// We are not parsing `'"'`, `'\\'`, or U+0000 to U+001F.
            Normal,
            /// We just encountered the escape character.
            Escape,
            /// We just encountered `b"\\u"`.
            UnicodeEscape,
            /// We just encountered `b"\\u0"`.
            UnicodeHex1,
            /// We just encountered `b"\\u00"`.
            UnicodeHex2,
            /// We just encountered `b"\\u000"` or `b"\\u001"`. The contained `u8` is `0` iff the former; otherwise
            /// `0x10`.
            UnicodeHex3(u8),
        }
        // We parse this as UTF-8 only at the end iff it is not empty. This contains all the potential Unicode scalar
        // values after de-escaping.
        let mut utf8 = Vec::new();
        // We check for all `u8`s already; thus we might as well check if we encounter a non-ASCII `u8`.
        // If we don't, then we can rely on `str::from_utf8_unchecked`.
        let mut all_ascii = true;
        // This tracks the start index of the next slice to add. We add slices iff we encounter the escape character or
        // we return the parsed `Cow` (i.e., encounter an unescaped `b'"'`).
        let mut cur_idx = 0;
        // The state of the yet-to-be-parsed Unicode scalar value.
        let mut state = State::Normal;
        for (counter, &b) in val.iter().enumerate() {
            match state {
                State::Normal => {
                    match b {
                        b'"' => {
                            if utf8.is_empty() {
                                if all_ascii {
                                    // `cur_idx` is 0 or 1. The latter is true iff `val` starts with a
                                    // `b'\\'` or `b'"'` but contains no other escaped characters.
                                    let s = &val[cur_idx..counter];
                                    // SAFETY:
                                    // `all_ascii` is `false` iff we encountered any `u8` that was not
                                    // an ASCII `u8`; thus we know `s` is valid ASCII which in turn means
                                    // it's valid UTF-8.
                                    let v = unsafe { str::from_utf8_unchecked(s) };
                                    // `val.len() > counter`, so indexing is fine and overflow cannot happen.
                                    return Ok((Cow::Borrowed(v), &val[counter + 1..]));
                                }
                                // `cur_idx` is 0 or 1. The latter is true iff `val` starts with a
                                // `b'\\'` or `b'"'` but contains no other escaped characters.
                                return str::from_utf8(&val[cur_idx..counter])
                                    .map_err(CollectedClientDataErr::Utf8)
                                    // `val.len() > counter`, so indexing is fine and overflow cannot happen.
                                    .map(|v| (Cow::Borrowed(v), &val[counter + 1..]));
                            }
                            // `val.len() > counter && counter >= cur_idx`, so indexing is fine and overflow
                            // cannot happen.
                            utf8.extend_from_slice(&val[cur_idx..counter]);
                            if all_ascii {
                                // SAFETY:
                                // `all_ascii` is `false` iff we encountered any `u8` that was not
                                // an ASCII `u8`; thus we know `utf8` is valid ASCII which in turn means
                                // it's valid UTF-8.
                                let v = unsafe { String::from_utf8_unchecked(utf8) };
                                // `val.len() > counter`, so indexing is fine and overflow cannot happen.
                                return Ok((Cow::Owned(v), &val[counter + 1..]));
                            }
                            return String::from_utf8(utf8)
                                .map_err(CollectedClientDataErr::Utf8Owned)
                                // `val.len() > counter`, so indexing is fine and overflow cannot happen.
                                .map(|v| (Cow::Owned(v), &val[counter + 1..]));
                        }
                        b'\\' => {
                            // Write the current slice of data.
                            utf8.extend_from_slice(&val[cur_idx..counter]);
                            state = State::Escape;
                        }
                        // ASCII is a subset of UTF-8 and this is a subset of ASCII. The code unit that is used for an
                        // ASCII Unicode scalar value _never_ appears in multi-code-unit Unicode scalar values; thus we
                        // error immediately.
                        ..=0x1f => return Err(CollectedClientDataErr::InvalidEscapedString),
                        128.. => all_ascii = false,
                        _ => (),
                    }
                }
                State::Escape => {
                    match b {
                        b'"' | b'\\' => {
                            // We start the next slice here since we need to add it.
                            cur_idx = counter;
                            state = State::Normal;
                        }
                        b'u' => {
                            state = State::UnicodeEscape;
                        }
                        _ => {
                            return Err(CollectedClientDataErr::InvalidEscapedString);
                        }
                    }
                }
                State::UnicodeEscape => {
                    if b != b'0' {
                        return Err(CollectedClientDataErr::InvalidEscapedString);
                    }
                    state = State::UnicodeHex1;
                }
                State::UnicodeHex1 => {
                    if b != b'0' {
                        return Err(CollectedClientDataErr::InvalidEscapedString);
                    }
                    state = State::UnicodeHex2;
                }
                State::UnicodeHex2 => {
                    state = State::UnicodeHex3(match b {
                        b'0' => 0,
                        b'1' => 0x10,
                        _ => return Err(CollectedClientDataErr::InvalidEscapedString),
                    });
                }
                State::UnicodeHex3(v) => {
                    match b {
                        // Only and all _lowercase_ hex is allowed.
                        b'0'..=b'9' | b'a'..=b'f' => {
                            // When `b < b'a'`, then `b >= b'0'`; and `b'a' > 87`; thus underflow cannot happen.
                            // Note `b'a' - 10 == 87`.
                            utf8.push(v | (b - if b < b'a' { b'0' } else { 87 }));
                            // `counter < val.len()`, so overflow cannot happen.
                            cur_idx = counter + 1;
                            state = State::Normal;
                        }
                        _ => return Err(CollectedClientDataErr::InvalidEscapedString),
                    }
                }
            }
        }
        // We never encountered an unescaped `b'"'`; thus we could not parse a string.
        Err(CollectedClientDataErr::InvalidObject)
    }
}
impl<const R: bool> ClientDataJsonParser for LimitedVerificationParser<R> {
    type Err = CollectedClientDataErr;
    #[expect(clippy::little_endian_bytes, reason = "Challenge::serialize and this need to be consistent across architectures")]
    #[expect(clippy::too_many_lines, reason = "110 lines is fine")]
    fn parse(json: &[u8]) -> Result<CollectedClientData<'_>, Self::Err> {
        // `{"type":"webauthn.<create|get>","challenge":"<22 bytes>","origin":"<bytes>","crossOrigin":<true|false>[,"topOrigin":"<bytes>"][,<anything>]}`.
        /// First portion of `value`.
        const HEADER: &[u8; 18] = br#"{"type":"webauthn."#;
        /// `get`.
        const GET: &[u8; 3] = b"get";
        /// `create`.
        const CREATE: &[u8; 6] = b"create";
        /// Value after type before the start of the base64url-encoded challenge.
        const AFTER_TYPE: &[u8; 15] = br#"","challenge":""#;
        /// Value after challenge before the start of the origin value.
        const AFTER_CHALLENGE: &[u8; 12] = br#"","origin":""#;
        /// Value after origin before the start of the crossOrigin value.
        const AFTER_ORIGIN: &[u8; 15] = br#","crossOrigin":"#;
        /// `true`.
        const TRUE: &[u8; 4] = b"true";
        /// `false`.
        const FALSE: &[u8; 5] = b"false";
        /// Value after crossOrigin before the start of the topOrigin value.
        const AFTER_CROSS: &[u8; 13] = br#""topOrigin":""#;
        json.split_last().ok_or(CollectedClientDataErr::Len).and_then(|(last, last_rem)| {
            if *last == b'}' {
                last_rem.split_at_checked(HEADER.len()).ok_or(CollectedClientDataErr::Len).and_then(|(header, header_rem)| {
                    if header == HEADER {
                        if R {
                            header_rem.split_at_checked(CREATE.len()).ok_or(CollectedClientDataErr::Len).and_then(|(create, create_rem)| {
                                if create == CREATE {
                                    Ok(create_rem)
                                } else {
                                    Err(CollectedClientDataErr::Type)
                                }
                            })
                        } else {
                            header_rem.split_at_checked(GET.len()).ok_or(CollectedClientDataErr::Len).and_then(|(get, get_rem)| {
                                if get == GET {
                                    Ok(get_rem)
                                } else {
                                    Err(CollectedClientDataErr::Type)
                                }
                            })
                        }.and_then(|type_rem| {
                            type_rem.split_at_checked(AFTER_TYPE.len()).ok_or(CollectedClientDataErr::Len).and_then(|(chall_key, chall_key_rem)| {
                                if chall_key == AFTER_TYPE {
                                    chall_key_rem.split_at_checked(Challenge::BASE64_LEN).ok_or(CollectedClientDataErr::Len).and_then(|(base64_chall, base64_chall_rem)| {
                                        let mut chall = [0; 16];
                                        base64url_nopad::decode_buffer_exact(base64_chall, chall.as_mut_slice()).map_err(|_e| CollectedClientDataErr::Challenge).and_then(|()| {
                                            base64_chall_rem.split_at_checked(AFTER_CHALLENGE.len()).ok_or(CollectedClientDataErr::Len).and_then(|(origin_key, origin_key_rem)| {
                                                if origin_key == AFTER_CHALLENGE {
                                                    Self::parse_string(origin_key_rem).and_then(|(origin, origin_rem)| {
                                                        origin_rem.split_at_checked(AFTER_ORIGIN.len()).ok_or(CollectedClientDataErr::Len).and_then(|(cross_key, cross_key_rem)| {
                                                            if cross_key == AFTER_ORIGIN {
                                                                // `FALSE.len() > TRUE.len()`, so we check for `FALSE` in `and_then`.
                                                                cross_key_rem.split_at_checked(TRUE.len()).ok_or(CollectedClientDataErr::Len).and_then(|(cross_true, cross_true_rem)| {
                                                                    if cross_true == TRUE {
                                                                        Ok((true, cross_true_rem))
                                                                    } else {
                                                                        cross_key_rem.split_at_checked(FALSE.len()).ok_or(CollectedClientDataErr::Len).and_then(|(cross_false, cross_false_rem)| {
                                                                            if cross_false == FALSE {
                                                                                Ok((false, cross_false_rem))
                                                                            } else {
                                                                                Err(CollectedClientDataErr::CrossOrigin)
                                                                            }
                                                                        })
                                                                    }.and_then(|(cross, cross_rem)| {
                                                                        cross_rem.split_first().map_or(Ok((cross, None)), |(comma, comma_rem)| {
                                                                            if *comma == b',' {
                                                                                comma_rem.split_at_checked(AFTER_CROSS.len()).map_or(Ok((cross, None)), |(top, top_rem)| {
                                                                                    if top == AFTER_CROSS {
                                                                                        if cross {
                                                                                            Self::parse_string(top_rem).and_then(|(top_origin, top_origin_rem)| {
                                                                                                top_origin_rem.first().map_or(Ok(()), |v| {
                                                                                                    if *v == b',' {
                                                                                                        Ok(())
                                                                                                    } else {
                                                                                                        Err(CollectedClientDataErr::InvalidObject)
                                                                                                    }
                                                                                                }).and_then(|()| {
                                                                                                    if origin == top_origin {
                                                                                                        Err(CollectedClientDataErr::TopOriginSameAsOrigin)
                                                                                                    } else {
                                                                                                        Ok((true, Some(Origin(top_origin))))
                                                                                                    }
                                                                                                })
                                                                                            })
                                                                                        } else {
                                                                                            Err(CollectedClientDataErr::TopOriginWithoutCrossOrigin)
                                                                                        }
                                                                                    } else {
                                                                                        Ok((cross, None))
                                                                                    }
                                                                                })
                                                                            } else {
                                                                                Err(CollectedClientDataErr::InvalidObject)
                                                                            }
                                                                        }).map(|(cross_origin, top_origin)| CollectedClientData { challenge: SentChallenge(u128::from_le_bytes(chall)), origin: Origin(origin), cross_origin, top_origin, })
                                                                    })
                                                                })
                                                            } else {
                                                                Err(CollectedClientDataErr::CrossOriginKey)
                                                            }
                                                        })
                                                    })
                                                } else {
                                                    Err(CollectedClientDataErr::OriginKey)
                                                }
                                            })
                                        })
                                    })
                                } else {
                                    Err(CollectedClientDataErr::ChallengeKey)
                                }
                            })
                        })
                    } else {
                        Err(CollectedClientDataErr::InvalidStart)
                    }
                })
            } else {
                Err(CollectedClientDataErr::InvalidObject)
            }
        })
    }
    #[expect(clippy::arithmetic_side_effects, reason = "comment justifies correctness")]
    #[expect(clippy::little_endian_bytes, reason = "Challenge::serialize and this need to be consistent across architectures")]
    fn get_sent_challenge(json: &[u8]) -> Result<SentChallenge, Self::Err> {
        // Index 39.
        // `{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA"...`.
        // Index 36.
        // `{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA"...`.
        let idx = if R { 39 } else { 36 };
        // This maxes at 39 + 22 = 61; thus overflow is not an issue.
        json.get(idx..idx + Challenge::BASE64_LEN).ok_or(CollectedClientDataErr::Len).and_then(|chall_slice| {
            let mut chall = [0; 16];
            base64url_nopad::decode_buffer_exact(chall_slice, chall.as_mut_slice()).map_err(|_e| CollectedClientDataErr::Challenge).map(|()| {
                SentChallenge(u128::from_le_bytes(chall))
            })
        })
    }
}
/// Authenticator extension outputs;
pub(super) trait AuthExtOutput {
    /// MUST return `true` iff there is no data.
    fn missing(self) -> bool;
}
/// Successful return type from [`FromCbor::from_cbor`].
struct CborSuccess<'a, T> {
    /// Value parsed from the slice.
    value: T,
    /// Remaining unprocessed data.
    remaining: &'a [u8],
}
/// Types that parse
/// [CTAP2 canonical CBOR encoding form](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#ctap2-canonical-cbor-encoding-form)
/// data without necessarily consuming all the data.
///
/// The purpose of this `trait` is to allow chains of types to progressively consume `cbor` by passing
/// [`CborSuccess::remaining`] into the next `FromCbor` type.
trait FromCbor<'a>: Sized {
    /// Error when conversion fails.
    type Err;
    /// Parses `cbor` into `Self`.
    ///
    /// # Errors
    ///
    /// Errors if `cbor` cannot be parsed into `Self:`.
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err>;
}
/// Error returned from [`A::from_cbor`] `where A: AuthData`.
enum AuthenticatorDataErr<UpErr, CredData, AuthExt> {
    /// The `slice` had an invalid length.
    Len,
    /// [UP](https://www.w3.org/TR/webauthn-3/#authdata-flags-at) bit was 0.
    UserNotPresent(UpErr),
    /// Bit 1 in [`flags`](https://www.w3.org/TR/webauthn-3/#authdata-flags) is not 0.
    FlagsBit1Not0,
    /// Bit 5 in [`flags`](https://www.w3.org/TR/webauthn-3/#authdata-flags) is not 0.
    FlagsBit5Not0,
    /// [AT](https://www.w3.org/TR/webauthn-3/#authdata-flags-at) bit was 0 during registration or was 1
    /// during authentication.
    AttestedCredentialData,
    /// [BE](https://www.w3.org/TR/webauthn-3/#authdata-flags-be) and
    /// [BS](https://www.w3.org/TR/webauthn-3/#authdata-flags-bs) bits were 0 and 1 respectively.
    BackupWithoutEligibility,
    /// Error returned from [`AttestedCredentialData::from_cbor`].
    AttestedCredential(CredData),
    /// Error returned from [`register::AuthenticatorExtensionOutput::from_cbor`] and
    /// [`auth::AuthenticatorExtensionOutput::from_cbor`].
    AuthenticatorExtension(AuthExt),
    /// [ED](https://www.w3.org/TR/webauthn-3/#authdata-flags-ed) bit was 0, but
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions) existed.
    NoExtensionBitWithData,
    /// [ED](https://www.w3.org/TR/webauthn-3/#authdata-flags-ed) bit was 1, but
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions) did not exist.
    ExtensionBitWithoutData,
    /// There was trailing data that could not be deserialized.
    TrailingData,
}
impl<U, C: Display, A: Display> Display for AuthenticatorDataErr<U, C, A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Len => f.write_str("authenticator data had an invalid length"),
            Self::UserNotPresent(_) => f.write_str("user was not present"),
            Self::FlagsBit1Not0 => f.write_str("flags 1-bit was 1"),
            Self::FlagsBit5Not0 => f.write_str("flags 5-bit was 1"),
            Self::AttestedCredentialData => f.write_str("attested credential data was included during authentication or was not included during registration"),
            Self::BackupWithoutEligibility => {
                f.write_str("backup state bit was 1 despite backup eligibility being 0")
            }
            Self::AttestedCredential(ref err) => err.fmt(f),
            Self::AuthenticatorExtension(ref err) => err.fmt(f),
            Self::NoExtensionBitWithData => {
                f.write_str("extension bit was 0 despite extensions existing")
            }
            Self::ExtensionBitWithoutData => {
                f.write_str("extension bit was 1 despite no extensions existing")
            }
            Self::TrailingData => {
                f.write_str("slice had trailing data that could not be deserialized")
            }
        }
    }
}
impl From<AuthenticatorDataErr<Infallible, AttestedCredentialDataErr, RegAuthExtErr>> for RegAuthDataErr {
    #[inline]
    fn from(value: AuthenticatorDataErr<Infallible, AttestedCredentialDataErr, RegAuthExtErr>) -> Self {
        match value {
            AuthenticatorDataErr::Len => Self::Len,
            AuthenticatorDataErr::UserNotPresent(v) => match v {},
            AuthenticatorDataErr::FlagsBit1Not0 => Self::FlagsBit1Not0,
            AuthenticatorDataErr::FlagsBit5Not0 => Self::FlagsBit5Not0,
            AuthenticatorDataErr::AttestedCredentialData => Self::AttestedCredentialDataNotIncluded,
            AuthenticatorDataErr::BackupWithoutEligibility => Self::BackupWithoutEligibility,
            AuthenticatorDataErr::AttestedCredential(err) => Self::AttestedCredential(err),
            AuthenticatorDataErr::AuthenticatorExtension(err) => Self::AuthenticatorExtension(err),
            AuthenticatorDataErr::NoExtensionBitWithData => Self::NoExtensionBitWithData,
            AuthenticatorDataErr::ExtensionBitWithoutData => Self::ExtensionBitWithoutData,
            AuthenticatorDataErr::TrailingData => Self::TrailingData,
        }
    }
}
impl From<AuthenticatorDataErr<(), Infallible, AuthAuthExtErr>> for AuthAuthDataErr {
    #[inline]
    fn from(value: AuthenticatorDataErr<(), Infallible, AuthAuthExtErr>) -> Self {
        match value {
            AuthenticatorDataErr::Len => Self::Len,
            AuthenticatorDataErr::UserNotPresent(()) => Self::UserNotPresent,
            AuthenticatorDataErr::FlagsBit1Not0 => Self::FlagsBit1Not0,
            AuthenticatorDataErr::FlagsBit5Not0 => Self::FlagsBit5Not0,
            AuthenticatorDataErr::AttestedCredentialData => Self::AttestedCredentialDataIncluded,
            AuthenticatorDataErr::AttestedCredential(val) => match val {},
            AuthenticatorDataErr::BackupWithoutEligibility => Self::BackupWithoutEligibility,
            AuthenticatorDataErr::AuthenticatorExtension(err) => Self::AuthenticatorExtension(err),
            AuthenticatorDataErr::NoExtensionBitWithData => Self::NoExtensionBitWithData,
            AuthenticatorDataErr::ExtensionBitWithoutData => Self::ExtensionBitWithoutData,
            AuthenticatorDataErr::TrailingData => Self::TrailingData,
        }
    }
}
impl<'a, A> FromCbor<'a> for A
where
    A: AuthData<'a>,
    A::CredData: FromCbor<'a>,
    A::Ext: FromCbor<'a>,
{
    type Err = AuthenticatorDataErr<A::UpBitErr, <A::CredData as FromCbor<'a>>::Err, <A::Ext as FromCbor<'a>>::Err>;
    #[expect(clippy::big_endian_bytes, reason = "CBOR integers are in big-endian")]
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// Length of `signCount`.
        const SIGN_COUNT_LEN: usize = 4;
        /// `UP` bit (i.e., bit 0) set to 1.
        const UP: u8 = 0b0000_0001;
        /// `RFU1` bit (i.e., bit 1) set to 1.
        const RFU1: u8 = UP << 1;
        /// `UV` bit (i.e., bit 2) set to 1.
        const UV: u8 = RFU1 << 1;
        /// `BE` bit (i.e., bit 3) set to 1.
        const BE: u8 = UV << 1;
        /// `BS` bit (i.e., bit 4) set to 1.
        const BS: u8 = BE << 1;
        /// `RFU2` bit (i.e., bit 5) set to 1.
        const RFU2: u8 = BS << 1;
        /// `AT` bit (i.e., bit 6) set to 1.
        const AT: u8 = RFU2 << 1;
        /// `ED` bit (i.e., bit 7) set to 1.
        const ED: u8 = AT << 1;
        cbor.split_at_checked(Sha256::output_size()).ok_or_else(|| AuthenticatorDataErr::Len).and_then(|(rp_id_slice, rp_id_rem)| {
            rp_id_rem.split_first().ok_or_else(|| AuthenticatorDataErr::Len).and_then(|(&flag, flag_rem)| {
                let user_present = flag & UP == UP;
                if user_present {
                    Ok(())
                } else {
                    A::user_is_not_present().map_err(AuthenticatorDataErr::UserNotPresent)   
                }
                .and_then(|()| {
                    if flag & RFU1 == 0 {
                        if flag & RFU2 == 0 {
                            let at_bit = A::contains_at_bit();
                            if flag & AT == AT {
                                if at_bit {
                                    Ok(())
                                } else {
                                    Err(AuthenticatorDataErr::AttestedCredentialData)
                                }
                            } else if at_bit {
                                Err(AuthenticatorDataErr::AttestedCredentialData)
                            } else {
                                Ok(())
                            }.and_then(|()| {
                                let bs = flag & BS == BS;
                                if flag & BE == BE {
                                    if bs {
                                        Ok(Backup::Exists)
                                    } else {
                                        Ok(Backup::Eligible)
                                    }
                                } else if bs {
                                    Err(AuthenticatorDataErr::BackupWithoutEligibility)
                                } else {
                                    Ok(Backup::NotEligible)
                                }
                                .and_then(|backup| {
                                    flag_rem.split_at_checked(SIGN_COUNT_LEN).ok_or_else(|| AuthenticatorDataErr::Len).and_then(|(count_slice, count_rem)| {
                                        A::CredData::from_cbor(count_rem).map_err(AuthenticatorDataErr::AttestedCredential).and_then(|att_data| {
                                            A::Ext::from_cbor(att_data.remaining).map_err(AuthenticatorDataErr::AuthenticatorExtension).and_then(|ext| {
                                                if ext.remaining.is_empty() {
                                                    let ed = flag & ED == ED;
                                                    if ext.value.missing() {
                                                        if ed {
                                                            Err(AuthenticatorDataErr::ExtensionBitWithoutData)
                                                        } else {
                                                            Ok(())
                                                        }
                                                    } else if ed {
                                                        Ok(())
                                                    } else {
                                                        Err(AuthenticatorDataErr::NoExtensionBitWithData)
                                                    }.map(|()| {
                                                        let mut sign_count = [0; SIGN_COUNT_LEN];
                                                        sign_count.copy_from_slice(count_slice);
                                                        // `signCount` is in big-endian.
                                                        CborSuccess { value: A::new(rp_id_slice, Flag { user_present, user_verified: flag & UV == UV, backup, }, u32::from_be_bytes(sign_count), att_data.value, ext.value), remaining: ext.remaining, }
                                                    })
                                                } else {
                                                    Err(AuthenticatorDataErr::TrailingData)
                                                }
                                            })
                                        })
                                    })
                                })
                            })
                        } else {
                            Err(AuthenticatorDataErr::FlagsBit5Not0)
                        }
                    } else {
                        Err(AuthenticatorDataErr::FlagsBit1Not0)
                    }
                })
            })
        })
    }
}
/// Data returned by [`AuthDataContainer::from_data`].
pub(super) struct ParsedAuthData<'a, A> {
    /// The data the CBOR is parsed into.
    data: A,
    /// The raw authenticator data and 32-bytes of trailing data.
    auth_data_and_32_trailing_bytes: &'a [u8],
}
/// Error returned by [`AuthResponse::parse_data_and_verify_sig`].
pub(super) enum AuthRespErr<AuthDataErr> {
    /// Variant returned when parsing
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson)
    /// into [`CollectedClientData`] fails.
    CollectedClientData(CollectedClientDataErr),
    /// Variant returned when parsing
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson)
    /// in a "relaxed" way into [`CollectedClientData`] fails.
    #[cfg(feature = "serde_relaxed")]
    CollectedClientDataRelaxed(SerdeJsonErr),
    /// Variant returned when parsing [`AuthResponse::Auth`] fails.
    Auth(AuthDataErr),
    /// Variant when the [`CompressedPubKey`] or [`UncompressePubKey`] is not valid.
    PubKey(PubKeyErr),
    /// Variant returned when the signature, if one exists, associated with
    /// [`Self::AuthResponse`] is invalid.
    Signature,
}
impl<A: Display> Display for AuthRespErr<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::CollectedClientData(ref err) => write!(f, "CollectedClientData could not be parsed: {err}"),
            #[cfg(feature = "serde_relaxed")]
            Self::CollectedClientDataRelaxed(ref err) => write!(f, "CollectedClientData could not be parsed: {err}"),
            Self::Auth(ref err) => write!(f, "auth data could not be parsed: {err}"),
            Self::PubKey(err) => err.fmt(f),
            Self::Signature => f.write_str("the signature over the authenticator data and CollectedClientData could not be verified"),
        }
    }
}
impl From<AuthRespErr<AttestationObjectErr>> for RegCeremonyErr {
    #[inline]
    fn from(value: AuthRespErr<AttestationObjectErr>) -> Self {
        match value {
            AuthRespErr::CollectedClientData(err) => Self::CollectedClientData(err),
            #[cfg(feature = "serde_relaxed")]
            AuthRespErr::CollectedClientDataRelaxed(err) => Self::CollectedClientDataRelaxed(err),
            AuthRespErr::Auth(err) => Self::AttestationObject(err),
            AuthRespErr::PubKey(err) => Self::PubKey(err),
            AuthRespErr::Signature => Self::AttestationSignature,
        }
    }
}
impl From<AuthRespErr<AuthAuthDataErr>> for AuthCeremonyErr {
    #[inline]
    fn from(value: AuthRespErr<AuthAuthDataErr>) -> Self {
        match value {
            AuthRespErr::CollectedClientData(err) => Self::CollectedClientData(err),
            #[cfg(feature = "serde_relaxed")]
            AuthRespErr::CollectedClientDataRelaxed(err) => Self::CollectedClientDataRelaxed(err),
            AuthRespErr::Auth(err) => Self::AuthenticatorData(err),
            AuthRespErr::PubKey(err) => Self::PubKey(err),
            AuthRespErr::Signature => Self::AssertionSignature,
        }
    }
}
/// [Authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data)
/// container.
///
/// Note [`Self::Auth`] may be `Self`.
pub(super) trait AuthDataContainer<'a>: Sized {
    /// [Authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data).
    type Auth: AuthData<'a>;
    /// Error returned from [`Self::from_data`].
    type Err;
    /// Converts `data` into [`ParsedAuthData`].
    ///
    /// # Errors
    ///
    /// Errors iff `data` cannot be converted into `ParsedAuthData`.
    fn from_data(data: &'a [u8]) -> Result<ParsedAuthData<'a, Self>, Self::Err>;
    /// Returns the contained
    /// [authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data).
    fn authenticator_data(&self) -> &Self::Auth;
}
/// [`AuthenticatorResponse`](https://www.w3.org/TR/webauthn-3/#authenticatorresponse).
pub(super) trait AuthResponse {
    /// [Attestation object](https://www.w3.org/TR/webauthn-3/#attestation-object) or
    /// [authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data).
    type Auth<'a>: AuthDataContainer<'a> where Self: 'a;
    /// Public key to use to verify the contained signature.
    type CredKey<'a>;
    /// Parses
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson)
    /// based on `RELAXED` and [`Self::Auth`] via [`AuthDataContainer::from_data`] in addition to
    /// verifying any possible signature over the concatenation of the raw
    /// [`AuthDataContainer::Auth`] and `clientDataJSON` using `key` or the contained
    /// public key if one exists. If `Self` contains a public key and should not be passed one, then it should set
    /// [`Self::CredKey`] to `()`.
    ///
    /// # Errors
    ///
    /// Errors iff parsing `clientDataJSON` errors, [`AuthDataContainer::from_data`] does, or the signature
    /// is invalid.
    ///
    /// # Panics
    ///
    /// `panic`s iff `relaxed` and `serde_relaxed` is not enabled.
    #[expect(
        clippy::type_complexity,
        reason = "type aliases with bounds are even more problematic at least until lazy_type_alias is stable"
    )]
    fn parse_data_and_verify_sig(&self, key: Self::CredKey<'_>, relaxed: bool) -> Result<(CollectedClientData<'_>, Self::Auth<'_>), AuthRespErr<<Self::Auth<'_> as AuthDataContainer<'_>>::Err>>;
}
/// Ceremony response (i.e., [`PublicKeyCredential`](https://www.w3.org/TR/webauthn-3/#publickeycredential)).
pub(super) trait Response {
    /// [`AuthenticatorResponse`](https://www.w3.org/TR/webauthn-3/#authenticatorresponse).
    type Auth: AuthResponse;
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response).
    fn auth(&self) -> &Self::Auth;
}
/// Error returned from [`Ceremony::partial_validate`].
pub(super) enum CeremonyErr<AuthDataErr> {
    /// Timeout occurred.
    Timeout,
    /// Read [`AuthRespErr`] for information.
    AuthResp(AuthRespErr<AuthDataErr>),
    /// Origin did not validate.
    OriginMismatch,
    /// Cross origin was `true` but was not allowed to be.
    CrossOrigin,
    /// Top origin did not validate.
    TopOriginMismatch,
    /// Challenges don't match.
    ChallengeMismatch,
    /// `rpIdHash` does not match the SHA-256 hash of the [`RpId`].
    RpIdHashMismatch,
    /// User was not verified despite being required to.
    UserNotVerified,
    /// [`Backup::NotEligible`] was not sent back despite [`BackupReq::NotEligible`].
    BackupEligible,
    /// [`Backup::NotEligible`] was sent back despite [`BackupReq::Eligible`].
    BackupNotEligible,
    /// [`Backup::Eligible`] was not sent back despite [`BackupReq::EligibleNoteExists`].
    BackupExists,
    /// [`Backup::Exists`] was not sent back despite [`BackupReq::Exists`].
    BackupDoesNotExist,
}
impl<A: Display> Display for CeremonyErr<A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Timeout => f.write_str("ceremony timed out"),
            Self::AuthResp(ref err) => err.fmt(f),
            Self::OriginMismatch => {
                f.write_str("the origin sent from the client is not an allowed origin")
            }
            Self::CrossOrigin => {
                f.write_str("cross origin was from the client, but it is not allowed")
            }
            Self::TopOriginMismatch => {
                f.write_str("the top origin sent from the client is not an allowed top origin")
            }
            Self::ChallengeMismatch => f.write_str(
                "the challenge sent to the client does not match the challenge sent back",
            ),
            Self::RpIdHashMismatch => f.write_str(
                "the SHA-256 hash of the RP ID doesn't match the hash sent from the client",
            ),
            Self::UserNotVerified => f.write_str("user was not verified despite being required to"),
            Self::BackupEligible => f.write_str("credential is eligible to be backed up despite requiring that it not be"),
            Self::BackupNotEligible => f.write_str("credential is not eligible to be backed up despite requiring that it be"),
            Self::BackupExists => f.write_str("credential backup exists despite requiring that a backup not exist"),
            Self::BackupDoesNotExist => f.write_str("credential backup does not exist despite requiring that a backup exist"),
        }
    }
}
impl From<CeremonyErr<AttestationObjectErr>> for RegCeremonyErr {
    #[inline]
    fn from(value: CeremonyErr<AttestationObjectErr>) -> Self {
        match value {
            CeremonyErr::Timeout => Self::Timeout,
            CeremonyErr::AuthResp(err) => err.into(),
            CeremonyErr::OriginMismatch => Self::OriginMismatch,
            CeremonyErr::CrossOrigin => Self::CrossOrigin,
            CeremonyErr::TopOriginMismatch => Self::TopOriginMismatch,
            CeremonyErr::ChallengeMismatch => Self::ChallengeMismatch,
            CeremonyErr::RpIdHashMismatch => Self::RpIdHashMismatch,
            CeremonyErr::UserNotVerified => Self::UserNotVerified,
            CeremonyErr::BackupEligible => Self::BackupEligible,
            CeremonyErr::BackupNotEligible => Self::BackupNotEligible,
            CeremonyErr::BackupExists => Self::BackupExists,
            CeremonyErr::BackupDoesNotExist => Self::BackupDoesNotExist,
        }
    }
}
impl From<CeremonyErr<AuthAuthDataErr>> for AuthCeremonyErr {
    #[inline]
    fn from(value: CeremonyErr<AuthAuthDataErr>) -> Self {
        match value {
            CeremonyErr::Timeout => Self::Timeout,
            CeremonyErr::AuthResp(err) => err.into(),
            CeremonyErr::OriginMismatch => Self::OriginMismatch,
            CeremonyErr::CrossOrigin => Self::CrossOrigin,
            CeremonyErr::TopOriginMismatch => Self::TopOriginMismatch,
            CeremonyErr::ChallengeMismatch => Self::ChallengeMismatch,
            CeremonyErr::RpIdHashMismatch => Self::RpIdHashMismatch,
            CeremonyErr::UserNotVerified => Self::UserNotVerified,
            CeremonyErr::BackupEligible => Self::BackupEligible,
            CeremonyErr::BackupNotEligible => Self::BackupNotEligible,
            CeremonyErr::BackupExists => Self::BackupExists,
            CeremonyErr::BackupDoesNotExist => Self::BackupDoesNotExist,
        }
    }
}
/// [`AllAcceptedCredentialsOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-allacceptedcredentialsoptions).
///
/// This can be sent to _an already authenticated user_ to inform what credentials are currently registered.
/// This can be useful when a user deletes credentials on the RP's side but does not do so on the authenticator.
/// When the client forwards this response to the authenticator, it can remove all credentials that don't have
/// a [`CredentialId`] in [`Self::all_accepted_credential_ids`].
#[derive(Debug)]
pub struct AllAcceptedCredentialsOptions<'rp, 'user, const USER_LEN: usize> {
    /// [`rpId`](https://www.w3.org/TR/webauthn-3/#dictdef-allacceptedcredentialsoptions-rpid).
    pub rp_id: &'rp RpId,
    /// [`userId`](https://www.w3.org/TR/webauthn-3/#dictdef-allacceptedcredentialsoptions-userid).
    pub user_id: &'user UserHandle<USER_LEN>,
    /// [`allAcceptedCredentialIds`](https://www.w3.org/TR/webauthn-3/#dictdef-allacceptedcredentialsoptions-allacceptedcredentialids).
    pub all_accepted_credential_ids: Vec<CredentialId<Box<[u8]>>>,
}
/// [`CurrentUserDetailsOptions`](https://www.w3.org/TR/webauthn-3/#dictdef-currentuserdetailsoptions).
///
/// This can be sent to _an already authenticated user_ to inform the user information.
/// This can be useful when a user updates their user information on the RP's side but does not do so on the authenticator.
/// When the client forwards this response to the authenticator, it can update the user info for the associated credential.
#[derive(Debug)]
pub struct CurrentUserDetailsOptions<'rp_id, 'name, 'display_name, 'id, const LEN: usize> {
    /// [`rpId`](https://www.w3.org/TR/webauthn-3/#dictdef-currentuserdetailsoptions-rpid).
    pub rp_id: &'rp_id RpId,
    /// [`userId`](https://www.w3.org/TR/webauthn-3/#dictdef-currentuserdetailsoptions-userid),
    /// [`name`](https://www.w3.org/TR/webauthn-3/#dictdef-currentuserdetailsoptions-name), and
    /// [`displayName`](https://www.w3.org/TR/webauthn-3/#dictdef-currentuserdetailsoptions-displayname).
    pub user: PublicKeyCredentialUserEntity<'name, 'display_name, 'id, LEN>,
}
/// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
/// during authentication and
/// [`hmac-secret-mc`](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-make-cred-extension)
/// during registration.
///
/// `REG` iff `hmac-secret-mc`.
enum HmacSecretGet<const REG: bool> {
    /// No `hmac-secret` response.
    None,
    /// One encrypted `hmac-secret`.
    One,
    /// Two encrypted `hmac-secret`s.
    Two,
}
/// Error returned by [`HmacSecretGet::from_cbor`]
enum HmacSecretGetErr {
    /// Error related to the length of the CBOR input.
    Len,
    /// Error related to the type of the CBOR key.
    Type,
    /// Error related to the value of the CBOR value.
    Value,
}
impl<const REG: bool> FromCbor<'_> for HmacSecretGet<REG> {
    type Err = HmacSecretGetErr;
    fn from_cbor(cbor: &[u8]) -> Result<CborSuccess<'_, Self>, Self::Err> {
        /// AES block size.
        const AES_BLOCK_SIZE: usize = 16;
        /// HMAC-SHA-256 output length.
        const HMAC_SHA_256_LEN: usize = 32;
        /// Length of two HMAC-SHA-256 outputs concatenated together.
        const TWO_HMAC_SHA_256_LEN: usize = HMAC_SHA_256_LEN << 1;
        // We need the smallest multiple of `AES_BLOCK_SIZE` that
        // is strictly greater than `HMAC_SHA_256_LEN`.
        /// AES-256 output length on a 32-byte input.
        #[expect(
            clippy::integer_division_remainder_used,
            reason = "doesn't need to be constant time"
        )]
        const ONE_SECRET_LEN: usize =
            HMAC_SHA_256_LEN + (AES_BLOCK_SIZE - (HMAC_SHA_256_LEN % AES_BLOCK_SIZE));
        // We need the smallest multiple of `AES_BLOCK_SIZE` that
        // is strictly greater than `TWO_HMAC_SHA_256_LEN`.
        /// AES-256 output length on a 64-byte input.
        #[expect(
            clippy::integer_division_remainder_used,
            reason = "doesn't need to be constant time"
        )]
        const TWO_SECRET_LEN: usize =
            TWO_HMAC_SHA_256_LEN + (AES_BLOCK_SIZE - (TWO_HMAC_SHA_256_LEN % AES_BLOCK_SIZE));
        /// `hmac-secret-mc`.
        ///
        /// This is the key iff `REG`.
        const KEY: [u8; 15] = [
            cbor::TEXT_14,
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
            b'-',
            b'm',
            b'c',
        ];
        /// Helper that unifies `HmacSecretGet`.
        enum CborVal<'a> {
            /// Extension does not exist with remaining payload
            Success,
            /// Extension exists with remaining payload.
            Continue(&'a [u8]),
        }
        if REG {
            cbor.split_at_checked(KEY.len()).map_or(
                Ok(CborVal::Success),
                |(key, key_rem)| {
                    if key == KEY {
                        Ok(CborVal::Continue(key_rem))
                    } else {
                        Ok(CborVal::Success)
                    }
                }
            )
        } else {
            cbor.split_at_checked(cbor::HMAC_SECRET.len()).map_or(
                Ok(CborVal::Success),
                |(key, key_rem)| {
                    if key == cbor::HMAC_SECRET {
                        Ok(CborVal::Continue(key_rem))
                    } else {
                        Ok(CborVal::Success)
                    }
                }
            )
        }.and_then(|cbor_val| {
            match cbor_val {
                CborVal::Success => Ok(CborSuccess { value: Self::None, remaining: cbor, }),
                CborVal::Continue(key_rem) => {
                    key_rem
                        .split_first()
                        .ok_or(HmacSecretGetErr::Len)
                        .and_then(|(bytes, bytes_rem)| {
                            if *bytes == cbor::BYTES_INFO_24 {
                                bytes_rem
                                    .split_first()
                                    .ok_or(HmacSecretGetErr::Len)
                                    .and_then(|(&len, len_rem)| {
                                        len_rem.split_at_checked(usize::from(len)).ok_or(HmacSecretGetErr::Len).and_then(|(_, remaining)| {
                                            match usize::from(len) {
                                                ONE_SECRET_LEN => {
                                                    Ok(CborSuccess {
                                                        value: Self::One,
                                                        remaining,
                                                    })
                                                }
                                                TWO_SECRET_LEN => {
                                                    Ok(CborSuccess {
                                                        value: Self::Two,
                                                        remaining,
                                                    })
                                                }
                                                _ => Err(HmacSecretGetErr::Value),
                                            }
                                        })
                                    })
                            } else {
                                Err(HmacSecretGetErr::Type)
                            }
                        })
                }
            }
        })
    }
}
