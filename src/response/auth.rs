#[cfg(feature = "serde_relaxed")]
use self::{
    super::ser_relaxed::{RelaxedClientDataJsonParser, SerdeJsonErr},
    ser_relaxed::{AuthenticationRelaxed, CustomAuthentication},
};
#[cfg(doc)]
use super::super::{
    AuthenticatedCredential, RegisteredCredential, StaticState,
    hash::hash_set::MaxLenHashSet,
    request::{
        Challenge,
        auth::{
            CredentialSpecificExtension, DiscoverableAuthenticationServerState, Extension,
            NonDiscoverableAuthenticationServerState, PublicKeyCredentialRequestOptions,
        },
        register::{self, UserHandle16, UserHandle64},
    },
};
use super::{
    super::{UserHandle, request::register::USER_HANDLE_MAX_LEN},
    AuthData, AuthDataContainer, AuthExtOutput, AuthRespErr, AuthResponse, AuthenticatorAttachment,
    CborSuccess, ClientDataJsonParser as _, CollectedClientData, CredentialId, Flag, FromCbor,
    HmacSecretGet, HmacSecretGetErr, LimitedVerificationParser, ParsedAuthData, Response,
    SentChallenge,
    auth::error::{AuthenticatorDataErr, AuthenticatorExtensionOutputErr, MissingUserHandleErr},
    cbor,
    error::CollectedClientDataErr,
    register::CompressedPubKeyBorrowed,
};
use core::convert::Infallible;
use ed25519_dalek::{Signature, Verifier as _};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, Signature as MlDsaSig};
use p256::ecdsa::DerSignature as P256DerSig;
use p384::ecdsa::DerSignature as P384DerSig;
use rsa::{
    pkcs1v15,
    sha2::{Sha256, digest::Digest as _},
};
#[cfg(feature = "serde_relaxed")]
use serde::Deserialize;
/// Contains error types.
pub mod error;
/// Contains functionality to deserialize data from a client.
#[cfg(feature = "serde")]
pub(super) mod ser;
/// Contains functionality to deserialize data from a client in a "relaxed" way.
#[cfg(feature = "serde_relaxed")]
pub mod ser_relaxed;
/// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension).
///
/// This is only relevant when [`Extension::prf`] or [`CredentialSpecificExtension::prf`] is `Some` and for
/// authenticators that implement [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension) on top of
/// `hmac-secret`.
///
/// Note while many authenticators that implement `prf` don't require `prf` to have been sent during registration
/// (i.e., [`register::Extension::prf`]), it is recommended to do so for those authenticators that do require it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HmacSecret {
    /// No `hmac-secret` response.
    ///
    /// Either [`Extension::prf`] was not sent, the credential is not PRF-capable, or the authenticator does not use
    /// the
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// extension.
    None,
    /// One encrypted `hmac-secret`.
    ///
    /// [`Extension::prf`] was sent with one PRF input for a PRF-capable credential whose authenticator implements
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension) on top of the
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// extension.
    One,
    /// Two encrypted `hmac-secret`s.
    ///
    /// [`Extension::prf`] was sent with two PRF inputs for a PRF-capable credential whose authenticator implements
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#prf-extension) on top of the
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// extension.
    Two,
}
/// [Authenticator extension output](https://www.w3.org/TR/webauthn-3/#authenticator-extension-output).
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatorExtensionOutput {
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension).
    pub hmac_secret: HmacSecret,
}
impl AuthExtOutput for AuthenticatorExtensionOutput {
    fn missing(self) -> bool {
        matches!(self.hmac_secret, HmacSecret::None)
    }
}
impl From<HmacSecretGetErr> for AuthenticatorExtensionOutputErr {
    #[inline]
    fn from(value: HmacSecretGetErr) -> Self {
        match value {
            HmacSecretGetErr::Len => Self::Len,
            HmacSecretGetErr::Type => Self::HmacSecretType,
            HmacSecretGetErr::Value => Self::HmacSecretValue,
        }
    }
}
impl FromCbor<'_> for AuthenticatorExtensionOutput {
    type Err = AuthenticatorExtensionOutputErr;
    fn from_cbor(cbor: &[u8]) -> Result<CborSuccess<'_, Self>, Self::Err> {
        // We don't allow unsupported extensions; thus the only possibilities is any ordered element of
        // the power set of {"hmac-secret":<HmacSecret>}.
        let mut hmac_secret = HmacSecret::None;
        let mut remaining = cbor;
        cbor.split_first()
            .map_or(Ok(()), |(map, map_rem)| {
                if *map == cbor::MAP_1 {
                    HmacSecretGet::<false>::from_cbor(map_rem)
                        .map_err(AuthenticatorExtensionOutputErr::from)
                        .and_then(|hmac_succ| match hmac_succ.value {
                            HmacSecretGet::None => Err(AuthenticatorExtensionOutputErr::Missing),
                            HmacSecretGet::One => {
                                hmac_secret = HmacSecret::One;
                                remaining = hmac_succ.remaining;
                                Ok(())
                            }
                            HmacSecretGet::Two => {
                                hmac_secret = HmacSecret::Two;
                                remaining = hmac_succ.remaining;
                                Ok(())
                            }
                        })
                } else {
                    Err(AuthenticatorExtensionOutputErr::CborHeader)
                }
            })
            .map(|()| CborSuccess {
                value: Self { hmac_secret },
                remaining,
            })
    }
}
/// Unit type for `AuthData::CredData`.
pub(crate) struct NoCred;
impl FromCbor<'_> for NoCred {
    type Err = Infallible;
    fn from_cbor(cbor: &[u8]) -> Result<CborSuccess<'_, Self>, Self::Err> {
        Ok(CborSuccess {
            value: Self,
            remaining: cbor,
        })
    }
}
/// [Authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data).
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatorData<'a> {
    /// [`rpIdHash`](https://www.w3.org/TR/webauthn-3/#authdata-rpidhash).
    rp_id_hash: &'a [u8],
    /// [`flags`](https://www.w3.org/TR/webauthn-3/#authdata-flags).
    flags: Flag,
    /// [`signCount`](https://www.w3.org/TR/webauthn-3/#authdata-signcount).
    sign_count: u32,
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions).
    extensions: AuthenticatorExtensionOutput,
}
impl<'a> AuthenticatorData<'a> {
    /// [`rpIdHash`](https://www.w3.org/TR/webauthn-3/#authdata-rpidhash).
    #[inline]
    #[must_use]
    pub const fn rp_id_hash(&self) -> &'a [u8] {
        self.rp_id_hash
    }
    /// [`flags`](https://www.w3.org/TR/webauthn-3/#authdata-flags).
    #[inline]
    #[must_use]
    pub const fn flags(&self) -> Flag {
        self.flags
    }
    /// [`signCount`](https://www.w3.org/TR/webauthn-3/#authdata-signcount).
    #[inline]
    #[must_use]
    pub const fn sign_count(&self) -> u32 {
        self.sign_count
    }
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions).
    #[inline]
    #[must_use]
    pub const fn extensions(&self) -> AuthenticatorExtensionOutput {
        self.extensions
    }
}
impl<'a> AuthData<'a> for AuthenticatorData<'a> {
    type UpBitErr = ();
    type CredData = NoCred;
    type Ext = AuthenticatorExtensionOutput;
    fn contains_at_bit() -> bool {
        false
    }
    fn user_is_not_present() -> Result<(), Self::UpBitErr> {
        Err(())
    }
    fn new(
        rp_id_hash: &'a [u8],
        flags: Flag,
        sign_count: u32,
        _: Self::CredData,
        extensions: Self::Ext,
    ) -> Self {
        Self {
            rp_id_hash,
            flags,
            sign_count,
            extensions,
        }
    }
    fn rp_hash(&self) -> &'a [u8] {
        self.rp_id_hash
    }
    fn flag(&self) -> Flag {
        self.flags
    }
}
impl<'a> AuthDataContainer<'a> for AuthenticatorData<'a> {
    type Auth = Self;
    type Err = AuthenticatorDataErr;
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    #[expect(clippy::indexing_slicing, reason = "comment justifies its correctness")]
    fn from_data(data: &'a [u8]) -> Result<ParsedAuthData<'a, Self>, Self::Err> {
        // `data.len().checked_sub(Sha256::output_size()).unwrap()` is less than `data.len()`,
        // so indexing is fine.
        Self::try_from(&data[..data.len().checked_sub(Sha256::output_size()).unwrap_or_else(|| unreachable!("AuthenticatorData::from_data must be passed a slice with 32 bytes of trailing data"))]).map(|auth_data| ParsedAuthData { data: auth_data, auth_data_and_32_trailing_bytes: data, })
    }
    fn authenticator_data(&self) -> &Self::Auth {
        self
    }
}
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for AuthenticatorData<'b> {
    type Error = AuthenticatorDataErr;
    /// Deserializes `value` based on the
    /// [authenticator data structure](https://www.w3.org/TR/webauthn-3/#table-authData).
    #[expect(
        clippy::panic_in_result_fn,
        reason = "we want to crash when there is a bug"
    )]
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_cbor(value)
            .map_err(AuthenticatorDataErr::from)
            .map(|auth_data| {
                assert!(
                    auth_data.remaining.is_empty(),
                    "there is a bug in AuthenticatorData::from_cbor"
                );
                auth_data.value
            })
    }
}
/// [`AuthenticatorAssertionResponse`](https://www.w3.org/TR/webauthn-3/#authenticatorassertionresponse).
#[derive(Debug)]
pub struct AuthenticatorAssertion<const USER_LEN: usize, const DISCOVERABLE: bool> {
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson).
    client_data_json: Vec<u8>,
    /// [`authenticatorData`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-authenticatordata)
    /// followed by the SHA-256 hash of [`Self::client_data_json`].
    authenticator_data_and_c_data_hash: Vec<u8>,
    /// [`signature`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-signature).
    signature: Vec<u8>,
    /// [`userHandle`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle).
    user_handle: Option<UserHandle<USER_LEN>>,
}
impl<const USER_LEN: usize, const DISCOVERABLE: bool>
    AuthenticatorAssertion<USER_LEN, DISCOVERABLE>
{
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson).
    #[inline]
    #[must_use]
    pub const fn client_data_json(&self) -> &[u8] {
        self.client_data_json.as_slice()
    }
    /// [`authenticatorData`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-authenticatordata).
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "comment justifies their correctness"
    )]
    #[inline]
    #[must_use]
    pub fn authenticator_data(&self) -> &[u8] {
        // We only allow creation via [`Self::new`] which creates [`Self::authenticator_data_and_c_data_hash`]
        // by appending the SHA-256 hash of [`Self::client_data_json`] to the authenticator data that was passed;
        // thus indexing is fine and subtraction won't cause underflow.
        &self.authenticator_data_and_c_data_hash
            [..self.authenticator_data_and_c_data_hash.len() - Sha256::output_size()]
    }
    /// [`signature`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-signature).
    #[inline]
    #[must_use]
    pub const fn signature(&self) -> &[u8] {
        self.signature.as_slice()
    }
    /// Constructs an instance of `Self` with the contained data.
    ///
    /// Note calling code is encouraged to ensure `authenticator_data` has at least 32 bytes
    /// of available capacity; if not, a reallocation will occur.
    fn new_inner(
        client_data_json: Vec<u8>,
        mut authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Option<UserHandle<USER_LEN>>,
    ) -> Self {
        authenticator_data.extend_from_slice(&Sha256::digest(client_data_json.as_slice()));
        Self {
            client_data_json,
            authenticator_data_and_c_data_hash: authenticator_data,
            signature,
            user_handle,
        }
    }
}
impl<const USER_LEN: usize> AuthenticatorAssertion<USER_LEN, false> {
    /// [`userHandle`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle).
    #[inline]
    #[must_use]
    pub const fn user_handle(&self) -> Option<&UserHandle<USER_LEN>> {
        self.user_handle.as_ref()
    }
    /// Constructs an instance of `Self` with the contained data.
    ///
    /// Note calling code is encouraged to ensure `authenticator_data` has at least 32 bytes
    /// of available capacity; if not, a reallocation will occur.
    #[inline]
    #[must_use]
    pub fn with_optional_user(
        client_data_json: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Option<UserHandle<USER_LEN>>,
    ) -> Self {
        Self::new_inner(client_data_json, authenticator_data, signature, user_handle)
    }
    /// Same as [`Self::with_optional_user`] with `None` used for `user_handle`.
    #[inline]
    #[must_use]
    pub fn without_user(
        client_data_json: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Self::with_optional_user(client_data_json, authenticator_data, signature, None)
    }
    /// Same as [`Self::with_optional_user`] with `Some(user_handle)` used for `user_handle`.
    #[inline]
    #[must_use]
    pub fn with_user(
        client_data_json: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: UserHandle<USER_LEN>,
    ) -> Self {
        Self::with_optional_user(
            client_data_json,
            authenticator_data,
            signature,
            Some(user_handle),
        )
    }
}
impl<const USER_LEN: usize> AuthenticatorAssertion<USER_LEN, true> {
    /// [`userHandle`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle).
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    #[inline]
    #[must_use]
    pub fn user_handle(&self) -> &UserHandle<USER_LEN> {
        self.user_handle
            .as_ref()
            .unwrap_or_else(|| unreachable!("bug in AuthenticatorAssertion<USER_LEN, true>"))
    }
    /// Constructs an instance of `Self` with the contained data.
    ///
    /// Note calling code is encouraged to ensure `authenticator_data` has at least 32 bytes
    /// of available capacity; if not, a reallocation will occur.
    #[inline]
    #[must_use]
    pub fn new(
        client_data_json: Vec<u8>,
        authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: UserHandle<USER_LEN>,
    ) -> Self {
        Self::new_inner(
            client_data_json,
            authenticator_data,
            signature,
            Some(user_handle),
        )
    }
}
impl<const USER_LEN: usize, const DISCOVERABLE: bool> AuthResponse
    for AuthenticatorAssertion<USER_LEN, DISCOVERABLE>
{
    type Auth<'a>
        = AuthenticatorData<'a>
    where
        Self: 'a;
    type CredKey<'a> = CompressedPubKeyBorrowed<'a>;
    #[expect(clippy::too_many_lines, reason = "134 lines is OK")]
    fn parse_data_and_verify_sig(
        &self,
        key: Self::CredKey<'_>,
        relaxed: bool,
    ) -> Result<
        (CollectedClientData<'_>, Self::Auth<'_>),
        AuthRespErr<<Self::Auth<'_> as AuthDataContainer<'_>>::Err>,
    > {
        /// Always `panic`s.
        #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
        #[cfg(not(feature = "serde_relaxed"))]
        fn get_client_collected_data<const LEN: usize, const DISC: bool>(_: &[u8]) -> ! {
            unreachable!(
                "AuthenticatorAssertion::parse_data_and_verify_sig must be passed false when serde_relaxed is not enabled"
            );
        }
        /// Parses `data` using `CollectedClientData::from_client_data_json_relaxed::<false>`.
        #[cfg(feature = "serde_relaxed")]
        fn get_client_collected_data<const LEN: usize, const DISC: bool>(
            data: &[u8],
        ) -> Result<
            CollectedClientData<'_>,
            AuthRespErr<
                <<AuthenticatorAssertion<LEN, DISC> as AuthResponse>::Auth<'_> as AuthDataContainer<'_>>::Err,
            >,
        >{
            CollectedClientData::from_client_data_json_relaxed::<false>(data)
                .map_err(AuthRespErr::CollectedClientDataRelaxed)
        }
        if relaxed {
            get_client_collected_data::<USER_LEN, DISCOVERABLE>(self.client_data_json.as_slice())
        } else {
            CollectedClientData::from_client_data_json::<false>(self.client_data_json.as_slice())
                .map_err(AuthRespErr::CollectedClientData)
        }
        .and_then(|client_data_json| {
            Self::Auth::from_data(self.authenticator_data_and_c_data_hash.as_slice())
                .map_err(AuthRespErr::Auth)
                .and_then(|val| {
                    match key {
                        CompressedPubKeyBorrowed::MlDsa87(k) => self
                            .signature
                            .as_slice()
                            .try_into()
                            .map_err(|_e| AuthRespErr::Signature)
                            .and_then(|s| {
                                MlDsaSig::<MlDsa87>::decode(s)
                                    .ok_or(AuthRespErr::Signature)
                                    .and_then(|sig| {
                                        k.into_ver_key()
                                            .verify(
                                                self.authenticator_data_and_c_data_hash.as_slice(),
                                                &sig,
                                            )
                                            .map_err(|_e| AuthRespErr::Signature)
                                    })
                            }),
                        CompressedPubKeyBorrowed::MlDsa65(k) => self
                            .signature
                            .as_slice()
                            .try_into()
                            .map_err(|_e| AuthRespErr::Signature)
                            .and_then(|s| {
                                MlDsaSig::<MlDsa65>::decode(s)
                                    .ok_or(AuthRespErr::Signature)
                                    .and_then(|sig| {
                                        k.into_ver_key()
                                            .verify(
                                                self.authenticator_data_and_c_data_hash.as_slice(),
                                                &sig,
                                            )
                                            .map_err(|_e| AuthRespErr::Signature)
                                    })
                            }),
                        CompressedPubKeyBorrowed::MlDsa44(k) => self
                            .signature
                            .as_slice()
                            .try_into()
                            .map_err(|_e| AuthRespErr::Signature)
                            .and_then(|s| {
                                MlDsaSig::<MlDsa44>::decode(s)
                                    .ok_or(AuthRespErr::Signature)
                                    .and_then(|sig| {
                                        k.into_ver_key()
                                            .verify(
                                                self.authenticator_data_and_c_data_hash.as_slice(),
                                                &sig,
                                            )
                                            .map_err(|_e| AuthRespErr::Signature)
                                    })
                            }),
                        CompressedPubKeyBorrowed::Ed25519(k) => k
                            .into_ver_key()
                            .map_err(AuthRespErr::PubKey)
                            .and_then(|ver_key| {
                                Signature::from_slice(self.signature.as_slice())
                                    .and_then(|sig| {
                                        // We don't need to use `VerifyingKey::verify_strict` since
                                        // `Ed25519PubKey::into_ver_key` verifies the public key is not
                                        // in the small-order subgroup. `VerifyingKey::verify_strict` additionally
                                        // ensures _R_ of the signature is not in the small-order subgroup, but this
                                        // doesn't provide additional benefits and is still not enough to comply
                                        // with standards like RFC 8032 or NIST SP 800-186.
                                        ver_key.verify(
                                            self.authenticator_data_and_c_data_hash.as_slice(),
                                            &sig,
                                        )
                                    })
                                    .map_err(|_e| AuthRespErr::Signature)
                            }),
                        CompressedPubKeyBorrowed::P256(k) => k
                            .into_ver_key()
                            .map_err(AuthRespErr::PubKey)
                            .and_then(|ver_key| {
                                P256DerSig::from_bytes(self.signature.as_slice())
                                    .and_then(|sig| {
                                        ver_key.verify(
                                            self.authenticator_data_and_c_data_hash.as_slice(),
                                            &sig,
                                        )
                                    })
                                    .map_err(|_e| AuthRespErr::Signature)
                            }),
                        CompressedPubKeyBorrowed::P384(k) => k
                            .into_ver_key()
                            .map_err(AuthRespErr::PubKey)
                            .and_then(|ver_key| {
                                P384DerSig::from_bytes(self.signature.as_slice())
                                    .and_then(|sig| {
                                        ver_key.verify(
                                            self.authenticator_data_and_c_data_hash.as_slice(),
                                            &sig,
                                        )
                                    })
                                    .map_err(|_e| AuthRespErr::Signature)
                            }),
                        CompressedPubKeyBorrowed::Rsa(k) => {
                            pkcs1v15::Signature::try_from(self.signature.as_slice())
                                .and_then(|sig| {
                                    k.as_ver_key().verify(
                                        self.authenticator_data_and_c_data_hash.as_slice(),
                                        &sig,
                                    )
                                })
                                .map_err(|_e| AuthRespErr::Signature)
                        }
                    }
                    .map(|()| (client_data_json, val.data))
                })
        })
    }
}
/// `AuthenticatorAssertion` with a required `UserHandle`.
pub type DiscoverableAuthenticatorAssertion<const USER_LEN: usize> =
    AuthenticatorAssertion<USER_LEN, true>;
/// `AuthenticatorAssertion` with an optional `UserHandle`.
pub type NonDiscoverableAuthenticatorAssertion<const USER_LEN: usize> =
    AuthenticatorAssertion<USER_LEN, false>;
impl<const USER_LEN: usize> From<DiscoverableAuthenticatorAssertion<USER_LEN>>
    for NonDiscoverableAuthenticatorAssertion<USER_LEN>
{
    #[inline]
    fn from(value: DiscoverableAuthenticatorAssertion<USER_LEN>) -> Self {
        Self {
            client_data_json: value.client_data_json,
            authenticator_data_and_c_data_hash: value.authenticator_data_and_c_data_hash,
            signature: value.signature,
            user_handle: value.user_handle,
        }
    }
}
impl<const USER_LEN: usize> TryFrom<NonDiscoverableAuthenticatorAssertion<USER_LEN>>
    for DiscoverableAuthenticatorAssertion<USER_LEN>
{
    type Error = MissingUserHandleErr;
    #[inline]
    fn try_from(
        value: NonDiscoverableAuthenticatorAssertion<USER_LEN>,
    ) -> Result<Self, MissingUserHandleErr> {
        if value.user_handle.is_some() {
            Ok(Self {
                client_data_json: value.client_data_json,
                authenticator_data_and_c_data_hash: value.authenticator_data_and_c_data_hash,
                signature: value.signature,
                user_handle: value.user_handle,
            })
        } else {
            Err(MissingUserHandleErr)
        }
    }
}
/// [`PublicKeyCredential`](https://www.w3.org/TR/webauthn-3/#iface-pkcredential) for authentication ceremonies.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "no invariants to uphold"
)]
#[derive(Debug)]
pub struct Authentication<const USER_LEN: usize, const DISCOVERABLE: bool> {
    /// [`rawId`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-rawid).
    pub(crate) raw_id: CredentialId<Box<[u8]>>,
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response)
    pub(crate) response: AuthenticatorAssertion<USER_LEN, DISCOVERABLE>,
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment).
    pub(crate) authenticator_attachment: AuthenticatorAttachment,
}
impl<const USER_LEN: usize, const DISCOVERABLE: bool> Authentication<USER_LEN, DISCOVERABLE> {
    /// [`rawId`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-rawid).
    #[inline]
    #[must_use]
    pub fn raw_id(&self) -> CredentialId<&[u8]> {
        (&self.raw_id).into()
    }
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response).
    #[inline]
    #[must_use]
    pub const fn response(&self) -> &AuthenticatorAssertion<USER_LEN, DISCOVERABLE> {
        &self.response
    }
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment).
    #[inline]
    #[must_use]
    pub const fn authenticator_attachment(&self) -> AuthenticatorAttachment {
        self.authenticator_attachment
    }
    /// Constructs an `Authentication`.
    #[cfg(feature = "custom")]
    #[inline]
    #[must_use]
    pub const fn new(
        raw_id: CredentialId<Box<[u8]>>,
        response: AuthenticatorAssertion<USER_LEN, DISCOVERABLE>,
        authenticator_attachment: AuthenticatorAttachment,
    ) -> Self {
        Self {
            raw_id,
            response,
            authenticator_attachment,
        }
    }
    /// Returns the associated `SentChallenge`.
    ///
    /// This is useful when wanting to extract the corresponding [`DiscoverableAuthenticationServerState`]
    /// or [`NonDiscoverableAuthenticationServerState`] from an in-memory collection (e.g., [`MaxLenHashSet`]) or
    /// storage.
    ///
    /// Note if [`CollectedClientData::from_client_data_json`] returns `Ok`, then this will return `Ok`
    /// containing the same value as [`CollectedClientData::challenge`]; however the converse is _not_ true.
    /// This is because this function parses the minimal amount of data possible.
    ///
    /// # Errors
    ///
    /// Errors iff [`AuthenticatorAssertion::client_data_json`] does not contain a base64url-encoded
    /// [`Challenge`] in the required position.
    #[inline]
    pub fn challenge(&self) -> Result<SentChallenge, CollectedClientDataErr> {
        LimitedVerificationParser::<false>::get_sent_challenge(
            self.response.client_data_json.as_slice(),
        )
    }
    /// Returns the associated `SentChallenge`.
    ///
    /// This is useful when wanting to extract the corresponding [`DiscoverableAuthenticationServerState`]
    /// or [`NonDiscoverableAuthenticationServerState`] from an in-memory collection (e.g.,
    /// [`MaxLenHashSet`]) or storage.
    ///
    /// Note if [`CollectedClientData::from_client_data_json_relaxed`] returns `Ok`, then this will return
    /// `Ok` containing the same value as [`CollectedClientData::challenge`]; however the converse
    /// is _not_ true. This is because this function attempts to reduce the amount of data parsed.
    ///
    /// # Errors
    ///
    /// Errors iff [`AuthenticatorAssertion::client_data_json`] is invalid JSON _after_ ignoring
    /// a leading U+FEFF and replacing any sequences of invalid UTF-8 code units with U+FFFD or
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge) does not exist
    /// or is not a base64url-encoded [`Challenge`].
    #[cfg(feature = "serde_relaxed")]
    #[inline]
    pub fn challenge_relaxed(&self) -> Result<SentChallenge, SerdeJsonErr> {
        RelaxedClientDataJsonParser::<false>::get_sent_challenge(
            self.response.client_data_json.as_slice(),
        )
    }
    /// Convenience function for [`AuthenticationRelaxed::deserialize`].
    ///
    /// # Errors
    ///
    /// Errors iff [`AuthenticationRelaxed::deserialize`] does.
    #[cfg(feature = "serde_relaxed")]
    #[inline]
    pub fn from_json_relaxed<'a>(json: &'a [u8]) -> Result<Self, SerdeJsonErr>
    where
        UserHandle<USER_LEN>: Deserialize<'a>,
    {
        serde_json::from_slice::<AuthenticationRelaxed<USER_LEN, DISCOVERABLE>>(json)
            .map(|val| val.0)
    }
    /// Convenience function for [`CustomAuthentication::deserialize`].
    ///
    /// # Errors
    ///
    /// Errors iff [`CustomAuthentication::deserialize`] does.
    #[cfg(feature = "serde_relaxed")]
    #[inline]
    pub fn from_json_custom<'a>(json: &'a [u8]) -> Result<Self, SerdeJsonErr>
    where
        UserHandle<USER_LEN>: Deserialize<'a>,
    {
        serde_json::from_slice::<CustomAuthentication<USER_LEN, DISCOVERABLE>>(json)
            .map(|val| val.0)
    }
}
impl<const USER_LEN: usize, const DISCOVERABLE: bool> Response
    for Authentication<USER_LEN, DISCOVERABLE>
{
    type Auth = AuthenticatorAssertion<USER_LEN, DISCOVERABLE>;
    fn auth(&self) -> &Self::Auth {
        &self.response
    }
}
/// `Authentication` with a required [`UserHandle`].
pub type DiscoverableAuthentication<const USER_LEN: usize> = Authentication<USER_LEN, true>;
/// `Authentication` with a required [`UserHandle64`].
pub type DiscoverableAuthentication64 = Authentication<USER_HANDLE_MAX_LEN, true>;
/// `Authentication` with a required [`UserHandle16`].
pub type DiscoverableAuthentication16 = Authentication<16, true>;
/// `Authentication` with an optional [`UserHandle`].
pub type NonDiscoverableAuthentication<const USER_LEN: usize> = Authentication<USER_LEN, false>;
impl<const USER_LEN: usize> From<DiscoverableAuthentication<USER_LEN>>
    for NonDiscoverableAuthentication<USER_LEN>
{
    #[inline]
    fn from(value: DiscoverableAuthentication<USER_LEN>) -> Self {
        Self {
            raw_id: value.raw_id,
            response: value.response.into(),
            authenticator_attachment: value.authenticator_attachment,
        }
    }
}
impl<const USER_LEN: usize> TryFrom<NonDiscoverableAuthentication<USER_LEN>>
    for DiscoverableAuthentication<USER_LEN>
{
    type Error = MissingUserHandleErr;
    #[inline]
    fn try_from(
        value: NonDiscoverableAuthentication<USER_LEN>,
    ) -> Result<Self, MissingUserHandleErr> {
        value.response.try_into().map(|response| Self {
            raw_id: value.raw_id,
            response,
            authenticator_attachment: value.authenticator_attachment,
        })
    }
}
/// `Authentication` with an optional [`UserHandle64`].
pub type NonDiscoverableAuthentication64 = Authentication<USER_HANDLE_MAX_LEN, false>;
/// `Authentication` with an optional [`UserHandle16`].
pub type NonDiscoverableAuthentication16 = Authentication<16, false>;
