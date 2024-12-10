#[cfg(all(doc, feature = "serde_relaxed"))]
use super::super::request::FixedCapHashSet;
#[cfg(doc)]
use super::super::{
    request::auth::{AuthenticationServerState, PublicKeyCredentialRequestOptions},
    AuthenticatedCredential, RegisteredCredential, StaticState,
};
#[cfg(feature = "serde_relaxed")]
use super::ser_relaxed::SerdeJsonErr;
use super::{
    super::UserHandle,
    auth::error::{AuthenticatorDataErr, AuthenticatorExtensionOutputErr},
    cbor,
    error::CollectedClientDataErr,
    register::CompressedPubKey,
    AuthData, AuthDataContainer, AuthExtOutput, AuthRespErr, AuthResponse, AuthenticatorAttachment,
    CborSuccess, CollectedClientData, CredentialId, Flag, FromCbor, ParsedAuthData, Response,
    SentChallenge,
};
use core::convert::Infallible;
use ed25519_dalek::{Signature, Verifier as _};
use p256::ecdsa::DerSignature as P256DerSig;
use p384::ecdsa::DerSignature as P384DerSig;
use rsa::{
    pkcs1v15,
    sha2::{digest::Digest as _, Sha256},
};
/// Contains error types.
pub mod error;
/// Contains functionality to deserialize data from a client.
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
pub(super) mod ser;
/// Contains functionality to deserialize data from a client in a "relaxed" way.
#[cfg_attr(docsrs, doc(cfg(feature = "serde_relaxed")))]
#[cfg(feature = "serde_relaxed")]
pub mod ser_relaxed;
/// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension).
#[derive(Clone, Copy, Debug)]
pub enum HmacSecret {
    /// No `hmac-secret` response.
    None,
    /// One encrypted `hmac-secret`.
    One,
    /// Two encrypted `hmac-secret`s.
    Two,
}
impl FromCbor<'_> for HmacSecret {
    type Err = AuthenticatorExtensionOutputErr;
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
        cbor.split_at_checked(cbor::HMAC_SECRET.len())
            .ok_or(AuthenticatorExtensionOutputErr::Len)
            .and_then(|(key, key_rem)| {
                if key == cbor::HMAC_SECRET {
                    key_rem
                        .split_first()
                        .ok_or(AuthenticatorExtensionOutputErr::Len)
                        .and_then(|(bytes, bytes_rem)| {
                            if *bytes == cbor::BYTES_INFO_24 {
                                bytes_rem
                                    .split_first()
                                    .ok_or(AuthenticatorExtensionOutputErr::Len)
                                    .and_then(|(&len, len_rem)| {
                                        len_rem.split_at_checked(usize::from(len)).ok_or(AuthenticatorExtensionOutputErr::Len).and_then(|(_, remaining)| {
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
                                                _ => Err(AuthenticatorExtensionOutputErr::HmacSecretValue),
                                            }
                                        })
                                    })
                            } else {
                                Err(AuthenticatorExtensionOutputErr::HmacSecretType)
                            }
                        })
                } else {
                    Err(AuthenticatorExtensionOutputErr::Unsupported)
                }
            })
    }
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
impl FromCbor<'_> for AuthenticatorExtensionOutput {
    type Err = AuthenticatorExtensionOutputErr;
    fn from_cbor(cbor: &[u8]) -> Result<CborSuccess<'_, Self>, Self::Err> {
        // We don't allow unsupported extensions; thus the only possibilities is any ordered element of
        // the power set of {"hmac-secret":<HmacSecret>}.
        cbor.split_first().map_or_else(
            || {
                Ok(CborSuccess {
                    value: Self {
                        hmac_secret: HmacSecret::None,
                    },
                    remaining: cbor,
                })
            },
            |(map, map_rem)| {
                if *map == cbor::MAP_1 {
                    HmacSecret::from_cbor(map_rem).map(|success| CborSuccess {
                        value: Self {
                            hmac_secret: success.value,
                        },
                        remaining: success.remaining,
                    })
                } else {
                    Err(AuthenticatorExtensionOutputErr::CborHeader)
                }
            },
        )
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
pub struct AuthenticatorAssertion {
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson).
    client_data_json: Vec<u8>,
    /// [`authenticatorData`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-authenticatordata)
    /// followed by the SHA-256 hash of [`Self::client_data_json`].
    authenticator_data_and_c_data_hash: Vec<u8>,
    /// [`signature`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-signature).
    signature: Vec<u8>,
    /// [`userHandle`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle).
    user_handle: Option<UserHandle<Vec<u8>>>,
}
impl AuthenticatorAssertion {
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson).
    #[inline]
    #[must_use]
    pub fn client_data_json(&self) -> &[u8] {
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
    pub fn signature(&self) -> &[u8] {
        self.signature.as_slice()
    }
    /// [`userHandle`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorassertionresponse-userhandle).
    #[inline]
    #[must_use]
    pub fn user_handle(&self) -> Option<UserHandle<&[u8]>> {
        self.user_handle.as_ref().map(UserHandle::from)
    }
    /// Constructs an instance of `Self` with the contained data.
    ///
    /// Note calling code is encouraged to ensure `authenticator_data` has at least 32 bytes
    /// of available capacity; if not, a reallocation will occur.
    #[inline]
    #[must_use]
    pub fn new(
        client_data_json: Vec<u8>,
        mut authenticator_data: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Option<UserHandle<Vec<u8>>>,
    ) -> Self {
        authenticator_data
            .extend_from_slice(Sha256::digest(client_data_json.as_slice()).as_slice());
        Self {
            client_data_json,
            authenticator_data_and_c_data_hash: authenticator_data,
            signature,
            user_handle,
        }
    }
}
impl AuthResponse for AuthenticatorAssertion {
    type Auth<'a>
        = AuthenticatorData<'a>
    where
        Self: 'a;
    type CredKey<'a> = CompressedPubKey<&'a [u8], &'a [u8], &'a [u8], &'a [u8]>;
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
        fn get_client_collected_data(_: &[u8]) -> ! {
            unreachable!("AuthenticatorAssertion::parse_data_and_verify_sig must be passed false when serde_relaxed is not enabled");
        }
        /// Parses `data` using `CollectedClientData::from_client_data_json_relaxed::<false>`.
        #[cfg(feature = "serde_relaxed")]
        fn get_client_collected_data(
            data: &[u8],
        ) -> Result<
            CollectedClientData<'_>,
            AuthRespErr<
                <<AuthenticatorAssertion as AuthResponse>::Auth<'_> as AuthDataContainer<'_>>::Err,
            >,
        > {
            CollectedClientData::from_client_data_json_relaxed::<false>(data)
                .map_err(AuthRespErr::CollectedClientDataRelaxed)
        }
        if relaxed {
            get_client_collected_data(self.client_data_json.as_slice())
        } else {
            CollectedClientData::from_client_data_json::<false>(self.client_data_json.as_slice())
                .map_err(AuthRespErr::CollectedClientData)
        }
        .and_then(|client_data_json| {
            Self::Auth::from_data(self.authenticator_data_and_c_data_hash.as_slice())
                .map_err(AuthRespErr::Auth)
                .and_then(|val| {
                    match key {
                        CompressedPubKey::Ed25519(k) => k
                            .into_ver_key()
                            .map_err(AuthRespErr::PubKey)
                            .and_then(|ver_key| {
                                Signature::from_slice(self.signature.as_slice())
                                    .and_then(|sig| {
                                        ver_key.verify(
                                            self.authenticator_data_and_c_data_hash.as_slice(),
                                            &sig,
                                        )
                                    })
                                    .map_err(|_e| AuthRespErr::Signature)
                            }),
                        CompressedPubKey::P256(k) => k
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
                        CompressedPubKey::P384(k) => k
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
                        CompressedPubKey::Rsa(k) => k
                            .as_ver_key()
                            .map_err(AuthRespErr::PubKey)
                            .and_then(|ver_key| {
                                pkcs1v15::Signature::try_from(self.signature.as_slice())
                                    .and_then(|sig| {
                                        ver_key.verify(
                                            self.authenticator_data_and_c_data_hash.as_slice(),
                                            &sig,
                                        )
                                    })
                                    .map_err(|_e| AuthRespErr::Signature)
                            }),
                    }
                    .map(|()| (client_data_json, val.data))
                })
        })
    }
}
/// [`PublicKeyCredential`](https://www.w3.org/TR/webauthn-3/#iface-pkcredential) for authentication ceremonies.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "no invariants to uphold"
)]
#[derive(Debug)]
pub struct Authentication {
    /// [`rawId`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-rawid).
    pub(crate) raw_id: CredentialId<Vec<u8>>,
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response)
    pub(crate) response: AuthenticatorAssertion,
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment).
    pub(crate) authenticator_attachment: AuthenticatorAttachment,
}
impl Authentication {
    /// [`rawId`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-rawid).
    #[inline]
    #[must_use]
    pub fn raw_id(&self) -> CredentialId<&[u8]> {
        (&self.raw_id).into()
    }
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response).
    #[inline]
    #[must_use]
    pub const fn response(&self) -> &AuthenticatorAssertion {
        &self.response
    }
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment).
    #[inline]
    #[must_use]
    pub const fn authenticator_attachment(&self) -> AuthenticatorAttachment {
        self.authenticator_attachment
    }
    /// Constructs an `Authentication`.
    #[cfg_attr(docsrs, doc(cfg(feature = "custom")))]
    #[cfg(feature = "custom")]
    #[inline]
    #[must_use]
    pub const fn new(
        raw_id: CredentialId<Vec<u8>>,
        response: AuthenticatorAssertion,
        authenticator_attachment: AuthenticatorAttachment,
    ) -> Self {
        Self {
            raw_id,
            response,
            authenticator_attachment,
        }
    }
    /// Convenience function for
    /// `CollectedClientData::from_client_data_json::<false>(self.response().client_data_json()).map(|c| c.challenge)`.
    ///
    /// This is useful when wanting to extract the corresponding [`AuthenticationServerState`] from
    /// an in-memory collection (e.g., [`FixedCapHashSet`]) or storage.
    ///
    /// # Errors
    ///
    /// Errors iff [`CollectedClientData::from_client_data_json`] does.
    #[inline]
    pub fn challenge(&self) -> Result<SentChallenge, CollectedClientDataErr> {
        CollectedClientData::from_client_data_json::<false>(
            self.response.client_data_json.as_slice(),
        )
        .map(|c| c.challenge)
    }
    /// Convenience function for
    /// `CollectedClientData::from_client_data_json_relaxed::<false>(self.response().client_data_json()).map(|c| c.challenge)`.
    ///
    /// This is useful when wanting to extract the corresponding [`AuthenticationServerState`] from
    /// an in-memory collection (e.g., [`FixedCapHashSet`]) or storage.
    ///
    /// # Errors
    ///
    /// Errors iff [`CollectedClientData::from_client_data_json_relaxed`] does.
    #[cfg_attr(docsrs, doc(cfg(feature = "serde_relaxed")))]
    #[cfg(feature = "serde_relaxed")]
    #[inline]
    pub fn challenge_relaxed(&self) -> Result<SentChallenge, SerdeJsonErr> {
        CollectedClientData::from_client_data_json_relaxed::<false>(
            self.response.client_data_json.as_slice(),
        )
        .map(|c| c.challenge)
    }
}
impl Response for Authentication {
    type Auth = AuthenticatorAssertion;
    fn auth(&self) -> &Self::Auth {
        &self.response
    }
}
