#[cfg(test)]
mod tests;
#[cfg(feature = "serde_relaxed")]
use self::{
    super::ser_relaxed::{RelaxedClientDataJsonParser, SerdeJsonErr},
    ser_relaxed::{CustomRegistration, RegistrationRelaxed},
};
#[cfg(all(doc, feature = "bin"))]
use super::super::bin::{Decode, Encode};
#[cfg(feature = "bin")]
use super::register::bin::{AaguidOwned, MetadataOwned};
use super::{
    super::request::register::{FourToSixtyThree, ResidentKeyRequirement},
    AuthData, AuthDataContainer, AuthExtOutput, AuthRespErr, AuthResponse, AuthTransports,
    AuthenticatorAttachment, Backup, CborSuccess, ClientDataJsonParser as _, CollectedClientData,
    CredentialId, Flag, FromCbor, HmacSecretGet, HmacSecretGetErr, LimitedVerificationParser,
    ParsedAuthData, Response, SentChallenge, cbor,
    error::CollectedClientDataErr,
    register::error::{
        AaguidErr, AttestationErr, AttestationObjectErr, AttestedCredentialDataErr,
        AuthenticatorDataErr, AuthenticatorExtensionOutputErr, CompressedP256PubKeyErr,
        CompressedP384PubKeyErr, CoseKeyErr, Ed25519PubKeyErr, Ed25519SignatureErr,
        MlDsa44PubKeyErr, MlDsa65PubKeyErr, MlDsa87PubKeyErr, PubKeyErr, RsaPubKeyErr,
        UncompressedP256PubKeyErr, UncompressedP384PubKeyErr,
    },
};
#[cfg(doc)]
use super::{
    super::{
        AuthenticatedCredential, RegisteredCredential,
        hash::hash_set::MaxLenHashSet,
        request::{
            Challenge, UserVerificationRequirement,
            auth::{
                AuthenticationVerificationOptions, BackupStateReq,
                PublicKeyCredentialRequestOptions,
            },
            register::{CoseAlgorithmIdentifier, Extension, RegistrationServerState},
        },
    },
    AuthenticatorTransport,
};
use core::{
    cmp::Ordering,
    convert::Infallible,
    fmt::{self, Display, Formatter},
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, Signature as MlDsaSignature, VerifyingKey as MlDsaVerKey};
use p256::{
    AffinePoint as P256Affine, NistP256, Sec1Point as P256Pt,
    ecdsa::{DerSignature as P256Sig, VerifyingKey as P256VerKey},
    elliptic_curve::{Curve, common::typenum::ToInt as _, point::DecompressPoint as _},
};
use p384::{
    AffinePoint as P384Affine, NistP384, Sec1Point as P384Pt,
    ecdsa::{DerSignature as P384Sig, VerifyingKey as P384VerKey},
};
use rsa::{
    BoxedUint, RsaPublicKey,
    pkcs1v15::{self, VerifyingKey as RsaVerKey},
    sha2::{Sha256, digest::Digest as _},
};
#[cfg(all(doc, feature = "serde_relaxed"))]
use serde::Deserialize;
/// Contains functionality to (de)serialize data to a data store.
#[cfg(feature = "bin")]
pub mod bin;
/// Contains error types.
pub mod error;
/// Contains functionality to deserialize data from a client.
#[cfg(feature = "serde")]
mod ser;
/// Contains functionality to deserialize data from a client in a "relaxed" way.
#[cfg(feature = "serde_relaxed")]
pub mod ser_relaxed;
/// [`credentialProtectionPolicy`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#dom-authenticationextensionsclientinputs-credentialprotectionpolicy).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialProtectionPolicy {
    /// `credProtect` was not sent.
    None,
    /// [`userVerificationOptional`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationoptional).
    UserVerificationOptional,
    /// [`userVerificationOptionalWithCredentialIDList`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationoptionalwithcredentialidlist).
    UserVerificationOptionalWithCredentialIdList,
    /// [`userVerificationRequired`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationrequired).
    UserVerificationRequired,
}
impl Display for CredentialProtectionPolicy {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::None => "no credential protection policy sent",
            Self::UserVerificationOptional => "user verification optional",
            Self::UserVerificationOptionalWithCredentialIdList => {
                "user verification optional with credential ID list"
            }
            Self::UserVerificationRequired => "user verification required",
        })
    }
}
#[expect(clippy::too_long_first_doc_paragraph, reason = "false positive")]
/// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
/// and
/// [`hmac-secret-mc`](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-make-cred-extension).
///
/// Note `hmac-secret-mc` can only exist if `hmac-secret` exists with a value of `true`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HmacSecret {
    /// No `hmac-secret` extension.
    None,
    /// `hmac-secret` extension with a value of `false`.
    NotEnabled,
    /// `hmac-secret` extension with a value of `true`.
    Enabled,
    /// `hmac-secret` extension with a value of `true` and `hmac-secret-mc` contained one encrypted PRF output.
    One,
    /// `hmac-secret` extension with a value of `true` and `hmac-secret-mc` contained two encrypted PRF outputs.
    Two,
}
/// [Authenticator extension output](https://www.w3.org/TR/webauthn-3/#authenticator-extension-output).
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatorExtensionOutput {
    /// [`credProtect`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-credProtect-extension).
    pub cred_protect: CredentialProtectionPolicy,
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// and
    /// [`hmac-secret-mc`](https://fidoalliance.org/specs/fido-v2.2-ps-20250228/fido-client-to-authenticator-protocol-v2.2-ps-20250228.html#sctn-hmac-secret-make-cred-extension).
    pub hmac_secret: HmacSecret,
    /// [`minPinLength`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-minpinlength-extension).
    pub min_pin_length: Option<FourToSixtyThree>,
}
impl AuthExtOutput for AuthenticatorExtensionOutput {
    fn missing(self) -> bool {
        matches!(self.cred_protect, CredentialProtectionPolicy::None)
            && matches!(self.hmac_secret, HmacSecret::None)
            && self.min_pin_length.is_none()
    }
}
/// [`AuthenticatorExtensionOutput`] extensions that are saved in [`StaticState`] because they are used during
/// authentication ceremonies.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatorExtensionOutputStaticState {
    /// [`AuthenticatorExtensionOutput::cred_protect`].
    pub cred_protect: CredentialProtectionPolicy,
    /// [`AuthenticatorExtensionOutput::hmac_secret`].
    ///
    /// Note we only care about whether or not it has been enabled. Specifcally this is `None` iff
    /// [`HmacSecret::None`], `Some(false)` iff [`HmacSecret::NotEnabled`]; otherwise `Some(true)`.
    pub hmac_secret: Option<bool>,
}
/// [`AuthenticatorExtensionOutput`] extensions that are saved in [`Metadata`] because they are purely informative
/// and not used during authentication ceremonies.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatorExtensionOutputMetadata {
    /// [`AuthenticatorExtensionOutput::min_pin_length`].
    pub min_pin_length: Option<FourToSixtyThree>,
}
impl From<AuthenticatorExtensionOutput> for AuthenticatorExtensionOutputMetadata {
    #[inline]
    fn from(value: AuthenticatorExtensionOutput) -> Self {
        Self {
            min_pin_length: value.min_pin_length,
        }
    }
}
impl From<AuthenticatorExtensionOutput> for AuthenticatorExtensionOutputStaticState {
    #[inline]
    fn from(value: AuthenticatorExtensionOutput) -> Self {
        Self {
            cred_protect: value.cred_protect,
            hmac_secret: match value.hmac_secret {
                HmacSecret::None => None,
                HmacSecret::NotEnabled => Some(false),
                HmacSecret::Enabled | HmacSecret::One | HmacSecret::Two => Some(true),
            },
        }
    }
}
impl FromCbor<'_> for CredentialProtectionPolicy {
    type Err = AuthenticatorExtensionOutputErr;
    fn from_cbor(cbor: &[u8]) -> Result<CborSuccess<'_, Self>, Self::Err> {
        /// [`userVerificationOptional`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationoptional).
        const USER_VERIFICATION_OPTIONAL: u8 = cbor::ONE;
        /// [`userVerificationOptionalWithCredentialIDList`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationoptionalwithcredentialidlist).
        const USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST: u8 = cbor::TWO;
        /// [`userVerificationRequired`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#userverificationrequired).
        const USER_VERIFICATION_REQUIRED: u8 = cbor::THREE;
        /// `credProtect` key.
        const KEY: [u8; 12] = [
            cbor::TEXT_11,
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
        ];
        cbor.split_at_checked(KEY.len()).map_or(
            Ok(CborSuccess {
                value: Self::None,
                remaining: cbor,
            }),
            |(key, key_rem)| {
                if key == KEY {
                    key_rem
                        .split_first()
                        .ok_or(AuthenticatorExtensionOutputErr::Len)
                        .and_then(|(uv, remaining)| {
                            match *uv {
                                USER_VERIFICATION_OPTIONAL => Ok(Self::UserVerificationOptional),
                                USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST => {
                                    Ok(Self::UserVerificationOptionalWithCredentialIdList)
                                }
                                USER_VERIFICATION_REQUIRED => Ok(Self::UserVerificationRequired),
                                _ => Err(AuthenticatorExtensionOutputErr::CredProtectValue),
                            }
                            .map(|value| CborSuccess { value, remaining })
                        })
                } else {
                    Ok(CborSuccess {
                        value: Self::None,
                        remaining: cbor,
                    })
                }
            },
        )
    }
}
/// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension).
enum HmacSecretEnabled {
    /// No `hmac-secret` extension.
    None,
    /// `hmac-secret` set to the contained `bool`.
    Val(bool),
}
impl FromCbor<'_> for HmacSecretEnabled {
    type Err = AuthenticatorExtensionOutputErr;
    fn from_cbor(cbor: &[u8]) -> Result<CborSuccess<'_, Self>, Self::Err> {
        cbor.split_at_checked(cbor::HMAC_SECRET.len()).map_or(
            Ok(CborSuccess {
                value: Self::None,
                remaining: cbor,
            }),
            |(key, key_rem)| {
                if key == cbor::HMAC_SECRET {
                    key_rem
                        .split_first()
                        .ok_or(AuthenticatorExtensionOutputErr::Len)
                        .and_then(|(hmac, remaining)| {
                            match *hmac {
                                cbor::SIMPLE_FALSE => Ok(Self::Val(false)),
                                cbor::SIMPLE_TRUE => Ok(Self::Val(true)),
                                _ => Err(AuthenticatorExtensionOutputErr::HmacSecretValue),
                            }
                            .map(|value| CborSuccess { value, remaining })
                        })
                } else {
                    Ok(CborSuccess {
                        value: Self::None,
                        remaining: cbor,
                    })
                }
            },
        )
    }
}
/// [`minPinLength`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-minpinlength-extension).
enum MinPinLength {
    /// No `minPinLength` extension.
    None,
    /// `minPinLength` with the value of the contained `FourToSixtyThree`.
    Val(FourToSixtyThree),
}
impl FromCbor<'_> for MinPinLength {
    type Err = AuthenticatorExtensionOutputErr;
    fn from_cbor(cbor: &[u8]) -> Result<CborSuccess<'_, Self>, Self::Err> {
        /// `minPinLength` key.
        const KEY: [u8; 13] = [
            cbor::TEXT_12,
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
        ];
        cbor.split_at_checked(KEY.len()).map_or(
            Ok(CborSuccess {
                value: Self::None,
                remaining: cbor,
            }),
            |(key, key_rem)| {
                if key == KEY {
                    key_rem
                        .split_first()
                        .ok_or(AuthenticatorExtensionOutputErr::Len)
                        .and_then(|(&key_len, remaining)| match key_len.cmp(&24) {
                            Ordering::Less => FourToSixtyThree::from_u8(key_len)
                                .ok_or(AuthenticatorExtensionOutputErr::MinPinLengthValue)
                                .map(|val| CborSuccess {
                                    value: Self::Val(val),
                                    remaining,
                                }),
                            Ordering::Equal => remaining
                                .split_first()
                                .ok_or(AuthenticatorExtensionOutputErr::Len)
                                .and_then(|(&key_24, rem)| {
                                    if key_24 > 23 {
                                        FourToSixtyThree::from_u8(key_24)
                                            .ok_or(
                                                AuthenticatorExtensionOutputErr::MinPinLengthValue,
                                            )
                                            .map(|val| CborSuccess {
                                                value: Self::Val(val),
                                                remaining: rem,
                                            })
                                    } else {
                                        Err(AuthenticatorExtensionOutputErr::MinPinLengthValue)
                                    }
                                }),
                            Ordering::Greater => {
                                Err(AuthenticatorExtensionOutputErr::MinPinLengthValue)
                            }
                        })
                } else {
                    Ok(CborSuccess {
                        value: Self::None,
                        remaining: cbor,
                    })
                }
            },
        )
    }
}
impl From<HmacSecretGetErr> for AuthenticatorExtensionOutputErr {
    #[inline]
    fn from(value: HmacSecretGetErr) -> Self {
        match value {
            HmacSecretGetErr::Len => Self::Len,
            HmacSecretGetErr::Type => Self::HmacSecretMcType,
            HmacSecretGetErr::Value => Self::HmacSecretMcValue,
        }
    }
}
impl FromCbor<'_> for AuthenticatorExtensionOutput {
    type Err = AuthenticatorExtensionOutputErr;
    #[expect(
        clippy::too_many_lines,
        reason = "don't want to move logic into outer scope"
    )]
    fn from_cbor(cbor: &[u8]) -> Result<CborSuccess<'_, Self>, Self::Err> {
        // We don't allow unsupported extensions; thus the only possibilities is any ordered element of
        // the power set of {"credProtect":<1, 2, or 3>, "hmac-secret":<true or false>, "minPinLength":<0-255>,
        // "hmac-secret-mc":<48|80 bytes>}.
        // Since the keys are the same type (text), order is first done based on length; and then
        // byte-wise lexical order is followed; thus `credProtect` must come before `hmac-secret` which
        // must come before `minPinLength` which comes before `hmac-secret-mc`.
        //
        // Note `hmac-secret-mc` can only exist if `hmac-secret` exists with a value of `true`.
        let mut cred_protect = CredentialProtectionPolicy::None;
        let mut hmac_secret = HmacSecret::None;
        let mut min_pin_length = None;
        let mut remaining = cbor;
        cbor.split_first().map_or(
            Ok(()),
            |(map, map_rem)| {
                match *map {
                    cbor::MAP_1 => {
                        CredentialProtectionPolicy::from_cbor(map_rem).and_then(|cred_success| {
                            if matches!(cred_success.value, CredentialProtectionPolicy::None) {
                                HmacSecretEnabled::from_cbor(cred_success.remaining).and_then(
                                    |hmac_success| if let HmacSecretEnabled::Val(hmac) = hmac_success.value {
                                        hmac_secret = if hmac {
                                            HmacSecret::Enabled
                                        } else {
                                            HmacSecret::NotEnabled
                                        };
                                        remaining = hmac_success.remaining;
                                        Ok(())
                                    } else {
                                        MinPinLength::from_cbor(hmac_success.remaining).and_then(|pin_success| if let MinPinLength::Val(min_pin_len) = pin_success.value {
                                            min_pin_length = Some(min_pin_len);
                                            remaining = pin_success.remaining;
                                            Ok(())
                                        } else {
                                            // We don't even bother checking for `HmacSecretGet` since
                                            // it's only valid when `HmacSecretEnabled` exists with a value
                                            // of `true`.
                                            Err(AuthenticatorExtensionOutputErr::Missing)
                                        })
                                    }
                                )
                            } else {
                                cred_protect = cred_success.value;
                                remaining = cred_success.remaining;
                                Ok(())
                            }
                        })
                    }
                    cbor::MAP_2 => {
                        CredentialProtectionPolicy::from_cbor(map_rem).and_then(|cred_success| {
                            if matches!(cred_success.value, CredentialProtectionPolicy::None) {
                                HmacSecretEnabled::from_cbor(cred_success.remaining).and_then(|hmac_success| if let HmacSecretEnabled::Val(hmac) = hmac_success.value {
                                    MinPinLength::from_cbor(hmac_success.remaining).and_then(|pin_success| if let MinPinLength::Val(min_pin_len) = pin_success.value {
                                        hmac_secret = if hmac {
                                            HmacSecret::Enabled
                                        } else {
                                            HmacSecret::NotEnabled
                                        };
                                        min_pin_length = Some(min_pin_len);
                                        remaining = pin_success.remaining;
                                        Ok(())
                                    } else if hmac {
                                        HmacSecretGet::<true>::from_cbor(pin_success.remaining).map_err(AuthenticatorExtensionOutputErr::from).and_then(|hmac_get| match hmac_get.value {
                                            HmacSecretGet::None => Err(AuthenticatorExtensionOutputErr::Missing),
                                            HmacSecretGet::One => {
                                                hmac_secret = HmacSecret::One;
                                                remaining = hmac_get.remaining;
                                                Ok(())
                                            },
                                            HmacSecretGet::Two => {
                                                hmac_secret = HmacSecret::Two;
                                                remaining = hmac_get.remaining;
                                                Ok(())
                                            },
                                        })
                                    } else {
                                        // We don't even bother checking for `HmacSecretGet` since
                                        // it's only valid when `HmacSecretEnabled` exists with a value
                                        // of `true`.
                                        Err(AuthenticatorExtensionOutputErr::Missing)
                                    })
                                } else {
                                    // We don't even bother checking for `HmacSecretGet` since
                                    // it's only valid when `HmacSecretEnabled` exists with a value
                                    // of `true`.
                                    Err(AuthenticatorExtensionOutputErr::Missing)
                                })
                            } else {
                                HmacSecretEnabled::from_cbor(cred_success.remaining).and_then(|hmac_success| if let HmacSecretEnabled::Val(hmac) = hmac_success.value {
                                    cred_protect = cred_success.value;
                                    hmac_secret = if hmac {
                                        HmacSecret::Enabled
                                    } else {
                                        HmacSecret::NotEnabled
                                    };
                                    remaining = hmac_success.remaining;
                                    Ok(())
                                } else {
                                    MinPinLength::from_cbor(hmac_success.remaining).and_then(|pin_success| if let MinPinLength::Val(min_pin_len) = pin_success.value {
                                        cred_protect = cred_success.value;
                                        min_pin_length = Some(min_pin_len);
                                        remaining = pin_success.remaining;
                                        Ok(())
                                    } else {
                                        // We don't even bother checking for `HmacSecretGet` since
                                        // it's only valid when `HmacSecretEnabled` exists with a value
                                        // of `true`.
                                        Err(AuthenticatorExtensionOutputErr::Missing)
                                    })
                                })
                            }
                        })
                    }
                    cbor::MAP_3 => {
                        CredentialProtectionPolicy::from_cbor(map_rem).and_then(|cred_success| {
                            if matches!(cred_success.value, CredentialProtectionPolicy::None) {
                                HmacSecretEnabled::from_cbor(cred_success.remaining).and_then(|hmac_success| if let HmacSecretEnabled::Val(hmac) = hmac_success.value && hmac {
                                    MinPinLength::from_cbor(hmac_success.remaining).and_then(|pin_success| if let MinPinLength::Val(min_pin_len) = pin_success.value {
                                        HmacSecretGet::<true>::from_cbor(pin_success.remaining).map_err(AuthenticatorExtensionOutputErr::from).and_then(|hmac_get| match hmac_get.value {
                                            HmacSecretGet::None => Err(AuthenticatorExtensionOutputErr::Missing),
                                            HmacSecretGet::One => {
                                                hmac_secret = HmacSecret::One;
                                                min_pin_length = Some(min_pin_len);
                                                remaining = hmac_get.remaining;
                                                Ok(())
                                            },
                                            HmacSecretGet::Two => {
                                                hmac_secret = HmacSecret::Two;
                                                min_pin_length = Some(min_pin_len);
                                                remaining = hmac_get.remaining;
                                                Ok(())
                                            },
                                        })
                                    } else {
                                        Err(AuthenticatorExtensionOutputErr::Missing)
                                    })
                                } else {
                                    // We don't even bother checking for `HmacSecretGet` since
                                    // it's only valid when `HmacSecretEnabled` exists with a value
                                    // of `true`.
                                    Err(AuthenticatorExtensionOutputErr::Missing)
                                })
                            } else {
                                HmacSecretEnabled::from_cbor(cred_success.remaining).and_then(|hmac_success| if let HmacSecretEnabled::Val(hmac) = hmac_success.value {
                                    MinPinLength::from_cbor(hmac_success.remaining).and_then(|pin_success| if let MinPinLength::Val(min_pin_len) = pin_success.value {
                                        cred_protect = cred_success.value;
                                        hmac_secret = if hmac { HmacSecret::Enabled } else { HmacSecret::NotEnabled };
                                        min_pin_length = Some(min_pin_len);
                                        remaining = pin_success.remaining;
                                        Ok(())
                                    } else if hmac {
                                        HmacSecretGet::<true>::from_cbor(pin_success.remaining).map_err(AuthenticatorExtensionOutputErr::from).and_then(|hmac_get| match hmac_get.value {
                                            HmacSecretGet::None => Err(AuthenticatorExtensionOutputErr::Missing),
                                            HmacSecretGet::One => {
                                                cred_protect = cred_success.value;
                                                hmac_secret = HmacSecret::One;
                                                remaining = hmac_get.remaining;
                                                Ok(())
                                            }
                                            HmacSecretGet::Two => {
                                                cred_protect = cred_success.value;
                                                hmac_secret = HmacSecret::Two;
                                                remaining = hmac_get.remaining;
                                                Ok(())
                                            }
                                        })
                                    } else{
                                        // We don't even bother checking for `HmacSecretGet` since
                                        // it's only valid when `HmacSecretEnabled` exists with a value
                                        // of `true`.
                                        Err(AuthenticatorExtensionOutputErr::Missing)
                                    })
                                } else {
                                    // We don't even bother checking for `HmacSecretGet` since
                                    // it's only valid when `HmacSecretEnabled` exists with a value
                                    // of `true`.
                                    Err(AuthenticatorExtensionOutputErr::Missing)
                                })
                            }
                        })
                    }
                    cbor::MAP_4 => {
                        CredentialProtectionPolicy::from_cbor(map_rem).and_then(|cred_success| {
                            if matches!(cred_success.value, CredentialProtectionPolicy::None) {
                                Err(AuthenticatorExtensionOutputErr::Missing)
                            } else {
                                HmacSecretEnabled::from_cbor(cred_success.remaining).and_then(|hmac_success| if let HmacSecretEnabled::Val(hmac) = hmac_success.value && hmac {
                                    MinPinLength::from_cbor(hmac_success.remaining).and_then(|pin_success| if let MinPinLength::Val(min_pin_len) = pin_success.value {
                                        HmacSecretGet::<true>::from_cbor(pin_success.remaining).map_err(AuthenticatorExtensionOutputErr::from).and_then(|hmac_get| match hmac_get.value {
                                            HmacSecretGet::None => Err(AuthenticatorExtensionOutputErr::Missing),
                                            HmacSecretGet::One => {
                                                cred_protect = cred_success.value;
                                                hmac_secret = HmacSecret::One;
                                                min_pin_length = Some(min_pin_len);
                                                remaining = hmac_get.remaining;
                                                Ok(())
                                            },
                                            HmacSecretGet::Two => {
                                                cred_protect = cred_success.value;
                                                hmac_secret = HmacSecret::Two;
                                                min_pin_length = Some(min_pin_len);
                                                remaining = hmac_get.remaining;
                                                Ok(())
                                            },
                                        })
                                    } else {
                                        Err(AuthenticatorExtensionOutputErr::Missing)
                                    })
                                } else {
                                    // We don't even bother checking for `HmacSecretGet` since
                                    // it's only valid when `HmacSecretEnabled` exists with a value
                                    // of `true`.
                                    Err(AuthenticatorExtensionOutputErr::Missing)
                                })
                            }
                        })
                    }
                    _ => Err(AuthenticatorExtensionOutputErr::CborHeader),
                }
            }
        ).map(|()| CborSuccess { value: Self { cred_protect, hmac_secret, min_pin_length }, remaining })
    }
}
/// 2592 bytes representing an alleged ML-DSA-87 public key.
#[derive(Clone, Copy, Debug)]
pub struct MlDsa87PubKey<T>(T);
impl<T> MlDsa87PubKey<T> {
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
impl<T: AsRef<[u8]>> MlDsa87PubKey<T> {
    /// Returns the contained data.
    #[inline]
    #[must_use]
    pub fn encoded_data(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl MlDsa87PubKey<&[u8]> {
    /// Converts `self` into an [`MlDsaVerKey`].
    pub(super) fn into_ver_key(self) -> MlDsaVerKey<MlDsa87> {
        self.into_owned().into_ver_key()
    }
    /// Transforms `self` into an "owned" version.
    #[inline]
    #[must_use]
    pub fn into_owned(self) -> MlDsa87PubKey<Box<[u8]>> {
        MlDsa87PubKey(self.0.into())
    }
}
impl MlDsa87PubKey<Box<[u8]>> {
    /// Converts `self` into [`MlDsaVerKey`].
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    fn into_ver_key(self) -> MlDsaVerKey<MlDsa87> {
        MlDsaVerKey::decode(
            self.0
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array"))
                .into(),
        )
    }
}
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for MlDsa87PubKey<&'b [u8]> {
    type Error = MlDsa87PubKeyErr;
    /// Interprets `value` as an encoded ML-DSA-87 public key.
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() == 2592 {
            Ok(Self(value))
        } else {
            Err(MlDsa87PubKeyErr)
        }
    }
}
impl TryFrom<Box<[u8]>> for MlDsa87PubKey<Box<[u8]>> {
    type Error = MlDsa87PubKeyErr;
    /// Interprets `value` as an encoded ML-DSA-87 public key.
    #[inline]
    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        if value.len() == 2592 {
            Ok(Self(value))
        } else {
            Err(MlDsa87PubKeyErr)
        }
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<MlDsa87PubKey<T>> for MlDsa87PubKey<T2> {
    #[inline]
    fn eq(&self, other: &MlDsa87PubKey<T>) -> bool {
        self.0 == other.0
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<MlDsa87PubKey<T>> for &MlDsa87PubKey<T2> {
    #[inline]
    fn eq(&self, other: &MlDsa87PubKey<T>) -> bool {
        **self == *other
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<&MlDsa87PubKey<T>> for MlDsa87PubKey<T2> {
    #[inline]
    fn eq(&self, other: &&MlDsa87PubKey<T>) -> bool {
        *self == **other
    }
}
impl<T: Eq> Eq for MlDsa87PubKey<T> {}
/// 1952 bytes representing an alleged ML-DSA-65 public key.
#[derive(Clone, Copy, Debug)]
pub struct MlDsa65PubKey<T>(T);
impl<T> MlDsa65PubKey<T> {
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
impl<T: AsRef<[u8]>> MlDsa65PubKey<T> {
    /// Returns the contained data.
    #[inline]
    #[must_use]
    pub fn encoded_data(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl MlDsa65PubKey<&[u8]> {
    /// Converts `self` into an [`MlDsaVerKey`].
    pub(super) fn into_ver_key(self) -> MlDsaVerKey<MlDsa65> {
        self.into_owned().into_ver_key()
    }
    /// Transforms `self` into an "owned" version.
    #[inline]
    #[must_use]
    pub fn into_owned(self) -> MlDsa65PubKey<Box<[u8]>> {
        MlDsa65PubKey(self.0.into())
    }
}
impl MlDsa65PubKey<Box<[u8]>> {
    /// Converts `self` into [`MlDsaVerKey`].
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    fn into_ver_key(self) -> MlDsaVerKey<MlDsa65> {
        MlDsaVerKey::decode(
            self.0
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array"))
                .into(),
        )
    }
}
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for MlDsa65PubKey<&'b [u8]> {
    type Error = MlDsa65PubKeyErr;
    /// Interprets `value` as an encoded ML-DSA-65 public key.
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() == 1952 {
            Ok(Self(value))
        } else {
            Err(MlDsa65PubKeyErr)
        }
    }
}
impl TryFrom<Box<[u8]>> for MlDsa65PubKey<Box<[u8]>> {
    type Error = MlDsa65PubKeyErr;
    /// Interprets `value` as an encoded ML-DSA-65 public key.
    #[inline]
    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        if value.len() == 1952 {
            Ok(Self(value))
        } else {
            Err(MlDsa65PubKeyErr)
        }
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<MlDsa65PubKey<T>> for MlDsa65PubKey<T2> {
    #[inline]
    fn eq(&self, other: &MlDsa65PubKey<T>) -> bool {
        self.0 == other.0
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<MlDsa65PubKey<T>> for &MlDsa65PubKey<T2> {
    #[inline]
    fn eq(&self, other: &MlDsa65PubKey<T>) -> bool {
        **self == *other
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<&MlDsa65PubKey<T>> for MlDsa65PubKey<T2> {
    #[inline]
    fn eq(&self, other: &&MlDsa65PubKey<T>) -> bool {
        *self == **other
    }
}
impl<T: Eq> Eq for MlDsa65PubKey<T> {}
/// 1312 bytes representing an alleged ML-DSA-44 public key.
#[derive(Clone, Copy, Debug)]
pub struct MlDsa44PubKey<T>(T);
impl<T> MlDsa44PubKey<T> {
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
impl<T: AsRef<[u8]>> MlDsa44PubKey<T> {
    /// Returns the contained data.
    #[inline]
    #[must_use]
    pub fn encoded_data(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl MlDsa44PubKey<&[u8]> {
    /// Converts `self` into an [`MlDsaVerKey`].
    pub(super) fn into_ver_key(self) -> MlDsaVerKey<MlDsa44> {
        self.into_owned().into_ver_key()
    }
    /// Transforms `self` into an "owned" version.
    #[inline]
    #[must_use]
    pub fn into_owned(self) -> MlDsa44PubKey<Box<[u8]>> {
        MlDsa44PubKey(self.0.into())
    }
}
impl MlDsa44PubKey<Box<[u8]>> {
    /// Converts `self` into [`MlDsaVerKey`].
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    fn into_ver_key(self) -> MlDsaVerKey<MlDsa44> {
        MlDsaVerKey::decode(
            self.0
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array"))
                .into(),
        )
    }
}
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for MlDsa44PubKey<&'b [u8]> {
    type Error = MlDsa44PubKeyErr;
    /// Interprets `value` as an encoded ML-DSA-44 public key.
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() == 1312 {
            Ok(Self(value))
        } else {
            Err(MlDsa44PubKeyErr)
        }
    }
}
impl TryFrom<Box<[u8]>> for MlDsa44PubKey<Box<[u8]>> {
    type Error = MlDsa44PubKeyErr;
    /// Interprets `value` as an encoded ML-DSA-44 public key.
    #[inline]
    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        if value.len() == 1312 {
            Ok(Self(value))
        } else {
            Err(MlDsa44PubKeyErr)
        }
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<MlDsa44PubKey<T>> for MlDsa44PubKey<T2> {
    #[inline]
    fn eq(&self, other: &MlDsa44PubKey<T>) -> bool {
        self.0 == other.0
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<MlDsa44PubKey<T>> for &MlDsa44PubKey<T2> {
    #[inline]
    fn eq(&self, other: &MlDsa44PubKey<T>) -> bool {
        **self == *other
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<&MlDsa44PubKey<T>> for MlDsa44PubKey<T2> {
    #[inline]
    fn eq(&self, other: &&MlDsa44PubKey<T>) -> bool {
        *self == **other
    }
}
impl<T: Eq> Eq for MlDsa44PubKey<T> {}
/// 32-bytes representing an alleged Ed25519 public key (i.e., compressed y-coordinate).
#[derive(Clone, Copy, Debug)]
pub struct Ed25519PubKey<T>(T);
impl<T> Ed25519PubKey<T> {
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
impl<T: AsRef<[u8]>> Ed25519PubKey<T> {
    /// Returns the compressed y-coordinate.
    #[inline]
    #[must_use]
    pub fn compressed_y_coordinate(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl Ed25519PubKey<&[u8]> {
    /// Validates `self` is in fact a valid Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Errors iff `self` is not a valid Ed25519 public key.
    #[inline]
    pub fn validate(self) -> Result<(), PubKeyErr> {
        self.into_ver_key().map(|_| ())
    }
    /// Converts `self` into [`VerifyingKey`].
    pub(super) fn into_ver_key(self) -> Result<VerifyingKey, PubKeyErr> {
        self.into_owned().into_ver_key()
    }
    /// Transforms `self` into an "owned" version.
    #[inline]
    #[must_use]
    pub fn into_owned(self) -> Ed25519PubKey<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> {
        Ed25519PubKey(*Ed25519PubKey::<&[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::from(self).0)
    }
}
impl Ed25519PubKey<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> {
    /// Validates `self` is in fact a valid Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Errors iff `self` is not a valid Ed25519 public key.
    #[inline]
    pub fn validate(self) -> Result<(), PubKeyErr> {
        self.into_ver_key().map(|_| ())
    }
    /// Converts `self` into [`VerifyingKey`].
    fn into_ver_key(self) -> Result<VerifyingKey, PubKeyErr> {
        // ["Taming the many EdDSAs"](https://eprint.iacr.org/2020/1244.pdf) goes over
        // and proves varying levels of signature security. The only property that is
        // important for WebAuthn is existential unforgeability under chosen message
        // attacks (EUF-CMA). No matter how `ed25519-dalek` is used this is met.
        // Additional properties that may be of importance are strong unforgeability
        // under chosen message attacks (SUF-CMA), binding signature (BS), and
        // strongly binding signature (SBS).
        // No matter how `ed25519-dalek` is used, SUF-CMA is achieved. Because
        // we always achieve SUF-CMA, we elect—despite no benefit in WebAuthn—to also
        // achieve SBS. One can achieve SBS-secure by simply rejecting small-order
        // keys which is precisely what `VerifyingKey::is_weak` does.
        // Note this means we _don't_ conform to [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)
        // nor [NIST SP 800-186](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf).
        // As stated, there is no additional security by conforming to the above specs though;
        // furthermore, RFC 8032 does not require rejecting small-order points despite requiring
        // canonical encoding of points; thus it does not achieve SBS-security.
        // NIST SP 800-186 does achieve SUF-CMA and SBS-security but requires additional properties
        // that have no cryptographic importance. Specifically it mandates canonicity of encodings
        // for both public keys and signatures and requires not only that points not be small-order
        // but more strictly that points are in the prime-order subgroup (excluding the identity).
        // This is more work for no benefit, so we elect to stay within the confines of the exposed API.
        VerifyingKey::from_bytes(&self.0)
            .map_err(|_e| PubKeyErr::Ed25519)
            .and_then(|key| {
                if key.is_weak() {
                    Err(PubKeyErr::Ed25519)
                } else {
                    Ok(key)
                }
            })
    }
}
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for Ed25519PubKey<&'b [u8]> {
    type Error = Ed25519PubKeyErr;
    /// Interprets `value` as the compressed y-coordinate of an Ed25519 public key.
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() == ed25519_dalek::PUBLIC_KEY_LENGTH {
            Ok(Self(value))
        } else {
            Err(Ed25519PubKeyErr)
        }
    }
}
impl From<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>
    for Ed25519PubKey<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>
{
    #[inline]
    fn from(value: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH]) -> Self {
        Self(value)
    }
}
impl<'a: 'b, 'b> From<&'a Ed25519PubKey<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>>
    for Ed25519PubKey<&'b [u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>
{
    #[inline]
    fn from(value: &'a Ed25519PubKey<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>) -> Self {
        Self(&value.0)
    }
}
impl<'a: 'b, 'b> From<Ed25519PubKey<&'a [u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>>
    for Ed25519PubKey<&'b [u8]>
{
    #[inline]
    fn from(value: Ed25519PubKey<&'a [u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>) -> Self {
        Self(value.0.as_slice())
    }
}
impl<'a: 'b, 'b> From<&'a Ed25519PubKey<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>>
    for Ed25519PubKey<&'b [u8]>
{
    #[inline]
    fn from(value: &'a Ed25519PubKey<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>) -> Self {
        Self(value.0.as_slice())
    }
}
impl<'a: 'b, 'b> From<Ed25519PubKey<&'a [u8]>>
    for Ed25519PubKey<&'b [u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>
{
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    #[inline]
    fn from(value: Ed25519PubKey<&'a [u8]>) -> Self {
        Self(
            value
                .0
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array")),
        )
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<Ed25519PubKey<T>> for Ed25519PubKey<T2> {
    #[inline]
    fn eq(&self, other: &Ed25519PubKey<T>) -> bool {
        self.0 == other.0
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<Ed25519PubKey<T>> for &Ed25519PubKey<T2> {
    #[inline]
    fn eq(&self, other: &Ed25519PubKey<T>) -> bool {
        **self == *other
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<&Ed25519PubKey<T>> for Ed25519PubKey<T2> {
    #[inline]
    fn eq(&self, other: &&Ed25519PubKey<T>) -> bool {
        *self == **other
    }
}
impl<T: Eq> Eq for Ed25519PubKey<T> {}
/// Two 32-byte regions representing the big-endian x and y coordinates of an alleged P-256 public key.
#[derive(Clone, Copy, Debug)]
pub struct UncompressedP256PubKey<'a>(&'a [u8], &'a [u8]);
impl<'a> UncompressedP256PubKey<'a> {
    /// Returns the big-endian x-coordinate.
    #[inline]
    #[must_use]
    pub const fn x(self) -> &'a [u8] {
        self.0
    }
    /// Returns the big-endian y-coordinate.
    #[inline]
    #[must_use]
    pub const fn y(self) -> &'a [u8] {
        self.1
    }
    /// Validates `self` is in fact a valid P-256 public key.
    ///
    /// # Errors
    ///
    /// Errors iff `self` is not a valid P-256 public key.
    #[inline]
    pub fn validate(self) -> Result<(), PubKeyErr> {
        self.into_ver_key().map(|_| ())
    }
    /// Converts `self` into [`P256VerKey`].
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    fn into_ver_key(self) -> Result<P256VerKey, PubKeyErr> {
        P256VerKey::from_sec1_point(&P256Pt::from_affine_coordinates(
            self.0
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array"))
                .into(),
            self.1
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array"))
                .into(),
            false,
        ))
        .map_err(|_e| PubKeyErr::P256)
    }
    /// Returns `true` iff [`Self::y`] is odd.
    #[expect(clippy::indexing_slicing, reason = "comment justifies correctness")]
    #[inline]
    #[must_use]
    pub const fn y_is_odd(self) -> bool {
        // `self.1.len() == 32`, so this won't `panic`.
        self.1[31] & 1 == 1
    }
    /// Transforms `self` into the compressed version that owns the data.
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    #[inline]
    #[must_use]
    pub fn into_compressed(
        self,
    ) -> CompressedP256PubKey<[u8; <NistP256 as Curve>::FieldBytesSize::INT]> {
        CompressedP256PubKey {
            x: self.0.try_into().unwrap_or_else(|_e| unreachable!("there is a bug in UncompressedP256PubKey that allows for the x-coordinate to not be 32 bytes in length")),
            y_is_odd: self.y_is_odd(),
        }
    }
}
impl<'a: 'b, 'b> TryFrom<(&'a [u8], &'a [u8])> for UncompressedP256PubKey<'b> {
    type Error = UncompressedP256PubKeyErr;
    /// The first item is the big-endian x-coordinate, and the second item is the big-endian y-coordinate.
    #[inline]
    fn try_from((x, y): (&'a [u8], &'a [u8])) -> Result<Self, Self::Error> {
        /// Number of bytes each coordinate is made of.
        const COORD_LEN: usize = <NistP256 as Curve>::FieldBytesSize::INT;
        if x.len() == COORD_LEN {
            if y.len() == COORD_LEN {
                Ok(Self(x, y))
            } else {
                Err(UncompressedP256PubKeyErr::Y)
            }
        } else {
            Err(UncompressedP256PubKeyErr::X)
        }
    }
}
impl PartialEq<UncompressedP256PubKey<'_>> for UncompressedP256PubKey<'_> {
    #[inline]
    fn eq(&self, other: &UncompressedP256PubKey<'_>) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}
impl PartialEq<UncompressedP256PubKey<'_>> for &UncompressedP256PubKey<'_> {
    #[inline]
    fn eq(&self, other: &UncompressedP256PubKey<'_>) -> bool {
        **self == *other
    }
}
impl PartialEq<&UncompressedP256PubKey<'_>> for UncompressedP256PubKey<'_> {
    #[inline]
    fn eq(&self, other: &&UncompressedP256PubKey<'_>) -> bool {
        *self == **other
    }
}
impl Eq for UncompressedP256PubKey<'_> {}
/// 32-bytes representing the big-endian x-coordinate and a `bool` representing whether the y-coordinate
/// is odd of an alleged P-256 public key.
#[derive(Clone, Copy, Debug)]
pub struct CompressedP256PubKey<T> {
    /// 32-byte x-coordinate.
    x: T,
    /// `true` iff the y-coordinate is odd.
    y_is_odd: bool,
}
impl<T> CompressedP256PubKey<T> {
    /// Returns [`Self::x`] and [`Self::y_is_odd`] consuming `self`.
    #[inline]
    pub fn into_parts(self) -> (T, bool) {
        (self.x, self.y_is_odd)
    }
    /// Returns [`Self::x`] and [`Self::y_is_odd`].
    #[inline]
    pub const fn as_parts(&self) -> (&T, bool) {
        (&self.x, self.y_is_odd)
    }
    /// Returns the 32-byte big-endian x-coordinate.
    #[inline]
    pub const fn x(&self) -> &T {
        &self.x
    }
    /// `true` iff the y-coordinate is odd.
    #[inline]
    pub const fn y_is_odd(&self) -> bool {
        self.y_is_odd
    }
}
impl CompressedP256PubKey<[u8; <NistP256 as Curve>::FieldBytesSize::INT]> {
    /// Validates `self` is in fact a valid P-256 public key.
    ///
    /// # Errors
    ///
    /// Errors iff `self` is not a valid P-256 public key.
    #[inline]
    pub fn validate(self) -> Result<(), PubKeyErr> {
        self.into_ver_key().map(|_| ())
    }
    /// Converts `self` into [`P256VerKey`].
    pub(super) fn into_ver_key(self) -> Result<P256VerKey, PubKeyErr> {
        P256Affine::decompress(&self.x.into(), u8::from(self.y_is_odd).into())
            .into_option()
            .ok_or(PubKeyErr::P256)
            .and_then(|pt| P256VerKey::from_affine(pt).map_err(|_e| PubKeyErr::P256))
    }
}
impl CompressedP256PubKey<&[u8]> {
    /// Validates `self` is in fact a valid P-256 public key.
    ///
    /// # Errors
    ///
    /// Errors iff `self` is not a valid P-256 public key.
    #[inline]
    pub fn validate(self) -> Result<(), PubKeyErr> {
        self.into_ver_key().map(|_| ())
    }
    /// Converts `self` into [`P256VerKey`].
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    pub(super) fn into_ver_key(self) -> Result<P256VerKey, PubKeyErr> {
        P256Affine::decompress(
            self.x
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array"))
                .into(),
            u8::from(self.y_is_odd).into(),
        )
        .into_option()
        .ok_or(PubKeyErr::P256)
        .and_then(|pt| P256VerKey::from_affine(pt).map_err(|_e| PubKeyErr::P256))
    }
}
impl<'a: 'b, 'b> TryFrom<(&'a [u8], bool)> for CompressedP256PubKey<&'b [u8]> {
    type Error = CompressedP256PubKeyErr;
    #[inline]
    fn try_from((x, y_is_odd): (&'a [u8], bool)) -> Result<Self, Self::Error> {
        /// The number of bytes the x-coordinate is.
        const X_LEN: usize = <NistP256 as Curve>::FieldBytesSize::INT;
        if x.len() == X_LEN {
            Ok(Self { x, y_is_odd })
        } else {
            Err(CompressedP256PubKeyErr)
        }
    }
}
impl From<([u8; <NistP256 as Curve>::FieldBytesSize::INT], bool)>
    for CompressedP256PubKey<[u8; <NistP256 as Curve>::FieldBytesSize::INT]>
{
    #[inline]
    fn from((x, y_is_odd): ([u8; <NistP256 as Curve>::FieldBytesSize::INT], bool)) -> Self {
        Self { x, y_is_odd }
    }
}
impl<'a: 'b, 'b> From<&'a CompressedP256PubKey<[u8; <NistP256 as Curve>::FieldBytesSize::INT]>>
    for CompressedP256PubKey<&'b [u8; <NistP256 as Curve>::FieldBytesSize::INT]>
{
    #[inline]
    fn from(
        value: &'a CompressedP256PubKey<[u8; <NistP256 as Curve>::FieldBytesSize::INT]>,
    ) -> Self {
        Self {
            x: &value.x,
            y_is_odd: value.y_is_odd,
        }
    }
}
impl<'a: 'b, 'b> From<CompressedP256PubKey<&'a [u8; <NistP256 as Curve>::FieldBytesSize::INT]>>
    for CompressedP256PubKey<&'b [u8]>
{
    #[inline]
    fn from(
        value: CompressedP256PubKey<&'a [u8; <NistP256 as Curve>::FieldBytesSize::INT]>,
    ) -> Self {
        Self {
            x: value.x.as_slice(),
            y_is_odd: value.y_is_odd,
        }
    }
}
impl<'a: 'b, 'b> From<&'a CompressedP256PubKey<[u8; <NistP256 as Curve>::FieldBytesSize::INT]>>
    for CompressedP256PubKey<&'b [u8]>
{
    #[inline]
    fn from(
        value: &'a CompressedP256PubKey<[u8; <NistP256 as Curve>::FieldBytesSize::INT]>,
    ) -> Self {
        Self {
            x: value.x.as_slice(),
            y_is_odd: value.y_is_odd,
        }
    }
}
impl<'a: 'b, 'b> From<CompressedP256PubKey<&'a [u8]>>
    for CompressedP256PubKey<&'b [u8; <NistP256 as Curve>::FieldBytesSize::INT]>
{
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    #[inline]
    fn from(value: CompressedP256PubKey<&'a [u8]>) -> Self {
        Self {
            x: value
                .x
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array")),
            y_is_odd: value.y_is_odd,
        }
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<CompressedP256PubKey<T>>
    for CompressedP256PubKey<T2>
{
    #[inline]
    fn eq(&self, other: &CompressedP256PubKey<T>) -> bool {
        self.x == other.x && self.y_is_odd == other.y_is_odd
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<CompressedP256PubKey<T>>
    for &CompressedP256PubKey<T2>
{
    #[inline]
    fn eq(&self, other: &CompressedP256PubKey<T>) -> bool {
        **self == *other
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<&CompressedP256PubKey<T>>
    for CompressedP256PubKey<T2>
{
    #[inline]
    fn eq(&self, other: &&CompressedP256PubKey<T>) -> bool {
        *self == **other
    }
}
impl<T: Eq> Eq for CompressedP256PubKey<T> {}
/// Two 48-byte regions representing the big-endian x and y coordinates of an alleged P-384 public key.
#[derive(Clone, Copy, Debug)]
pub struct UncompressedP384PubKey<'a>(&'a [u8], &'a [u8]);
impl<'a> UncompressedP384PubKey<'a> {
    /// Returns the big-endian x-coordinate.
    #[inline]
    #[must_use]
    pub const fn x(self) -> &'a [u8] {
        self.0
    }
    /// Returns the big-endian y-coordinate.
    #[inline]
    #[must_use]
    pub const fn y(self) -> &'a [u8] {
        self.1
    }
    /// Validates `self` is in fact a valid P-384 public key.
    ///
    /// # Errors
    ///
    /// Errors iff `self` is not a valid P-384 public key.
    #[inline]
    pub fn validate(self) -> Result<(), PubKeyErr> {
        self.into_ver_key().map(|_| ())
    }
    /// Converts `self` into [`P384VerKey`].
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    fn into_ver_key(self) -> Result<P384VerKey, PubKeyErr> {
        P384VerKey::from_sec1_point(&P384Pt::from_affine_coordinates(
            self.0
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array"))
                .into(),
            self.1
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array"))
                .into(),
            false,
        ))
        .map_err(|_e| PubKeyErr::P384)
    }
    /// Returns `true` iff [`Self::y`] is odd.
    #[expect(clippy::indexing_slicing, reason = "comment justifies correctness")]
    #[inline]
    #[must_use]
    pub const fn y_is_odd(self) -> bool {
        // `self.1.len() == 48`, so this won't `panic`.
        self.1[47] & 1 == 1
    }
    /// Transforms `self` into the compressed version that owns the data.
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    #[inline]
    #[must_use]
    pub fn into_compressed(
        self,
    ) -> CompressedP384PubKey<[u8; <NistP384 as Curve>::FieldBytesSize::INT]> {
        CompressedP384PubKey {
            x: self.0.try_into().unwrap_or_else(|_e| unreachable!("there is a bug in UncompressedP384PubKey that allows for the x-coordinate to not be 48 bytes in length")),
            y_is_odd: self.y_is_odd(),
        }
    }
}
impl<'a: 'b, 'b> TryFrom<(&'a [u8], &'a [u8])> for UncompressedP384PubKey<'b> {
    type Error = UncompressedP384PubKeyErr;
    /// The first item is the big-endian x-coordinate, and the second item is the big-endian y-coordinate.
    #[inline]
    fn try_from((x, y): (&'a [u8], &'a [u8])) -> Result<Self, Self::Error> {
        /// Number of bytes each coordinate is made of.
        const COORD_LEN: usize = <NistP384 as Curve>::FieldBytesSize::INT;
        if x.len() == COORD_LEN {
            if y.len() == COORD_LEN {
                Ok(Self(x, y))
            } else {
                Err(UncompressedP384PubKeyErr::Y)
            }
        } else {
            Err(UncompressedP384PubKeyErr::X)
        }
    }
}
impl PartialEq<UncompressedP384PubKey<'_>> for UncompressedP384PubKey<'_> {
    #[inline]
    fn eq(&self, other: &UncompressedP384PubKey<'_>) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}
impl PartialEq<UncompressedP384PubKey<'_>> for &UncompressedP384PubKey<'_> {
    #[inline]
    fn eq(&self, other: &UncompressedP384PubKey<'_>) -> bool {
        **self == *other
    }
}
impl PartialEq<&UncompressedP384PubKey<'_>> for UncompressedP384PubKey<'_> {
    #[inline]
    fn eq(&self, other: &&UncompressedP384PubKey<'_>) -> bool {
        *self == **other
    }
}
impl Eq for UncompressedP384PubKey<'_> {}
/// 48-bytes representing the big-endian x-coordinate and a `bool` representing whether the y-coordinate
/// is odd of an alleged P-384 public key.
#[derive(Clone, Copy, Debug)]
pub struct CompressedP384PubKey<T> {
    /// 48-byte x-coordinate.
    x: T,
    /// `true` iff the y-coordinate is odd.
    y_is_odd: bool,
}
impl<T> CompressedP384PubKey<T> {
    /// Returns [`Self::x`] and [`Self::y_is_odd`] consuming `self`.
    #[inline]
    pub fn into_parts(self) -> (T, bool) {
        (self.x, self.y_is_odd)
    }
    /// Returns [`Self::x`] and [`Self::y_is_odd`].
    #[inline]
    pub const fn as_parts(&self) -> (&T, bool) {
        (&self.x, self.y_is_odd)
    }
    /// Returns the 48-byte big-endian x-coordinate.
    #[inline]
    pub const fn x(&self) -> &T {
        &self.x
    }
    /// `true` iff the y-coordinate is odd.
    #[inline]
    #[must_use]
    pub const fn y_is_odd(&self) -> bool {
        self.y_is_odd
    }
}
impl CompressedP384PubKey<[u8; <NistP384 as Curve>::FieldBytesSize::INT]> {
    /// Validates `self` is in fact a valid P-384 public key.
    ///
    /// # Errors
    ///
    /// Errors iff `self` is not a valid P-384 public key.
    #[inline]
    pub fn validate(self) -> Result<(), PubKeyErr> {
        self.into_ver_key().map(|_| ())
    }
    /// Converts `self` into [`P384VerKey`].
    pub(super) fn into_ver_key(self) -> Result<P384VerKey, PubKeyErr> {
        P384Affine::decompress(&self.x.into(), u8::from(self.y_is_odd).into())
            .into_option()
            .ok_or(PubKeyErr::P384)
            .and_then(|pt| P384VerKey::from_affine(pt).map_err(|_e| PubKeyErr::P384))
    }
}
impl CompressedP384PubKey<&[u8]> {
    /// Validates `self` is in fact a valid P-384 public key.
    ///
    /// # Errors
    ///
    /// Errors iff `self` is not a valid P-384 public key.
    #[inline]
    pub fn validate(self) -> Result<(), PubKeyErr> {
        self.into_ver_key().map(|_| ())
    }
    /// Converts `self` into [`P384VerKey`].
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    pub(super) fn into_ver_key(self) -> Result<P384VerKey, PubKeyErr> {
        P384Affine::decompress(
            self.x
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array"))
                .into(),
            u8::from(self.y_is_odd).into(),
        )
        .into_option()
        .ok_or(PubKeyErr::P384)
        .and_then(|pt| P384VerKey::from_affine(pt).map_err(|_e| PubKeyErr::P384))
    }
}
impl<'a: 'b, 'b> TryFrom<(&'a [u8], bool)> for CompressedP384PubKey<&'b [u8]> {
    type Error = CompressedP384PubKeyErr;
    #[inline]
    fn try_from((x, y_is_odd): (&'a [u8], bool)) -> Result<Self, Self::Error> {
        /// Number of bytes of the x-coordinate is.
        const X_LEN: usize = <NistP384 as Curve>::FieldBytesSize::INT;
        if x.len() == X_LEN {
            Ok(Self { x, y_is_odd })
        } else {
            Err(CompressedP384PubKeyErr)
        }
    }
}
impl From<([u8; <NistP384 as Curve>::FieldBytesSize::INT], bool)>
    for CompressedP384PubKey<[u8; <NistP384 as Curve>::FieldBytesSize::INT]>
{
    #[inline]
    fn from((x, y_is_odd): ([u8; <NistP384 as Curve>::FieldBytesSize::INT], bool)) -> Self {
        Self { x, y_is_odd }
    }
}
impl<'a: 'b, 'b> From<&'a CompressedP384PubKey<[u8; <NistP384 as Curve>::FieldBytesSize::INT]>>
    for CompressedP384PubKey<&'b [u8; <NistP384 as Curve>::FieldBytesSize::INT]>
{
    #[inline]
    fn from(
        value: &'a CompressedP384PubKey<[u8; <NistP384 as Curve>::FieldBytesSize::INT]>,
    ) -> Self {
        Self {
            x: &value.x,
            y_is_odd: value.y_is_odd,
        }
    }
}
impl<'a: 'b, 'b> From<CompressedP384PubKey<&'a [u8; <NistP384 as Curve>::FieldBytesSize::INT]>>
    for CompressedP384PubKey<&'b [u8]>
{
    #[inline]
    fn from(
        value: CompressedP384PubKey<&'a [u8; <NistP384 as Curve>::FieldBytesSize::INT]>,
    ) -> Self {
        Self {
            x: value.x.as_slice(),
            y_is_odd: value.y_is_odd,
        }
    }
}
impl<'a: 'b, 'b> From<&'a CompressedP384PubKey<[u8; <NistP384 as Curve>::FieldBytesSize::INT]>>
    for CompressedP384PubKey<&'b [u8]>
{
    #[inline]
    fn from(
        value: &'a CompressedP384PubKey<[u8; <NistP384 as Curve>::FieldBytesSize::INT]>,
    ) -> Self {
        Self {
            x: value.x.as_slice(),
            y_is_odd: value.y_is_odd,
        }
    }
}
impl<'a: 'b, 'b> From<CompressedP384PubKey<&'a [u8]>>
    for CompressedP384PubKey<&'b [u8; <NistP384 as Curve>::FieldBytesSize::INT]>
{
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    #[inline]
    fn from(value: CompressedP384PubKey<&'a [u8]>) -> Self {
        Self {
            x: value
                .x
                .as_array()
                .unwrap_or_else(|| unreachable!("there is a bug in slice::as_array")),
            y_is_odd: value.y_is_odd,
        }
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<CompressedP384PubKey<T>>
    for CompressedP384PubKey<T2>
{
    #[inline]
    fn eq(&self, other: &CompressedP384PubKey<T>) -> bool {
        self.x == other.x && self.y_is_odd == other.y_is_odd
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<CompressedP384PubKey<T>>
    for &CompressedP384PubKey<T2>
{
    #[inline]
    fn eq(&self, other: &CompressedP384PubKey<T>) -> bool {
        **self == *other
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<&CompressedP384PubKey<T>>
    for CompressedP384PubKey<T2>
{
    #[inline]
    fn eq(&self, other: &&CompressedP384PubKey<T>) -> bool {
        *self == **other
    }
}
impl<T: Eq> Eq for CompressedP384PubKey<T> {}
/// The minimum RSA public key exponent allowed by [`RsaPubKey`].
///
/// [RFC 8017 § 3.1](https://www.rfc-editor.org/rfc/rfc8017#section-3.1) states the smallest valid RSA public
/// exponent is 3.
pub const MIN_RSA_E: u32 = 3;
/// The most bits an RSA public key modulus is allowed to consist of per [`RsaPubKey`].
///
/// [RFC 8230 § 6.1](https://www.rfc-editor.org/rfc/rfc8230#section-6.1) recommends allowing moduli up to 16K bits.
pub const MAX_RSA_N_BITS: usize = 0x4000;
/// The fewest bits an RSA public key modulus is allowed to consist of per [`RsaPubKey`].
///
/// [RFC 8230 § 6.1](https://www.rfc-editor.org/rfc/rfc8230#section-6.1) requires the modulus to be at least 2048
/// bits.
pub const MIN_RSA_N_BITS: usize = 0x800;
/// [`MIN_RSA_N_BITS`]–[`MAX_RSA_N_BITS`] bits representing the big-endian modulus and a `u32` `>=`
/// [`MIN_RSA_E`] representing the exponent of an alleged RSA public key.
///
/// Note the modulus and exponent are always odd.
#[derive(Clone, Copy, Debug)]
pub struct RsaPubKey<T>(T, u32);
impl<T> RsaPubKey<T> {
    /// Returns [`Self::n`] and [`Self::e`] consuming `self`.
    #[inline]
    pub fn into_parts(self) -> (T, u32) {
        (self.0, self.1)
    }
    /// Returns [`Self::n`] and [`Self::e`].
    #[inline]
    pub const fn as_parts(&self) -> (&T, u32) {
        (&self.0, self.1)
    }
    /// Returns the big-endian modulus.
    #[inline]
    pub const fn n(&self) -> &T {
        &self.0
    }
    /// Returns the exponent.
    #[inline]
    pub const fn e(&self) -> u32 {
        self.1
    }
}
impl<T: AsRef<[u8]>> RsaPubKey<T> {
    /// Converts `self` into [`RsaVerKey`].
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        reason = "comment justifies correctness"
    )]
    pub(super) fn as_ver_key(&self) -> RsaVerKey<Sha256> {
        let n = self.0.as_ref();
        RsaVerKey::new(RsaPublicKey::new_unchecked(
            // [`MAX_RSA_N_BITS`] is smaller than `u16::MAX`, so we can multiply by 8
            // and cast to a `u32` without fear.
            // [`MIN_RSA_BITS`]` is greater than 0, so we won't underflow from
            // subtracting leading 0 bits from the first byte which is not empty
            // since `MIN_RSA_BITS > 0`.
            BoxedUint::from_be_slice(n, ((n.len() as u32) << 3) - n[0].leading_zeros()).unwrap_or_else(|_e| unreachable!("there is a bug in response::register::RsaPubKey where one can construct it without ensuring the modulus is valid")),
            self.1.into(),
        ))
    }
}
impl RsaPubKey<&[u8]> {
    /// Transforms `self` into an "owned" version.
    #[inline]
    #[must_use]
    pub fn into_owned(self) -> RsaPubKey<Box<[u8]>> {
        RsaPubKey(self.0.into(), self.1)
    }
}
impl<'a: 'b, 'b> TryFrom<(&'a [u8], u32)> for RsaPubKey<&'b [u8]> {
    type Error = RsaPubKeyErr;
    /// The first item is the big-endian modulus, and the second item is the exponent.
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        reason = "comment justifies correctness"
    )]
    #[inline]
    fn try_from((n, e): (&'a [u8], u32)) -> Result<Self, Self::Error> {
        n.first().map_or(Err(RsaPubKeyErr::NSize), |fst| {
            // `fst.leading_zeros()` is inclusively between `0` and `8`, so it's safe to convert to a
            // `usize`.
            let zeros = fst.leading_zeros() as usize;
            if zeros == 8 {
                Err(RsaPubKeyErr::NLeading0)
                // `bits` is at least 8 since `n.len()` is at least 1; thus underflow cannot occur.
            } else if let Some(bits) = n.len().checked_mul(8)
                && (MIN_RSA_N_BITS..=MAX_RSA_N_BITS).contains(&(bits - zeros))
            {
                // We know `n` is not empty, so this won't `panic`.
                if n.last()
                    .unwrap_or_else(|| unreachable!("there is a bug in RsaPubKey::try_from"))
                    & 1
                    == 0
                {
                    Err(RsaPubKeyErr::NEven)
                } else if e < MIN_RSA_E {
                    Err(RsaPubKeyErr::ESize)
                } else if e & 1 == 0 {
                    Err(RsaPubKeyErr::EEven)
                } else {
                    Ok(Self(n, e))
                }
            } else {
                Err(RsaPubKeyErr::NSize)
            }
        })
    }
}
impl TryFrom<(Box<[u8]>, u32)> for RsaPubKey<Box<[u8]>> {
    type Error = RsaPubKeyErr;
    /// Similar to [`RsaPubKey::try_from`] except `n` is a `Box`.
    #[inline]
    fn try_from((n, e): (Box<[u8]>, u32)) -> Result<Self, Self::Error> {
        match RsaPubKey::<&[u8]>::try_from((&*n, e)) {
            Ok(_) => Ok(Self(n, e)),
            Err(err) => Err(err),
        }
    }
}
impl<'a: 'b, 'b> From<&'a RsaPubKey<Box<[u8]>>> for RsaPubKey<&'b Box<[u8]>> {
    #[inline]
    fn from(value: &'a RsaPubKey<Box<[u8]>>) -> Self {
        Self(&value.0, value.1)
    }
}
impl<'a: 'b, 'b> From<RsaPubKey<&'a Box<[u8]>>> for RsaPubKey<&'b [u8]> {
    #[inline]
    fn from(value: RsaPubKey<&'a Box<[u8]>>) -> Self {
        Self(value.0, value.1)
    }
}
impl<'a: 'b, 'b> From<&'a RsaPubKey<Box<[u8]>>> for RsaPubKey<&'b [u8]> {
    #[inline]
    fn from(value: &'a RsaPubKey<Box<[u8]>>) -> Self {
        Self(&value.0, value.1)
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<RsaPubKey<T>> for RsaPubKey<T2> {
    #[inline]
    fn eq(&self, other: &RsaPubKey<T>) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<RsaPubKey<T>> for &RsaPubKey<T2> {
    #[inline]
    fn eq(&self, other: &RsaPubKey<T>) -> bool {
        **self == *other
    }
}
impl<T: PartialEq<T2>, T2: PartialEq<T>> PartialEq<&RsaPubKey<T>> for RsaPubKey<T2> {
    #[inline]
    fn eq(&self, other: &&RsaPubKey<T>) -> bool {
        *self == **other
    }
}
impl<T: Eq> Eq for RsaPubKey<T> {}
/// `kty` COSE key common parameter as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters).
const KTY: u8 = cbor::ONE;
/// `OKP` COSE key type as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type).
const OKP: u8 = cbor::ONE;
/// `EC2` COSE key type as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type).
const EC2: u8 = cbor::TWO;
/// `RSA` COSE key type as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type).
const RSA: u8 = cbor::THREE;
/// `AKP` COSE key type as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type).
const AKP: u8 = cbor::SEVEN;
/// `alg` COSE key common parameter as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters).
const ALG: u8 = cbor::THREE;
/// `EdDSA` COSE algorithm as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
const EDDSA: u8 = cbor::NEG_EIGHT;
/// `ES256` COSE algorithm as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
const ES256: u8 = cbor::NEG_SEVEN;
/// `ES384` COSE algorithm as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
///
/// This is -35 encoded in cbor which is encoded as |-35| - 1 = 35 - 1 = 34. Note
/// this must be preceded with `cbor::NEG_INFO_24`.
const ES384: u8 = 34;
/// `ML-DSA-44` COSE algorithm as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
///
/// This is -48 encoded in cbor which is encoded as |-48| - 1 = 48 - 1 = 47. Note
/// this must be preceded with `cbor::NEG_INFO_24`.
const MLDSA44: u8 = 47;
/// `ML-DSA-65` COSE algorithm as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
///
/// This is -49 encoded in cbor which is encoded as |-49| - 1 = 49 - 1 = 48. Note
/// this must be preceded with `cbor::NEG_INFO_24`.
const MLDSA65: u8 = 48;
/// `ML-DSA-87` COSE algorithm as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
///
/// This is -50 encoded in cbor which is encoded as |-50| - 1 = 50 - 1 = 49. Note
/// this must be preceded with `cbor::NEG_INFO_24`.
const MLDSA87: u8 = 49;
/// `RS256` COSE algorithm as defined by
/// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms).
///
/// This is -257 encoded in cbor which is encoded as |-257| - 1 = 257 - 1 = 256 = [1, 0] in big endian.
/// Note this must be preceded with `cbor::NEG_INFO_25`.
const RS256: [u8; 2] = [1, 0];
impl<'a> FromCbor<'a> for MlDsa87PubKey<&'a [u8]> {
    type Err = CoseKeyErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// `pub` COSE key type parameter for [`AKP`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const PUB: u8 = cbor::NEG_ONE;
        /// COSE header.
        /// {kty:AKP,alg:ML-DSA-87,pub:<encodedKey>}.
        /// `kty` and `alg` come before `pub` since map order first
        /// is done by data type and `cbor::UINT`s come before `cbor::NEG`s.
        /// `kty` comes before `alg` since order is done byte-wise and
        /// 1 is before 3.
        const HEADER: [u8; 10] = [
            cbor::MAP_3,
            KTY,
            AKP,
            ALG,
            cbor::NEG_INFO_24,
            MLDSA87,
            PUB,
            cbor::BYTES_INFO_25,
            // 10 *256 + 32 = 2592
            10,
            32,
        ];
        cbor.split_at_checked(HEADER.len())
            .ok_or(CoseKeyErr::Len)
            .and_then(|(header, header_rem)| {
                if header == HEADER {
                    header_rem
                        .split_at_checked(2592)
                        .ok_or(CoseKeyErr::Len)
                        .map(|(key, remaining)| CborSuccess {
                            value: Self(key),
                            remaining,
                        })
                } else {
                    Err(CoseKeyErr::MlDsa87CoseEncoding)
                }
            })
    }
}
impl<'a> FromCbor<'a> for MlDsa65PubKey<&'a [u8]> {
    type Err = CoseKeyErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// `pub` COSE key type parameter for [`AKP`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const PUB: u8 = cbor::NEG_ONE;
        /// COSE header.
        /// {kty:AKP,alg:ML-DSA-65,pub:<encodedKey>}.
        /// `kty` and `alg` come before `pub` since map order first
        /// is done by data type and `cbor::UINT`s come before `cbor::NEG`s.
        /// `kty` comes before `alg` since order is done byte-wise and
        /// 1 is before 3.
        const HEADER: [u8; 10] = [
            cbor::MAP_3,
            KTY,
            AKP,
            ALG,
            cbor::NEG_INFO_24,
            MLDSA65,
            PUB,
            cbor::BYTES_INFO_25,
            // 7 *256 + 160 = 1952
            7,
            160,
        ];
        cbor.split_at_checked(HEADER.len())
            .ok_or(CoseKeyErr::Len)
            .and_then(|(header, header_rem)| {
                if header == HEADER {
                    header_rem
                        .split_at_checked(1952)
                        .ok_or(CoseKeyErr::Len)
                        .map(|(key, remaining)| CborSuccess {
                            value: Self(key),
                            remaining,
                        })
                } else {
                    Err(CoseKeyErr::MlDsa65CoseEncoding)
                }
            })
    }
}
impl<'a> FromCbor<'a> for MlDsa44PubKey<&'a [u8]> {
    type Err = CoseKeyErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// `pub` COSE key type parameter for [`AKP`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const PUB: u8 = cbor::NEG_ONE;
        /// COSE header.
        /// {kty:AKP,alg:ML-DSA-44,pub:<encodedKey>}.
        /// `kty` and `alg` come before `pub` since map order first
        /// is done by data type and `cbor::UINT`s come before `cbor::NEG`s.
        /// `kty` comes before `alg` since order is done byte-wise and
        /// 1 is before 3.
        const HEADER: [u8; 10] = [
            cbor::MAP_3,
            KTY,
            AKP,
            ALG,
            cbor::NEG_INFO_24,
            MLDSA44,
            PUB,
            cbor::BYTES_INFO_25,
            // 5 *256 + 32 = 1312
            5,
            32,
        ];
        cbor.split_at_checked(HEADER.len())
            .ok_or(CoseKeyErr::Len)
            .and_then(|(header, header_rem)| {
                if header == HEADER {
                    header_rem
                        .split_at_checked(1312)
                        .ok_or(CoseKeyErr::Len)
                        .map(|(key, remaining)| CborSuccess {
                            value: Self(key),
                            remaining,
                        })
                } else {
                    Err(CoseKeyErr::MlDsa44CoseEncoding)
                }
            })
    }
}
impl<'a> FromCbor<'a> for Ed25519PubKey<&'a [u8]> {
    type Err = CoseKeyErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// `crv` COSE key type parameter for [`OKP`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const CRV: u8 = cbor::NEG_ONE;
        /// `Ed25519` COSE elliptic curve as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves).
        const ED25519: u8 = cbor::SIX;
        /// `x` COSE key type parameter for [`OKP`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const X: u8 = cbor::NEG_TWO;
        // `32 as u8` is OK.
        /// `ed25519_dalek::PUBLIC_KEY_LENGTH` as a `u8`.
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "explained above and want a const"
        )]
        const KEY_LEN_U8: u8 = ed25519_dalek::PUBLIC_KEY_LENGTH as u8;
        /// COSE header.
        /// {kty:OKP,alg:EdDSA,crv:Ed25519,x:<CompressedEdwardsYPoint>}.
        /// `kty` and `alg` come before `crv` and `x` since map order first
        /// is done by data type and `cbor::UINT`s come before `cbor::NEG`s.
        /// `kty` comes before `alg` since order is done byte-wise and
        /// 1 is before 3. `crv` is before `x` since `0b001_00000` comes before
        /// `0b001_00001` byte-wise.
        const HEADER: [u8; 10] = [
            cbor::MAP_4,
            KTY,
            OKP,
            ALG,
            EDDSA,
            CRV,
            ED25519,
            X,
            cbor::BYTES_INFO_24,
            KEY_LEN_U8,
        ];
        cbor.split_at_checked(HEADER.len())
            .ok_or(CoseKeyErr::Len)
            .and_then(|(header, header_rem)| {
                if header == HEADER {
                    header_rem
                        .split_at_checked(ed25519_dalek::PUBLIC_KEY_LENGTH)
                        .ok_or(CoseKeyErr::Len)
                        .map(|(key, remaining)| CborSuccess {
                            value: Self(key),
                            remaining,
                        })
                } else {
                    Err(CoseKeyErr::Ed25519CoseEncoding)
                }
            })
    }
}
impl<'a> FromCbor<'a> for UncompressedP256PubKey<'a> {
    type Err = CoseKeyErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// `crv` COSE key type parameter for [`EC2`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const CRV: u8 = cbor::NEG_ONE;
        /// `P-256` COSE elliptic curve as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves).
        const P256: u8 = cbor::ONE;
        /// `x` COSE key type parameter for [`EC2`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const X: u8 = cbor::NEG_TWO;
        /// `y` COSE key type parameter for [`EC2`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const Y: u8 = cbor::NEG_THREE;
        /// Number of bytes the x-coordinate takes.
        const X_LEN: usize = <NistP256 as Curve>::FieldBytesSize::INT;
        // `32 as u8` is OK.
        /// `X_LEN` as a `u8`.
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "explained above and want a const"
        )]
        const X_LEN_U8: u8 = X_LEN as u8;
        /// Number of bytes the y-coordinate takes.
        const Y_LEN: usize = <NistP256 as Curve>::FieldBytesSize::INT;
        // `32 as u8` is OK.
        /// `Y_LEN` as a `u8`.
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "explained above and want a const"
        )]
        const Y_LEN_U8: u8 = Y_LEN as u8;
        /// COSE header.
        // {kty:EC2,alg:ES256,crv:P-256,x:<affine x-coordinate>,...}.
        /// `kty` and `alg` come before `crv`, `x`, and `y` since map order first
        /// is done by data type and `cbor::UINT`s come before `cbor::NEG`s.
        /// `kty` comes before `alg` since order is done byte-wise and
        /// 1 is before 3. `crv` is before `x` which is before `y` since
        /// `0b001_00000` comes before `0b001_00001` which comes before
        /// `0b001_00010` byte-wise.
        const HEADER: [u8; 10] = [
            cbor::MAP_5,
            KTY,
            EC2,
            ALG,
            ES256,
            CRV,
            P256,
            X,
            cbor::BYTES_INFO_24,
            X_LEN_U8,
        ];
        /// {...y:<affine y-coordinate>}.
        const Y_META: [u8; 3] = [Y, cbor::BYTES_INFO_24, Y_LEN_U8];
        cbor.split_at_checked(HEADER.len())
            .ok_or(CoseKeyErr::Len)
            .and_then(|(header, header_rem)| {
                if header == HEADER {
                    header_rem
                        .split_at_checked(X_LEN)
                        .ok_or(CoseKeyErr::Len)
                        .and_then(|(x, x_rem)| {
                            x_rem
                                .split_at_checked(Y_META.len())
                                .ok_or(CoseKeyErr::Len)
                                .and_then(|(y_meta, y_meta_rem)| {
                                    if y_meta == Y_META {
                                        y_meta_rem
                                            .split_at_checked(Y_LEN)
                                            .ok_or(CoseKeyErr::Len)
                                            .map(|(y, remaining)| CborSuccess {
                                                value: Self(x, y),
                                                remaining,
                                            })
                                    } else {
                                        Err(CoseKeyErr::P256CoseEncoding)
                                    }
                                })
                        })
                } else {
                    Err(CoseKeyErr::P256CoseEncoding)
                }
            })
    }
}
impl<'a> FromCbor<'a> for UncompressedP384PubKey<'a> {
    type Err = CoseKeyErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// `crv` COSE key type parameter for [`EC2`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const CRV: u8 = cbor::NEG_ONE;
        /// `P-384` COSE elliptic curve as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves).
        const P384: u8 = cbor::TWO;
        /// `x` COSE key type parameter for [`EC2`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const X: u8 = cbor::NEG_TWO;
        /// `y` COSE key type parameter for [`EC2`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const Y: u8 = cbor::NEG_THREE;
        /// Number of bytes the x-coordinate takes.
        const X_LEN: usize = <NistP384 as Curve>::FieldBytesSize::INT;
        // `48 as u8` is OK.
        /// `X_LEN` as a `u8`.
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "explained above and want a const"
        )]
        const X_LEN_U8: u8 = X_LEN as u8;
        /// Number of bytes the y-coordinate takes.
        const Y_LEN: usize = <NistP384 as Curve>::FieldBytesSize::INT;
        // `48 as u8` is OK.
        /// `Y_LEN` as a `u8`.
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "explained above and want a const"
        )]
        const Y_LEN_U8: u8 = Y_LEN as u8;
        /// COSE header.
        // {kty:EC2,alg:ES384,crv:P-384,x:<affine x-coordinate>,...}.
        /// `kty` and `alg` come before `crv`, `x`, and `y` since map order first
        /// is done by data type and `cbor::UINT`s come before `cbor::NEG`s.
        /// `kty` comes before `alg` since order is done byte-wise and
        /// 1 is before 3. `crv` is before `x` which is before `y` since
        /// `0b001_00000` comes before `0b001_00001` which comes before
        /// `0b001_00010` byte-wise.
        const HEADER: [u8; 11] = [
            cbor::MAP_5,
            KTY,
            EC2,
            ALG,
            cbor::NEG_INFO_24,
            ES384,
            CRV,
            P384,
            X,
            cbor::BYTES_INFO_24,
            X_LEN_U8,
        ];
        /// {...y:<affine y-coordinate>}.
        const Y_META: [u8; 3] = [Y, cbor::BYTES_INFO_24, Y_LEN_U8];
        cbor.split_at_checked(HEADER.len())
            .ok_or(CoseKeyErr::Len)
            .and_then(|(header, header_rem)| {
                if header == HEADER {
                    header_rem
                        .split_at_checked(X_LEN)
                        .ok_or(CoseKeyErr::Len)
                        .and_then(|(x, x_rem)| {
                            x_rem
                                .split_at_checked(Y_META.len())
                                .ok_or(CoseKeyErr::Len)
                                .and_then(|(y_meta, y_meta_rem)| {
                                    if y_meta == Y_META {
                                        y_meta_rem
                                            .split_at_checked(Y_LEN)
                                            .ok_or(CoseKeyErr::Len)
                                            .map(|(y, remaining)| CborSuccess {
                                                value: Self(x, y),
                                                remaining,
                                            })
                                    } else {
                                        Err(CoseKeyErr::P384CoseEncoding)
                                    }
                                })
                        })
                } else {
                    Err(CoseKeyErr::P384CoseEncoding)
                }
            })
    }
}
impl<'a> FromCbor<'a> for RsaPubKey<&'a [u8]> {
    type Err = CoseKeyErr;
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::big_endian_bytes,
        clippy::indexing_slicing,
        clippy::missing_asserts_for_indexing,
        reason = "comments justify their correctness"
    )]
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// `n` COSE key type parameter for [`RSA`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const N: u8 = cbor::NEG_ONE;
        /// `e` COSE key type parameter for [`RSA`] as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters).
        const E: u8 = cbor::NEG_TWO;
        /// COSE header.
        /// {kty:RSA,alg:RS256,n:<RSA modulus>,...}.
        /// `kty` and `alg` come before `n` and `e` since map order first
        /// is done by data type and `cbor::UINT`s come before `cbor::NEG`s.
        /// `kty` comes before `alg` since order is done byte-wise and
        /// 1 is before 3. `n` is before `e` since `0b001_00000` comes before
        /// `0b001_00001` byte-wise.
        ///
        /// Note `RS256` COSE algorithm as defined by
        /// [IANA](https://www.iana.org/assignments/cose/cose.xhtml#algorithms)
        /// is encoded as -257 which is encoded in CBOR as `[cbor::NEG_INFO_25, 1, 0]` since
        /// |-257| - 1 = 256 which takes two bytes to encode as 1, 0 in big-endian.
        /// Ditto for a byte string of length 0x100 to 0xFFFF inclusively replacing `cbor::NEG_INFO_25` with
        /// `cbor::BYTES_INFO_25`.
        ///
        /// Recall that [`RsaPubKey`] requires the modulus to be at least 256 bytes in length but no greater than
        /// 2048 bytes in length; thus we know a valid and allowed `n` will have length whose metadata
        /// takes exactly two bytes.
        const HEADER: [u8; 9] = [
            cbor::MAP_4,
            KTY,
            RSA,
            ALG,
            cbor::NEG_INFO_25,
            1,
            0,
            N,
            cbor::BYTES_INFO_25,
        ];
        cbor.split_at_checked(HEADER.len()).ok_or(CoseKeyErr::Len).and_then(|(header, header_rem)| {
            if header == HEADER {
                header_rem.split_at_checked(2).ok_or(CoseKeyErr::Len).and_then(|(n_len_slice, n_len_rem)| {
                    let mut len = [0; 2];
                    len.copy_from_slice(n_len_slice);
                    // cbor uints are in big-endian.
                    let n_len = usize::from(u16::from_be_bytes(len));
                    if n_len > 255 {
                        n_len_rem.split_at_checked(n_len).ok_or(CoseKeyErr::Len).and_then(|(n, n_rem)| {
                            n_rem.split_at_checked(2).ok_or(CoseKeyErr::RsaCoseEncoding).and_then(|(e_meta, e_meta_rem)| {
                                // `e_meta.len() == 2`, so this is fine.
                                if e_meta[0] == E {
                                    // `e_meta.len() == 2`, so this is fine.
                                    let e_meta_len = e_meta[1];
                                    if e_meta_len & cbor::BYTES == cbor::BYTES {
                                        let e_len = usize::from(e_meta_len ^ cbor::BYTES);
                                        if e_len < 5 {
                                            e_meta_rem.split_at_checked(e_len).ok_or(CoseKeyErr::Len).and_then(|(e_slice, remaining)| {
                                                e_slice.first().ok_or(CoseKeyErr::Len).and_then(|e_first| {
                                                    // We ensure the leading byte is not 0; otherwise the
                                                    // exponent is not properly encoded. Note the exponent
                                                    //  can never be 0.
                                                    if *e_first > 0 {
                                                        let mut e = [0; 4];
                                                        // `e_slice.len()` is `e_len` which is less than 5.
                                                        // We also know it is greater than 0 since `e_slice.first()` did not err.
                                                        // Thus this won't `panic`.
                                                        e[4 - e_len..].copy_from_slice(e_slice);
                                                        Self::try_from((n, u32::from_be_bytes(e))).map_err(CoseKeyErr::RsaPubKey).map(|value| CborSuccess { value, remaining, } )
                                                    } else {
                                                        Err(CoseKeyErr::RsaCoseEncoding)
                                                    }
                                                })
                                            })
                                        } else {
                                            Err(CoseKeyErr::RsaExponentTooLarge)
                                        }
                                    } else {
                                        Err(CoseKeyErr::RsaCoseEncoding)
                                    }
                                } else {
                                    Err(CoseKeyErr::RsaCoseEncoding)
                                }
                            })
                        })
                    } else {
                        Err(CoseKeyErr::RsaCoseEncoding)
                    }
                })
            } else {
                Err(CoseKeyErr::RsaCoseEncoding)
            }
        })
    }
}
/// An alleged uncompressed public key that borrows the key data.
///
/// Note [`Self::MlDsa87`], [`Self::MlDsa65`], [`Self::MlDsa44`], and [`Self::Ed25519`] are compressed.
#[derive(Clone, Copy, Debug)]
pub enum UncompressedPubKey<'a> {
    /// An alleged ML-DSA-87 public key.
    MlDsa87(MlDsa87PubKey<&'a [u8]>),
    /// An alleged ML-DSA-65 public key.
    MlDsa65(MlDsa65PubKey<&'a [u8]>),
    /// An alleged ML-DSA-44 public key.
    MlDsa44(MlDsa44PubKey<&'a [u8]>),
    /// An alleged Ed25519 public key.
    Ed25519(Ed25519PubKey<&'a [u8]>),
    /// An alleged uncompressed P-256 public key.
    P256(UncompressedP256PubKey<'a>),
    /// An alleged uncompressed P-384 public key.
    P384(UncompressedP384PubKey<'a>),
    /// An alleged RSA public key.
    Rsa(RsaPubKey<&'a [u8]>),
}
impl UncompressedPubKey<'_> {
    /// Validates `self` is in fact a valid public key.
    ///
    /// # Errors
    ///
    /// Errors iff `self` is not a valid public key.
    #[inline]
    pub fn validate(self) -> Result<(), PubKeyErr> {
        match self {
            Self::MlDsa87(_) | Self::MlDsa65(_) | Self::MlDsa44(_) | Self::Rsa(_) => Ok(()),
            Self::Ed25519(k) => k.validate(),
            Self::P256(k) => k.validate(),
            Self::P384(k) => k.validate(),
        }
    }
    /// Transforms `self` into the compressed version that owns the data.
    #[inline]
    #[must_use]
    pub fn into_compressed(self) -> CompressedPubKeyOwned {
        match self {
            Self::MlDsa87(key) => CompressedPubKeyOwned::MlDsa87(key.into_owned()),
            Self::MlDsa65(key) => CompressedPubKeyOwned::MlDsa65(key.into_owned()),
            Self::MlDsa44(key) => CompressedPubKeyOwned::MlDsa44(key.into_owned()),
            Self::Ed25519(key) => CompressedPubKeyOwned::Ed25519(key.into_owned()),
            Self::P256(key) => CompressedPubKeyOwned::P256(key.into_compressed()),
            Self::P384(key) => CompressedPubKeyOwned::P384(key.into_compressed()),
            Self::Rsa(key) => CompressedPubKeyOwned::Rsa(key.into_owned()),
        }
    }
}
impl PartialEq<UncompressedPubKey<'_>> for UncompressedPubKey<'_> {
    #[inline]
    fn eq(&self, other: &UncompressedPubKey<'_>) -> bool {
        match *self {
            Self::MlDsa87(k) => matches!(*other, UncompressedPubKey::MlDsa87(k2) if k == k2),
            Self::MlDsa65(k) => matches!(*other, UncompressedPubKey::MlDsa65(k2) if k == k2),
            Self::MlDsa44(k) => matches!(*other, UncompressedPubKey::MlDsa44(k2) if k == k2),
            Self::Ed25519(k) => matches!(*other, UncompressedPubKey::Ed25519(k2) if k == k2),
            Self::P256(k) => matches!(*other, UncompressedPubKey::P256(k2) if k == k2),
            Self::P384(k) => matches!(*other, UncompressedPubKey::P384(k2) if k == k2),
            Self::Rsa(k) => matches!(*other, UncompressedPubKey::Rsa(k2) if k == k2),
        }
    }
}
impl PartialEq<&UncompressedPubKey<'_>> for UncompressedPubKey<'_> {
    #[inline]
    fn eq(&self, other: &&UncompressedPubKey<'_>) -> bool {
        *self == **other
    }
}
impl PartialEq<UncompressedPubKey<'_>> for &UncompressedPubKey<'_> {
    #[inline]
    fn eq(&self, other: &UncompressedPubKey<'_>) -> bool {
        **self == *other
    }
}
impl Eq for UncompressedPubKey<'_> {}
/// An alleged compressed public key.
///
/// Note [`Self::Rsa`] is uncompressed.
#[derive(Clone, Copy, Debug)]
pub enum CompressedPubKey<T, T2, T3, T4, T5, T6, T7> {
    /// An alleged ML-DSA-87 public key.
    MlDsa87(MlDsa87PubKey<T>),
    /// An alleged ML-DSA-65 public key.
    MlDsa65(MlDsa65PubKey<T2>),
    /// An alleged ML-DSA-44 public key.
    MlDsa44(MlDsa44PubKey<T3>),
    /// An alleged Ed25519 public key.
    Ed25519(Ed25519PubKey<T4>),
    /// An alleged compressed P-256 public key.
    P256(CompressedP256PubKey<T5>),
    /// An alleged compressed P-384 public key.
    P384(CompressedP384PubKey<T6>),
    /// An alleged RSA public key.
    Rsa(RsaPubKey<T7>),
}
/// `CompressedPubKey` that owns the key data.
pub type CompressedPubKeyOwned = CompressedPubKey<
    Box<[u8]>,
    Box<[u8]>,
    Box<[u8]>,
    [u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    [u8; <NistP256 as Curve>::FieldBytesSize::INT],
    [u8; <NistP384 as Curve>::FieldBytesSize::INT],
    Box<[u8]>,
>;
/// `CompressedPubKey` that borrows the key data.
pub type CompressedPubKeyBorrowed<'a> =
    CompressedPubKey<&'a [u8], &'a [u8], &'a [u8], &'a [u8], &'a [u8], &'a [u8], &'a [u8]>;
impl CompressedPubKeyBorrowed<'_> {
    /// Validates `self` is in fact a valid public key.
    ///
    /// # Errors
    ///
    /// Errors iff `self` is not a valid public key.
    #[inline]
    pub fn validate(self) -> Result<(), PubKeyErr> {
        match self {
            Self::MlDsa87(_) | Self::MlDsa65(_) | Self::MlDsa44(_) | Self::Rsa(_) => Ok(()),
            Self::Ed25519(k) => k.validate(),
            Self::P256(k) => k.validate(),
            Self::P384(k) => k.validate(),
        }
    }
}
impl<
    'a: 'b,
    'b,
    T: AsRef<[u8]>,
    T2: AsRef<[u8]>,
    T3: AsRef<[u8]>,
    T4: AsRef<[u8]>,
    T5: AsRef<[u8]>,
    T6: AsRef<[u8]>,
    T7: AsRef<[u8]>,
> From<&'a CompressedPubKey<T, T2, T3, T4, T5, T6, T7>> for CompressedPubKeyBorrowed<'b>
{
    #[inline]
    fn from(value: &'a CompressedPubKey<T, T2, T3, T4, T5, T6, T7>) -> Self {
        match *value {
            CompressedPubKey::MlDsa87(ref val) => Self::MlDsa87(MlDsa87PubKey(val.0.as_ref())),
            CompressedPubKey::MlDsa65(ref val) => Self::MlDsa65(MlDsa65PubKey(val.0.as_ref())),
            CompressedPubKey::MlDsa44(ref val) => Self::MlDsa44(MlDsa44PubKey(val.0.as_ref())),
            CompressedPubKey::Ed25519(ref val) => Self::Ed25519(Ed25519PubKey(val.0.as_ref())),
            CompressedPubKey::P256(ref val) => Self::P256(CompressedP256PubKey {
                x: val.x.as_ref(),
                y_is_odd: val.y_is_odd,
            }),
            CompressedPubKey::P384(ref val) => Self::P384(CompressedP384PubKey {
                x: val.x.as_ref(),
                y_is_odd: val.y_is_odd,
            }),
            CompressedPubKey::Rsa(ref val) => Self::Rsa(RsaPubKey(val.0.as_ref(), val.1)),
        }
    }
}
impl<
    T: PartialEq<T8>,
    T8: PartialEq<T>,
    T2: PartialEq<T9>,
    T9: PartialEq<T2>,
    T3: PartialEq<T10>,
    T10: PartialEq<T3>,
    T4: PartialEq<T11>,
    T11: PartialEq<T4>,
    T5: PartialEq<T12>,
    T12: PartialEq<T5>,
    T6: PartialEq<T13>,
    T13: PartialEq<T6>,
    T7: PartialEq<T14>,
    T14: PartialEq<T7>,
> PartialEq<CompressedPubKey<T, T2, T3, T4, T5, T6, T7>>
    for CompressedPubKey<T8, T9, T10, T11, T12, T13, T14>
{
    #[inline]
    fn eq(&self, other: &CompressedPubKey<T, T2, T3, T4, T5, T6, T7>) -> bool {
        match *self {
            Self::MlDsa87(ref val) => {
                matches!(*other, CompressedPubKey::MlDsa87(ref val2) if val == val2)
            }
            Self::MlDsa65(ref val) => {
                matches!(*other, CompressedPubKey::MlDsa65(ref val2) if val == val2)
            }
            Self::MlDsa44(ref val) => {
                matches!(*other, CompressedPubKey::MlDsa44(ref val2) if val == val2)
            }
            Self::Ed25519(ref val) => {
                matches!(*other, CompressedPubKey::Ed25519(ref val2) if val == val2)
            }
            Self::P256(ref val) => {
                matches!(*other, CompressedPubKey::P256(ref val2) if val == val2)
            }
            Self::P384(ref val) => {
                matches!(*other, CompressedPubKey::P384(ref val2) if val == val2)
            }
            Self::Rsa(ref val) => matches!(*other, CompressedPubKey::Rsa(ref val2) if val == val2),
        }
    }
}
impl<
    T: PartialEq<T8>,
    T8: PartialEq<T>,
    T2: PartialEq<T9>,
    T9: PartialEq<T2>,
    T3: PartialEq<T10>,
    T10: PartialEq<T3>,
    T4: PartialEq<T11>,
    T11: PartialEq<T4>,
    T5: PartialEq<T12>,
    T12: PartialEq<T5>,
    T6: PartialEq<T13>,
    T13: PartialEq<T6>,
    T7: PartialEq<T14>,
    T14: PartialEq<T7>,
> PartialEq<CompressedPubKey<T, T2, T3, T4, T5, T6, T7>>
    for &CompressedPubKey<T8, T9, T10, T11, T12, T13, T14>
{
    #[inline]
    fn eq(&self, other: &CompressedPubKey<T, T2, T3, T4, T5, T6, T7>) -> bool {
        **self == *other
    }
}
impl<
    T: PartialEq<T8>,
    T8: PartialEq<T>,
    T2: PartialEq<T9>,
    T9: PartialEq<T2>,
    T3: PartialEq<T10>,
    T10: PartialEq<T3>,
    T4: PartialEq<T11>,
    T11: PartialEq<T4>,
    T5: PartialEq<T12>,
    T12: PartialEq<T5>,
    T6: PartialEq<T13>,
    T13: PartialEq<T6>,
    T7: PartialEq<T14>,
    T14: PartialEq<T7>,
> PartialEq<&CompressedPubKey<T, T2, T3, T4, T5, T6, T7>>
    for CompressedPubKey<T8, T9, T10, T11, T12, T13, T14>
{
    #[inline]
    fn eq(&self, other: &&CompressedPubKey<T, T2, T3, T4, T5, T6, T7>) -> bool {
        *self == **other
    }
}
impl<T: Eq, T2: Eq, T3: Eq, T4: Eq, T5: Eq, T6: Eq, T7: Eq> Eq
    for CompressedPubKey<T, T2, T3, T4, T5, T6, T7>
{
}
impl<'a> FromCbor<'a> for UncompressedPubKey<'a> {
    type Err = CoseKeyErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        // {kty:<type>...}.
        cbor.get(2)
            .ok_or(CoseKeyErr::Len)
            .and_then(|kty| match *kty {
                OKP => Ed25519PubKey::from_cbor(cbor).map(|key| CborSuccess {
                    value: Self::Ed25519(key.value),
                    remaining: key.remaining,
                }),
                // {kty:EC2,alg:ES256|ES384,...}
                EC2 => cbor.get(4).ok_or(CoseKeyErr::Len).and_then(|alg| {
                    if *alg == ES256 {
                        UncompressedP256PubKey::from_cbor(cbor).map(|key| CborSuccess {
                            value: Self::P256(key.value),
                            remaining: key.remaining,
                        })
                    } else {
                        UncompressedP384PubKey::from_cbor(cbor).map(|key| CborSuccess {
                            value: Self::P384(key.value),
                            remaining: key.remaining,
                        })
                    }
                }),
                RSA => RsaPubKey::from_cbor(cbor).map(|key| CborSuccess {
                    value: Self::Rsa(key.value),
                    remaining: key.remaining,
                }),
                // {kty:AKP,alg:ML-DSA-87|ML-DSA-65|ML-DSA-44,...}
                AKP => cbor
                    .get(5)
                    .ok_or(CoseKeyErr::Len)
                    .and_then(|alg| match *alg {
                        MLDSA44 => MlDsa44PubKey::from_cbor(cbor).map(|key| CborSuccess {
                            value: Self::MlDsa44(key.value),
                            remaining: key.remaining,
                        }),
                        MLDSA65 => MlDsa65PubKey::from_cbor(cbor).map(|key| CborSuccess {
                            value: Self::MlDsa65(key.value),
                            remaining: key.remaining,
                        }),
                        _ => MlDsa87PubKey::from_cbor(cbor).map(|key| CborSuccess {
                            value: Self::MlDsa87(key.value),
                            remaining: key.remaining,
                        }),
                    }),
                _ => Err(CoseKeyErr::CoseKeyType),
            })
    }
}
/// Length of AAGUID.
const AAGUID_LEN: usize = 16;
/// 16 bytes representing an
/// [Authenticator Attestation Globally Unique Identifier (AAGUID)](https://www.w3.org/TR/webauthn-3/#aaguid).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Aaguid<'a>(&'a [u8]);
impl<'a> Aaguid<'a> {
    /// Returns the contained data.
    #[inline]
    #[must_use]
    pub const fn data(self) -> &'a [u8] {
        self.0
    }
}
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for Aaguid<'b> {
    type Error = AaguidErr;
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() == AAGUID_LEN {
            Ok(Self(value))
        } else {
            Err(AaguidErr)
        }
    }
}
/// [Attested credential data](https://www.w3.org/TR/webauthn-3/#attested-credential-data).
#[derive(Debug)]
pub struct AttestedCredentialData<'a> {
    /// [`aaguid`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata-aaguid).
    pub aaguid: Aaguid<'a>,
    /// [`credentialId`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata-credentialid).
    pub credential_id: CredentialId<&'a [u8]>,
    /// [`credentialPublicKey`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata-credentialpublickey).
    pub credential_public_key: UncompressedPubKey<'a>,
}
impl<'a> FromCbor<'a> for AttestedCredentialData<'a> {
    type Err = AttestedCredentialDataErr;
    #[expect(clippy::big_endian_bytes, reason = "CBOR integers are big-endian")]
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// Number of bytes the `CredentialId` length is encoded into.
        const CRED_LEN_LEN: usize = 2;
        cbor.split_at_checked(AAGUID_LEN)
            .ok_or(AttestedCredentialDataErr::Len)
            .and_then(|(aaguid, aaguid_rem)| {
                aaguid_rem
                    .split_at_checked(CRED_LEN_LEN)
                    .ok_or(AttestedCredentialDataErr::Len)
                    .and_then(|(cred_len_slice, cred_len_rem)| {
                        let mut cred_len = [0; CRED_LEN_LEN];
                        cred_len.copy_from_slice(cred_len_slice);
                        // `credentialIdLength` is in big-endian.
                        cred_len_rem
                            .split_at_checked(usize::from(u16::from_be_bytes(cred_len)))
                            .ok_or(AttestedCredentialDataErr::Len)
                            .and_then(|(cred_id, cred_id_rem)| {
                                CredentialId::from_slice(cred_id)
                                    .map_err(AttestedCredentialDataErr::CredentialId)
                                    .and_then(|credential_id| {
                                        UncompressedPubKey::from_cbor(cred_id_rem)
                                            .map_err(AttestedCredentialDataErr::CoseKey)
                                            .map(|cose| CborSuccess {
                                                value: Self {
                                                    aaguid: Aaguid(aaguid),
                                                    credential_id,
                                                    credential_public_key: cose.value,
                                                },
                                                remaining: cose.remaining,
                                            })
                                    })
                            })
                    })
            })
    }
}
/// [Authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data).
#[derive(Debug)]
pub struct AuthenticatorData<'a> {
    /// [`rpIdHash`](https://www.w3.org/TR/webauthn-3/#authdata-rpidhash).
    rp_id_hash: &'a [u8],
    /// [`flags`](https://www.w3.org/TR/webauthn-3/#authdata-flags).
    flags: Flag,
    /// [`signCount`](https://www.w3.org/TR/webauthn-3/#authdata-signcount).
    sign_count: u32,
    /// [`attestedCredentialData`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata).
    attested_credential_data: AttestedCredentialData<'a>,
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
    /// [`attestedCredentialData`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata).
    #[inline]
    #[must_use]
    pub const fn attested_credential_data(&self) -> &AttestedCredentialData<'a> {
        &self.attested_credential_data
    }
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions).
    #[inline]
    #[must_use]
    pub const fn extensions(&self) -> AuthenticatorExtensionOutput {
        self.extensions
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
            .map(|success| {
                assert!(
                    success.remaining.is_empty(),
                    "there is a bug in AuthenticatorData::from_cbor"
                );
                success.value
            })
    }
}
impl<'a> AuthData<'a> for AuthenticatorData<'a> {
    type UpBitErr = Infallible;
    type CredData = AttestedCredentialData<'a>;
    type Ext = AuthenticatorExtensionOutput;
    fn contains_at_bit() -> bool {
        true
    }
    fn user_is_not_present() -> Result<(), Self::UpBitErr> {
        Ok(())
    }
    fn new(
        rp_id_hash: &'a [u8],
        flags: Flag,
        sign_count: u32,
        attested_credential_data: Self::CredData,
        extensions: Self::Ext,
    ) -> Self {
        Self {
            rp_id_hash,
            flags,
            sign_count,
            attested_credential_data,
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
/// [None](https://www.w3.org/TR/webauthn-3/#sctn-none-attestation).
struct NoneAttestation;
impl FromCbor<'_> for NoneAttestation {
    type Err = AttestationErr;
    fn from_cbor(cbor: &[u8]) -> Result<CborSuccess<'_, Self>, Self::Err> {
        cbor.split_first()
            .ok_or(AttestationErr::Len)
            .and_then(|(map, remaining)| {
                if *map == cbor::MAP_0 {
                    Ok(CborSuccess {
                        value: Self,
                        remaining,
                    })
                } else {
                    Err(AttestationErr::NoneFormat)
                }
            })
    }
}
/// A 4627-byte slice that allegedly represents an ML-DSA-87 signature.
struct MlDsa87Signature<'a>(&'a [u8]);
impl<'a> FromCbor<'a> for MlDsa87Signature<'a> {
    type Err = AttestationErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// CBOR metadata describing the signature.
        /// 18 * 256 + 19 = 4627.
        const HEADER: [u8; 3] = [cbor::BYTES_INFO_25, 18, 19];
        cbor.split_at_checked(HEADER.len())
            .ok_or(AttestationErr::Len)
            .and_then(|(header, header_rem)| {
                if header == HEADER {
                    header_rem
                        .split_at_checked(4627)
                        .ok_or(AttestationErr::Len)
                        .map(|(sig, remaining)| CborSuccess {
                            value: Self(sig),
                            remaining,
                        })
                } else {
                    Err(AttestationErr::PackedFormatCborMlDsa87Signature)
                }
            })
    }
}
/// A 3309-byte slice that allegedly represents an ML-DSA-65 signature.
struct MlDsa65Signature<'a>(&'a [u8]);
impl<'a> FromCbor<'a> for MlDsa65Signature<'a> {
    type Err = AttestationErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// CBOR metadata describing the signature.
        /// 12 * 256 + 237 = 3309.
        const HEADER: [u8; 3] = [cbor::BYTES_INFO_25, 12, 237];
        cbor.split_at_checked(HEADER.len())
            .ok_or(AttestationErr::Len)
            .and_then(|(header, header_rem)| {
                if header == HEADER {
                    header_rem
                        .split_at_checked(3309)
                        .ok_or(AttestationErr::Len)
                        .map(|(sig, remaining)| CborSuccess {
                            value: Self(sig),
                            remaining,
                        })
                } else {
                    Err(AttestationErr::PackedFormatCborMlDsa65Signature)
                }
            })
    }
}
/// A 2420-byte slice that allegedly represents an ML-DSA-44 signature.
struct MlDsa44Signature<'a>(&'a [u8]);
impl<'a> FromCbor<'a> for MlDsa44Signature<'a> {
    type Err = AttestationErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// CBOR metadata describing the signature.
        /// 9 * 256 + 116 = 2420.
        const HEADER: [u8; 3] = [cbor::BYTES_INFO_25, 9, 116];
        cbor.split_at_checked(HEADER.len())
            .ok_or(AttestationErr::Len)
            .and_then(|(header, header_rem)| {
                if header == HEADER {
                    header_rem
                        .split_at_checked(2420)
                        .ok_or(AttestationErr::Len)
                        .map(|(sig, remaining)| CborSuccess {
                            value: Self(sig),
                            remaining,
                        })
                } else {
                    Err(AttestationErr::PackedFormatCborMlDsa44Signature)
                }
            })
    }
}
/// A 64-byte slice that allegedly represents an Ed25519 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed25519Signature<'a>(&'a [u8]);
impl<'a> Ed25519Signature<'a> {
    /// Returns signature.
    #[inline]
    #[must_use]
    pub const fn data(self) -> &'a [u8] {
        self.0
    }
    /// Transforms `self` into `Signature`.
    fn into_sig(self) -> Signature {
        let mut sig = [0; ed25519_dalek::SIGNATURE_LENGTH];
        sig.copy_from_slice(self.0);
        Signature::from_bytes(&sig)
    }
}
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for Ed25519Signature<'b> {
    type Error = Ed25519SignatureErr;
    /// Interprets `value` as an Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Errors iff `value.len() != 64`.
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.len() == ed25519_dalek::SIGNATURE_LENGTH {
            Ok(Self(value))
        } else {
            Err(Ed25519SignatureErr)
        }
    }
}
impl<'a> FromCbor<'a> for Ed25519Signature<'a> {
    type Err = AttestationErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        // `64 as u8` is OK.
        /// CBOR metadata describing the signature.
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "comments justify their correctness"
        )]
        const HEADER: [u8; 2] = [cbor::BYTES_INFO_24, ed25519_dalek::SIGNATURE_LENGTH as u8];
        cbor.split_at_checked(HEADER.len())
            .ok_or(AttestationErr::Len)
            .and_then(|(header, header_rem)| {
                if header == HEADER {
                    header_rem
                        .split_at_checked(ed25519_dalek::SIGNATURE_LENGTH)
                        .ok_or(AttestationErr::Len)
                        .map(|(sig, remaining)| CborSuccess {
                            value: Self(sig),
                            remaining,
                        })
                } else {
                    Err(AttestationErr::PackedFormatCborEd25519Signature)
                }
            })
    }
}
/// An alleged DER-encoded P-256 signature using SHA-256.
struct P256DerSig<'a>(&'a [u8]);
impl<'a> FromCbor<'a> for P256DerSig<'a> {
    type Err = AttestationErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        // ```asn
        // Signature ::= SEQUENCE {
        //     r INTEGER,
        //     s INTEGER
        // }
        // ```
        // We assume `r` and `s` can be _any_ 32-byte unsigned integer; thus when DER-encoded without metadata,
        // the number of bytes is inclusively between 1 and 33—INTEGER is a signed integer; thus a 0 byte must
        // be prepended iff the high bit is 1 (i.e., 32-byte unsigned integers with the high bit set take 33 bytes).
        // With metadata this makes the lengths inclusively between 3 and 35—we add 1 for the INTEGER tag and 1
        // for the number of bytes it takes to encode the integer. The total encoded length is thus inclusively
        // between 8 = 1 + 1 + 2(3) and 72 = 1 + 1 + 2(35)—we add 1 for the CONSTRUCTED SEQUENCE tag and 1 for
        // the number of bytes to encode the sequence. Instead of handling that specific range of lengths,
        // we handle all lengths inclusively between 0 and 255.
        cbor.split_first()
            .ok_or(AttestationErr::Len)
            .and_then(|(bytes, bytes_rem)| {
                if bytes & cbor::BYTES == cbor::BYTES {
                    let len_info = bytes ^ cbor::BYTES;
                    match len_info {
                        ..=23 => Ok((bytes_rem, len_info)),
                        24 => bytes_rem.split_first().ok_or(AttestationErr::Len).and_then(
                            |(&len, len_rem)| {
                                if len > 23 {
                                    Ok((len_rem, len))
                                } else {
                                    Err(AttestationErr::PackedFormatCborP256Signature)
                                }
                            },
                        ),
                        _ => Err(AttestationErr::PackedFormatCborP256Signature),
                    }
                    .and_then(|(rem, len)| {
                        rem.split_at_checked(usize::from(len))
                            .ok_or(AttestationErr::Len)
                            .map(|(sig, remaining)| CborSuccess {
                                value: Self(sig),
                                remaining,
                            })
                    })
                } else {
                    Err(AttestationErr::PackedFormatCborP256Signature)
                }
            })
    }
}
/// An alleged DER-encoded P-384 signature using SHA-384.
struct P384DerSig<'a>(&'a [u8]);
impl<'a> FromCbor<'a> for P384DerSig<'a> {
    type Err = AttestationErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        // ```asn
        // Signature ::= SEQUENCE {
        //     r INTEGER,
        //     s INTEGER
        // }
        // ```
        // We assume `r` and `s` can be _any_ 48-byte unsigned integer; thus when DER-encoded without metadata,
        // the number of bytes is inclusively between 1 and 49—INTEGER is a signed integer; thus a 0 byte must
        // be prepended iff the high bit is 1 (i.e., 48-byte unsigned integers with the high bit set take 49 bytes).
        // With metadata this makes the lengths inclusively between 3 and 51—we add 1 for the INTEGER tag and 1
        // for the number of bytes it takes to encode the integer. The total encoded length is thus inclusively
        // between 8 = 1 + 1 + 2(3) and 104 = 1 + 1 + 2(51)—we add 1 for the CONSTRUCTED SEQUENCE tag and 1 for
        // the number of bytes to encode the sequence. Instead of handling that specific range of lengths,
        // we handle all lengths inclusively between 0 and 255.
        cbor.split_first()
            .ok_or(AttestationErr::Len)
            .and_then(|(bytes, bytes_rem)| {
                if bytes & cbor::BYTES == cbor::BYTES {
                    let len_info = bytes ^ cbor::BYTES;
                    match len_info {
                        ..=23 => Ok((bytes_rem, len_info)),
                        24 => bytes_rem.split_first().ok_or(AttestationErr::Len).and_then(
                            |(&len, len_rem)| {
                                if len > 23 {
                                    Ok((len_rem, len))
                                } else {
                                    Err(AttestationErr::PackedFormatCborP384Signature)
                                }
                            },
                        ),
                        _ => Err(AttestationErr::PackedFormatCborP384Signature),
                    }
                    .and_then(|(rem, len)| {
                        rem.split_at_checked(usize::from(len))
                            .ok_or(AttestationErr::Len)
                            .map(|(sig, remaining)| CborSuccess {
                                value: Self(sig),
                                remaining,
                            })
                    })
                } else {
                    Err(AttestationErr::PackedFormatCborP384Signature)
                }
            })
    }
}
/// An alleged RSASSA-PKCS1-v1_5 signature using SHA-256.
struct RsaPkcs1v15Sig<'a>(&'a [u8]);
impl<'a> FromCbor<'a> for RsaPkcs1v15Sig<'a> {
    type Err = AttestationErr;
    #[expect(clippy::big_endian_bytes, reason = "CBOR integers are big-endian")]
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        // RSASSA-PKCS1-v1_5 signatures are the same length as the modulus. We only allow moduli consisting of
        // [`MIN_RSA_N_BYTES`] to [`MAX_RSA_N_BYTES`] bytes inclusively. This means
        // all signatures will use the same CBOR metadata tag (i.e., `cbor::BYTES_INFO_25`).
        cbor.split_first()
            .ok_or(AttestationErr::Len)
            .and_then(|(bytes, bytes_rem)| {
                if *bytes == cbor::BYTES_INFO_25 {
                    bytes_rem
                        .split_at_checked(2)
                        .ok_or(AttestationErr::Len)
                        .and_then(|(len_slice, len_rem)| {
                            let mut cbor_len = [0; 2];
                            cbor_len.copy_from_slice(len_slice);
                            // CBOR uints are big-endian.
                            let len = usize::from(u16::from_be_bytes(cbor_len));
                            if len > 255 {
                                len_rem
                                    .split_at_checked(len)
                                    .ok_or(AttestationErr::Len)
                                    .map(|(sig, remaining)| CborSuccess {
                                        value: Self(sig),
                                        remaining,
                                    })
                            } else {
                                Err(AttestationErr::PackedFormatCborRs256Signature)
                            }
                        })
                } else {
                    Err(AttestationErr::PackedFormatCborRs256Signature)
                }
            })
    }
}
/// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sig<'a> {
    /// Alleged ML-DSA-87.
    MlDsa87(&'a [u8]),
    /// Alleged ML-DSA-65.
    MlDsa65(&'a [u8]),
    /// Alleged ML-DSA-44.
    MlDsa44(&'a [u8]),
    /// Alleged Ed25519 signature.
    Ed25519(Ed25519Signature<'a>),
    /// Alleged DER-encoded P-256 signature using SHA-256.
    P256(&'a [u8]),
    /// Alleged DER-encoded P-384 signature using SHA-384.
    P384(&'a [u8]),
    /// Alleged RSASSA-PKCS1-v1_5 signature using SHA-256.
    Rs256(&'a [u8]),
}
/// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedAttestation<'a> {
    /// [Attestation signature](https://www.w3.org/TR/webauthn-3/#attestation-signature).
    pub signature: Sig<'a>,
}
impl<'a> FromCbor<'a> for PackedAttestation<'a> {
    type Err = AttestationErr;
    #[expect(
        clippy::too_many_lines,
        reason = "don't want to move code to an outer scope"
    )]
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        /// Parses `data` as packed attestation up until `x5c` _without_ the `cbor::MAP_2` or `cbor::MAP_3` header.
        fn parse_to_cert_chain(data: &[u8]) -> Result<CborSuccess<'_, Sig<'_>>, AttestationErr> {
            // {"alg":CoseAlgorithmIdentifier,"sig":sig_bytes...}
            /// "alg" key.
            const ALG: [u8; 4] = [cbor::TEXT_3, b'a', b'l', b'g'];
            /// "sig" key.
            const SIG: [u8; 4] = [cbor::TEXT_3, b's', b'i', b'g'];
            data.split_at_checked(ALG.len())
                .ok_or(AttestationErr::Len)
                .and_then(|(alg, alg_rem)| {
                    if alg == ALG {
                        alg_rem.split_first().ok_or(AttestationErr::Len).and_then(
                            |(cose, cose_rem)| match *cose {
                                EDDSA => cose_rem
                                    .split_at_checked(SIG.len())
                                    .ok_or(AttestationErr::Len)
                                    .and_then(|(sig, sig_rem)| {
                                        if sig == SIG {
                                            Ed25519Signature::from_cbor(sig_rem).map(|success| {
                                                CborSuccess {
                                                    value: Sig::Ed25519(success.value),
                                                    remaining: success.remaining,
                                                }
                                            })
                                        } else {
                                            Err(AttestationErr::PackedFormatMissingSig)
                                        }
                                    }),
                                ES256 => cose_rem
                                    .split_at_checked(SIG.len())
                                    .ok_or(AttestationErr::Len)
                                    .and_then(|(sig, sig_rem)| {
                                        if sig == SIG {
                                            P256DerSig::from_cbor(sig_rem).map(|success| {
                                                CborSuccess {
                                                    value: Sig::P256(success.value.0),
                                                    remaining: success.remaining,
                                                }
                                            })
                                        } else {
                                            Err(AttestationErr::PackedFormatMissingSig)
                                        }
                                    }),
                                cbor::NEG_INFO_24 => cose_rem
                                    .split_first()
                                    .ok_or(AttestationErr::Len)
                                    .and_then(|(len, len_rem)| match *len {
                                        ES384 => len_rem
                                            .split_at_checked(SIG.len())
                                            .ok_or(AttestationErr::Len)
                                            .and_then(|(sig, sig_rem)| {
                                                if sig == SIG {
                                                    P384DerSig::from_cbor(sig_rem).map(|success| {
                                                        CborSuccess {
                                                            value: Sig::P384(success.value.0),
                                                            remaining: success.remaining,
                                                        }
                                                    })
                                                } else {
                                                    Err(AttestationErr::PackedFormatMissingSig)
                                                }
                                            }),
                                        MLDSA44 => len_rem
                                            .split_at_checked(SIG.len())
                                            .ok_or(AttestationErr::Len)
                                            .and_then(|(sig, sig_rem)| {
                                                if sig == SIG {
                                                    MlDsa44Signature::from_cbor(sig_rem).map(
                                                        |success| CborSuccess {
                                                            value: Sig::MlDsa44(success.value.0),
                                                            remaining: success.remaining,
                                                        },
                                                    )
                                                } else {
                                                    Err(AttestationErr::PackedFormatMissingSig)
                                                }
                                            }),
                                        MLDSA65 => len_rem
                                            .split_at_checked(SIG.len())
                                            .ok_or(AttestationErr::Len)
                                            .and_then(|(sig, sig_rem)| {
                                                if sig == SIG {
                                                    MlDsa65Signature::from_cbor(sig_rem).map(
                                                        |success| CborSuccess {
                                                            value: Sig::MlDsa65(success.value.0),
                                                            remaining: success.remaining,
                                                        },
                                                    )
                                                } else {
                                                    Err(AttestationErr::PackedFormatMissingSig)
                                                }
                                            }),
                                        MLDSA87 => len_rem
                                            .split_at_checked(SIG.len())
                                            .ok_or(AttestationErr::Len)
                                            .and_then(|(sig, sig_rem)| {
                                                if sig == SIG {
                                                    MlDsa87Signature::from_cbor(sig_rem).map(
                                                        |success| CborSuccess {
                                                            value: Sig::MlDsa87(success.value.0),
                                                            remaining: success.remaining,
                                                        },
                                                    )
                                                } else {
                                                    Err(AttestationErr::PackedFormatMissingSig)
                                                }
                                            }),
                                        _ => Err(AttestationErr::PackedFormatUnsupportedAlg),
                                    }),
                                cbor::NEG_INFO_25 => cose_rem
                                    .split_at_checked(2)
                                    .ok_or(AttestationErr::Len)
                                    .and_then(|(len, len_rem)| {
                                        if len == RS256 {
                                            len_rem
                                                .split_at_checked(SIG.len())
                                                .ok_or(AttestationErr::Len)
                                                .and_then(|(sig, sig_rem)| {
                                                    if sig == SIG {
                                                        RsaPkcs1v15Sig::from_cbor(sig_rem).map(
                                                            |success| CborSuccess {
                                                                value: Sig::Rs256(success.value.0),
                                                                remaining: success.remaining,
                                                            },
                                                        )
                                                    } else {
                                                        Err(AttestationErr::PackedFormatMissingSig)
                                                    }
                                                })
                                        } else {
                                            Err(AttestationErr::PackedFormatUnsupportedAlg)
                                        }
                                    }),
                                _ => Err(AttestationErr::PackedFormatUnsupportedAlg),
                            },
                        )
                    } else {
                        Err(AttestationErr::PackedFormatMissingAlg)
                    }
                })
        }
        cbor.split_first()
            .ok_or(AttestationErr::Len)
            .and_then(|(map, map_rem)| match *map {
                cbor::MAP_2 => parse_to_cert_chain(map_rem).map(|success| CborSuccess {
                    value: Self {
                        signature: success.value,
                    },
                    remaining: success.remaining,
                }),
                _ => Err(AttestationErr::PackedFormat),
            })
    }
}
/// [Attestation statement format identifiers](https://www.w3.org/TR/webauthn-3/#sctn-attstn-fmt-ids).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationFormat<'a> {
    /// [None](https://www.w3.org/TR/webauthn-3/#sctn-none-attestation).
    None,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation).
    Packed(PackedAttestation<'a>),
}
impl<'a> FromCbor<'a> for AttestationFormat<'a> {
    type Err = AttestationErr;
    fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, Self::Err> {
        // Note we assume that cbor starts _after_ `cbor::MAP_3`.
        // {"fmt":"none"|"packed", "attStmt": NoneAttestation|CborPacked, ...}.
        /// "fmt" key.
        const FMT: [u8; 4] = [cbor::TEXT_3, b'f', b'm', b't'];
        /// "none" value.
        const NONE: [u8; 5] = [cbor::TEXT_4, b'n', b'o', b'n', b'e'];
        /// "packed" value.
        const PACKED: [u8; 7] = [cbor::TEXT_6, b'p', b'a', b'c', b'k', b'e', b'd'];
        /// "attStmt" key.
        const ATT_STMT: [u8; 8] = [cbor::TEXT_7, b'a', b't', b't', b'S', b't', b'm', b't'];
        cbor.split_at_checked(FMT.len())
            .ok_or(AttestationErr::Len)
            .and_then(|(fmt, fmt_rem)| {
                if fmt == FMT {
                    fmt_rem
                        .split_at_checked(NONE.len())
                        .ok_or(AttestationErr::Len)
                        // `PACKED.len() > NONE.len()`, so we check for `PACKED` in `and_then`.
                        .and_then(|(none, none_rem)| {
                            if none == NONE {
                                none_rem
                                    .split_at_checked(ATT_STMT.len())
                                    .ok_or(AttestationErr::Len)
                                    .and_then(|(att, att_rem)| {
                                        if att == ATT_STMT {
                                            NoneAttestation::from_cbor(att_rem).map(|success| {
                                                CborSuccess {
                                                    value: Self::None,
                                                    remaining: success.remaining,
                                                }
                                            })
                                        } else {
                                            Err(AttestationErr::MissingStatement)
                                        }
                                    })
                            } else {
                                fmt_rem
                                    .split_at_checked(PACKED.len())
                                    .ok_or(AttestationErr::Len)
                                    .and_then(|(packed, packed_rem)| {
                                        if packed == PACKED {
                                            packed_rem
                                                .split_at_checked(ATT_STMT.len())
                                                .ok_or(AttestationErr::Len)
                                                .and_then(|(att, att_rem)| {
                                                    if att == ATT_STMT {
                                                        PackedAttestation::from_cbor(att_rem).map(
                                                            |success| CborSuccess {
                                                                value: Self::Packed(success.value),
                                                                remaining: success.remaining,
                                                            },
                                                        )
                                                    } else {
                                                        Err(AttestationErr::MissingStatement)
                                                    }
                                                })
                                        } else {
                                            Err(AttestationErr::UnsupportedFormat)
                                        }
                                    })
                            }
                        })
                } else {
                    Err(AttestationErr::MissingFormat)
                }
            })
    }
}
impl<'a> AttestationObject<'a> {
    /// [Attestation statement format identifiers](https://www.w3.org/TR/webauthn-3/#sctn-attstn-fmt-ids).
    #[inline]
    #[must_use]
    pub const fn attestation(&self) -> AttestationFormat<'a> {
        self.attestation
    }
    /// [Authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data).
    #[inline]
    #[must_use]
    pub const fn auth_data(&self) -> &AuthenticatorData<'a> {
        &self.auth_data
    }
    /// Deserializes `data` based on the
    /// [attestation object layout](https://www.w3.org/TR/webauthn-3/#attestation-object)
    /// returning [`Self`] and the index within `data` that the authenticator data portion
    /// begins.
    #[expect(single_use_lifetimes, reason = "false positive")]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "we want to crash when there is a bug"
    )]
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment justifies its correctness"
    )]
    #[expect(clippy::big_endian_bytes, reason = "cbor lengths are in big-endian")]
    fn parse_data<'b: 'a>(data: &'b [u8]) -> Result<(Self, usize), AttestationObjectErr> {
        /// `authData` key.
        const AUTH_DATA_KEY: [u8; 9] =
            [cbor::TEXT_8, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a'];
        // {"fmt":<AttestationFormat>, "attStmt":<AttestationObject>, "authData":<AuthentcatorData>}.
        data.split_first().ok_or(AttestationObjectErr::Len).and_then(|(map, map_rem)| {
            if *map == cbor::MAP_3 {
                AttestationFormat::from_cbor(map_rem).map_err(AttestationObjectErr::Attestation).and_then(|att| {
                    att.remaining.split_at_checked(AUTH_DATA_KEY.len()).ok_or(AttestationObjectErr::Len).and_then(|(key, key_rem)| {
                        if key == AUTH_DATA_KEY {
                            key_rem.split_first().ok_or(AttestationObjectErr::Len).and_then(|(bytes, bytes_rem)| {
                                if bytes & cbor::BYTES == cbor::BYTES {
                                    match bytes ^ cbor::BYTES {
                                        24 => bytes_rem.split_first().ok_or(AttestationObjectErr::Len).and_then(|(&len, auth_data)| {
                                            if len > 23 {
                                                Ok((usize::from(len), auth_data))
                                            } else {
                                                Err(AttestationObjectErr::AuthDataLenInfo)
                                            }
                                        }),
                                        25 => bytes_rem.split_at_checked(2).ok_or(AttestationObjectErr::Len).and_then(|(len_slice, auth_data)| {
                                            let mut auth_len = [0; 2];
                                            auth_len.copy_from_slice(len_slice);
                                            // Length is encoded as big-endian.
                                            let len = usize::from(u16::from_be_bytes(auth_len));
                                            if len > 255 {
                                                Ok((len, auth_data))
                                            } else {
                                                Err(AttestationObjectErr::AuthDataLenInfo)
                                            }
                                        }),
                                        _ => Err(AttestationObjectErr::AuthDataLenInfo),
                                    }.and_then(|(cbor_auth_data_len, auth_slice)| {
                                        if cbor_auth_data_len == auth_slice.len() {
                                            AuthenticatorData::from_cbor(auth_slice).map_err(|e| AttestationObjectErr::AuthData(e.into())).and_then(|auth_data| {
                                                assert!(auth_data.remaining.is_empty(), "there is a bug in AuthenticatorData::from_cbor");
                                                match att.value {
                                                    AttestationFormat::None => Ok(()),
                                                    AttestationFormat::Packed(ref val) => match val.signature {
                                                        Sig::MlDsa87(_) => if matches!(auth_data.value.attested_credential_data.credential_public_key, UncompressedPubKey::MlDsa87(_)) {
                                                            Ok(())
                                                        } else {
                                                            Err(AttestationObjectErr::SelfAttestationAlgorithmMismatch)
                                                        },
                                                        Sig::MlDsa65(_) => if matches!(auth_data.value.attested_credential_data.credential_public_key, UncompressedPubKey::MlDsa65(_)) {
                                                            Ok(())
                                                        } else {
                                                            Err(AttestationObjectErr::SelfAttestationAlgorithmMismatch)
                                                        },
                                                        Sig::MlDsa44(_) => if matches!(auth_data.value.attested_credential_data.credential_public_key, UncompressedPubKey::MlDsa44(_)) {
                                                            Ok(())
                                                        } else {
                                                            Err(AttestationObjectErr::SelfAttestationAlgorithmMismatch)
                                                        },
                                                        Sig::Ed25519(_) => if matches!(auth_data.value.attested_credential_data.credential_public_key, UncompressedPubKey::Ed25519(_)) {
                                                            Ok(())
                                                        } else {
                                                            Err(AttestationObjectErr::SelfAttestationAlgorithmMismatch)
                                                        },
                                                        Sig::P256(_) => if matches!(auth_data.value.attested_credential_data.credential_public_key, UncompressedPubKey::P256(_)) {
                                                            Ok(())
                                                        } else {
                                                            Err(AttestationObjectErr::SelfAttestationAlgorithmMismatch)
                                                        },
                                                        Sig::P384(_) => if matches!(auth_data.value.attested_credential_data.credential_public_key, UncompressedPubKey::P384(_)) {
                                                            Ok(())
                                                        } else {
                                                            Err(AttestationObjectErr::SelfAttestationAlgorithmMismatch)
                                                        },
                                                        Sig::Rs256(_) => if matches!(auth_data.value.attested_credential_data.credential_public_key, UncompressedPubKey::Rsa(_)) {
                                                            Ok(())
                                                        } else {
                                                            Err(AttestationObjectErr::SelfAttestationAlgorithmMismatch)
                                                        },
                                                    },
                                                    // `cbor_auth_data_len == `auth_slice.len()` and `auth_slice.len() < data.len()`, so underflow won't happen.
                                                }.map(|()| (Self { attestation: att.value, auth_data: auth_data.value }, data.len() - cbor_auth_data_len))
                                            })
                                        } else {
                                            Err(AttestationObjectErr::CborAuthDataLenMismatch)
                                        }
                                    })
                                } else {
                                    Err(AttestationObjectErr::AuthDataType)
                                }
                            })
                        } else {
                            Err(AttestationObjectErr::MissingAuthData)
                        }
                    })
                })
            } else {
                Err(AttestationObjectErr::NotAMapOf3)
            }
        })
    }
}
/// [Attestation object](https://www.w3.org/TR/webauthn-3/#attestation-object).
#[derive(Debug)]
pub struct AttestationObject<'a> {
    /// [Attestation statement format identifiers](https://www.w3.org/TR/webauthn-3/#sctn-attstn-fmt-ids).
    attestation: AttestationFormat<'a>,
    /// [Authenticator data](https://www.w3.org/TR/webauthn-3/#authenticator-data).
    auth_data: AuthenticatorData<'a>,
}
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for AttestationObject<'b> {
    type Error = AttestationObjectErr;
    /// Deserializes `value` based on the
    /// [attestation object layout](https://www.w3.org/TR/webauthn-3/#attestation-object).
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::parse_data(value).map(|(val, _)| val)
    }
}
impl<'a> AuthDataContainer<'a> for AttestationObject<'a> {
    type Auth = AuthenticatorData<'a>;
    type Err = AttestationObjectErr;
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    #[expect(clippy::indexing_slicing, reason = "comment justifies its correctness")]
    fn from_data(data: &'a [u8]) -> Result<ParsedAuthData<'a, Self>, Self::Err> {
        // `data.len().checked_sub(Sha256::output_size())` is clearly less than `data.len()`;
        // thus indexing wont `panic`.
        Self::parse_data(&data[..data.len().checked_sub(Sha256::output_size()).unwrap_or_else(|| unreachable!("AttestationObject::from_data must be passed a slice with 32 bytes of trailing data"))]).map(|(attest, auth_idx)| ParsedAuthData { data: attest, auth_data_and_32_trailing_bytes: &data[auth_idx..], })
    }
    fn authenticator_data(&self) -> &Self::Auth {
        &self.auth_data
    }
}
/// [`AuthenticatorAttestationResponse`](https://www.w3.org/TR/webauthn-3/#authenticatorattestationresponse).
#[derive(Debug)]
pub struct AuthenticatorAttestation {
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson).
    client_data_json: Vec<u8>,
    /// [attestation object](https://www.w3.org/TR/webauthn-3/#attestation-object) followed by the SHA-256 hash
    /// of [`Self::client_data_json`].
    attestation_object_and_c_data_hash: Vec<u8>,
    /// [`getTransports`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-gettransports).
    transports: AuthTransports,
}
impl AuthenticatorAttestation {
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson).
    #[inline]
    #[must_use]
    pub const fn client_data_json(&self) -> &[u8] {
        self.client_data_json.as_slice()
    }
    /// [attestation object](https://www.w3.org/TR/webauthn-3/#attestation-object).
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "comment justifies their correctness"
    )]
    #[inline]
    #[must_use]
    pub fn attestation_object(&self) -> &[u8] {
        // We only allow creation via [`Self::new`] which creates [`Self::attestation_object_and_c_data_hash`]
        // by appending the SHA-256 hash of [`Self::client_data_json`] to the attestation object that was passed;
        // thus indexing is fine and subtraction won't cause underflow.
        &self.attestation_object_and_c_data_hash
            [..self.attestation_object_and_c_data_hash.len() - Sha256::output_size()]
    }
    /// [`getTransports`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-gettransports).
    #[inline]
    #[must_use]
    pub const fn transports(&self) -> AuthTransports {
        self.transports
    }
    /// Constructs an instance of `Self` with the contained data.
    ///
    /// Note calling code is encouraged to ensure `attestation_object` has at least 32 bytes
    /// of available capacity; if not, a reallocation will occur which may hinder performance
    /// depending on its size.
    #[inline]
    #[must_use]
    pub fn new(
        client_data_json: Vec<u8>,
        mut attestation_object: Vec<u8>,
        transports: AuthTransports,
    ) -> Self {
        attestation_object.extend_from_slice(&Sha256::digest(client_data_json.as_slice()));
        Self {
            client_data_json,
            attestation_object_and_c_data_hash: attestation_object,
            transports,
        }
    }
}
impl AuthResponse for AuthenticatorAttestation {
    type Auth<'a>
        = AttestationObject<'a>
    where
        Self: 'a;
    type CredKey<'a> = ();
    #[expect(clippy::unreachable, reason = "when there is a bug, we want to crash")]
    fn parse_data_and_verify_sig(
        &self,
        (): Self::CredKey<'_>,
        relaxed: bool,
    ) -> Result<
        (CollectedClientData<'_>, Self::Auth<'_>),
        AuthRespErr<<Self::Auth<'_> as AuthDataContainer<'_>>::Err>,
    > {
        if relaxed {
            #[cfg(not(feature = "serde_relaxed"))]
            unreachable!("AuthenticatorAttestation::parse_data_and_verify_sig: must be passed false when serde_relaxed is not enabled");
            #[cfg(feature = "serde_relaxed")]
            CollectedClientData::from_client_data_json_relaxed::<true>(
                self.client_data_json.as_slice(),
            ).map_err(AuthRespErr::CollectedClientDataRelaxed)
        } else {
            CollectedClientData::from_client_data_json::<true>(self.client_data_json.as_slice()).map_err(AuthRespErr::CollectedClientData)
        }
        .and_then(|client_data_json| {
            Self::Auth::from_data(self.attestation_object_and_c_data_hash.as_slice())
                .map_err(AuthRespErr::Auth)
                .and_then(|val| {
                    match val.data.auth_data.attested_credential_data.credential_public_key {
                        UncompressedPubKey::MlDsa87(key) => {
                            match val.data.attestation {
                                AttestationFormat::None => Ok(()),
                                AttestationFormat::Packed(packed) => match packed.signature {
                                    Sig::MlDsa87(sig) => MlDsaSignature::<MlDsa87>::decode(sig.as_array().unwrap_or_else(|| unreachable!("there is a bug in slice::as_array")).into()).ok_or(AuthRespErr::Signature).and_then(|s| key.into_ver_key().verify(val.auth_data_and_32_trailing_bytes, &s).map_err(|_e| AuthRespErr::Signature)),
                                    Sig::MlDsa65(_) | Sig::MlDsa44(_) | Sig::Ed25519(_) | Sig::P256(_) | Sig::P384(_) | Sig::Rs256(_) => unreachable!("there is a bug in AttestationObject::from_data"),
                                }
                            }
                        }
                        UncompressedPubKey::MlDsa65(key) => {
                            match val.data.attestation {
                                AttestationFormat::None => Ok(()),
                                AttestationFormat::Packed(packed) => match packed.signature {
                                    Sig::MlDsa65(sig) => MlDsaSignature::<MlDsa65>::decode(sig.as_array().unwrap_or_else(|| unreachable!("there is a bug in slice::as_array")).into()).ok_or(AuthRespErr::Signature).and_then(|s| key.into_ver_key().verify(val.auth_data_and_32_trailing_bytes, &s).map_err(|_e| AuthRespErr::Signature)),
                                    Sig::MlDsa87(_) | Sig::MlDsa44(_) | Sig::Ed25519(_) | Sig::P256(_) | Sig::P384(_) | Sig::Rs256(_) => unreachable!("there is a bug in AttestationObject::from_data"),
                                }
                            }
                        }
                        UncompressedPubKey::MlDsa44(key) => {
                            match val.data.attestation {
                                AttestationFormat::None => Ok(()),
                                AttestationFormat::Packed(packed) => match packed.signature {
                                    Sig::MlDsa44(sig) => MlDsaSignature::<MlDsa44>::decode(sig.as_array().unwrap_or_else(|| unreachable!("there is a bug in slice::as_array")).into()).ok_or(AuthRespErr::Signature).and_then(|s| key.into_ver_key().verify(val.auth_data_and_32_trailing_bytes, &s).map_err(|_e| AuthRespErr::Signature)),
                                    Sig::MlDsa87(_) | Sig::MlDsa65(_) | Sig::Ed25519(_) | Sig::P256(_) | Sig::P384(_) | Sig::Rs256(_) => unreachable!("there is a bug in AttestationObject::from_data"),
                                }
                            }
                        }
                        UncompressedPubKey::Ed25519(key) => key.into_ver_key().map_err(AuthRespErr::PubKey).and_then(|ver_key| {
                            match val.data.attestation {
                                AttestationFormat::None => Ok(()),
                                AttestationFormat::Packed(packed) => match packed.signature {
                                    // We don't need to use `VerifyingKey::verify_strict` since
                                    // `Ed25519PubKey::into_ver_key` verifies the public key is not
                                    // in the small-order subgroup. `VerifyingKey::verify_strict` additionally
                                    // ensures _R_ of the signature is not in the small-order subgroup, but this
                                    // doesn't provide additional benefits and is still not enough to comply
                                    // with standards like RFC 8032 or NIST SP 800-186.
                                    Sig::Ed25519(sig) => ver_key.verify(val.auth_data_and_32_trailing_bytes, &sig.into_sig()).map_err(|_e| AuthRespErr::Signature),
                                    Sig::MlDsa87(_) | Sig::MlDsa65(_) | Sig::MlDsa44(_) | Sig::P256(_) | Sig::P384(_) | Sig::Rs256(_) => unreachable!("there is a bug in AttestationObject::from_data"),
                                }
                            }
                        }),
                        UncompressedPubKey::P256(key) => key.into_ver_key().map_err(AuthRespErr::PubKey).and_then(|ver_key| {
                            match val.data.attestation {
                                AttestationFormat::None => Ok(()),
                                AttestationFormat::Packed(packed) => match packed.signature {
                                    Sig::P256(sig) => P256Sig::from_bytes(sig).map_err(|_e| AuthRespErr::Signature).and_then(|s| ver_key.verify(val.auth_data_and_32_trailing_bytes, &s).map_err(|_e| AuthRespErr::Signature)),
                                    Sig::MlDsa87(_) | Sig::MlDsa65(_) | Sig::MlDsa44(_) | Sig::Ed25519(_) | Sig::P384(_) | Sig::Rs256(_) => unreachable!("there is a bug in AttestationObject::from_data"),
                                }
                            }
                        }),
                        UncompressedPubKey::P384(key) => key.into_ver_key().map_err(AuthRespErr::PubKey).and_then(|ver_key| {
                            match val.data.attestation {
                                AttestationFormat::None => Ok(()),
                                AttestationFormat::Packed(packed) => match packed.signature {
                                    Sig::P384(sig) => P384Sig::from_bytes(sig).map_err(|_e| AuthRespErr::Signature).and_then(|s| ver_key.verify(val.auth_data_and_32_trailing_bytes, &s).map_err(|_e| AuthRespErr::Signature)),
                                    Sig::MlDsa87(_) | Sig::MlDsa65(_) | Sig::MlDsa44(_) | Sig::Ed25519(_) | Sig::P256(_) | Sig::Rs256(_) => unreachable!("there is a bug in AttestationObject::from_data"),
                                }
                            }
                        }),
                        UncompressedPubKey::Rsa(key) => match val.data.attestation {
                            AttestationFormat::None => Ok(()),
                            AttestationFormat::Packed(packed) => match packed.signature {
                                Sig::Rs256(sig) => pkcs1v15::Signature::try_from(sig).map_err(|_e| AuthRespErr::Signature).and_then(|s| key.as_ver_key().verify(val.auth_data_and_32_trailing_bytes, &s).map_err(|_e| AuthRespErr::Signature)),
                                Sig::MlDsa87(_) | Sig::MlDsa65(_) | Sig::MlDsa44(_) | Sig::Ed25519(_) | Sig::P256(_) | Sig::P384(_) => unreachable!("there is a bug in AttestationObject::from_data"),
                            }
                        },
                    }.map(|()| (client_data_json, val.data))
                })
        })
    }
}
/// [`CredentialPropertiesOutput`](https://www.w3.org/TR/webauthn-3/#dictdef-credentialpropertiesoutput).
///
/// Note [`Self::rk`] is frequently unreliable. For example there are times it is `Some(false)` despite the
/// credential being stored client-side. One may have better luck checking if [`AuthTransports::contains`]
/// [`AuthenticatorTransport::Internal`] and using that as an indicator if a client-side credential was created.
#[derive(Clone, Copy, Debug)]
pub struct CredentialPropertiesOutput {
    /// [`rk`](https://www.w3.org/TR/webauthn-3/#dom-credentialpropertiesoutput-rk).
    pub rk: Option<bool>,
}
/// [`AuthenticationExtensionsPRFOutputs`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfoutputs).
///
/// Note since this is a server-side library, we don't store
/// [`results`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-results)
/// since it contains sensitive data that should remain client-side.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticationExtensionsPrfOutputs {
    /// [`enabled`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-enabled).
    pub enabled: bool,
}
/// [`AuthenticationExtensionsClientOutputs`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientoutputs).
#[derive(Clone, Copy, Debug)]
pub struct ClientExtensionsOutputs {
    /// [`credProps`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsclientoutputs-credprops).
    pub cred_props: Option<CredentialPropertiesOutput>,
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsclientoutputs-prf).
    pub prf: Option<AuthenticationExtensionsPrfOutputs>,
}
/// [`ClientExtensionsOutputs`] extensions that are saved in [`Metadata`] because they are purely informative
/// and not used during authentication ceremonies.
#[derive(Clone, Copy, Debug)]
pub struct ClientExtensionsOutputsMetadata {
    /// [`ClientExtensionsOutputs::cred_props`].
    pub cred_props: Option<CredentialPropertiesOutput>,
}
/// [`ClientExtensionsOutputs`] extensions that are saved in [`StaticState`] because they are used during
/// authentication ceremonies.
#[derive(Clone, Copy, Debug)]
pub struct ClientExtensionsOutputsStaticState {
    /// [`ClientExtensionsOutputs::prf`].
    pub prf: Option<AuthenticationExtensionsPrfOutputs>,
}
impl From<ClientExtensionsOutputs> for ClientExtensionsOutputsMetadata {
    #[inline]
    fn from(value: ClientExtensionsOutputs) -> Self {
        Self {
            cred_props: value.cred_props,
        }
    }
}
impl From<ClientExtensionsOutputs> for ClientExtensionsOutputsStaticState {
    #[inline]
    fn from(value: ClientExtensionsOutputs) -> Self {
        Self { prf: value.prf }
    }
}
/// [`PublicKeyCredential`](https://www.w3.org/TR/webauthn-3/#iface-pkcredential) for registration ceremonies.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "no invariants to uphold"
)]
#[derive(Debug)]
pub struct Registration {
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response).
    pub(crate) response: AuthenticatorAttestation,
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment).
    pub(crate) authenticator_attachment: AuthenticatorAttachment,
    /// [`getClientExtensionResults()`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-getclientextensionresults).
    pub(crate) client_extension_results: ClientExtensionsOutputs,
}
impl Registration {
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-response).
    #[inline]
    #[must_use]
    pub const fn response(&self) -> &AuthenticatorAttestation {
        &self.response
    }
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment).
    #[inline]
    #[must_use]
    pub const fn authenticator_attachment(&self) -> AuthenticatorAttachment {
        self.authenticator_attachment
    }
    /// [`getClientExtensionResults()`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-getclientextensionresults).
    #[inline]
    #[must_use]
    pub const fn client_extension_results(&self) -> ClientExtensionsOutputs {
        self.client_extension_results
    }
    /// Constructs a `Registration` based on the passed arguments.
    #[cfg(feature = "custom")]
    #[inline]
    #[must_use]
    pub const fn new(
        response: AuthenticatorAttestation,
        authenticator_attachment: AuthenticatorAttachment,
        client_extension_results: ClientExtensionsOutputs,
    ) -> Self {
        Self {
            response,
            authenticator_attachment,
            client_extension_results,
        }
    }
    /// Returns the associated `SentChallenge`.
    ///
    /// This is useful when wanting to extract the corresponding [`RegistrationServerState`] from
    /// an in-memory collection (e.g., [`MaxLenHashSet`]) or storage.
    ///
    /// Note if [`CollectedClientData::from_client_data_json`] returns `Ok`, then this will return
    /// `Ok` containing the same value as [`CollectedClientData::challenge`]; however the converse
    /// is _not_ true. This is because this function parses the minimal amount of data possible.
    ///
    /// # Errors
    ///
    /// Errors iff [`AuthenticatorAttestation::client_data_json`] does not contain a base64url-encoded
    /// [`Challenge`] in the required position.
    #[inline]
    pub fn challenge(&self) -> Result<SentChallenge, CollectedClientDataErr> {
        LimitedVerificationParser::<true>::get_sent_challenge(
            self.response.client_data_json.as_slice(),
        )
    }
    /// Returns the associated `SentChallenge`.
    ///
    /// This is useful when wanting to extract the corresponding [`RegistrationServerState`] from
    /// an in-memory collection (e.g., [`MaxLenHashSet`]) or storage.
    ///
    /// Note if [`CollectedClientData::from_client_data_json_relaxed`] returns `Ok`, then this will return
    /// `Ok` containing the same value as [`CollectedClientData::challenge`]; however the converse
    /// is _not_ true. This is because this function attempts to reduce the amount of data parsed.
    ///
    /// # Errors
    ///
    /// Errors iff [`AuthenticatorAttestation::client_data_json`] is invalid JSON _after_ ignoring
    /// a leading U+FEFF and replacing any sequences of invalid UTF-8 code units with U+FFFD or
    /// [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge) does not exist
    /// or is not a base64url-encoded [`Challenge`].
    #[cfg(feature = "serde_relaxed")]
    #[inline]
    pub fn challenge_relaxed(&self) -> Result<SentChallenge, SerdeJsonErr> {
        RelaxedClientDataJsonParser::<true>::get_sent_challenge(
            self.response.client_data_json.as_slice(),
        )
    }
    /// Convenience function for [`RegistrationRelaxed::deserialize`].
    ///
    /// # Errors
    ///
    /// Errors iff [`RegistrationRelaxed::deserialize`] does.
    #[cfg(feature = "serde_relaxed")]
    #[inline]
    pub fn from_json_relaxed(json: &[u8]) -> Result<Self, SerdeJsonErr> {
        serde_json::from_slice::<RegistrationRelaxed>(json).map(|val| val.0)
    }
    /// Convenience function for [`CustomRegistration::deserialize`].
    ///
    /// # Errors
    ///
    /// Errors iff [`CustomRegistration::deserialize`] does.
    #[cfg(feature = "serde_relaxed")]
    #[inline]
    pub fn from_json_custom(json: &[u8]) -> Result<Self, SerdeJsonErr> {
        serde_json::from_slice::<CustomRegistration>(json).map(|val| val.0)
    }
}
impl Response for Registration {
    type Auth = AuthenticatorAttestation;
    fn auth(&self) -> &Self::Auth {
        &self.response
    }
}
/// [Attestation statement](https://www.w3.org/TR/webauthn-3/#attestation-statement).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Attestation {
    /// [None](https://www.w3.org/TR/webauthn-3/#none).
    None,
    /// [Self](https://www.w3.org/TR/webauthn-3/#self).
    Surrogate,
}
/// Metadata associated with a [`RegisteredCredential`].
///
/// This information exists purely for informative reasons as it is not used in any way during authentication
/// ceremonies; consequently, one may not want to store this information.
#[derive(Clone, Copy, Debug)]
pub struct Metadata<'a> {
    /// [Attestation statement](https://www.w3.org/TR/webauthn-3/#attestation-statement).
    pub attestation: Attestation,
    /// [`aaguid`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata-aaguid).
    pub aaguid: Aaguid<'a>,
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions) output during registration that is
    /// never used during authentication ceremonies.
    pub extensions: AuthenticatorExtensionOutputMetadata,
    /// [`getClientExtensionResults`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-getclientextensionresults)
    /// output during registration that is never used during authentication ceremonies.
    pub client_extension_results: ClientExtensionsOutputsMetadata,
    /// `ResidentKeyRequirement` sent during registration.
    pub resident_key: ResidentKeyRequirement,
}
impl Metadata<'_> {
    /// Transforms `self` into a JSON object conforming to the following pseudo-schema:
    ///
    /// ```json
    /// // MetadataJSON:
    /// {
    ///   "attestation": "none" | "self",
    ///   "aaguid": "<32-uppercase-hexadecimal digits>",
    ///   "extensions": {
    ///     "min_pin_length": null | <8-bit unsigned integer without leading 0s>
    ///   },
    ///   "client_extension_results": {
    ///     "cred_props": null | CredPropsJSON
    ///   },
    ///   "resident_key": "required" | "discouraged" | "preferred"
    /// }
    /// // CredPropsJSON:
    /// {
    ///   "rk": null | false | true
    /// }
    /// // PrfJSON:
    /// {
    ///   "enabled": false | true
    /// }
    /// ```
    /// where unnecessary whitespace does not exist.
    ///
    /// This primarily exists so that one can store the data in a human-readable way without the need of
    /// bringing the data back into the application. This allows one to read the data using some external
    /// means purely for informative reasons. If one wants the ability to "act" on the data; then one should
    /// [`Metadata::encode`] the data instead, or in addition to, that way it can be [`MetadataOwned::decode`]d.
    ///
    /// # Examples
    ///
    /// ```
    /// # use core::str::FromStr;
    /// # use webauthn_rp::{
    /// #     request::register::{FourToSixtyThree, ResidentKeyRequirement},
    /// #     response::register::{
    /// #         Aaguid, Attestation,
    /// #         AuthenticatorExtensionOutputMetadata, ClientExtensionsOutputsMetadata, CredentialPropertiesOutput,
    /// #         Metadata,
    /// #     },
    /// # };
    /// let metadata = Metadata {
    ///     attestation: Attestation::None,
    ///     aaguid: Aaguid::try_from([15; 16].as_slice())?,
    ///     extensions: AuthenticatorExtensionOutputMetadata {
    ///         min_pin_length: Some(FourToSixtyThree::Sixteen),
    ///     },
    ///     client_extension_results: ClientExtensionsOutputsMetadata {
    ///         cred_props: Some(CredentialPropertiesOutput {
    ///             rk: Some(true),
    ///         }),
    ///     },
    ///     resident_key: ResidentKeyRequirement::Required
    /// };
    /// let json = serde_json::json!({
    ///     "attestation": "none",
    ///     "aaguid": "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
    ///     "extensions": {
    ///         "min_pin_length": 16
    ///     },
    ///     "client_extension_results": {
    ///         "cred_props": {
    ///             "rk": true
    ///         }
    ///     },
    ///     "resident_key": "required"
    /// });
    /// assert_eq!(metadata.into_json(), json.to_string());
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[expect(unsafe_code, reason = "comment justifies its correctness and reason")]
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "comments justify their correctness"
    )]
    #[inline]
    #[must_use]
    pub fn into_json(self) -> String {
        // Maximum capacity needed is not _that_ much larger than the minimum, 173. An example is the
        // following:
        // `{"attestation":"none","aaguid":"00000000000000000000000000000000","extensions":{"min_pin_length":null},"client_extension_results":{"cred_props":{"rk":false},"prf":{"enabled":false}},"resident_key":"discouraged"}`.
        // We use a raw `Vec` instead of a `String` since we need to transform some binary values into ASCII which
        // is easier to do as bytes.
        let mut buffer = Vec::with_capacity(187);
        buffer.extend_from_slice(br#"{"attestation":"#);
        buffer.extend_from_slice(match self.attestation {
            Attestation::None => br#""none","aaguid":""#,
            Attestation::Surrogate => br#""self","aaguid":""#,
        });
        self.aaguid.0.iter().fold((), |(), byt| {
            // Get the first nibble.
            let nib_fst = byt & 0xf0;
            // We simply add the appropriate offset. For decimal digits this means simply adding `b'0'`; but
            // for uppercase hexadecimal, this means adding 55 since `b'A'` is 65.
            // Overflow cannot occur since this maxes at `b'F'`.
            buffer.push(nib_fst + if nib_fst < 0xa { b'0' } else { 55 });
            // Get the second nibble.
            let nib_snd = byt & 0xf;
            // We simply add the appropriate offset. For decimal digits this means simply adding `b'0'`; but
            // for uppercase hexadecimal, this means adding 55 since `b'A'` is 65.
            // Overflow cannot occur since this maxes at `b'F'`.
            buffer.push(nib_snd + if nib_snd < 0xa { b'0' } else { 55 });
        });
        buffer.extend_from_slice(br#"","extensions":{"min_pin_length":"#);
        match self.extensions.min_pin_length {
            None => buffer.extend_from_slice(b"null"),
            Some(pin) => {
                // Clearly correct.
                let dig_1 = pin.into_u8() / 10;
                // Clearly correct.
                let dig_2 = pin.into_u8() % 10;
                if dig_1 > 0 {
                    // We simply add the appropriate offset which is `b'0` for decimal digits.
                    // Overflow cannot occur since this maxes at `b'9'`.
                    buffer.push(dig_1 + b'0');
                }
                // We simply add the appropriate offset which is `b'0` for decimal digits.
                // Overflow cannot occur since this maxes at `b'9'`.
                buffer.push(dig_2 + b'0');
            }
        }
        buffer.extend_from_slice(br#"},"client_extension_results":{"cred_props":"#);
        match self.client_extension_results.cred_props {
            None => buffer.extend_from_slice(b"null"),
            Some(props) => {
                buffer.extend_from_slice(br#"{"rk":"#);
                match props.rk {
                    None => buffer.extend_from_slice(b"null}"),
                    Some(rk) => buffer.extend_from_slice(if rk { b"true}" } else { b"false}" }),
                }
            }
        }
        buffer.extend_from_slice(br#"},"resident_key":"#);
        buffer.extend_from_slice(match self.resident_key {
            ResidentKeyRequirement::Required => br#""required"}"#,
            ResidentKeyRequirement::Discouraged => br#""discouraged"}"#,
            ResidentKeyRequirement::Preferred => br#""preferred"}"#,
        });
        // SAFETY:
        // Clearly above only appends ASCII, a subset of UTF-8, to `buffer`; thus `buffer`
        // is valid UTF-8.
        unsafe { String::from_utf8_unchecked(buffer) }
    }
    /// Transforms `self` into an "owned" version.
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    #[cfg(feature = "bin")]
    #[inline]
    #[must_use]
    pub fn into_owned(self) -> MetadataOwned {
        MetadataOwned {
            attestation: self.attestation,
            aaguid: AaguidOwned(self.aaguid.0.try_into().unwrap_or_else(|_e| {
                unreachable!(
                    "there is a bug in Metadata that allows AAGUID to not have length of 16"
                )
            })),
            extensions: self.extensions,
            client_extension_results: self.client_extension_results,
            resident_key: self.resident_key,
        }
    }
}
/// [`RegisteredCredential`] and [`AuthenticatedCredential`] static state.
///
/// `PublicKey` needs to be [`UncompressedPubKey`] or [`CompressedPubKey`] for this type to be of any use.
#[derive(Clone, Copy, Debug)]
pub struct StaticState<PublicKey> {
    /// [`credentialPublicKey`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata-credentialpublickey).
    pub credential_public_key: PublicKey,
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions) output during registration that are
    /// used during authentication ceremonies.
    pub extensions: AuthenticatorExtensionOutputStaticState,
    /// [`getClientExtensionResults`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-getclientextensionresults)
    /// output during registration that are used during authentication ceremonies.
    pub client_extension_results: ClientExtensionsOutputsStaticState,
}
impl<
    'a: 'b,
    'b,
    T: AsRef<[u8]>,
    T2: AsRef<[u8]>,
    T3: AsRef<[u8]>,
    T4: AsRef<[u8]>,
    T5: AsRef<[u8]>,
    T6: AsRef<[u8]>,
    T7: AsRef<[u8]>,
> From<&'a StaticState<CompressedPubKey<T, T2, T3, T4, T5, T6, T7>>>
    for StaticState<CompressedPubKeyBorrowed<'b>>
{
    #[inline]
    fn from(value: &'a StaticState<CompressedPubKey<T, T2, T3, T4, T5, T6, T7>>) -> Self {
        Self {
            credential_public_key: (&value.credential_public_key).into(),
            extensions: value.extensions,
            client_extension_results: value.client_extension_results,
        }
    }
}
/// `StaticState` with an uncompressed [`Self::credential_public_key`].
pub type StaticStateUncompressed<'a> = StaticState<UncompressedPubKey<'a>>;
/// `StaticState` with a compressed [`Self::credential_public_key`] that owns the key data.
pub type StaticStateCompressed = StaticState<CompressedPubKeyOwned>;
impl StaticStateUncompressed<'_> {
    /// Transforms `self` into `StaticState` that contains the compressed version of the public key.
    #[inline]
    #[must_use]
    pub fn into_compressed(self) -> StaticStateCompressed {
        StaticStateCompressed {
            credential_public_key: self.credential_public_key.into_compressed(),
            extensions: self.extensions,
            client_extension_results: self.client_extension_results,
        }
    }
}
/// [`RegisteredCredential`] and [`AuthenticatedCredential`] dynamic state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicState {
    /// [`UV`](https://www.w3.org/TR/webauthn-3/#authdata-flags-uv).
    ///
    /// Once this is `true`, it will remain `true`. It will be set to `true` when `false` iff
    /// [`Flag::user_verified`] and [`AuthenticationVerificationOptions::update_uv`]. In other words, this only
    /// means that the user has been verified _at some point in the past_; but it does _not_ mean the user has
    /// most-recently been verified this is because user verification is a _ceremony-specific_ property. To
    /// enforce user verification for all ceremonies, [`UserVerificationRequirement::Required`] must always be
    /// sent.
    pub user_verified: bool,
    /// This can only be updated if [`BackupStateReq`] allows for it.
    pub backup: Backup,
    /// [`signCount`](https://www.w3.org/TR/webauthn-3/#authdata-signcount).
    ///
    /// This is only updated if the authenticator supports
    /// [signature counters](https://www.w3.org/TR/webauthn-3/#signature-counter), and the behavior of how it is
    /// updated is controlled by [`AuthenticationVerificationOptions::sig_counter_enforcement`].
    pub sign_count: u32,
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredential-authenticatorattachment).
    ///
    /// [`AuthenticationVerificationOptions::auth_attachment_enforcement`] controls if/how this updated.
    pub authenticator_attachment: AuthenticatorAttachment,
}
impl PartialEq<&Self> for DynamicState {
    #[inline]
    fn eq(&self, other: &&Self) -> bool {
        *self == **other
    }
}
impl PartialEq<DynamicState> for &DynamicState {
    #[inline]
    fn eq(&self, other: &DynamicState) -> bool {
        **self == *other
    }
}
