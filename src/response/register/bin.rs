use super::{
    super::super::bin::{
        Decode, DecodeBuffer, EncDecErr, Encode, EncodeBuffer, EncodeBufferFallible as _,
    },
    Aaguid, Attestation, AuthenticationExtensionsPrfOutputs, AuthenticatorAttachment,
    AuthenticatorExtensionOutputMetadata, AuthenticatorExtensionOutputStaticState, Backup,
    ClientExtensionsOutputsMetadata, ClientExtensionsOutputsStaticState, CompressedP256PubKey,
    CompressedP384PubKey, CompressedPubKeyOwned, CredentialPropertiesOutput,
    CredentialProtectionPolicy, DynamicState, Ed25519PubKey, FourToSixtyThree, Metadata,
    MlDsa44PubKey, MlDsa65PubKey, MlDsa87PubKey, ResidentKeyRequirement, RsaPubKey, StaticState,
    UncompressedP256PubKey, UncompressedP384PubKey, UncompressedPubKey,
};
use core::{
    convert::Infallible,
    error::Error,
    fmt::{self, Display, Formatter},
};
use p256::{
    NistP256,
    elliptic_curve::{Curve, common::typenum::ToInt as _},
};
use p384::NistP384;
impl EncodeBuffer for CredentialProtectionPolicy {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::None => 0u8,
            Self::UserVerificationOptional => 1,
            Self::UserVerificationOptionalWithCredentialIdList => 2,
            Self::UserVerificationRequired => 3,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for CredentialProtectionPolicy {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => Ok(Self::None),
            1 => Ok(Self::UserVerificationOptional),
            2 => Ok(Self::UserVerificationOptionalWithCredentialIdList),
            3 => Ok(Self::UserVerificationRequired),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBuffer for ResidentKeyRequirement {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::Required => 0u8,
            Self::Discouraged => 1,
            Self::Preferred => 2,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for ResidentKeyRequirement {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => Ok(Self::Required),
            1 => Ok(Self::Discouraged),
            2 => Ok(Self::Preferred),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBuffer for MlDsa87PubKey<&[u8]> {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        // We don't rely on `[u8]::encode_into_buffer` since
        // we always know the `slice` has length 2592; thus
        // we want to "pretend" this is an array (i.e., don't encode the length).
        buffer.extend_from_slice(self.0);
    }
}
impl<'a> DecodeBuffer<'a> for MlDsa87PubKey<Box<[u8]>> {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        // Only `array`s that implement `Default` implement `DecodeBuffer`;
        // thus we must manually implement it.
        let mut key = vec![0; 2592];
        data.split_at_checked(key.len())
            .ok_or(EncDecErr)
            .map(|(key_slice, rem)| {
                *data = rem;
                key.copy_from_slice(key_slice);
                Self(key.into_boxed_slice())
            })
    }
}
impl EncodeBuffer for MlDsa65PubKey<&[u8]> {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        // We don't rely on `[u8]::encode_into_buffer` since
        // we always know the `slice` has length 1952; thus
        // we want to "pretend" this is an array (i.e., don't encode the length).
        buffer.extend_from_slice(self.0);
    }
}
impl<'a> DecodeBuffer<'a> for MlDsa65PubKey<Box<[u8]>> {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        // Only `array`s that implement `Default` implement `DecodeBuffer`;
        // thus we must manually implement it.
        let mut key = vec![0; 1952];
        data.split_at_checked(key.len())
            .ok_or(EncDecErr)
            .map(|(key_slice, rem)| {
                *data = rem;
                key.copy_from_slice(key_slice);
                Self(key.into_boxed_slice())
            })
    }
}
impl EncodeBuffer for MlDsa44PubKey<&[u8]> {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        // We don't rely on `[u8]::encode_into_buffer` since
        // we always know the `slice` has length 1312; thus
        // we want to "pretend" this is an array (i.e., don't encode the length).
        buffer.extend_from_slice(self.0);
    }
}
impl<'a> DecodeBuffer<'a> for MlDsa44PubKey<Box<[u8]>> {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        // Only `array`s that implement `Default` implement `DecodeBuffer`;
        // thus we must manually implement it.
        let mut key = vec![0; 1312];
        data.split_at_checked(key.len())
            .ok_or(EncDecErr)
            .map(|(key_slice, rem)| {
                *data = rem;
                key.copy_from_slice(key_slice);
                Self(key.into_boxed_slice())
            })
    }
}
impl EncodeBuffer for Ed25519PubKey<&[u8]> {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        // We don't rely on `[u8]::encode_into_buffer` since
        // we always know the `slice` has length 32; thus
        // we want to "pretend" this is an array (i.e., don't encode the length).
        buffer.extend_from_slice(self.0);
    }
}
impl<'a> DecodeBuffer<'a> for Ed25519PubKey<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]> {
    type Err = EncDecErr;
    // We don't verify `Self` is in fact "valid" (i.e., we don't call
    // [`Self::validate`]) since that's expensive and an error will
    // happen later during authentication anyway. Note even if we did,
    // that wouldn't detect a public key that was altered in persistent
    // storage in such a way that it's still valid; thus there is no
    // benefit in performing "expensive" validation checks.
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        <[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::decode_from_buffer(data).map(Self)
    }
}
impl EncodeBuffer for UncompressedP256PubKey<'_> {
    #[expect(clippy::indexing_slicing, reason = "comment justifies its correctness")]
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        /// Number of bytes the y-coordinate takes.
        const Y_LEN: usize = <NistP256 as Curve>::FieldBytesSize::INT;
        /// The index of the least significant byte of the y-coordinate.
        const ODD_BYTE_INDEX: usize = Y_LEN - 1;
        // We don't rely on `[u8]::encode_into_buffer` since
        // we always know the `slice` has length 32; thus
        // we want to "pretend" this is an array (i.e., don't encode the length).
        buffer.extend_from_slice(self.0);
        // `self.1.len() == 32` and `ODD_BYTE_INDEX == 31`, so indexing is fine.
        (self.1[ODD_BYTE_INDEX] & 1 == 1).encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for CompressedP256PubKey<[u8; <NistP256 as Curve>::FieldBytesSize::INT]> {
    type Err = EncDecErr;
    // We don't verify `Self` is in fact "valid" (i.e., we don't call
    // [`Self::validate`]) since that's expensive and an error will
    // happen later during authentication anyway. Note even if we did,
    // that wouldn't detect a public key that was altered in persistent
    // storage in such a way that it's still valid; thus there is no
    // benefit in performing "expensive" validation checks.
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        <[u8; <NistP256 as Curve>::FieldBytesSize::INT]>::decode_from_buffer(data)
            .and_then(|x| bool::decode_from_buffer(data).map(|y_is_odd| Self { x, y_is_odd }))
    }
}
impl EncodeBuffer for UncompressedP384PubKey<'_> {
    #[expect(clippy::indexing_slicing, reason = "comment justifies its correctness")]
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        /// Number of bytes the y-coordinate takes.
        const Y_LEN: usize = <NistP384 as Curve>::FieldBytesSize::INT;
        /// The index of the least significant byte of the y-coordinate.
        const ODD_BYTE_INDEX: usize = Y_LEN - 1;
        // We don't rely on `[u8]::encode_into_buffer` since
        // we always know the `slice` has length 48; thus
        // we want to "pretend" this is an array (i.e., don't encode the length).
        buffer.extend_from_slice(self.0);
        // `self.1.len() == 48` and `ODD_BYTE_INDEX == 47`, so indexing is fine.
        (self.1[ODD_BYTE_INDEX] & 1 == 1).encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for CompressedP384PubKey<[u8; <NistP384 as Curve>::FieldBytesSize::INT]> {
    type Err = EncDecErr;
    // We don't verify `Self` is in fact "valid" (i.e., we don't call
    // [`Self::validate`]) since that's expensive and an error will
    // happen later during authentication anyway. Note even if we did,
    // that wouldn't detect a public key that was altered in persistent
    // storage in such a way that it's still valid; thus there is no
    // benefit in performing "expensive" validation checks.
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        // Only `array`s that implement `Default` implement `DecodeBuffer`;
        // thus we must manually implement it.
        let mut x = [0; <NistP384 as Curve>::FieldBytesSize::INT];
        data.split_at_checked(x.len())
            .ok_or(EncDecErr)
            .and_then(|(x_slice, rem)| {
                *data = rem;
                bool::decode_from_buffer(data).map(|y_is_odd| {
                    x.copy_from_slice(x_slice);
                    Self { x, y_is_odd }
                })
            })
    }
}
impl EncodeBuffer for RsaPubKey<&[u8]> {
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        // Max length is 2048, so this won't error.
        self.0
            .encode_into_buffer(buffer)
            .unwrap_or_else(|_e| unreachable!("there is a bug in [u8]::encode_into_buffer"));
        self.1.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for RsaPubKey<Box<[u8]>> {
    type Err = EncDecErr;
    // We don't verify `Self` is in fact "valid" (i.e., we don't call
    // [`Self::validate`]) since that's expensive and an error will
    // happen later during authentication anyway. Note even if we did,
    // that wouldn't detect a public key that was altered in persistent
    // storage in such a way that it's still valid; thus there is no
    // benefit in performing "expensive" validation checks.
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        Box::decode_from_buffer(data).and_then(|n| {
            u32::decode_from_buffer(data)
                .and_then(|e| Self::try_from((n, e)).map_err(|_e| EncDecErr))
        })
    }
}
impl EncodeBuffer for UncompressedPubKey<'_> {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::MlDsa87(key) => {
                4u8.encode_into_buffer(buffer);
                key.encode_into_buffer(buffer);
            }
            Self::MlDsa65(key) => {
                5u8.encode_into_buffer(buffer);
                key.encode_into_buffer(buffer);
            }
            Self::MlDsa44(key) => {
                6u8.encode_into_buffer(buffer);
                key.encode_into_buffer(buffer);
            }
            Self::Ed25519(key) => {
                0u8.encode_into_buffer(buffer);
                key.encode_into_buffer(buffer);
            }
            Self::P256(key) => {
                1u8.encode_into_buffer(buffer);
                key.encode_into_buffer(buffer);
            }
            Self::P384(key) => {
                2u8.encode_into_buffer(buffer);
                key.encode_into_buffer(buffer);
            }
            Self::Rsa(key) => {
                3u8.encode_into_buffer(buffer);
                key.encode_into_buffer(buffer);
            }
        }
    }
}
impl<'a> DecodeBuffer<'a> for CompressedPubKeyOwned {
    type Err = EncDecErr;
    // We don't verify `Self` is in fact "valid" (i.e., we don't call
    // [`Self::validate`]) since that's expensive and an error will
    // happen later during authentication anyway. Note even if we did,
    // that wouldn't detect a public key that was altered in persistent
    // storage in such a way that it's still valid; thus there is no
    // benefit in performing "expensive" validation checks.
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => Ed25519PubKey::decode_from_buffer(data).map(Self::Ed25519),
            1 => CompressedP256PubKey::decode_from_buffer(data).map(Self::P256),
            2 => CompressedP384PubKey::decode_from_buffer(data).map(Self::P384),
            3 => RsaPubKey::decode_from_buffer(data).map(Self::Rsa),
            4 => MlDsa87PubKey::decode_from_buffer(data).map(Self::MlDsa87),
            5 => MlDsa65PubKey::decode_from_buffer(data).map(Self::MlDsa65),
            6 => MlDsa44PubKey::decode_from_buffer(data).map(Self::MlDsa44),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBuffer for AuthenticatorExtensionOutputStaticState {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.cred_protect.encode_into_buffer(buffer);
        self.hmac_secret.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for AuthenticatorExtensionOutputStaticState {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        CredentialProtectionPolicy::decode_from_buffer(data).and_then(|cred_protect| {
            Option::decode_from_buffer(data).map(|hmac_secret| Self {
                cred_protect,
                hmac_secret,
            })
        })
    }
}
impl EncodeBuffer for Attestation {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::None => 0u8,
            Self::Surrogate => 1,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for Attestation {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => Ok(Self::None),
            1 => Ok(Self::Surrogate),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBuffer for Aaguid<'_> {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.0);
    }
}
/// Owned version of [`Aaguid`] that exists for [`MetadataOwned::aaguid`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AaguidOwned(pub [u8; super::AAGUID_LEN]);
impl<'a: 'b, 'b> From<&'a AaguidOwned> for Aaguid<'b> {
    #[inline]
    fn from(value: &'a AaguidOwned) -> Self {
        Self(value.0.as_slice())
    }
}
impl<'a> DecodeBuffer<'a> for AaguidOwned {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        <[u8; super::AAGUID_LEN]>::decode_from_buffer(data).map(Self)
    }
}
impl EncodeBuffer for FourToSixtyThree {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.into_u8().encode_into_buffer(buffer);
    }
}
impl EncodeBuffer for AuthenticatorExtensionOutputMetadata {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.min_pin_length.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for FourToSixtyThree {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| Self::from_u8(val).ok_or(EncDecErr))
    }
}
impl<'a> DecodeBuffer<'a> for AuthenticatorExtensionOutputMetadata {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        Option::decode_from_buffer(data).map(|min_pin_length| Self { min_pin_length })
    }
}
impl EncodeBuffer for CredentialPropertiesOutput {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.rk.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for CredentialPropertiesOutput {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        Option::decode_from_buffer(data).map(|rk| Self { rk })
    }
}
impl EncodeBuffer for AuthenticationExtensionsPrfOutputs {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.enabled.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for AuthenticationExtensionsPrfOutputs {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        bool::decode_from_buffer(data).map(|enabled| Self { enabled })
    }
}
impl EncodeBuffer for ClientExtensionsOutputsMetadata {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.cred_props.encode_into_buffer(buffer);
    }
}
impl EncodeBuffer for ClientExtensionsOutputsStaticState {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.prf.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for ClientExtensionsOutputsMetadata {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        Option::decode_from_buffer(data).map(|cred_props| Self { cred_props })
    }
}
impl<'a> DecodeBuffer<'a> for ClientExtensionsOutputsStaticState {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        Option::decode_from_buffer(data).map(|prf| Self { prf })
    }
}
impl Encode for Metadata<'_> {
    type Output<'a>
        = Vec<u8>
    where
        Self: 'a;
    type Err = Infallible;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        // Length of the anticipated most common output:
        // * 1 for `Attestation`
        // * 16 for `Aaguid`.
        // * 1 or 2 for `AuthenticatorExtensionOutputMetadata` where we assume 1 is the most common
        // * 1–3 for `ClientExtensionsOutputsMetadata` where we assume 1 is the most common
        // * 1 for `ResidentKeyRequirement`
        let mut buffer = Vec::with_capacity(1 + 16 + 1 + 1 + 1);
        self.attestation.encode_into_buffer(&mut buffer);
        self.aaguid.encode_into_buffer(&mut buffer);
        self.extensions.encode_into_buffer(&mut buffer);
        self.client_extension_results
            .encode_into_buffer(&mut buffer);
        self.resident_key.encode_into_buffer(&mut buffer);
        Ok(buffer)
    }
}
/// Owned version of [`Metadata`] that exists to [`Self::decode`] the output of [`Metadata::encode`].
#[derive(Clone, Copy, Debug)]
pub struct MetadataOwned {
    /// [`Metadata::attestation`].
    pub attestation: Attestation,
    /// [`Metadata::aaguid`].
    pub aaguid: AaguidOwned,
    /// [`Metadata::extensions`].
    pub extensions: AuthenticatorExtensionOutputMetadata,
    /// [`Metadata::client_extension_results`].
    pub client_extension_results: ClientExtensionsOutputsMetadata,
    /// [`Metadata::resident_key`].
    pub resident_key: ResidentKeyRequirement,
}
impl<'a: 'b, 'b> From<&'a MetadataOwned> for Metadata<'b> {
    #[inline]
    fn from(value: &'a MetadataOwned) -> Self {
        Self {
            attestation: value.attestation,
            aaguid: (&value.aaguid).into(),
            extensions: value.extensions,
            client_extension_results: value.client_extension_results,
            resident_key: value.resident_key,
        }
    }
}
/// Error returned from [`MetadataOwned::decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeMetadataOwnedErr {
    /// Variant returned when [`MetadataOwned::attestation`] could not be decoded.
    Attestation,
    /// Variant returned when [`MetadataOwned::aaguid`] could not be decoded.
    Aaguid,
    /// Variant returned when [`MetadataOwned::extensions`] could not be decoded.
    Extensions,
    /// Variant returned when [`MetadataOwned::client_extension_results`] could not be decoded.
    ClientExtensionResults,
    /// Variant returned when [`MetadataOwned::resident_key`] could not be decoded.
    ResidentKey,
    /// Variant returned when [`MetadataOwned`] was decoded with trailing data.
    TrailingData,
}
impl Display for DecodeMetadataOwnedErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Attestation => "attestation could not be decoded",
            Self::Aaguid => "aaguid could not be decoded",
            Self::Extensions => "extensions could not be decoded",
            Self::ClientExtensionResults => "client_extension_results could not be decoded",
            Self::ResidentKey => "resident_key could not be decoded",
            Self::TrailingData => "trailing data existed after decoding MetadataOwned",
        })
    }
}
impl Error for DecodeMetadataOwnedErr {}
impl Decode for MetadataOwned {
    type Input<'a> = &'a [u8];
    type Err = DecodeMetadataOwnedErr;
    #[inline]
    fn decode(mut input: Self::Input<'_>) -> Result<Self, Self::Err> {
        Attestation::decode_from_buffer(&mut input)
            .map_err(|_e| DecodeMetadataOwnedErr::Attestation)
            .and_then(|attestation| {
                AaguidOwned::decode_from_buffer(&mut input)
                    .map_err(|_e| DecodeMetadataOwnedErr::Aaguid)
                    .and_then(|aaguid| {
                        AuthenticatorExtensionOutputMetadata::decode_from_buffer(&mut input)
                            .map_err(|_e| DecodeMetadataOwnedErr::Extensions)
                            .and_then(|extensions| {
                                ClientExtensionsOutputsMetadata::decode_from_buffer(&mut input)
                                    .map_err(|_e| DecodeMetadataOwnedErr::ClientExtensionResults)
                                    .and_then(|client_extension_results| {
                                        ResidentKeyRequirement::decode_from_buffer(&mut input)
                                            .map_err(|_e| DecodeMetadataOwnedErr::ResidentKey)
                                            .and_then(|resident_key| {
                                                if input.is_empty() {
                                                    Ok(Self {
                                                        attestation,
                                                        aaguid,
                                                        extensions,
                                                        client_extension_results,
                                                        resident_key,
                                                    })
                                                } else {
                                                    Err(DecodeMetadataOwnedErr::TrailingData)
                                                }
                                            })
                                    })
                            })
                    })
            })
    }
}
impl Encode for StaticState<UncompressedPubKey<'_>> {
    type Output<'a>
        = Vec<u8>
    where
        Self: 'a;
    type Err = Infallible;
    /// Transforms `self` into a `Vec` that can subsequently be [`StaticState::decode`]d into a [`StaticState`] of
    /// [`CompressedPubKeyOwned`].
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment justifies its correctness"
    )]
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        let mut buffer = Vec::with_capacity(
            // The maximum value is 2593 so overflow cannot happen.
            // `key.0.len() <= MAX_RSA_N_BYTES` which is 2048.
            match self.credential_public_key {
                UncompressedPubKey::MlDsa87(_) => 2593,
                UncompressedPubKey::MlDsa65(_) => 1953,
                UncompressedPubKey::MlDsa44(_) => 1313,
                UncompressedPubKey::Ed25519(_) => 33,
                UncompressedPubKey::P256(_) => 34,
                UncompressedPubKey::P384(_) => 50,
                UncompressedPubKey::Rsa(key) => 1 + 2 + key.0.len() + 4,
            } + 1
                + 1
                + usize::from(self.extensions.hmac_secret.is_some())
                + 1
                + usize::from(self.client_extension_results.prf.is_some()),
        );
        self.credential_public_key.encode_into_buffer(&mut buffer);
        self.extensions.encode_into_buffer(&mut buffer);
        self.client_extension_results
            .encode_into_buffer(&mut buffer);
        Ok(buffer)
    }
}
/// Error returned from [`StaticState::decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeStaticStateErr {
    /// Variant returned when [`StaticState::credential_public_key`] could not be decoded.
    CredentialPublicKey,
    /// Variant returned when [`StaticState::extensions`] could not be decoded.
    Extensions,
    /// Variant returned when [`StaticState::client_extension_results`] could not be decoded.
    ClientExtensionResults,
    /// Variant returned when there was trailing data after decoding a [`StaticState`].
    TrailingData,
}
impl Display for DecodeStaticStateErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::CredentialPublicKey => "credential_public_key could not be decoded",
            Self::Extensions => "extensions could not be decoded",
            Self::ClientExtensionResults => "client_extension_results could not be decoded",
            Self::TrailingData => "there was trailing data after decoding a StaticState",
        })
    }
}
impl Error for DecodeStaticStateErr {}
impl Decode for StaticState<CompressedPubKeyOwned> {
    type Input<'a> = &'a [u8];
    type Err = DecodeStaticStateErr;
    /// Interprets `input` as the [`StaticState::Output`] of [`StaticState::encode`].
    #[inline]
    fn decode(mut input: Self::Input<'_>) -> Result<Self, Self::Err> {
        CompressedPubKeyOwned::decode_from_buffer(&mut input)
            .map_err(|_e| DecodeStaticStateErr::CredentialPublicKey)
            .and_then(|credential_public_key| {
                AuthenticatorExtensionOutputStaticState::decode_from_buffer(&mut input)
                    .map_err(|_e| DecodeStaticStateErr::Extensions)
                    .and_then(|extensions| {
                        ClientExtensionsOutputsStaticState::decode_from_buffer(&mut input)
                            .map_err(|_e| DecodeStaticStateErr::ClientExtensionResults)
                            .and_then(|client_extension_results| {
                                if input.is_empty() {
                                    Ok(Self {
                                        credential_public_key,
                                        extensions,
                                        client_extension_results,
                                    })
                                } else {
                                    Err(DecodeStaticStateErr::TrailingData)
                                }
                            })
                    })
            })
    }
}
impl Encode for DynamicState {
    type Output<'a>
        = [u8; 7]
    where
        Self: 'a;
    type Err = Infallible;
    #[expect(
        clippy::little_endian_bytes,
        reason = "need cross-platform correctness"
    )]
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        let mut buffer = [
            u8::from(self.user_verified),
            match self.backup {
                Backup::NotEligible => 0,
                Backup::Eligible => 1,
                Backup::Exists => 2,
            },
            0,
            0,
            0,
            0,
            match self.authenticator_attachment {
                AuthenticatorAttachment::None => 0,
                AuthenticatorAttachment::Platform => 1,
                AuthenticatorAttachment::CrossPlatform => 2,
            },
        ];
        buffer[2..6].copy_from_slice(self.sign_count.to_le_bytes().as_slice());
        Ok(buffer)
    }
}
/// Error returned from [`DynamicState::decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeDynamicStateErr {
    /// Variant returned when [`DynamicState::user_verified`] could not be decoded.
    UserVerified,
    /// Variant returned when [`DynamicState::backup`] could not be decoded.
    Backup,
    /// Variant returned when [`DynamicState::sign_count`] could not be decoded.
    SignCount,
    /// Variant returned when [`DynamicState::authenticator_attachment`] could not be decoded.
    AuthenticatorAttachment,
}
impl Display for DecodeDynamicStateErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::UserVerified => "user_verified could not be decoded",
            Self::Backup => "backup could not be decoded",
            Self::SignCount => "sign_count could not be decoded",
            Self::AuthenticatorAttachment => "authenticator_attachment could not be decoded",
        })
    }
}
impl Error for DecodeDynamicStateErr {}
impl Decode for DynamicState {
    type Input<'a> = [u8; 7];
    type Err = DecodeDynamicStateErr;
    #[expect(
        clippy::panic_in_result_fn,
        reason = "want to crash when there is a bug"
    )]
    #[inline]
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err> {
        let mut buffer = input.as_slice();
        bool::decode_from_buffer(&mut buffer)
            .map_err(|_e| DecodeDynamicStateErr::UserVerified)
            .and_then(|user_verified| {
                Backup::decode_from_buffer(&mut buffer)
                    .map_err(|_e| DecodeDynamicStateErr::Backup)
                    .and_then(|backup| {
                        u32::decode_from_buffer(&mut buffer)
                            .map_err(|_e| DecodeDynamicStateErr::SignCount)
                            .and_then(|sign_count| {
                                AuthenticatorAttachment::decode_from_buffer(&mut buffer)
                                    .map_err(|_e| DecodeDynamicStateErr::AuthenticatorAttachment)
                                    .map(|authenticator_attachment| {
                                        assert!(
                                            buffer.is_empty(),
                                            "there is a bug in DynamicState::decode"
                                        );
                                        Self {
                                            user_verified,
                                            backup,
                                            sign_count,
                                            authenticator_attachment,
                                        }
                                    })
                            })
                    })
            })
    }
}
