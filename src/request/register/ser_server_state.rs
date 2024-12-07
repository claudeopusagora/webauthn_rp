#![expect(
    clippy::unseparated_literal_suffix,
    reason = "noisy, opinionated, and likely doesn't prevent bugs or improve APIs"
)]
use super::{
    super::super::bin::{
        Decode, DecodeBuffer, EncDecErr, Encode, EncodeBuffer, EncodeBufferFallible as _,
    },
    AuthenticatorAttachmentReq, AuthenticatorSelectionCriteria, CoseAlgorithmIdentifiers,
    CredProtect, CredentialMediationRequirement, CrossPlatformHint, Extension, ExtensionInfo, Hint,
    PlatformHint, RegistrationServerState, ResidentKeyRequirement, SentChallenge,
    UserVerificationRequirement,
};
use core::{
    error::Error,
    fmt::{self, Display, Formatter},
};
use std::time::{SystemTime, SystemTimeError};
impl EncodeBuffer for CoseAlgorithmIdentifiers {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.0.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for CoseAlgorithmIdentifiers {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| {
            if val | Self::ALL.0 == Self::ALL.0 {
                Ok(Self(val))
            } else {
                Err(EncDecErr)
            }
        })
    }
}
impl EncodeBuffer for PlatformHint {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::None => 0u8,
            Self::ClientDevice => 1,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for PlatformHint {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => Ok(Self::None),
            1 => Ok(Self::ClientDevice),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBuffer for CrossPlatformHint {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::None => 0u8,
            Self::SecurityKey => 1,
            Self::Hybrid => 2,
            Self::SecurityKeyHybrid => 3,
            Self::HybridSecurityKey => 4,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for CrossPlatformHint {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => Ok(Self::None),
            1 => Ok(Self::SecurityKey),
            2 => Ok(Self::Hybrid),
            3 => Ok(Self::SecurityKeyHybrid),
            4 => Ok(Self::HybridSecurityKey),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBuffer for AuthenticatorAttachmentReq {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::None(hint) => {
                0u8.encode_into_buffer(buffer);
                hint.encode_into_buffer(buffer);
            }
            Self::Platform(hint) => {
                1u8.encode_into_buffer(buffer);
                hint.encode_into_buffer(buffer);
            }
            Self::CrossPlatform(hint) => {
                2u8.encode_into_buffer(buffer);
                hint.encode_into_buffer(buffer);
            }
        }
    }
}
impl<'a> DecodeBuffer<'a> for AuthenticatorAttachmentReq {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => Hint::decode_from_buffer(data).map(Self::None),
            1 => PlatformHint::decode_from_buffer(data).map(Self::Platform),
            2 => CrossPlatformHint::decode_from_buffer(data).map(Self::CrossPlatform),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBuffer for AuthenticatorSelectionCriteria {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.authenticator_attachment.encode_into_buffer(buffer);
        self.resident_key.encode_into_buffer(buffer);
        self.user_verification.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for AuthenticatorSelectionCriteria {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        AuthenticatorAttachmentReq::decode_from_buffer(data).and_then(|authenticator_attachment| {
            ResidentKeyRequirement::decode_from_buffer(data).and_then(|resident_key| {
                UserVerificationRequirement::decode_from_buffer(data).map(|user_verification| {
                    Self {
                        authenticator_attachment,
                        resident_key,
                        user_verification,
                    }
                })
            })
        })
    }
}
impl EncodeBuffer for CredProtect {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::None => 0u8.encode_into_buffer(buffer),
            Self::UserVerificationOptional(info) => {
                1u8.encode_into_buffer(buffer);
                info.encode_into_buffer(buffer);
            }
            Self::UserVerificationOptionalWithCredentialIdList(info) => {
                2u8.encode_into_buffer(buffer);
                info.encode_into_buffer(buffer);
            }
            Self::UserVerificationRequired(info) => {
                3u8.encode_into_buffer(buffer);
                info.encode_into_buffer(buffer);
            }
        }
    }
}
impl<'a> DecodeBuffer<'a> for CredProtect {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => Ok(Self::None),
            1 => ExtensionInfo::decode_from_buffer(data).map(Self::UserVerificationOptional),
            2 => ExtensionInfo::decode_from_buffer(data)
                .map(Self::UserVerificationOptionalWithCredentialIdList),
            3 => ExtensionInfo::decode_from_buffer(data).map(Self::UserVerificationRequired),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBuffer for Extension {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.cred_props.encode_into_buffer(buffer);
        self.cred_protect.encode_into_buffer(buffer);
        self.min_pin_length.encode_into_buffer(buffer);
        self.prf.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for Extension {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        Option::decode_from_buffer(data).and_then(|cred_props| {
            CredProtect::decode_from_buffer(data).and_then(|cred_protect| {
                Option::decode_from_buffer(data).and_then(|min_pin_length| {
                    Option::decode_from_buffer(data).map(|prf| Self {
                        cred_props,
                        cred_protect,
                        min_pin_length,
                        prf,
                    })
                })
            })
        })
    }
}
impl Encode for RegistrationServerState {
    type Output<'a>
        = Vec<u8>
    where
        Self: 'a;
    type Err = SystemTimeError;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        // Length of the anticipated most common output:
        // * 1 for `CredentialMediationRequirement`
        // * 16 for `SentChallenge`
        // * 1 for `CoseAlgorithmIdentifiers`
        // * 6 for `AuthenticatorSelectionCriteria`
        // * 4–8 for `Extension` where we assume 4 is the most common
        // * 12 for `SystemTime`
        let mut buffer = Vec::with_capacity(1 + 16 + 1 + 6 + 4 + 12);
        self.mediation.encode_into_buffer(&mut buffer);
        self.challenge.encode_into_buffer(&mut buffer);
        self.pub_key_cred_params.encode_into_buffer(&mut buffer);
        self.authenticator_selection.encode_into_buffer(&mut buffer);
        self.extensions.encode_into_buffer(&mut buffer);
        self.expiration
            .encode_into_buffer(&mut buffer)
            .map(|()| buffer)
    }
}
/// Error returned from [`RegistrationServerState::decode`].
#[derive(Clone, Copy, Debug)]
pub enum DecodeRegistrationServerStateErr {
    /// Variant returned when there was trailing data after decoding a [`RegistrationServerState`].
    TrailingData,
    /// Variant returned for all other errors.
    Other,
}
impl Display for DecodeRegistrationServerStateErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::TrailingData => "trailing data existed after decoding a RegistrationServerState",
            Self::Other => "RegistrationServerState could not be decoded",
        })
    }
}
impl Error for DecodeRegistrationServerStateErr {}
impl Decode for RegistrationServerState {
    type Input<'a> = &'a [u8];
    type Err = DecodeRegistrationServerStateErr;
    #[inline]
    fn decode(mut input: Self::Input<'_>) -> Result<Self, Self::Err> {
        CredentialMediationRequirement::decode_from_buffer(&mut input).map_err(|_e| DecodeRegistrationServerStateErr::Other).and_then(|mediation| {
            SentChallenge::decode_from_buffer(&mut input).map_err(|_e| DecodeRegistrationServerStateErr::Other).and_then(|challenge| {
                CoseAlgorithmIdentifiers::decode_from_buffer(&mut input).map_err(|_e| DecodeRegistrationServerStateErr::Other).and_then(|pub_key_cred_params| {
                    AuthenticatorSelectionCriteria::decode_from_buffer(&mut input).map_err(|_e| DecodeRegistrationServerStateErr::Other).and_then(
                        |authenticator_selection| {
                            Extension::decode_from_buffer(&mut input).map_err(|_e| DecodeRegistrationServerStateErr::Other).and_then(|extensions| {
                                super::validate_options_helper(authenticator_selection, extensions)
                                    .map_err(|_e| DecodeRegistrationServerStateErr::Other)
                                    .and_then(|()| {
                                        SystemTime::decode_from_buffer(&mut input).map_err(|_e| DecodeRegistrationServerStateErr::Other).and_then(|expiration| {
                                            if input.is_empty() {
                                                Ok(Self { mediation, challenge, pub_key_cred_params, authenticator_selection, extensions, expiration, })
                                            } else {
                                                Err(DecodeRegistrationServerStateErr::TrailingData)
                                            }
                                        })
                                    })
                            })
                        },
                    )
                })
            })
        })
    }
}
