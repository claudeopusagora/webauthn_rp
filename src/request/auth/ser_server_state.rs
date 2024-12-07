#![expect(
    clippy::question_mark_used,
    clippy::unseparated_literal_suffix,
    reason = "noisy, opinionated, and likely doesn't prevent bugs or improve APIs"
)]
use super::{
    super::super::bin::{
        Decode, DecodeBuffer, EncDecErr, Encode, EncodeBuffer, EncodeBufferFallible,
    },
    AuthenticationServerState, CredInfo, CredentialId, ExtensionReq, SentChallenge,
    ServerCredSpecificExtensionInfo, ServerExtensionInfo, ServerPrfInfo,
    SignatureCounterEnforcement, UserVerificationRequirement,
};
#[cfg(doc)]
use super::{AllowedCredential, PublicKeyCredentialRequestOptions};
use core::{
    error::Error,
    fmt::{self, Display, Formatter},
};
#[cfg(doc)]
use std::time::UNIX_EPOCH;
use std::time::{SystemTime, SystemTimeError};
impl EncodeBuffer for ServerPrfInfo {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::One(req) => {
                0u8.encode_into_buffer(buffer);
                req
            }
            Self::Two(req) => {
                1u8.encode_into_buffer(buffer);
                req
            }
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for ServerPrfInfo {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => ExtensionReq::decode_from_buffer(data).map(Self::One),
            1 => ExtensionReq::decode_from_buffer(data).map(Self::Two),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBuffer for ServerCredSpecificExtensionInfo {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.prf.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for ServerCredSpecificExtensionInfo {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        Option::decode_from_buffer(data).map(|prf| Self { prf })
    }
}
impl EncodeBuffer for CredInfo {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        CredentialId::<&[u8]>::from(&self.id).encode_into_buffer(buffer);
        self.ext.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for CredInfo {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        CredentialId::<Vec<u8>>::decode_from_buffer(data).and_then(|id| {
            ServerCredSpecificExtensionInfo::decode_from_buffer(data).map(|ext| Self { id, ext })
        })
    }
}
impl EncodeBuffer for ServerExtensionInfo {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.prf.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for ServerExtensionInfo {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        Option::decode_from_buffer(data).map(|prf| Self { prf })
    }
}
impl EncodeBuffer for SignatureCounterEnforcement {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::Fail => 0u8,
            Self::Update => 1,
            Self::Ignore => 2,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for SignatureCounterEnforcement {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => Ok(Self::Fail),
            1 => Ok(Self::Update),
            2 => Ok(Self::Ignore),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBufferFallible for &[CredInfo] {
    type Err = EncDecErr;
    /// # Errors
    ///
    /// Errors iff `self.len() > usize::from(u16::MAX)`.
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), EncDecErr> {
        u16::try_from(self.len())
            .map_err(|_e| EncDecErr)
            .map(|len| {
                len.encode_into_buffer(buffer);
                self.iter().fold((), |(), val| {
                    val.encode_into_buffer(buffer);
                });
            })
    }
}
impl<'a> DecodeBuffer<'a> for Vec<CredInfo> {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u16::decode_from_buffer(data).and_then(|len| {
            let l = usize::from(len);
            let mut creds = Self::with_capacity(l);
            while creds.len() < l {
                creds.push(CredInfo::decode_from_buffer(data)?);
            }
            Ok(creds)
        })
    }
}
/// Error returned from [`AuthenticationServerState::encode`].
#[derive(Debug)]
pub enum EncodeAuthenticationServerStateErr {
    /// Variant returned when
    /// [`AuthenticationServerState::expiration`](../struct.AuthenticationServerState.html#method.expiration-1)
    /// is before [`UNIX_EPOCH`].
    SystemTime(SystemTimeError),
    /// Variant returned when the corresponding [`PublicKeyCredentialRequestOptions::allow_credentials`] has more
    /// than [`u16::MAX`] [`AllowedCredential`]s.
    AllowedCredentialsCount,
}
impl Display for EncodeAuthenticationServerStateErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SystemTime(ref err) => err.fmt(f),
            Self::AllowedCredentialsCount => {
                f.write_str("there were more than 65,535 AllowedCredentials")
            }
        }
    }
}
impl Error for EncodeAuthenticationServerStateErr {}
impl Encode for AuthenticationServerState {
    type Output<'a> = Vec<u8> where Self: 'a;
    type Err = EncodeAuthenticationServerStateErr;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        // Length of the anticipated most common output:
        // * 16 for `SentChallenge`
        // * 2 + large range for `[CredInfo]` where we assume [`CredInfo`] being
        //   empty is the most common
        // * 1 for `UserVerificationRequirement`
        // * 1 or 3 for `ServerExtensionInfo` where we assume 1 is the most common
        // * 12 for `SystemTime`
        let mut buffer = Vec::with_capacity(16 + 2 + 1 + 1 + 12);
        self.challenge.encode_into_buffer(&mut buffer);
        self.allow_credentials
            .as_slice()
            .encode_into_buffer(&mut buffer)
            .map_err(|_e| EncodeAuthenticationServerStateErr::AllowedCredentialsCount)
            .and_then(|()| {
                self.user_verification.encode_into_buffer(&mut buffer);
                self.extensions.encode_into_buffer(&mut buffer);
                self.expiration
                    .encode_into_buffer(&mut buffer)
                    .map_err(EncodeAuthenticationServerStateErr::SystemTime)
                    .map(|()| buffer)
            })
    }
}
/// Error returned from [`AuthenticationServerState::decode`].
#[derive(Clone, Copy, Debug)]
pub enum DecodeAuthenticationServerStateErr {
    /// Variant returned when there was trailing data after decoding an [`AuthenticationServerState`].
    TrailingData,
    /// Variant returned for all other errors.
    Other,
}
impl Display for DecodeAuthenticationServerStateErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::TrailingData => "trailing data after decoding AuthenticationServerState",
            Self::Other => "AuthenticationServerState could not be decoded",
        })
    }
}
impl Error for DecodeAuthenticationServerStateErr {}
impl Decode for AuthenticationServerState {
    type Input<'a> = &'a [u8];
    type Err = DecodeAuthenticationServerStateErr;
    #[inline]
    fn decode(mut input: Self::Input<'_>) -> Result<Self, Self::Err> {
        SentChallenge::decode_from_buffer(&mut input).map_err(|_e| DecodeAuthenticationServerStateErr::Other).and_then(|challenge| {
            Vec::decode_from_buffer(&mut input).map_err(|_e| DecodeAuthenticationServerStateErr::Other).and_then(|allow_credentials| {
                UserVerificationRequirement::decode_from_buffer(&mut input).map_err(|_e| DecodeAuthenticationServerStateErr::Other).and_then(|user_verification| {
                    ServerExtensionInfo::decode_from_buffer(&mut input).map_err(|_e| DecodeAuthenticationServerStateErr::Other).and_then(|extensions| {
                        super::validate_options_helper(extensions, user_verification, &allow_credentials).map_err(|_e| DecodeAuthenticationServerStateErr::Other).and_then(|()| {
                            SystemTime::decode_from_buffer(&mut input).map_err(|_e| DecodeAuthenticationServerStateErr::Other).and_then(|expiration| {
                                if input.is_empty() {
                                    Ok(Self {
                                        challenge,
                                        allow_credentials,
                                        user_verification,
                                        extensions,
                                        expiration,
                                    })
                                } else {
                                    Err(DecodeAuthenticationServerStateErr::TrailingData)
                                }
                            })
                        })
                    })
                })
            })
        })
    }
}
