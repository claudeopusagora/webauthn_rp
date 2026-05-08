use super::{
    super::super::bin::{
        Decode, DecodeBuffer, EncDecErr, Encode, EncodeBuffer, EncodeBufferFallible,
    },
    AuthenticationServerState, CredInfo, CredentialId, DiscoverableAuthenticationServerState,
    ExtensionReq, NonDiscoverableAuthenticationServerState, SentChallenge,
    ServerCredSpecificExtensionInfo, ServerExtensionInfo, ServerPrfInfo,
    SignatureCounterEnforcement, UserVerificationRequirement,
};
#[cfg(doc)]
use super::{AllowedCredential, NonDiscoverableCredentialRequestOptions};
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
            Self::None => 0u8.encode_into_buffer(buffer),
            Self::One(req) => {
                1u8.encode_into_buffer(buffer);
                req.encode_into_buffer(buffer);
            }
            Self::Two(req) => {
                2u8.encode_into_buffer(buffer);
                req.encode_into_buffer(buffer);
            }
        }
    }
}
impl<'a> DecodeBuffer<'a> for ServerPrfInfo {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            0 => Ok(Self::None),
            1 => ExtensionReq::decode_from_buffer(data).map(Self::One),
            2 => ExtensionReq::decode_from_buffer(data).map(Self::Two),
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
        ServerPrfInfo::decode_from_buffer(data).map(|prf| Self { prf })
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
        CredentialId::<Box<[u8]>>::decode_from_buffer(data).and_then(|id| {
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
        ServerPrfInfo::decode_from_buffer(data).map(|prf| Self { prf })
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
impl<'a> DecodeBuffer<'a> for Box<[CredInfo]> {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u16::decode_from_buffer(data).and_then(|len| {
            let l = usize::from(len);
            let mut creds = Vec::with_capacity(l);
            while creds.len() < l {
                creds.push(CredInfo::decode_from_buffer(data)?);
            }
            Ok(creds.into_boxed_slice())
        })
    }
}
impl EncodeBufferFallible for AuthenticationServerState {
    type Err = SystemTimeError;
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        self.challenge.encode_into_buffer(buffer);
        self.user_verification.encode_into_buffer(buffer);
        self.extensions.encode_into_buffer(buffer);
        self.expiration.encode_into_buffer(buffer)
    }
}
impl Encode for DiscoverableAuthenticationServerState {
    type Output<'a>
        = Vec<u8>
    where
        Self: 'a;
    type Err = SystemTimeError;
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment justifies correctness"
    )]
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        // Length of the anticipated most common output:
        // * 16 for `SentChallenge`
        // * 1 for `UserVerificationRequirement`
        // * 1 or 2 for `ServerExtensionInfo`
        // * 12 for `SystemTime`
        // Clearly cannot overflow.
        let mut buffer = Vec::with_capacity(
            16 + 1 + 1 + usize::from(!matches!(self.0.extensions.prf, ServerPrfInfo::None)) + 12,
        );
        self.0.encode_into_buffer(&mut buffer).map(|()| buffer)
    }
}
/// Error returned from [`NonDiscoverableAuthenticationServerState::encode`].
#[derive(Debug)]
pub enum EncodeNonDiscoverableAuthenticationServerStateErr {
    /// Variant returned when
    /// [`NonDiscoverableAuthenticationServerState::expiration`](../struct.AuthenticationServerState.html#method.expiration-1)
    /// is before [`UNIX_EPOCH`].
    SystemTime(SystemTimeError),
    /// Variant returned when the corresponding [`NonDiscoverableCredentialRequestOptions::allow_credentials`] has more
    /// than [`u16::MAX`] [`AllowedCredential`]s.
    AllowedCredentialsCount,
}
impl Display for EncodeNonDiscoverableAuthenticationServerStateErr {
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
impl Error for EncodeNonDiscoverableAuthenticationServerStateErr {}
impl Encode for NonDiscoverableAuthenticationServerState {
    type Output<'a>
        = Vec<u8>
    where
        Self: 'a;
    type Err = EncodeNonDiscoverableAuthenticationServerStateErr;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        // Length of the anticipated most common output:
        // * 16 for `SentChallenge`
        // * 2 + Σ(2 + len(id_i) + (1|2)) from i = 1 to i = `self.allow_credentials.len()` where i is the
        //   1-based index of the `AllowedCredential` and len(id_i) is the number of bytes that makes up
        //   the ith `CredentialId`. Since `self.allow_credentials.len()` is inclusively between 1 and
        //   65,535, the smallest this can be is 2 + 2 + 16 + 1 = 21; and the largest this can be is
        //   2 + 65535(2 + 1023 + 2) = 67,304,447. We assume no credential-specific PRF is sent and the
        //   the average length of the `CredentialId`s is 128.
        // * 1 for `UserVerificationRequirement`
        // * 1 or 2 for `ServerExtensionInfo` where we assume 1 is the most common
        // * 12 for `SystemTime`
        // This is just an estimate; thus we rely on wrapping arithmetic. If the actual needed capacity is too big,
        // then a `panic` will happen anyway once we serialize the entire payload.
        let mut buffer = Vec::with_capacity(
            (16usize + 2 + 1 + 1 + 12)
                .wrapping_add(self.allow_credentials.len().wrapping_mul(2 + 128 + 1)),
        );
        self.state
            .encode_into_buffer(&mut buffer)
            .map_err(EncodeNonDiscoverableAuthenticationServerStateErr::SystemTime)
            .and_then(|()| {
                self.allow_credentials
                    .as_ref()
                    .encode_into_buffer(&mut buffer)
                    .map_err(|_e| {
                        EncodeNonDiscoverableAuthenticationServerStateErr::AllowedCredentialsCount
                    })
                    .map(|()| buffer)
            })
    }
}
impl<'a> DecodeBuffer<'a> for AuthenticationServerState {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        SentChallenge::decode_from_buffer(data).and_then(|challenge| {
            UserVerificationRequirement::decode_from_buffer(data).and_then(|user_verification| {
                ServerExtensionInfo::decode_from_buffer(data).and_then(|extensions| {
                    if super::validate_discoverable_options_helper(extensions, user_verification) {
                        SystemTime::decode_from_buffer(data).map(|expiration| Self {
                            challenge,
                            user_verification,
                            extensions,
                            expiration,
                        })
                    } else {
                        Err(EncDecErr)
                    }
                })
            })
        })
    }
}
/// Error returned from [`DiscoverableAuthenticationServerState::decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeDiscoverableAuthenticationServerStateErr {
    /// Variant returned when there was trailing data after decoding a [`DiscoverableAuthenticationServerState`].
    TrailingData,
    /// Variant returned for all other errors.
    Other,
}
impl Display for DecodeDiscoverableAuthenticationServerStateErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::TrailingData => {
                "trailing data after decoding DiscoverableAuthenticationServerState"
            }
            Self::Other => "DiscoverableAuthenticationServerState could not be decoded",
        })
    }
}
impl Error for DecodeDiscoverableAuthenticationServerStateErr {}
impl Decode for DiscoverableAuthenticationServerState {
    type Input<'a> = &'a [u8];
    type Err = DecodeDiscoverableAuthenticationServerStateErr;
    #[inline]
    fn decode(mut input: Self::Input<'_>) -> Result<Self, Self::Err> {
        AuthenticationServerState::decode_from_buffer(&mut input)
            .map_err(|_e| DecodeDiscoverableAuthenticationServerStateErr::Other)
            .and_then(|state| {
                if input.is_empty() {
                    Ok(Self(state))
                } else {
                    Err(DecodeDiscoverableAuthenticationServerStateErr::TrailingData)
                }
            })
    }
}
/// Error returned from [`NonDiscoverableAuthenticationServerState::decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeNonDiscoverableAuthenticationServerStateErr {
    /// Variant returned when there was trailing data after decoding a [`NonDiscoverableAuthenticationServerState`].
    TrailingData,
    /// Variant returned for all other errors.
    Other,
}
impl Display for DecodeNonDiscoverableAuthenticationServerStateErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::TrailingData => {
                "trailing data after decoding NonDiscoverableAuthenticationServerState"
            }
            Self::Other => "NonDiscoverableAuthenticationServerState could not be decoded",
        })
    }
}
impl Error for DecodeNonDiscoverableAuthenticationServerStateErr {}
impl Decode for NonDiscoverableAuthenticationServerState {
    type Input<'a> = &'a [u8];
    type Err = DecodeNonDiscoverableAuthenticationServerStateErr;
    #[inline]
    fn decode(mut input: Self::Input<'_>) -> Result<Self, Self::Err> {
        AuthenticationServerState::decode_from_buffer(&mut input)
            .map_err(|_e| DecodeNonDiscoverableAuthenticationServerStateErr::Other)
            .and_then(|state| {
                Box::decode_from_buffer(&mut input)
                    .map_err(|_e| DecodeNonDiscoverableAuthenticationServerStateErr::Other)
                    .and_then(|allow_credentials| {
                        super::validate_non_discoverable_options_helper(
                            state.user_verification,
                            &allow_credentials,
                        )
                        .map_err(|_e| DecodeNonDiscoverableAuthenticationServerStateErr::Other)
                        .and({
                            if allow_credentials.is_empty() {
                                Err(DecodeNonDiscoverableAuthenticationServerStateErr::Other)
                            } else if input.is_empty() {
                                Ok(Self {
                                    state,
                                    allow_credentials,
                                })
                            } else {
                                Err(DecodeNonDiscoverableAuthenticationServerStateErr::TrailingData)
                            }
                        })
                    })
            })
    }
}
