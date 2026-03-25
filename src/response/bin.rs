use super::{
    super::bin::{
        Decode, DecodeBuffer, EncDecErr, Encode, EncodeBuffer, EncodeBufferFallible as _,
    },
    AuthTransports, AuthenticatorAttachment, Backup, CredentialId, CredentialIdErr,
};
use core::{
    convert::Infallible,
    error::Error,
    fmt::{self, Display, Formatter},
};
/// [`Backup::NotEligible`] tag.
const BACKUP_NOT_ELIGIBLE: u8 = 0;
/// [`Backup::Eligible`] tag.
const BACKUP_ELIGIBLE: u8 = 1;
/// [`Backup::Exists`] tag.
const BACKUP_EXISTS: u8 = 2;
impl EncodeBuffer for Backup {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::NotEligible => BACKUP_NOT_ELIGIBLE,
            Self::Eligible => BACKUP_ELIGIBLE,
            Self::Exists => BACKUP_EXISTS,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for Backup {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            BACKUP_NOT_ELIGIBLE => Ok(Self::NotEligible),
            BACKUP_ELIGIBLE => Ok(Self::Eligible),
            BACKUP_EXISTS => Ok(Self::Exists),
            _ => Err(EncDecErr),
        })
    }
}
/// Error returned from [`AuthTransports::decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeAuthTransportsErr;
impl Display for DecodeAuthTransportsErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("AuthTransports could not be decoded")
    }
}
impl Error for DecodeAuthTransportsErr {}
impl Encode for AuthTransports {
    type Output<'a>
        = u8
    where
        Self: 'a;
    type Err = Infallible;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        Ok(self.0)
    }
}
impl Decode for AuthTransports {
    type Input<'a> = u8;
    type Err = DecodeAuthTransportsErr;
    #[inline]
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err> {
        if input <= Self::all().0 {
            Ok(Self(input))
        } else {
            Err(DecodeAuthTransportsErr)
        }
    }
}
impl EncodeBuffer for AuthTransports {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.0.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for AuthTransports {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| Self::decode(val).map_err(|_e| EncDecErr))
    }
}
impl<T: AsRef<[u8]>> Encode for CredentialId<T> {
    type Output<'a>
        = &'a [u8]
    where
        Self: 'a;
    type Err = Infallible;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        Ok(self.0.as_ref())
    }
}
impl Decode for CredentialId<Box<[u8]>> {
    type Input<'a> = Box<[u8]>;
    type Err = CredentialIdErr;
    #[inline]
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err> {
        match CredentialId::<&[u8]>::from_slice(&input) {
            Ok(_) => Ok(Self(input)),
            Err(e) => Err(e),
        }
    }
}
impl<'b> Decode for CredentialId<&'b [u8]> {
    type Input<'a> = &'b [u8];
    type Err = CredentialIdErr;
    #[inline]
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err> {
        match CredentialId::from_slice(input) {
            Ok(_) => Ok(Self(input)),
            Err(e) => Err(e),
        }
    }
}
impl<T: AsRef<[u8]>> EncodeBuffer for CredentialId<T> {
    #[expect(clippy::unreachable, reason = "when there is a bug, we want to crash")]
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        // Max length is 1023, so this won't error.
        self.0
            .as_ref()
            .encode_into_buffer(buffer)
            .unwrap_or_else(|_e| unreachable!("there is a bug in [u8]::encode_into_buffer"));
    }
}
impl<'a> DecodeBuffer<'a> for CredentialId<Box<[u8]>> {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        <&[u8]>::decode_from_buffer(data).and_then(|val| {
            CredentialId::<&[u8]>::from_slice(val)
                .map_err(|_e| EncDecErr)
                .map(|_| Self(val.into()))
        })
    }
}
/// [`AuthenticatorAttachment::None`] tag.
const AUTH_ATTACH_NONE: u8 = 0;
/// [`AuthenticatorAttachment::Platform`] tag.
const AUTH_ATTACH_PLATFORM: u8 = 1;
/// [`AuthenticatorAttachment::CrossPlatform`] tag.
const AUTH_ATTACH_CROSS_PLATFORM: u8 = 2;
impl EncodeBuffer for AuthenticatorAttachment {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::None => AUTH_ATTACH_NONE,
            Self::Platform => AUTH_ATTACH_PLATFORM,
            Self::CrossPlatform => AUTH_ATTACH_CROSS_PLATFORM,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for AuthenticatorAttachment {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            AUTH_ATTACH_NONE => Ok(Self::None),
            AUTH_ATTACH_PLATFORM => Ok(Self::Platform),
            AUTH_ATTACH_CROSS_PLATFORM => Ok(Self::CrossPlatform),
            _ => Err(EncDecErr),
        })
    }
}
