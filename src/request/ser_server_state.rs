use super::{
    super::bin::{DecodeBuffer, EncDecErr, Encode, EncodeBuffer, EncodeBufferFallible},
    CredentialMediationRequirement, ExtensionInfo, ExtensionReq, SentChallenge,
    UserVerificationRequirement,
};
use core::{convert::Infallible, num::NonZeroU32, time::Duration};
use std::time::{SystemTime, SystemTimeError, UNIX_EPOCH};
/// [`ExtensionInfo::RequireEnforceValue`] tag.
const EXT_INFO_REQUIRE_ENFORCE: u8 = 0;
/// [`ExtensionInfo::RequireDontEnforceValue`] tag.
const EXT_INFO_REQUIRE_DONT_ENFORCE: u8 = 1;
/// [`ExtensionInfo::AllowEnforceValue`] tag.
const EXT_INFO_ALLOW_ENFORCE: u8 = 2;
/// [`ExtensionInfo::AllowDontEnforceValue`] tag.
const EXT_INFO_ALLOW_DONT_ENFORCE: u8 = 3;
impl EncodeBuffer for ExtensionInfo {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::RequireEnforceValue => EXT_INFO_REQUIRE_ENFORCE,
            Self::RequireDontEnforceValue => EXT_INFO_REQUIRE_DONT_ENFORCE,
            Self::AllowEnforceValue => EXT_INFO_ALLOW_ENFORCE,
            Self::AllowDontEnforceValue => EXT_INFO_ALLOW_DONT_ENFORCE,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for ExtensionInfo {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            EXT_INFO_REQUIRE_ENFORCE => Ok(Self::RequireEnforceValue),
            EXT_INFO_REQUIRE_DONT_ENFORCE => Ok(Self::RequireDontEnforceValue),
            EXT_INFO_ALLOW_ENFORCE => Ok(Self::AllowEnforceValue),
            EXT_INFO_ALLOW_DONT_ENFORCE => Ok(Self::AllowDontEnforceValue),
            _ => Err(EncDecErr),
        })
    }
}
/// [`ExtensionReq::Require`] tag.
const EXT_REQ_REQUIRE: u8 = 0;
/// [`ExtensionReq::Allow`] tag.
const EXT_REQ_ALLOW: u8 = 1;
impl EncodeBuffer for ExtensionReq {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::Require => EXT_REQ_REQUIRE,
            Self::Allow => EXT_REQ_ALLOW,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for ExtensionReq {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            EXT_REQ_REQUIRE => Ok(Self::Require),
            EXT_REQ_ALLOW => Ok(Self::Allow),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBuffer for SentChallenge {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.0.encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for SentChallenge {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u128::decode_from_buffer(data).map(Self)
    }
}
impl Encode for SentChallenge {
    type Output<'a>
        = u128
    where
        Self: 'a;
    type Err = Infallible;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        Ok(self.0)
    }
}
/// [`UserVerificationRequirement::Required`] tag.
const USER_VER_REQ_REQUIRED: u8 = 0;
/// [`UserVerificationRequirement::Discouraged`] tag.
const USER_VER_REQ_DISCOURAGED: u8 = 1;
/// [`UserVerificationRequirement::Preferred`] tag.
const USER_VER_REQ_PREFERRED: u8 = 2;
impl EncodeBuffer for UserVerificationRequirement {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::Required => USER_VER_REQ_REQUIRED,
            Self::Discouraged => USER_VER_REQ_DISCOURAGED,
            Self::Preferred => USER_VER_REQ_PREFERRED,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for UserVerificationRequirement {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            USER_VER_REQ_REQUIRED => Ok(Self::Required),
            USER_VER_REQ_DISCOURAGED => Ok(Self::Discouraged),
            USER_VER_REQ_PREFERRED => Ok(Self::Preferred),
            _ => Err(EncDecErr),
        })
    }
}
/// [`CredentialMediationRequirement::Required`] tag.
const CRED_MED_REQ_REQUIRED: u8 = 0;
/// [`CredentialMediationRequirement::Conditional`] tag.
const CRED_MED_REQ_CONDITIONAL: u8 = 1;
impl EncodeBuffer for CredentialMediationRequirement {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::Required => CRED_MED_REQ_REQUIRED,
            Self::Conditional => CRED_MED_REQ_CONDITIONAL,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for CredentialMediationRequirement {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            CRED_MED_REQ_REQUIRED => Ok(Self::Required),
            CRED_MED_REQ_CONDITIONAL => Ok(Self::Conditional),
            _ => Err(EncDecErr),
        })
    }
}
impl EncodeBufferFallible for SystemTime {
    type Err = SystemTimeError;
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        self.duration_since(UNIX_EPOCH).map(|dur| {
            dur.as_secs().encode_into_buffer(buffer);
            dur.subsec_nanos().encode_into_buffer(buffer);
        })
    }
}
impl<'a> DecodeBuffer<'a> for SystemTime {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        /// Maximum duration possible for a timeout which is around 49.7 days.
        #[expect(
            clippy::as_conversions,
            reason = "u32 as u64 is always OK, and we can't use u64::from in const contexts"
        )]
        const MAX_TIMEOUT: Duration = Duration::from_millis(NonZeroU32::MAX.get() as u64);
        u64::decode_from_buffer(data).and_then(|secs| {
            u32::decode_from_buffer(data).and_then(|nanos| {
                if nanos < 1_000_000_000 {
                    UNIX_EPOCH
                        .checked_add(Duration::new(secs, nanos))
                        .ok_or(EncDecErr)
                        .and_then(|exp| {
                            // The latest we could have started the ceremony is now which means the maximum
                            // expiry is now plus the maximum timeout.
                            if let Some(max_exp) = Self::now().checked_add(MAX_TIMEOUT)
                                && max_exp < exp
                            {
                                Err(EncDecErr)
                            } else {
                                // Note even when `SystemTime::now().checked_add(MAX_TIMEOUT)` is `None`,
                                // this is valid since the ceremony could have very recently been started.
                                // While this is highly unlikely seeing how `MAX_TIMEOUT` is less than 50 days;
                                // it is _technically_ possible if `SystemTime::now` is within 50 days
                                // of the maximum representable `SystemTime`. It is _far_ more likely that
                                // this branch is taken since `max_exp >= exp`.
                                Ok(exp)
                            }
                        })
                } else {
                    Err(EncDecErr)
                }
            })
        })
    }
}
