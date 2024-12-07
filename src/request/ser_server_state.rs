use super::{
    super::bin::{DecodeBuffer, EncDecErr, Encode, EncodeBuffer, EncodeBufferFallible},
    CredentialMediationRequirement, ExtensionInfo, ExtensionReq, Hint, SentChallenge,
    UserVerificationRequirement,
};
use core::{convert::Infallible, time::Duration};
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
/// [`Hint::None`] tag.
const HINT_NONE: u8 = 0;
/// [`Hint::SecurityKey`] tag.
const HINT_SEC_KEY: u8 = 1;
/// [`Hint::ClientDevice`] tag.
const HINT_CLIENT_DEV: u8 = 2;
/// [`Hint::Hybrid`] tag.
const HINT_HYBRID: u8 = 3;
/// [`Hint::SecurityKeyClientDevice`] tag.
const HINT_SEC_KEY_CLIENT_DEV: u8 = 4;
/// [`Hint::ClientDeviceSecurityKey`] tag.
const HINT_CLIENT_DEV_SEC_KEY: u8 = 5;
/// [`Hint::SecurityKeyHybrid`] tag.
const HINT_SEC_KEY_HYBRID: u8 = 6;
/// [`Hint::HybridSecurityKey`] tag.
const HINT_HYBRID_SEC_KEY: u8 = 7;
/// [`Hint::ClientDeviceHybrid`] tag.
const HINT_CLIENT_DEV_HYBRID: u8 = 8;
/// [`Hint::HybridClientDevice`] tag.
const HINT_HYBRID_CLIENT_DEV: u8 = 9;
/// [`Hint::SecurityKeyClientDeviceHybrid`] tag.
const HINT_SEC_KEY_CLIENT_DEV_HYBRID: u8 = 10;
/// [`Hint::SecurityKeyHybridClientDevice`] tag.
const HINT_SEC_KEY_HYBRID_CLIENT_DEV: u8 = 11;
/// [`Hint::ClientDeviceSecurityKeyHybrid`] tag.
const HINT_CLIENT_DEV_SEC_KEY_HYBRID: u8 = 12;
/// [`Hint::ClientDeviceHybridSecurityKey`] tag.
const HINT_CLIENT_DEV_HYBRID_SEC_KEY: u8 = 13;
/// [`Hint::HybridSecurityKeyClientDevice`] tag.
const HINT_HYBRID_SEC_KEY_CLIENT_DEV: u8 = 14;
/// [`Hint::HybridClientDeviceSecurityKey`] tag.
const HINT_HYBRID_CLIENT_DEV_SEC_KEY: u8 = 15;
impl EncodeBuffer for Hint {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::None => HINT_NONE,
            Self::SecurityKey => HINT_SEC_KEY,
            Self::ClientDevice => HINT_CLIENT_DEV,
            Self::Hybrid => HINT_HYBRID,
            Self::SecurityKeyClientDevice => HINT_SEC_KEY_CLIENT_DEV,
            Self::ClientDeviceSecurityKey => HINT_CLIENT_DEV_SEC_KEY,
            Self::SecurityKeyHybrid => HINT_SEC_KEY_HYBRID,
            Self::HybridSecurityKey => HINT_HYBRID_SEC_KEY,
            Self::ClientDeviceHybrid => HINT_CLIENT_DEV_HYBRID,
            Self::HybridClientDevice => HINT_HYBRID_CLIENT_DEV,
            Self::SecurityKeyClientDeviceHybrid => HINT_SEC_KEY_CLIENT_DEV_HYBRID,
            Self::SecurityKeyHybridClientDevice => HINT_SEC_KEY_HYBRID_CLIENT_DEV,
            Self::ClientDeviceSecurityKeyHybrid => HINT_CLIENT_DEV_SEC_KEY_HYBRID,
            Self::ClientDeviceHybridSecurityKey => HINT_CLIENT_DEV_HYBRID_SEC_KEY,
            Self::HybridSecurityKeyClientDevice => HINT_HYBRID_SEC_KEY_CLIENT_DEV,
            Self::HybridClientDeviceSecurityKey => HINT_HYBRID_CLIENT_DEV_SEC_KEY,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for Hint {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            HINT_NONE => Ok(Self::None),
            HINT_SEC_KEY => Ok(Self::SecurityKey),
            HINT_CLIENT_DEV => Ok(Self::ClientDevice),
            HINT_HYBRID => Ok(Self::Hybrid),
            HINT_SEC_KEY_CLIENT_DEV => Ok(Self::SecurityKeyClientDevice),
            HINT_CLIENT_DEV_SEC_KEY => Ok(Self::ClientDeviceSecurityKey),
            HINT_SEC_KEY_HYBRID => Ok(Self::SecurityKeyHybrid),
            HINT_HYBRID_SEC_KEY => Ok(Self::HybridSecurityKey),
            HINT_CLIENT_DEV_HYBRID => Ok(Self::ClientDeviceHybrid),
            HINT_HYBRID_CLIENT_DEV => Ok(Self::HybridClientDevice),
            HINT_SEC_KEY_CLIENT_DEV_HYBRID => Ok(Self::SecurityKeyClientDeviceHybrid),
            HINT_SEC_KEY_HYBRID_CLIENT_DEV => Ok(Self::SecurityKeyHybridClientDevice),
            HINT_CLIENT_DEV_SEC_KEY_HYBRID => Ok(Self::ClientDeviceSecurityKeyHybrid),
            HINT_CLIENT_DEV_HYBRID_SEC_KEY => Ok(Self::ClientDeviceHybridSecurityKey),
            HINT_HYBRID_SEC_KEY_CLIENT_DEV => Ok(Self::HybridSecurityKeyClientDevice),
            HINT_HYBRID_CLIENT_DEV_SEC_KEY => Ok(Self::HybridClientDeviceSecurityKey),
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
    type Output<'a> = u128 where Self: 'a;
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
/// [`CredentialMediationRequirement::Silent`] tag.
const CRED_MED_REQ_SILENT: u8 = 0;
/// [`CredentialMediationRequirement::Optional`] tag.
const CRED_MED_REQ_OPTIONAL: u8 = 1;
/// [`CredentialMediationRequirement::Conditional`] tag.
const CRED_MED_REQ_CONDITIONAL: u8 = 2;
/// [`CredentialMediationRequirement::Required`] tag.
const CRED_MED_REQ_REQUIRED: u8 = 3;
impl EncodeBuffer for CredentialMediationRequirement {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            Self::Silent => CRED_MED_REQ_SILENT,
            Self::Optional => CRED_MED_REQ_OPTIONAL,
            Self::Conditional => CRED_MED_REQ_CONDITIONAL,
            Self::Required => CRED_MED_REQ_REQUIRED,
        }
        .encode_into_buffer(buffer);
    }
}
impl<'a> DecodeBuffer<'a> for CredentialMediationRequirement {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            CRED_MED_REQ_SILENT => Ok(Self::Silent),
            CRED_MED_REQ_OPTIONAL => Ok(Self::Optional),
            CRED_MED_REQ_CONDITIONAL => Ok(Self::Conditional),
            CRED_MED_REQ_REQUIRED => Ok(Self::Required),
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
        u64::decode_from_buffer(data).and_then(|secs| {
            u32::decode_from_buffer(data).and_then(|nanos| {
                if nanos < 1_000_000_000 {
                    UNIX_EPOCH
                        .checked_add(Duration::new(secs, nanos))
                        .ok_or(EncDecErr)
                } else {
                    Err(EncDecErr)
                }
            })
        })
    }
}
