use super::{USER_HANDLE_MAX_LEN, USER_HANDLE_MIN_LEN, UserHandle, UserHandleErr};
#[expect(clippy::fallible_impl_from, reason = "backward compatible fix")]
impl<const LEN: usize> From<[u8; LEN]> for UserHandle<[u8; LEN]> {
    #[expect(clippy::panic, reason = "backward compatible fix")]
    #[inline]
    fn from(value: [u8; LEN]) -> Self {
        if (USER_HANDLE_MIN_LEN..=USER_HANDLE_MAX_LEN).contains(&value.len()) {
            Self(value)
        } else {
            panic!(
                "UserHandle::from must only be passed an array of length 1 to 64 inclusively. Update webauthn_rp to 0.3.0 or greater to avoid this `panic` possibility"
            );
        }
    }
}
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for UserHandle<&'b [u8]> {
    type Error = UserHandleErr;
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}
impl TryFrom<Vec<u8>> for UserHandle<Vec<u8>> {
    type Error = UserHandleErr;
    #[inline]
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match UserHandle::<&[u8]>::try_from(value.as_slice()) {
            Ok(_) => Ok(Self(value)),
            Err(e) => Err(e),
        }
    }
}
