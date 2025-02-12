use super::{UserHandle, UserHandleErr};
impl<const LEN: usize> From<[u8; LEN]> for UserHandle<[u8; LEN]> {
    #[inline]
    fn from(value: [u8; LEN]) -> Self {
        Self(value)
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
