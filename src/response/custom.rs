use super::{CredentialId, CredentialIdErr};
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for CredentialId<&'b [u8]> {
    type Error = CredentialIdErr;
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}
impl TryFrom<Vec<u8>> for CredentialId<Vec<u8>> {
    type Error = CredentialIdErr;
    #[inline]
    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match CredentialId::<&[u8]>::try_from(value.as_slice()) {
            Ok(_) => Ok(Self(value)),
            Err(e) => Err(e),
        }
    }
}
