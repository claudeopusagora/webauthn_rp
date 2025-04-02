use super::UserHandle;
impl<const LEN: usize> From<[u8; LEN]> for UserHandle<LEN>
where
    Self: Default,
{
    #[inline]
    fn from(value: [u8; LEN]) -> Self {
        Self(value)
    }
}
