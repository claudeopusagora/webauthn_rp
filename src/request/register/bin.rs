use super::{
    super::super::bin::{Decode, Encode},
    UserHandle,
};
use core::convert::Infallible;
impl<const LEN: usize> Encode for UserHandle<LEN> {
    type Output<'a>
        = [u8; LEN]
    where
        Self: 'a;
    type Err = Infallible;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        Ok(self.0)
    }
}
impl<const LEN: usize> Decode for UserHandle<LEN>
where
    Self: Default,
{
    type Input<'a> = [u8; LEN];
    type Err = Infallible;
    #[inline]
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err> {
        Ok(Self(input))
    }
}
