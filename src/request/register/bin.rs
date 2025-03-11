extern crate alloc;
use super::{
    super::super::bin::{Decode, Encode},
    Nickname, NicknameErr, UserHandle, UserHandleErr, Username, UsernameErr,
};
use alloc::borrow::Cow;
use core::{
    convert::Infallible,
    error::Error,
    fmt::{self, Display, Formatter},
};
impl<T: AsRef<[u8]>> Encode for UserHandle<T> {
    type Output<'a>
        = &'a [u8]
    where
        Self: 'a;
    type Err = Infallible;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        Ok(self.as_ref())
    }
}
impl Decode for UserHandle<Vec<u8>> {
    type Input<'a> = Vec<u8>;
    type Err = UserHandleErr;
    #[inline]
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err> {
        match UserHandle::<&[u8]>::from_slice(input.as_slice()) {
            Ok(_) => Ok(Self(input)),
            Err(e) => Err(e),
        }
    }
}
impl<const LEN: usize> Decode for UserHandle<[u8; LEN]>
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
impl Encode for Nickname<'_> {
    type Output<'a>
        = &'a str
    where
        Self: 'a;
    type Err = Infallible;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        Ok(self.as_ref())
    }
}
/// Error returned from [`Nickname::decode`].
#[derive(Clone, Copy, Debug)]
pub enum DecodeNicknameErr {
    /// Variant returned when the encoded data could not be decoded
    /// into a [`Nickname`].
    Nickname(NicknameErr),
    /// Variant returned when the [`Nickname`] was not encoded
    /// into its canonical form.
    NotCanonical,
}
impl Display for DecodeNicknameErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Nickname(e) => e.fmt(f),
            Self::NotCanonical => f.write_str("Nickname was not encoded in its canonical form"),
        }
    }
}
impl Error for DecodeNicknameErr {}
impl Decode for Nickname<'_> {
    type Input<'a> = String;
    type Err = DecodeNicknameErr;
    #[inline]
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err> {
        match Nickname::try_from(input.as_str()).map_err(DecodeNicknameErr::Nickname) {
            Ok(v) => match v.0 {
                Cow::Borrowed(name) => {
                    if name == input.as_str() {
                        Ok(Self(Cow::Owned(input)))
                    } else {
                        Err(DecodeNicknameErr::NotCanonical)
                    }
                }
                Cow::Owned(_) => Err(DecodeNicknameErr::NotCanonical),
            },
            Err(e) => Err(e),
        }
    }
}
impl Encode for Username<'_> {
    type Output<'a>
        = &'a str
    where
        Self: 'a;
    type Err = Infallible;
    #[inline]
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err> {
        Ok(self.as_ref())
    }
}
/// Error returned from [`Username::decode`].
#[derive(Clone, Copy, Debug)]
pub enum DecodeUsernameErr {
    /// Variant returned when the encoded data could not be decoded
    /// into a [`Username`].
    Username(UsernameErr),
    /// Variant returned when the [`Username`] was not encoded
    /// into its canonical form.
    NotCanonical,
}
impl Display for DecodeUsernameErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Username(e) => e.fmt(f),
            Self::NotCanonical => f.write_str("Username was not encoded in its canonical form"),
        }
    }
}
impl Error for DecodeUsernameErr {}
impl Decode for Username<'_> {
    type Input<'a> = String;
    type Err = DecodeUsernameErr;
    #[inline]
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err> {
        match Username::try_from(input.as_str()).map_err(DecodeUsernameErr::Username) {
            Ok(v) => match v.0 {
                Cow::Borrowed(name) => {
                    if name == input.as_str() {
                        Ok(Self(Cow::Owned(input)))
                    } else {
                        Err(DecodeUsernameErr::NotCanonical)
                    }
                }
                Cow::Owned(_) => Err(DecodeUsernameErr::NotCanonical),
            },
            Err(e) => Err(e),
        }
    }
}
