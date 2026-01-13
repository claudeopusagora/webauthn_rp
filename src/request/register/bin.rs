extern crate alloc;
use super::{
    super::super::bin::{Decode, Encode},
    DisplayName, Nickname, NicknameErr, UserHandle, Username, UsernameErr,
};
use alloc::borrow::Cow;
use core::{
    convert::Infallible,
    error::Error,
    fmt::{self, Display, Formatter},
};
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
impl Encode for DisplayName<'_> {
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
/// Error returned from [`DisplayName::decode`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeDisplayNameErr {
    /// Variant returned when the encoded data could not be decoded
    /// into a [`DisplayName`].
    Nickname(NicknameErr),
    /// Variant returned when the [`DisplayName`] was not encoded
    /// into its canonical form.
    NotCanonical,
}
impl Display for DecodeDisplayNameErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Nickname(e) => e.fmt(f),
            Self::NotCanonical => f.write_str("DisplayName was not encoded in its canonical form"),
        }
    }
}
impl Error for DecodeDisplayNameErr {}
impl<'b> Decode for DisplayName<'b> {
    type Input<'a> = &'b str;
    type Err = DecodeDisplayNameErr;
    #[inline]
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err> {
        match DisplayName::try_from(input).map_err(DecodeDisplayNameErr::Nickname) {
            Ok(v) => match v {
                DisplayName::Blank => Ok(Self::Blank),
                DisplayName::Nickname(name) => match name.0 {
                    Cow::Borrowed(val) => {
                        if val == input {
                            Ok(Self::Nickname(Nickname(Cow::Borrowed(input))))
                        } else {
                            Err(DecodeDisplayNameErr::NotCanonical)
                        }
                    }
                    Cow::Owned(_) => Err(DecodeDisplayNameErr::NotCanonical),
                },
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
impl<'b> Decode for Username<'b> {
    type Input<'a> = &'b str;
    type Err = DecodeUsernameErr;
    #[inline]
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err> {
        match Username::try_from(input).map_err(DecodeUsernameErr::Username) {
            Ok(v) => match v.0 {
                Cow::Borrowed(name) => {
                    if name == input {
                        Ok(Self(Cow::Borrowed(input)))
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
