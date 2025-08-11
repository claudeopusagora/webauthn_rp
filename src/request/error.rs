#[cfg(doc)]
use super::{AsciiDomain, DomainOrigin, Port, RpId, Scheme, Url};
#[cfg(doc)]
use core::str::FromStr;
use core::{
    error::Error,
    fmt::{self, Display, Formatter},
    num::ParseIntError,
};
/// Error returned by [`AsciiDomain::try_from`] when the `Vec` is not a valid ASCII domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AsciiDomainErr {
    /// Variant returned when the domain is empty.
    Empty,
    /// Variant returned when the domain is the root domain (i.e., `'.'`).
    RootDomain,
    /// Variant returned when the domain is too long.
    Len,
    /// Variant returned when an empty label exists.
    EmptyLabel,
    /// Variant returned when a label is too long.
    LabelLen,
    /// Variant returned when a label contains a `u8` that is not valid ASCII.
    NotAscii,
}
impl Display for AsciiDomainErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Empty => "domain is empty",
            Self::RootDomain => "domain is the root domain",
            Self::Len => "domain is too long",
            Self::EmptyLabel => "domain has an empty label",
            Self::LabelLen => "domain has a label that is too long",
            Self::NotAscii => "domain has a label that contains a non-ASCII byte",
        })
    }
}
impl Error for AsciiDomainErr {}
/// Error returned by [`Url::from_str`] when the `str` passed to the
/// [URL serializer](https://url.spec.whatwg.org/#concept-url-serializer) leads to a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UrlErr;
impl Display for UrlErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("URL serializer failed")
    }
}
impl Error for UrlErr {}
/// Error returned by [`RpId::try_from`] when the `String` is not a valid [`AsciiDomain`] nor [`Url`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RpIdErr;
impl Display for RpIdErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("RpId is invalid")
    }
}
impl Error for RpIdErr {}
/// Error returned by [`Scheme::try_from`] when the passed [`str`] is empty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemeParseErr;
impl Display for SchemeParseErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("scheme was empty")
    }
}
impl Error for SchemeParseErr {}
/// Error returned by [`Port::from_str`] when the passed [`str`] is not a valid unsigned 16-bit integer in
/// decimal form without leading 0s.
#[derive(Debug, Eq, PartialEq)]
pub enum PortParseErr {
    /// Variant returned iff [`u16::from_str`] does.
    ParseInt(ParseIntError),
    /// Variant returned iff a `str` is a valid 16-bit unsigned integer with leading 0s.
    NotCanonical,
}
impl Display for PortParseErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ParseInt(ref err) => err.fmt(f),
            Self::NotCanonical => {
                f.write_str("string was a valid TCP/UDP port number, but it had leading 0s")
            }
        }
    }
}
impl Error for PortParseErr {}
/// Error returned by [`DomainOrigin::try_from`].
#[derive(Debug, Eq, PartialEq)]
pub enum DomainOriginParseErr {
    /// Variant returned when there is an error parsing the scheme.
    Scheme(SchemeParseErr),
    /// Variant returned when there is an error parsing the port.
    Port(PortParseErr),
}
impl Display for DomainOriginParseErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Scheme(err) => err.fmt(f),
            Self::Port(ref err) => err.fmt(f),
        }
    }
}
impl Error for DomainOriginParseErr {}
