#[cfg(test)]
mod tests;
use super::{AuthTransports, AuthenticatorTransport, CredentialId, CredentialIdErr};
use core::iter::FusedIterator;
impl<'a: 'b, 'b> TryFrom<&'a [u8]> for CredentialId<&'b [u8]> {
    type Error = CredentialIdErr;
    #[inline]
    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}
impl TryFrom<Box<[u8]>> for CredentialId<Box<[u8]>> {
    type Error = CredentialIdErr;
    #[inline]
    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        match CredentialId::<&[u8]>::try_from(&*value) {
            Ok(_) => Ok(Self(value)),
            Err(e) => Err(e),
        }
    }
}
/// [`Iterator`] of [`AuthenticatorTransport`]s returned from
/// [`AuthTransports::into_iter`].
#[derive(Debug)]
pub struct AuthTransportIter(AuthTransports);
impl Iterator for AuthTransportIter {
    type Item = AuthenticatorTransport;
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let mut nxt = self.0.remove(AuthenticatorTransport::Ble);
        if self.0.0 != nxt.0 {
            self.0 = nxt;
            return Some(AuthenticatorTransport::Ble);
        }
        nxt = self.0.remove(AuthenticatorTransport::Hybrid);
        if self.0.0 != nxt.0 {
            self.0 = nxt;
            return Some(AuthenticatorTransport::Hybrid);
        }
        nxt = self.0.remove(AuthenticatorTransport::Internal);
        if self.0.0 != nxt.0 {
            self.0 = nxt;
            return Some(AuthenticatorTransport::Internal);
        }
        nxt = self.0.remove(AuthenticatorTransport::Nfc);
        if self.0.0 != nxt.0 {
            self.0 = nxt;
            return Some(AuthenticatorTransport::Nfc);
        }
        nxt = self.0.remove(AuthenticatorTransport::SmartCard);
        if self.0.0 != nxt.0 {
            self.0 = nxt;
            return Some(AuthenticatorTransport::SmartCard);
        }
        nxt = self.0.remove(AuthenticatorTransport::Usb);
        if self.0.0 == nxt.0 {
            None
        } else {
            self.0 = nxt;
            Some(AuthenticatorTransport::Usb)
        }
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = self.len();
        (count, Some(count))
    }
    #[inline]
    fn count(self) -> usize
    where
        Self: Sized,
    {
        self.len()
    }
    #[inline]
    fn last(mut self) -> Option<Self::Item>
    where
        Self: Sized,
    {
        self.next_back()
    }
}
impl ExactSizeIterator for AuthTransportIter {
    #[expect(clippy::as_conversions, reason = "comment justifies correctness")]
    #[inline]
    fn len(&self) -> usize {
        // Maximum count is 6, so this is fine.
        self.0.count() as usize
    }
}
impl DoubleEndedIterator for AuthTransportIter {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        let mut nxt = self.0.remove(AuthenticatorTransport::Usb);
        if self.0.0 != nxt.0 {
            self.0 = nxt;
            return Some(AuthenticatorTransport::Usb);
        }
        nxt = self.0.remove(AuthenticatorTransport::SmartCard);
        if self.0.0 != nxt.0 {
            self.0 = nxt;
            return Some(AuthenticatorTransport::SmartCard);
        }
        nxt = self.0.remove(AuthenticatorTransport::Nfc);
        if self.0.0 != nxt.0 {
            self.0 = nxt;
            return Some(AuthenticatorTransport::Nfc);
        }
        nxt = self.0.remove(AuthenticatorTransport::Internal);
        if self.0.0 != nxt.0 {
            self.0 = nxt;
            return Some(AuthenticatorTransport::Internal);
        }
        nxt = self.0.remove(AuthenticatorTransport::Hybrid);
        if self.0.0 != nxt.0 {
            self.0 = nxt;
            return Some(AuthenticatorTransport::Hybrid);
        }
        nxt = self.0.remove(AuthenticatorTransport::Ble);
        if self.0.0 == nxt.0 {
            None
        } else {
            self.0 = nxt;
            Some(AuthenticatorTransport::Ble)
        }
    }
}
impl FusedIterator for AuthTransportIter {}
impl IntoIterator for AuthTransports {
    type Item = AuthenticatorTransport;
    type IntoIter = AuthTransportIter;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        AuthTransportIter(self)
    }
}
