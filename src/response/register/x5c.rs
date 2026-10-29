//! Agora fork, feature `packed_x5c`: a [packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation)
//! attestation statement with an `x5c` certificate chain, parsed and handed to the caller **unverified**.
//!
//! This library verifies nothing in such a statement: not the signature (it is made by the attestation key in
//! the leaf certificate, not by the credential key), not the chain, not the certificate requirements of
//! [§8.2.1](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements). The registration
//! ceremony therefore treats the statement as [`Attestation::None`](super::Attestation::None), as
//! [§7.1 step 24](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential) allows for an attestation
//! the relying party does not trust. A caller that wants to trust it calls
//! [`AuthenticatorAttestation::packed_x5c`](super::AuthenticatorAttestation::packed_x5c) after the ceremony
//! succeeded and does all of that verification itself, against its own trust anchors.
use super::{
    super::{CborSuccess, cbor},
    Aaguid, Sig,
    error::AttestationErr,
};
/// "x5c" key.
const X5C: [u8; 4] = [cbor::TEXT_3, b'x', b'5', b'c'];
/// CBOR major type 4, an array.
const ARRAY: u8 = 0b100_00000;
/// Mask of the major type in an initial byte.
const MAJOR_MASK: u8 = 0b111_00000;
/// Largest array length encoded in the initial byte.
const MAX_INLINE: u8 = 23;
/// The [`x5c`](https://www.w3.org/TR/webauthn-3/#packed-x5c) certificate chain of a packed attestation
/// statement: the attestation certificate first, then the certificates that chain it towards a root, each as DER.
///
/// Only the CBOR framing is checked: it holds between 1 and 23 byte strings. Nothing is known about their contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X5c<'a> {
    /// The CBOR byte strings, without the array header.
    items: &'a [u8],
    /// The number of byte strings in `items`.
    len: u8,
}
impl<'a> X5c<'a> {
    /// The number of certificates; at least 1.
    #[inline]
    #[must_use]
    pub fn len(self) -> usize {
        usize::from(self.len)
    }
    /// Always `false`: a chain holds at least one certificate.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        false
    }
    /// The certificates as DER, the attestation certificate first.
    #[inline]
    #[must_use]
    pub const fn certificates(self) -> X5cCertificates<'a> {
        X5cCertificates { items: self.items }
    }
    /// The attestation certificate (the leaf) as DER.
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    #[inline]
    #[must_use]
    pub fn attestation_certificate(self) -> &'a [u8] {
        self.certificates()
            .next()
            .unwrap_or_else(|| unreachable!("there is a bug in X5c::from_cbor"))
    }
    /// Parses `"x5c": [bytes, ...]`, the third entry of a packed attestation statement.
    pub(super) fn from_cbor(cbor: &'a [u8]) -> Result<CborSuccess<'a, Self>, AttestationErr> {
        cbor.split_at_checked(X5C.len())
            .ok_or(AttestationErr::Len)
            .and_then(|(key, key_rem)| {
                if key == X5C {
                    key_rem
                        .split_first()
                        .ok_or(AttestationErr::Len)
                        .and_then(|(&header, items)| {
                            let len = header ^ ARRAY;
                            if header & MAJOR_MASK == ARRAY && len > 0 && len <= MAX_INLINE {
                                (0..len)
                                    .try_fold(items, |rem, _| {
                                        byte_string(rem)
                                            .map(|(_, after)| after)
                                            .ok_or(AttestationErr::PackedFormatX5c)
                                    })
                                    .map(|remaining| CborSuccess {
                                        value: Self {
                                            // `remaining` is a suffix of `items`, so this won't underflow
                                            // and `split_at` won't panic.
                                            items: items
                                                .split_at(
                                                    items.len().saturating_sub(remaining.len()),
                                                )
                                                .0,
                                            len,
                                        },
                                        remaining,
                                    })
                            } else {
                                Err(AttestationErr::PackedFormatX5c)
                            }
                        })
                } else {
                    Err(AttestationErr::PackedFormatX5c)
                }
            })
    }
}
/// Splits a canonically encoded, non-empty CBOR byte string off the front of `cbor`, returning its contents
/// and what follows it. Lengths up to 65535 are accepted.
#[expect(clippy::big_endian_bytes, reason = "CBOR lengths are big-endian")]
fn byte_string(cbor: &[u8]) -> Option<(&[u8], &[u8])> {
    cbor.split_first().and_then(|(&header, rem)| {
        if header & MAJOR_MASK == cbor::BYTES {
            match header ^ cbor::BYTES {
                0 => None,
                len @ 1..=MAX_INLINE => Some((usize::from(len), rem)),
                24 => rem.split_first().and_then(|(&len, len_rem)| {
                    (len > MAX_INLINE).then_some((usize::from(len), len_rem))
                }),
                25 => rem.split_at_checked(2).and_then(|(len_slice, len_rem)| {
                    let mut len_bytes = [0; 2];
                    len_bytes.copy_from_slice(len_slice);
                    let len = u16::from_be_bytes(len_bytes);
                    (len > 255).then_some((usize::from(len), len_rem))
                }),
                _ => None,
            }
            .and_then(|(len, data)| data.split_at_checked(len))
        } else {
            None
        }
    })
}
/// Iterator over the certificates of an [`X5c`], as DER.
#[derive(Clone, Debug)]
pub struct X5cCertificates<'a> {
    /// The byte strings not yet returned.
    items: &'a [u8],
}
impl<'a> Iterator for X5cCertificates<'a> {
    type Item = &'a [u8];
    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        byte_string(self.items).map(|(cert, rem)| {
            self.items = rem;
            cert
        })
    }
}
/// A packed attestation statement with an `x5c` chain, as the client sent it, with what a caller needs to
/// verify it. **Nothing in it has been verified.**
///
/// To trust it, a caller must at least: verify [`Self::signature`] over [`Self::signed_data`] with the public
/// key of [`X5c::attestation_certificate`], with the algorithm the signature names; check that certificate
/// against [§8.2.1](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation-cert-requirements), including that
/// its `id-fido-gen-ce-aaguid` extension, if present, equals [`Self::aaguid`]; and validate the chain to a trust
/// anchor it chose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackedX5c<'a> {
    /// The attestation signature; its variant names the algorithm (`alg`).
    pub signature: Sig<'a>,
    /// The certificate chain.
    pub x5c: X5c<'a>,
    /// The AAGUID in the authenticator data.
    pub aaguid: Aaguid<'a>,
    /// The bytes the attestation signature covers: the authenticator data followed by the SHA-256 hash of the
    /// client data JSON.
    pub signed_data: &'a [u8],
}
#[cfg(test)]
mod tests;
