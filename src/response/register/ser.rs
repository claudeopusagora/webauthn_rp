#[cfg(test)]
mod tests;
use super::{
    super::{
        super::request::register::CoseAlgorithmIdentifier,
        ser::{
            AuthenticationExtensionsPrfOutputsHelper, AuthenticationExtensionsPrfValues,
            Base64DecodedVal, ClientExtensions, PublicKeyCredential,
        },
    },
    AttestationObject, AttestedCredentialData, AuthTransports, AuthenticationExtensionsPrfOutputs,
    AuthenticatorAttestation, ClientExtensionsOutputs, CredentialPropertiesOutput, FromCbor as _,
    Registration, UncompressedPubKey,
};
#[cfg(doc)]
use super::{AuthenticatorAttachment, CredentialId};
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
    str,
};
use rsa::sha2::{Sha256, digest::OutputSizeUser as _};
use serde::de::{Deserialize, Deserializer, Error, IgnoredAny, MapAccess, Unexpected, Visitor};
/// Functionality for deserializing DER-encoded `SubjectPublicKeyInfo` _without_ making copies of data or
/// verifying the key is valid. This exists purely to ensure that the public key we receive in JSON is the same as
/// the public key in the attestation object.
mod spki {
    use super::super::{
        Ed25519PubKey, MlDsa44PubKey, MlDsa65PubKey, MlDsa87PubKey, RsaPubKey, RsaPubKeyErr,
        UncompressedP256PubKey, UncompressedP384PubKey, UncompressedPubKey,
    };
    use core::fmt::{self, Display, Formatter};
    use p256::{
        NistP256,
        elliptic_curve::{Curve, common::typenum::type_operators::ToInt as _},
    };
    use p384::NistP384;
    /// Value assigned to the integer type under the universal tag class per
    /// [ITU-T X.680](https://www.itu.int/rec/T-REC-X.680-202102-I/en).
    const INTEGER: u8 = 2;
    /// Value assigned to the bitstring type under the universal tag class per
    /// [ITU-T X.680](https://www.itu.int/rec/T-REC-X.680-202102-I/en).
    const BITSTRING: u8 = 3;
    /// Value assigned to the null type under the universal tag class per
    /// [ITU-T X.680](https://www.itu.int/rec/T-REC-X.680-202102-I/en).
    const NULL: u8 = 5;
    /// Value assigned to the object identifier type under the universal tag class per
    /// [ITU-T X.680](https://www.itu.int/rec/T-REC-X.680-202102-I/en).
    const OID: u8 = 6;
    /// Value assigned to the sequence type under the universal tag class per
    /// [ITU-T X.680](https://www.itu.int/rec/T-REC-X.680-202102-I/en).
    const SEQUENCE: u8 = 16;
    /// Value assigned to a constructed [`SEQUENCE`] per
    /// [ITU-T X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en).
    ///
    /// All sequences are constructed once encoded, so this will likely always be used instead of
    /// `SEQUENCE`.
    const CONSTRUCTED_SEQUENCE: u8 = SEQUENCE | 0b0010_0000;
    /// Length of the header before the encoded key in a DER-encoded ASN.1 `SubjectPublicKeyInfo`
    /// for an ML-DSA-87 public key.
    const MLDSA87_HEADER_LEN: usize = 22;
    /// Length of a DER-encoded ASN.1 `SubjectPublicKeyInfo` for ML-DSA-87 public key.
    const MLDSA87_LEN: usize = MLDSA87_HEADER_LEN + 2592;
    /// Length of the header before the encoded key in a DER-encoded ASN.1 `SubjectPublicKeyInfo`
    /// for an ML-DSA-65 public key.
    const MLDSA65_HEADER_LEN: usize = 22;
    /// Length of a DER-encoded ASN.1 `SubjectPublicKeyInfo` for ML-DSA-65 public key.
    const MLDSA65_LEN: usize = MLDSA65_HEADER_LEN + 1952;
    /// Length of the header before the encoded key in a DER-encoded ASN.1 `SubjectPublicKeyInfo`
    /// for an ML-DSA-44 public key.
    const MLDSA44_HEADER_LEN: usize = 22;
    /// Length of a DER-encoded ASN.1 `SubjectPublicKeyInfo` for ML-DSA-44 public key.
    const MLDSA44_LEN: usize = MLDSA44_HEADER_LEN + 1312;
    /// Length of the header before the compressed y-coordinate in a DER-encoded ASN.1 `SubjectPublicKeyInfo`
    /// for an Ed25519 public key.
    const ED25519_HEADER_LEN: usize = 12;
    /// Length of a DER-encoded ASN.1 `SubjectPublicKeyInfo` for Ed25519 public key.
    const ED25519_LEN: usize = ED25519_HEADER_LEN + ed25519_dalek::PUBLIC_KEY_LENGTH;
    /// `ED25519_LEN` as a `u8`.
    // `44 as u8` is clearly OK.
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "comments above justify their correctness"
    )]
    const ED25519_LEN_U8: u8 = ED25519_LEN as u8;
    /// Length of the header before the uncompressed SEC- 1 pubic key in a DER-encoded ASN.1 `SubjectPublicKeyInfo`
    /// for an uncompressed ECDSA public key based on secp256r1/P-256.
    const P256_HEADER_LEN: usize = 27;
    /// Number of bytes the x-coordinate takes in an uncompressed P-256 public key.
    const P256_X_LEN: usize = <NistP256 as Curve>::FieldBytesSize::INT;
    /// Number of bytes the y-coordinate takes in an uncompressed P-256 public key.
    const P256_Y_LEN: usize = <NistP256 as Curve>::FieldBytesSize::INT;
    /// Number of bytes the x and y coordinates take in an uncompressed P-256 public key when concatenated together.
    const P256_COORD_LEN: usize = P256_X_LEN + P256_Y_LEN;
    /// Length of a DER-encoded ASN.1 `SubjectPublicKeyInfo` for an uncompressed SEC-1 ECDSA public key
    /// based on secp256r1/P-256.
    const P256_LEN: usize = P256_HEADER_LEN + P256_COORD_LEN;
    /// `P256_LEN` as a `u8`.
    // `91 as u8` is clearly OK.
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "comments above justify their correctness"
    )]
    const P256_LEN_U8: u8 = P256_LEN as u8;
    /// Length of the header before the uncompressed SEC- 1 pubic key in a DER-encoded ASN.1 `SubjectPublicKeyInfo`
    /// for an uncompressed ECDSA public key based on secp384r1/P-384.
    const P384_HEADER_LEN: usize = 24;
    /// Number of bytes the x-coordinate takes in an uncompressed P-384 public key.
    const P384_X_LEN: usize = <NistP384 as Curve>::FieldBytesSize::INT;
    /// Number of bytes the y-coordinate takes in an uncompressed P-384 public key.
    const P384_Y_LEN: usize = <NistP384 as Curve>::FieldBytesSize::INT;
    /// Number of bytes the x and y coordinates take in an uncompressed P-384 public key when concatenated together.
    const P384_COORD_LEN: usize = P384_X_LEN + P384_Y_LEN;
    /// Length of a DER-encoded ASN.1 `SubjectPublicKeyInfo` for an uncompressed SEC-1 ECDSA public key
    /// based on secp384r1/P-384.
    const P384_LEN: usize = P384_HEADER_LEN + P384_COORD_LEN;
    /// `P384_LEN` as a `u8`.
    // `120 as u8` is clearly OK.
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "comments above justify their correctness"
    )]
    const P384_LEN_U8: u8 = P384_LEN as u8;
    /// Error returned from [`SubjectPublicKeyInfo::from_der`].
    pub(super) enum SubjectPublicKeyInfoErr {
        /// The length of the DER-encoded ML-DSA-87 key was invalid.
        MlDsa87Len,
        /// The header of the DER-encoded ML-DSA-87 key was invalid.
        MlDsa87Header,
        /// The length of the DER-encoded ML-DSA-65 key was invalid.
        MlDsa65Len,
        /// The header of the DER-encoded ML-DSA-65 key was invalid.
        MlDsa65Header,
        /// The length of the DER-encoded ML-DSA-44 key was invalid.
        MlDsa44Len,
        /// The header of the DER-encoded ML-DSA-44 key was invalid.
        MlDsa44Header,
        /// The length of the DER-encoded Ed25519 key was invalid.
        Ed25519Len,
        /// The header of the DER-encoded Ed25519 key was invalid.
        Ed25519Header,
        /// The length of the DER-encoded P-256 key was invalid.
        P256Len,
        /// The header of the DER-encoded P-256 key was invalid.
        P256Header,
        /// The length of the DER-encoded P-384 key was invalid.
        P384Len,
        /// The header of the DER-encoded P-384 key was invalid.
        P384Header,
        /// The length of the DER-encoded RSA key was invalid.
        RsaLen,
        /// The DER-encoding of the RSA key was invalid.
        RsaEncoding,
        /// The exponent of the DER-encoded RSA key was too large.
        RsaExponentTooLarge,
        /// The DER-encoded RSA key was not a valid [`RsaPubKey`].
        RsaPubKey(RsaPubKeyErr),
    }
    impl Display for SubjectPublicKeyInfoErr {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match *self {
                Self::MlDsa87Len => {
                    f.write_str("length of the DER-encoded ML-DSA-87 key was invalid")
                }
                Self::MlDsa87Header => {
                    f.write_str("header of the DER-encoded ML-DSA-87 key was invalid")
                }
                Self::MlDsa65Len => {
                    f.write_str("length of the DER-encoded ML-DSA-65 key was invalid")
                }
                Self::MlDsa65Header => {
                    f.write_str("header of the DER-encoded ML-DSA-65 key was invalid")
                }
                Self::MlDsa44Len => {
                    f.write_str("length of the DER-encoded ML-DSA-44 key was invalid")
                }
                Self::MlDsa44Header => {
                    f.write_str("header of the DER-encoded ML-DSA-44 key was invalid")
                }
                Self::Ed25519Len => {
                    f.write_str("length of the DER-encoded Ed25519 key was invalid")
                }
                Self::Ed25519Header => {
                    f.write_str("header of the DER-encoded Ed25519 key was invalid")
                }
                Self::P256Len => f.write_str("length of the DER-encoded P-256 key was invalid"),
                Self::P256Header => f.write_str("header of the DER-encoded P-256 key was invalid"),
                Self::P384Len => f.write_str("length of the DER-encoded P-384 key was invalid"),
                Self::P384Header => f.write_str("header of the DER-encoded P-384 key was invalid"),
                Self::RsaLen => f.write_str("length of the DER-encoded RSA key was invalid"),
                Self::RsaEncoding => {
                    f.write_str("the DER-encoding of the RSA public key was invalid")
                }
                Self::RsaExponentTooLarge => {
                    f.write_str("the DER-encoded RSA public key had an exponent that was too large")
                }
                Self::RsaPubKey(err) => {
                    write!(f, "the DER-encoded RSA public was not valid: {err}")
                }
            }
        }
    }
    /// Types that can be deserialized from the DER-encoded ASN.1 `SubjectPublicKeyInfo` as defined in
    /// [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.1) and other applicable RFCs
    /// and documents (e.g., [ITU-T X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en)).
    pub(super) trait SubjectPublicKeyInfo<'a>: Sized {
        /// Transforms the DER-encoded ASN.1 `SubjectPublicKeyInfo` into `Self`.
        ///
        /// # Errors
        ///
        /// Errors iff `der` does not conform.
        #[expect(single_use_lifetimes, reason = "false positive")]
        fn from_der<'b: 'a>(der: &'b [u8]) -> Result<Self, SubjectPublicKeyInfoErr>;
    }
    impl<'a> SubjectPublicKeyInfo<'a> for MlDsa87PubKey<&'a [u8]> {
        #[expect(single_use_lifetimes, reason = "false positive")]
        fn from_der<'b: 'a>(der: &'b [u8]) -> Result<Self, SubjectPublicKeyInfoErr> {
            /// ```asn
            /// SubjectPublicKeyInfo ::= SEQUENCE {
            ///     algorithm           AlgorithmIdentifier,
            ///     subjectPublicKey    BIT STRING
            /// }
            ///
            /// AlgorithmIdentifier ::= SEQUENCE {
            ///     algorithm     OBJECT IDENTIFIER,
            ///     parameters    ANY DEFINED BY algorithm OPTIONAL
            /// }
            /// ```
            ///
            /// [RFC 9882](https://www.rfc-editor.org/rfc/rfc9882.html) requires parameters to not exist
            /// in `AlgorithmIdentifier`.
            ///
            /// RFC 9882 defines the OID as 2.16.840.1.101.3.4.3.19 which is encoded as 96.134.72.1.101.3.4.3.19
            /// per [X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en).
            ///
            /// [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) defines the bitstring as a reinterpretation of the byte string.
            const HEADER: [u8; MLDSA87_HEADER_LEN] = [
                CONSTRUCTED_SEQUENCE,
                130,
                10,
                50,
                CONSTRUCTED_SEQUENCE,
                9 + 2,
                OID,
                9,
                96,
                134,
                72,
                1,
                101,
                3,
                4,
                3,
                19,
                BITSTRING,
                130,
                10,
                33,
                // The number of unused bits.
                0,
            ];
            der.split_at_checked(HEADER.len())
                .ok_or(SubjectPublicKeyInfoErr::MlDsa87Len)
                .and_then(|(header, rem)| {
                    if header == HEADER {
                        if rem.len() == 2592 {
                            Ok(Self(rem))
                        } else {
                            Err(SubjectPublicKeyInfoErr::MlDsa87Len)
                        }
                    } else {
                        Err(SubjectPublicKeyInfoErr::MlDsa87Header)
                    }
                })
        }
    }
    impl<'a> SubjectPublicKeyInfo<'a> for MlDsa65PubKey<&'a [u8]> {
        #[expect(single_use_lifetimes, reason = "false positive")]
        fn from_der<'b: 'a>(der: &'b [u8]) -> Result<Self, SubjectPublicKeyInfoErr> {
            /// ```asn
            /// SubjectPublicKeyInfo ::= SEQUENCE {
            ///     algorithm           AlgorithmIdentifier,
            ///     subjectPublicKey    BIT STRING
            /// }
            ///
            /// AlgorithmIdentifier ::= SEQUENCE {
            ///     algorithm     OBJECT IDENTIFIER,
            ///     parameters    ANY DEFINED BY algorithm OPTIONAL
            /// }
            /// ```
            ///
            /// [RFC 9882](https://www.rfc-editor.org/rfc/rfc9882.html) requires parameters to not exist
            /// in `AlgorithmIdentifier`.
            ///
            /// RFC 9882 defines the OID as 2.16.840.1.101.3.4.3.18 which is encoded as 96.134.72.1.101.3.4.3.18
            /// per [X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en).
            ///
            /// [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) defines the bitstring as a reinterpretation of the byte string.
            const HEADER: [u8; MLDSA65_HEADER_LEN] = [
                CONSTRUCTED_SEQUENCE,
                130,
                7,
                178,
                CONSTRUCTED_SEQUENCE,
                9 + 2,
                OID,
                9,
                96,
                134,
                72,
                1,
                101,
                3,
                4,
                3,
                18,
                BITSTRING,
                130,
                7,
                161,
                // The number of unused bits.
                0,
            ];
            der.split_at_checked(HEADER.len())
                .ok_or(SubjectPublicKeyInfoErr::MlDsa65Len)
                .and_then(|(header, rem)| {
                    if header == HEADER {
                        if rem.len() == 1952 {
                            Ok(Self(rem))
                        } else {
                            Err(SubjectPublicKeyInfoErr::MlDsa65Len)
                        }
                    } else {
                        Err(SubjectPublicKeyInfoErr::MlDsa65Header)
                    }
                })
        }
    }
    impl<'a> SubjectPublicKeyInfo<'a> for MlDsa44PubKey<&'a [u8]> {
        #[expect(single_use_lifetimes, reason = "false positive")]
        fn from_der<'b: 'a>(der: &'b [u8]) -> Result<Self, SubjectPublicKeyInfoErr> {
            /// ```asn
            /// SubjectPublicKeyInfo ::= SEQUENCE {
            ///     algorithm           AlgorithmIdentifier,
            ///     subjectPublicKey    BIT STRING
            /// }
            ///
            /// AlgorithmIdentifier ::= SEQUENCE {
            ///     algorithm     OBJECT IDENTIFIER,
            ///     parameters    ANY DEFINED BY algorithm OPTIONAL
            /// }
            /// ```
            ///
            /// [RFC 9882](https://www.rfc-editor.org/rfc/rfc9882.html) requires parameters to not exist
            /// in `AlgorithmIdentifier`.
            ///
            /// RFC 9882 defines the OID as 2.16.840.1.101.3.4.3.17 which is encoded as 96.134.72.1.101.3.4.3.17
            /// per [X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en).
            ///
            /// [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) defines the bitstring as a reinterpretation of the byte string.
            const HEADER: [u8; MLDSA44_HEADER_LEN] = [
                CONSTRUCTED_SEQUENCE,
                130,
                5,
                50,
                CONSTRUCTED_SEQUENCE,
                9 + 2,
                OID,
                9,
                96,
                134,
                72,
                1,
                101,
                3,
                4,
                3,
                17,
                BITSTRING,
                130,
                5,
                33,
                // The number of unused bits.
                0,
            ];
            der.split_at_checked(HEADER.len())
                .ok_or(SubjectPublicKeyInfoErr::MlDsa44Len)
                .and_then(|(header, rem)| {
                    if header == HEADER {
                        if rem.len() == 1312 {
                            Ok(Self(rem))
                        } else {
                            Err(SubjectPublicKeyInfoErr::MlDsa44Len)
                        }
                    } else {
                        Err(SubjectPublicKeyInfoErr::MlDsa44Header)
                    }
                })
        }
    }
    impl<'a> SubjectPublicKeyInfo<'a> for Ed25519PubKey<&'a [u8]> {
        #[expect(single_use_lifetimes, reason = "false positive")]
        fn from_der<'b: 'a>(der: &'b [u8]) -> Result<Self, SubjectPublicKeyInfoErr> {
            /// ```asn
            /// SubjectPublicKeyInfo ::= SEQUENCE {
            ///     algorithm           AlgorithmIdentifier,
            ///     subjectPublicKey    BIT STRING
            /// }
            ///
            /// AlgorithmIdentifier ::= SEQUENCE {
            ///     algorithm     OBJECT IDENTIFIER,
            ///     parameters    ANY DEFINED BY algorithm OPTIONAL
            /// }
            /// ```
            ///
            /// [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410#section-3) requires parameters to not exist
            /// in `AlgorithmIdentifier`.
            ///
            /// RFC 8410 defines the OID as 1.3.101.112 which is encoded as 43.101.112
            /// per [X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en).
            ///
            /// RFC 8410 defines the bitstring as a reinterpretation of the byte string.
            const HEADER: [u8; ED25519_HEADER_LEN] = [
                CONSTRUCTED_SEQUENCE,
                // `ED25519_LEN_U8` is the length of the entire payload; thus we subtract
                // the "consumed" length.
                ED25519_LEN_U8 - 2,
                CONSTRUCTED_SEQUENCE,
                // AlgorithmIdentifier only contains the OID; thus it's length is 5.
                3 + 2,
                OID,
                3,
                43,
                101,
                112,
                BITSTRING,
                // `ED25519_LEN_U8` is the length of the entire payload; thus we subtract
                // the "consumed" length.
                ED25519_LEN_U8 - 11,
                // The number of unused bits.
                0,
            ];
            der.split_at_checked(HEADER.len())
                .ok_or(SubjectPublicKeyInfoErr::Ed25519Len)
                .and_then(|(header, rem)| {
                    if header == HEADER {
                        if rem.len() == ed25519_dalek::PUBLIC_KEY_LENGTH {
                            Ok(Self(rem))
                        } else {
                            Err(SubjectPublicKeyInfoErr::Ed25519Len)
                        }
                    } else {
                        Err(SubjectPublicKeyInfoErr::Ed25519Header)
                    }
                })
        }
    }
    impl<'a> SubjectPublicKeyInfo<'a> for UncompressedP256PubKey<'a> {
        #[expect(single_use_lifetimes, reason = "false positive")]
        fn from_der<'b: 'a>(der: &'b [u8]) -> Result<Self, SubjectPublicKeyInfoErr> {
            // ```asn
            // SubjectPublicKeyInfo ::= SEQUENCE {
            //     algorithm           AlgorithmIdentifier,
            //     subjectPublicKey    BIT STRING
            // }
            //
            // AlgorithmIdentifier ::= SEQUENCE {
            //     algorithm     OBJECT IDENTIFIER,
            //     parameters    ANY DEFINED BY algorithm OPTIONAL
            // }
            //
            // ECParameters ::= CHOICE {
            //     namedCurve         OBJECT IDENTIFIER
            //     -- implicitCurve   NULL
            //     -- specifiedCurve  SpecifiedECDomain
            // }
            // ```
            // [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1) requires parameters to exist and
            // be of the `ECParameters` form with the requirement that `namedCurve` is chosen.
            //
            // RFC 5480 defines the OID for id-ecPublicKey as 1.2.840.10045.2.1 and the OID for the namedCurve
            // secp256r1 as 1.2.840.10045.3.1.7. The former OID is encoded as 42.134.72.206.61.2.1 and the latter
            // is encoded as 42.134.72.206.61.3.1.7 per [X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en).
            //
            // [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480#section-5) only requires support for the
            // uncompressed form and only states that the compressed form MAY be supported. In practice this means
            // DER-encoded payloads almost always are of the uncompressed form for compatibility reasons. This in
            // conjunction with the fact the COSE key is required to be in the uncompressed form means we only support
            // DER-encoded payloads containing uncompressed keys.
            //
            // [SEC 1](https://secg.org/sec1-v2.pdf) defines the point as an octet string, and the conversion
            // to a bitstring simply requires reinterpreting the octet string as a bitstring.

            /// Header of the DER-encoded payload before the public key.
            const HEADER: [u8; P256_HEADER_LEN] = [
                CONSTRUCTED_SEQUENCE,
                // `P256_LEN_U8` is the length of the entire payload; thus we subtract
                // the "consumed" length.
                P256_LEN_U8 - 2,
                CONSTRUCTED_SEQUENCE,
                7 + 2 + 8 + 2,
                OID,
                7,
                42,
                134,
                72,
                206,
                61,
                2,
                1,
                OID,
                8,
                42,
                134,
                72,
                206,
                61,
                3,
                1,
                7,
                BITSTRING,
                // `P256_LEN_U8` is the length of the entire payload; thus we subtract
                // the "consumed" length.
                P256_LEN_U8 - 25,
                // The number of unused bits.
                0,
                // SEC-1 tag for an uncompressed key.
                4,
            ];
            der.split_at_checked(HEADER.len())
                .ok_or(SubjectPublicKeyInfoErr::P256Len)
                .and_then(|(header, header_rem)| {
                    if header == HEADER {
                        header_rem
                            .split_at_checked(P256_X_LEN)
                            .ok_or(SubjectPublicKeyInfoErr::P256Len)
                            .and_then(|(x, y)| {
                                if y.len() == P256_Y_LEN {
                                    Ok(Self(x, y))
                                } else {
                                    Err(SubjectPublicKeyInfoErr::P256Len)
                                }
                            })
                    } else {
                        Err(SubjectPublicKeyInfoErr::P256Header)
                    }
                })
        }
    }
    impl<'a> SubjectPublicKeyInfo<'a> for UncompressedP384PubKey<'a> {
        #[expect(single_use_lifetimes, reason = "false positive")]
        fn from_der<'b: 'a>(der: &'b [u8]) -> Result<Self, SubjectPublicKeyInfoErr> {
            // ```asn
            // SubjectPublicKeyInfo ::= SEQUENCE {
            //     algorithm           AlgorithmIdentifier,
            //     subjectPublicKey    BIT STRING
            // }
            //
            // AlgorithmIdentifier ::= SEQUENCE {
            //     algorithm     OBJECT IDENTIFIER,
            //     parameters    ANY DEFINED BY algorithm OPTIONAL
            // }
            //
            // ECParameters ::= CHOICE {
            //     namedCurve         OBJECT IDENTIFIER
            //     -- implicitCurve   NULL
            //     -- specifiedCurve  SpecifiedECDomain
            // }
            // ```
            // [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1) requires parameters to exist and
            // be of the `ECParameters` form with the requirement that `namedCurve` is chosen.
            //
            // RFC 5480 defines the OID for id-ecPublicKey as 1.2.840.10045.2.1 and the OID for the namedCurve
            // secp384r1 as 1.3.132.0.34. The former OID is encoded as 42.134.72.206.61.2.1 and the latter
            // is encoded as 43.129.4.0.34 per [X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en).
            //
            // [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480#section-5) only requires support for the
            // uncompressed form and only states that the compressed form MAY be supported. In practice this means
            // DER-encoded payloads almost always are of the uncompressed form for compatibility reasons. This in
            // conjunction with the fact the COSE key is required to be in the uncompressed form means we only support
            // DER-encoded payloads containing uncompressed keys.
            //
            // [SEC 1](https://secg.org/sec1-v2.pdf) defines the point as an octet string, and the conversion
            // to a bitstring simply requires reinterpreting the octet string as a bitstring.

            /// Header of the DER-encoded payload before the public key.
            const HEADER: [u8; P384_HEADER_LEN] = [
                CONSTRUCTED_SEQUENCE,
                // `P384_LEN_U8` is the length of the entire payload; thus we subtract
                // the "consumed" length.
                P384_LEN_U8 - 2,
                CONSTRUCTED_SEQUENCE,
                7 + 2 + 5 + 2,
                OID,
                7,
                42,
                134,
                72,
                206,
                61,
                2,
                1,
                OID,
                5,
                43,
                129,
                4,
                0,
                34,
                BITSTRING,
                // `P384_LEN_U8` is the length of the entire payload; thus we subtract
                // the "consumed" length.
                P384_LEN_U8 - 22,
                // The number of unused bits.
                0,
                // SEC-1 tag for an uncompressed key.
                4,
            ];
            der.split_at_checked(HEADER.len())
                .ok_or(SubjectPublicKeyInfoErr::P384Len)
                .and_then(|(header, header_rem)| {
                    if header == HEADER {
                        header_rem
                            .split_at_checked(P384_X_LEN)
                            .ok_or(SubjectPublicKeyInfoErr::P384Len)
                            .and_then(|(x, y)| {
                                if y.len() == P384_Y_LEN {
                                    Ok(Self(x, y))
                                } else {
                                    Err(SubjectPublicKeyInfoErr::P384Len)
                                }
                            })
                    } else {
                        Err(SubjectPublicKeyInfoErr::P384Header)
                    }
                })
        }
    }
    impl<'a> SubjectPublicKeyInfo<'a> for RsaPubKey<&'a [u8]> {
        #[expect(single_use_lifetimes, reason = "false positive")]
        #[expect(
            clippy::arithmetic_side_effects,
            clippy::big_endian_bytes,
            clippy::indexing_slicing,
            clippy::missing_asserts_for_indexing,
            reason = "comments justify their correctness"
        )]
        #[expect(
            clippy::too_many_lines,
            reason = "rsa keys are the only type that would benefit from a modular SubjectPublicKeyInfo (similar to FromCbor). if more types benefit in the future, then this will be done."
        )]
        fn from_der<'b: 'a>(der: &'b [u8]) -> Result<Self, SubjectPublicKeyInfoErr> {
            // ```asn
            // SubjectPublicKeyInfo ::= SEQUENCE {
            //     algorithm           AlgorithmIdentifier,
            //     subjectPublicKey    BIT STRING
            // }
            //
            // AlgorithmIdentifier ::= SEQUENCE {
            //     algorithm     OBJECT IDENTIFIER,
            //     parameters    ANY DEFINED BY algorithm OPTIONAL
            // }
            //
            // RSAPublicKey ::= SEQUENCE {
            //     modulus          INTEGER, -- n
            //     publicExponent   INTEGER  --e
            // }
            //
            // pkcs-1 OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
            //     rsadsi(113549) pkcs(1) 1
            // }
            //
            // rsaEncryption OBJECT IDENTIFIER ::= { pkcs-1 1}
            // ```
            // [RFC 3279](https://www.rfc-editor.org/rfc/rfc3279#section-2.3.1) requires parameters to exist and
            // be null.
            //
            // RFC 3279 defines the OID for rsaEncryption as 1.2.840.113549.1.1.1 which is encoded as
            // 42.134.72.134.247.13.1.1.1 per [X.690](https://www.itu.int/rec/T-REC-X.690-202102-I/en).
            //
            // Note we only allow moduli that are 256 to 2048 bytes in length inclusively. Additionally
            // we only allow `u32` exponents; consequently all lengths that include the modulus will always be
            // encoded with two bytes.

            /// `AlgorithmIdentifier` header including the `BITSTRING` and number of bytes the length
            /// is encoded in of the `BITSTRING` type of `subjectPublicKey`
            /// (130-128 = 2 bytes to encode the length).
            const ALG_OID_HEADER: [u8; 17] = [
                CONSTRUCTED_SEQUENCE,
                9 + 2 + 2,
                OID,
                9,
                42,
                134,
                72,
                134,
                247,
                13,
                1,
                1,
                1,
                NULL,
                0,
                BITSTRING,
                130,
            ];
            /// `CONSTRUCTED_SEQUENCE` whose length is encoded in two bytes.
            const SEQ_LONG: [u8; 2] = [CONSTRUCTED_SEQUENCE, 130];
            /// `INTEGER` whose length is encoded in two bytes.
            const INT_LONG: [u8; 2] = [INTEGER, 130];
            der.split_at_checked(SEQ_LONG.len())
                .ok_or(SubjectPublicKeyInfoErr::RsaLen)
                .and_then(|(seq, seq_rem)| {
                    if seq == SEQ_LONG {
                        seq_rem
                            .split_at_checked(2)
                            .ok_or(SubjectPublicKeyInfoErr::RsaLen)
                            .and_then(|(seq_len, seq_len_rem)| {
                                let mut len = [0; 2];
                                len.copy_from_slice(seq_len);
                                let rem_len = usize::from(u16::from_be_bytes(len));
                                if rem_len == seq_len_rem.len() {
                                    if rem_len > 255 {
                                        // We can safely split here since we know `seq_len_rem` is at least
                                        // 256 which is greater than `ALG_OID_HEADER.len()`.
                                        let (a_oid, a_oid_rem) = seq_len_rem.split_at(ALG_OID_HEADER.len());
                                        if a_oid == ALG_OID_HEADER {
                                            // `a_oid_rem.len()` is at least 239, so splitting is fine.
                                            let (bit_str_len_enc, bit_str_val) = a_oid_rem.split_at(2);
                                            let mut bit_string_len = [0; 2];
                                            bit_string_len.copy_from_slice(bit_str_len_enc);
                                            let bit_str_val_len = usize::from(u16::from_be_bytes(bit_string_len));
                                            if bit_str_val_len == bit_str_val.len() {
                                                if bit_str_val_len > 255 {
                                                    // `bit_str_val.len() > 255`, so splitting is fine.
                                                    let (unused_bits, bits_rem) = bit_str_val.split_at(1);
                                                    if unused_bits == [0] {
                                                        // We can safely split here since we know `bits_rem.len()` is at least
                                                        // 255.
                                                        let (rsa_seq, rsa_seq_rem) = bits_rem.split_at(SEQ_LONG.len());
                                                        if rsa_seq == SEQ_LONG {
                                                            // `rsa_seq_rem.len()` is at least 253, so splitting is fine.
                                                            let (rsa_seq_len_enc, rsa_seq_len_enc_rem) = rsa_seq_rem.split_at(2);
                                                            let mut rsa_seq_len = [0; 2];
                                                            rsa_seq_len.copy_from_slice(rsa_seq_len_enc);
                                                            let rsa_key_info_len = usize::from(u16::from_be_bytes(rsa_seq_len));
                                                            if rsa_key_info_len == rsa_seq_len_enc_rem.len() {
                                                                if rsa_key_info_len > 255 {
                                                                    // We can safely split here since we know `rsa_seq_len_enc_rem.len()`
                                                                    // is at least 256.
                                                                    let (n_meta, n_meta_rem) = rsa_seq_len_enc_rem.split_at(INT_LONG.len());
                                                                    if n_meta == INT_LONG {
                                                                        // `n_meta_rem.len()` is at least 254, so splitting is fine.
                                                                        let (n_len_enc, n_len_enc_rem) = n_meta_rem.split_at(2);
                                                                        let mut n_len = [0; 2];
                                                                        n_len.copy_from_slice(n_len_enc);
                                                                        let mod_len = usize::from(u16::from_be_bytes(n_len));
                                                                        if mod_len > 255 {
                                                                            n_len_enc_rem.split_at_checked(mod_len).ok_or(SubjectPublicKeyInfoErr::RsaLen).and_then(|(mut n, n_rem)| {
                                                                                // `n.len() > 255`, so indexing is fine.
                                                                                let n_first = n[0];
                                                                                // DER integers are signed; thus the most significant bit must be 0.
                                                                                // DER integers are minimally encoded; thus when a leading 0 exists,
                                                                                // the second byte must be at least 128.
                                                                                // `n.len() > 255`, so indexing is fine.
                                                                                if n_first < 128 && (n_first != 0 || n[1] > 127) {
                                                                                    if n_first == 0 {
                                                                                        // `n.len() > 255`, so indexing is fine.
                                                                                        // We must remove the leading 0.
                                                                                        n = &n[1..];
                                                                                    }
                                                                                    n_rem.split_first().ok_or(SubjectPublicKeyInfoErr::RsaLen).and_then(|(e_type, e_type_rem)| {
                                                                                        if *e_type == INTEGER {
                                                                                            e_type_rem.split_first().ok_or(SubjectPublicKeyInfoErr::RsaLen).and_then(|(e_len, e_len_rem)| {
                                                                                                let e_len_usize = usize::from(*e_len);
                                                                                                if e_len_usize == e_len_rem.len() {
                                                                                                    e_len_rem.first().ok_or(SubjectPublicKeyInfoErr::RsaLen).and_then(|&e_first| {
                                                                                                        // DER integers are signed; thus the most significant bit must be 0.
                                                                                                        if e_first < 128 {
                                                                                                            // `RsaPubKey` only allows `u32` exponents, which means we only care
                                                                                                            // about lengths up to 5.
                                                                                                            match e_len_usize {
                                                                                                                1 => Ok(u32::from(e_first)),
                                                                                                                2..=5 => if e_first == 0 {
                                                                                                                    // DER integers are minimally encoded; thus when a leading
                                                                                                                    // 0 exists, the second byte must be at least 128.
                                                                                                                    // We know the length is at least 2; thus this won't `panic`.
                                                                                                                    if e_len_rem[1] > 127 {
                                                                                                                        let mut e = [0; 4];
                                                                                                                        if e_len_usize == 5 {
                                                                                                                            // We know the length is at least 2; thus this won't `panic`.
                                                                                                                            e.copy_from_slice(&e_len_rem[1..]);
                                                                                                                        } else {
                                                                                                                            // `e.len() == 4` and `e_len_usize` is at most 4; thus underflow
                                                                                                                            // won't occur nor will indexing `panic`. `e` is big-endian,
                                                                                                                            // so we start from the right.
                                                                                                                            e[4 - e_len_usize..].copy_from_slice(e_len_rem);
                                                                                                                        }
                                                                                                                        Ok(u32::from_be_bytes(e))
                                                                                                                    } else {
                                                                                                                        Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                                                                                    }
                                                                                                                } else if e_len_usize == 5 {
                                                                                                                    // 5 bytes are only possible for `INTEGER`s that
                                                                                                                    // are greater than `i32::MAX`, which will be encoded
                                                                                                                    // with a leading 0.
                                                                                                                    Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                                                                                } else {
                                                                                                                    let mut e = [0; 4];
                                                                                                                    // `e.len() == 4` and `e_len_usize` is at most 4; thus underflow
                                                                                                                    // won't occur nor will indexing `panic`. `e` is big-endian,
                                                                                                                    // so we start from the right.
                                                                                                                    e[4 - e_len_usize..].copy_from_slice(e_len_rem);
                                                                                                                    Ok(u32::from_be_bytes(e))
                                                                                                                },
                                                                                                                _ => Err(SubjectPublicKeyInfoErr::RsaExponentTooLarge),
                                                                                                            }.and_then(|e| Self::try_from((n, e)).map_err(SubjectPublicKeyInfoErr::RsaPubKey))
                                                                                                        } else {
                                                                                                            Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                                                                        }
                                                                                                    })
                                                                                                } else {
                                                                                                    Err(SubjectPublicKeyInfoErr::RsaLen)
                                                                                                }
                                                                                            })
                                                                                        } else {
                                                                                            Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                                                        }
                                                                                    })
                                                                                } else {
                                                                                    Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                                                }
                                                                            })
                                                                        } else {
                                                                            Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                                        }
                                                                    } else {
                                                                        Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                                    }
                                                                } else {
                                                                    Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                                }
                                                            } else {
                                                                Err(SubjectPublicKeyInfoErr::RsaLen)
                                                            }
                                                        } else {
                                                            Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                        }
                                                    } else {
                                                        Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                    }
                                                } else {
                                                    Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                                }
                                            } else {
                                                Err(SubjectPublicKeyInfoErr::RsaLen)
                                            }
                                        } else {
                                            Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                        }
                                    } else {
                                        Err(SubjectPublicKeyInfoErr::RsaEncoding)
                                    }
                                } else {
                                    Err(SubjectPublicKeyInfoErr::RsaLen)
                                }
                            })
                    } else {
                        Err(SubjectPublicKeyInfoErr::RsaEncoding)
                    }
                })
        }
    }
    impl<'a> SubjectPublicKeyInfo<'a> for UncompressedPubKey<'a> {
        #[expect(clippy::indexing_slicing, reason = "comments justify correctness")]
        #[expect(single_use_lifetimes, reason = "false positive")]
        fn from_der<'b: 'a>(der: &'b [u8]) -> Result<Self, SubjectPublicKeyInfoErr> {
            /// Index in a DER-encoded payload of the ML-DSA-* public key that corresponds
            /// to the OID length.
            const ML_DSA_OID_LEN_IDX: usize = 5;
            /// Length of the OID for the DER-encoded ML-DSA-* public keys.
            ///
            /// Note this is _not_ the same as the OID length for an RSA public key (i.e., 13).
            const ML_DSA_OID_LEN: u8 = 11;
            // The only lengths that overlap is RSA with ML-DSA-44 and ML-DSA-65.
            match der.len() {
                // The minimum modulus we support for RSA is 2048 bits which is 256 bytes;
                // thus clearly its encoding will be at least 256 which is greater than
                // all of the non-ML-DSA-* values and less than the ML-DSA-* values.
                // The maximum modulus we support for RSA is 16K bits which is 2048 bytes and the maximum
                // exponent we support for RSA is 4 bytes which is hundreds of bytes less than 2614
                // (i.e., the length of a DER-encoded ML-DSAS-87 public key).
                ED25519_LEN => Ed25519PubKey::from_der(der).map(Self::Ed25519),
                P256_LEN => UncompressedP256PubKey::from_der(der).map(Self::P256),
                P384_LEN => UncompressedP384PubKey::from_der(der).map(Self::P384),
                MLDSA44_LEN => {
                    // `ML_DSA_OID_LEN_IDX < MLDSA44_LEN = der.len()` so indexing
                    // won't `panic`.
                    if der[ML_DSA_OID_LEN_IDX] == ML_DSA_OID_LEN {
                        MlDsa44PubKey::from_der(der).map(Self::MlDsa44)
                    } else {
                        RsaPubKey::from_der(der).map(Self::Rsa)
                    }
                }
                MLDSA65_LEN => {
                    // `ML_DSA_OID_LEN_IDX < MLDSA65_LEN = der.len()` so indexing
                    // won't `panic`.
                    if der[ML_DSA_OID_LEN_IDX] == ML_DSA_OID_LEN {
                        MlDsa65PubKey::from_der(der).map(Self::MlDsa65)
                    } else {
                        RsaPubKey::from_der(der).map(Self::Rsa)
                    }
                }
                MLDSA87_LEN => MlDsa87PubKey::from_der(der).map(Self::MlDsa87),
                _ => RsaPubKey::from_der(der).map(Self::Rsa),
            }
        }
    }
}
/// Helper type returned from [`AuthenticatorAttestationVisitor::visit_map`].
///
/// The purpose of this type is to hopefully avoid re-parsing the raw attestation object multiple times. In
/// particular [`Registration`] and [`super::ser_relaxed::RegistrationRelaxed`] will attempt to validate `id` is the
/// same as the [`CredentialId`] within the attestation object.
pub(super) struct AuthAttest {
    /// The data we care about.
    pub attest: AuthenticatorAttestation,
    /// [`CredentialId`] information. This is `None` iff `authenticatorData`, `publicKey`, and
    /// `publicKeyAlgorithm` do not exist and we are performing a `RELAXED` parsing. When `Some`, the first
    /// `usize` is the starting index of `CredentialId` within the attestation object; and the second `usize` is
    /// 1 past the last index of `CredentialId`.
    pub cred_info: Option<(usize, usize)>,
}
/// Fields in `AuthenticatorAttestationResponseJSON`.
enum AttestField<const IGNORE_UNKNOWN: bool> {
    /// `clientDataJSON`.
    ClientDataJson,
    /// `attestationObject`.
    AttestationObject,
    /// `authenticatorData`.
    AuthenticatorData,
    /// `transports`.
    Transports,
    /// `publicKey`.
    PublicKey,
    /// `publicKeyAlgorithm`.
    PublicKeyAlgorithm,
    /// Unknown fields.
    Other,
}
impl<'e, const I: bool> Deserialize<'e> for AttestField<I> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'e>,
    {
        /// `Visitor` for `AttestField`.
        struct AttestFieldVisitor<const IGNORE_UNKNOWN: bool>;
        impl<const IG: bool> Visitor<'_> for AttestFieldVisitor<IG> {
            type Value = AttestField<IG>;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "'{CLIENT_DATA_JSON}', '{ATTESTATION_OBJECT}', '{AUTHENTICATOR_DATA}', '{TRANSPORTS}', '{PUBLIC_KEY}', or '{PUBLIC_KEY_ALGORITHM}'"
                )
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                match v {
                    CLIENT_DATA_JSON => Ok(AttestField::ClientDataJson),
                    ATTESTATION_OBJECT => Ok(AttestField::AttestationObject),
                    AUTHENTICATOR_DATA => Ok(AttestField::AuthenticatorData),
                    TRANSPORTS => Ok(AttestField::Transports),
                    PUBLIC_KEY => Ok(AttestField::PublicKey),
                    PUBLIC_KEY_ALGORITHM => Ok(AttestField::PublicKeyAlgorithm),
                    _ => {
                        if IG {
                            Ok(AttestField::Other)
                        } else {
                            Err(E::unknown_field(v, AUTH_ATTEST_FIELDS))
                        }
                    }
                }
            }
        }
        deserializer.deserialize_identifier(AttestFieldVisitor::<I>)
    }
}
/// Attestation object. We use this instead of `Base64DecodedVal` since we want to manually
/// allocate the `Vec` in order to avoid re-allocation. Internally `AuthenticatorAttestation::new`
/// appends the SHA-256 hash to the passed attestation object `Vec` to avoid temporarily allocating
/// a `Vec` that contains the attestation object and hash for signature verification. Calling code
/// can avoid any reallocation that would occur when the capacity is not large enough by ensuring the
/// passed `Vec` has at least 32 bytes of available capacity.
pub(super) struct AttObj(pub Vec<u8>);
impl<'e> Deserialize<'e> for AttObj {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'e>,
    {
        /// `Visitor` for `AttObj`.
        struct AttObjVisitor;
        impl Visitor<'_> for AttObjVisitor {
            type Value = AttObj;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("base64url-encoded attestation object")
            }
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "comment justifies their correctness"
            )]
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                base64url_nopad::decode_len(v.len())
                    .ok_or_else(|| E::invalid_value(Unexpected::Str(v), &"base64url-encoded value"))
                    .and_then(|len| {
                        // The decoded length is 3/4 of the encoded length, so overflow could only occur
                        // if usize::MAX / 4 < 32 => usize::MAX < 128 < u8::MAX; thus overflow is not
                        // possible. We add 32 since the SHA-256 hash of `clientDataJSON` will be added to
                        // the raw attestation object by `AuthenticatorAttestation::new`.
                        let mut att_obj = vec![0; len + Sha256::output_size()];
                        att_obj.truncate(len);
                        base64url_nopad::decode_buffer_exact(v.as_bytes(), &mut att_obj)
                            .map_err(E::custom)
                            .map(|()| AttObj(att_obj))
                    })
            }
        }
        deserializer.deserialize_str(AttObjVisitor)
    }
}
/// `Visitor` for `AuthenticatorAttestation`.
///
/// Unknown fields are ignored and only `clientDataJSON` and `attestationObject` are required iff `RELAXED`.
pub(super) struct AuthenticatorAttestationVisitor<const RELAXED: bool>;
impl<'d, const R: bool> Visitor<'d> for AuthenticatorAttestationVisitor<R> {
    type Value = AuthAttest;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthenticatorAttestation")
    }
    #[expect(clippy::too_many_lines, reason = "find it easier to reason about")]
    #[expect(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "comments justify their correctness"
    )]
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'d>,
    {
        use spki::SubjectPublicKeyInfo as _;
        let mut client_data = None;
        let mut attest = None;
        let mut auth = None;
        let mut pub_key = None;
        let mut key_alg = None;
        let mut trans = None;
        while let Some(key) = map.next_key::<AttestField<R>>()? {
            match key {
                AttestField::ClientDataJson => {
                    if client_data.is_some() {
                        return Err(Error::duplicate_field(CLIENT_DATA_JSON));
                    }
                    client_data = map
                        .next_value::<Base64DecodedVal>()
                        .map(|c_data| Some(c_data.0))?;
                }
                AttestField::AttestationObject => {
                    if attest.is_some() {
                        return Err(Error::duplicate_field(ATTESTATION_OBJECT));
                    }
                    attest = map.next_value::<AttObj>().map(|att_obj| Some(att_obj.0))?;
                }
                AttestField::AuthenticatorData => {
                    if auth.is_some() {
                        return Err(Error::duplicate_field(AUTHENTICATOR_DATA));
                    }
                    auth = map.next_value::<Option<Base64DecodedVal>>().map(Some)?;
                }
                AttestField::Transports => {
                    if trans.is_some() {
                        return Err(Error::duplicate_field(TRANSPORTS));
                    }
                    trans = map.next_value::<Option<_>>().map(Some)?;
                }
                AttestField::PublicKey => {
                    if pub_key.is_some() {
                        return Err(Error::duplicate_field(PUBLIC_KEY));
                    }
                    pub_key = map.next_value::<Option<Base64DecodedVal>>().map(Some)?;
                }
                AttestField::PublicKeyAlgorithm => {
                    if key_alg.is_some() {
                        return Err(Error::duplicate_field(PUBLIC_KEY_ALGORITHM));
                    }
                    key_alg = map
                        .next_value::<Option<CoseAlgorithmIdentifier>>()
                        .map(Some)?;
                }
                AttestField::Other => map.next_value::<IgnoredAny>().map(|_| ())?,
            }
        }
        // Note the order of this matters from a performance perspective. In particular `auth` must be evaluated
        // before `pub_key` which must be evaluated before `key_alg` as this allows us to parse the attestation
        // object at most once and allow us to prioritize parsing `authenticatorData` over the attestation object.
        client_data.ok_or_else(|| Error::missing_field(CLIENT_DATA_JSON)).and_then(|client_data_json| attest.ok_or_else(|| Error::missing_field(ATTESTATION_OBJECT)).and_then(|attestation_object| {
            trans.ok_or(false).and_then(|opt_trans| opt_trans.ok_or(true)).or_else(
                |flag| {
                    if R {
                        Ok(AuthTransports::new())
                    } else if flag {
                        Err(Error::invalid_type(Unexpected::Other("null"), &format!("{TRANSPORTS} to be a sequence of AuthenticatorTransports").as_str()))
                    } else {
                        Err(Error::missing_field(TRANSPORTS))
                    }
                },
            ).and_then(|transports| {
                auth.ok_or(false).and_then(|opt_auth| opt_auth.ok_or(true)).as_ref().map_or_else(
                    |flag| {
                        if R {
                            Ok(None)
                        } else if *flag {
                            Err(Error::invalid_type(Unexpected::Other("null"), &format!("{AUTHENTICATOR_DATA} to be a base64url-encoded AuthenticatorData").as_str()))
                        } else {
                            Err(Error::missing_field(AUTHENTICATOR_DATA))
                        }
                    },
                    |a_data| {
                        if a_data.0.len() > 37 {
                            // The last portion of attestation object is always authenticator data.
                            attestation_object.len().checked_sub(a_data.0.len()).ok_or_else(|| Error::invalid_value(Unexpected::Bytes(a_data.0.as_slice()), &format!("authenticator data to match the authenticator data portion of attestation object: {attestation_object:?}").as_str())).and_then(|idx| {
                                // Indexing is fine; otherwise the above check would have returned `None`.
                                if *a_data.0 == attestation_object[idx..] {
                                    // We know `a_data.len() > 37`; thus indexing is fine.
                                    // We start at 37 since that is the beginning of `attestedCredentialData`.
                                    // Recall the first 32 bytes are `rpIdHash`, then a 1 byte `flags`, then a
                                    // 4-byte big-endian integer `signCount`.
                                    // The starting index of `credentialId` is 18 within `attestedCredentialData`.
                                    // Recall the first 16 bytes are `aaguid`, then a 2-byte big-endian integer
                                    // `credentialIdLength`. Consequently the starting index within
                                    // `attestation_object` is `idx + 37 + 18` = `idx + 55`. Overflow cannot occur
                                    // since we successfully parsed `AttestedCredentialData`.
                                    AttestedCredentialData::from_cbor(&a_data.0[37..]).map_err(Error::custom).map(|success| Some((success.value, idx + 55)))
                                } else {
                                    Err(Error::invalid_value(Unexpected::Bytes(a_data.0.as_slice()), &format!("authenticator data to match the authenticator data portion of attestation object: {:?}", &attestation_object[idx..]).as_str()))
                                }
                            })
                        } else {
                            Err(Error::invalid_value(Unexpected::Bytes(a_data.0.as_slice()), &"authenticator data to be long enough to contain attested credential data"))
                        }
                    }
                ).and_then(|attested_info| {
                    pub_key.ok_or(false).and_then(|opt_key| opt_key.ok_or(true)).map_or_else(
                        |flag| {
                            if R {
                                attested_info.as_ref().map_or(Ok(None), |&(ref attested_data, cred_id_start)| Ok(Some((match attested_data.credential_public_key {
                                    UncompressedPubKey::MlDsa87(_) => CoseAlgorithmIdentifier::Mldsa87,
                                    UncompressedPubKey::MlDsa65(_) => CoseAlgorithmIdentifier::Mldsa65,
                                    UncompressedPubKey::MlDsa44(_) => CoseAlgorithmIdentifier::Mldsa44,
                                    UncompressedPubKey::Ed25519(_) => CoseAlgorithmIdentifier::Eddsa,
                                    UncompressedPubKey::P256(_) => CoseAlgorithmIdentifier::Es256,
                                    UncompressedPubKey::P384(_) => CoseAlgorithmIdentifier::Es384,
                                    UncompressedPubKey::Rsa(_) => CoseAlgorithmIdentifier::Rs256,
                                    // Overflow won't occur since this is correct as
                                    // `AttestedCredentialData::from_cbor` would have erred if not.
                                }, cred_id_start, cred_id_start + attested_data.credential_id.0.len()))))
                            } else {
                                // `publicKey` is only allowed to not exist when `CoseAlgorithmIdentifier::Eddsa`,
                                // `CoseAlgorithmIdentifier::Es256`, or `CoseAlgorithmIdentifier::Rs256` is not
                                // used.
                                attested_info.as_ref().map_or_else(
                                    || AttestationObject::parse_data(attestation_object.as_slice()).map_err(Error::custom).and_then(|(att_obj, auth_idx)| {
                                        match att_obj.auth_data.attested_credential_data.credential_public_key {
                                            UncompressedPubKey::MlDsa87(_) => {
                                                // This won't overflow since `AttestationObject::parse_data` succeeded and `auth_idx`
                                                // is the start of the raw authenticator data which itself contains the raw Credential ID.
                                                Ok(Some((CoseAlgorithmIdentifier::Mldsa87, auth_idx,  auth_idx + att_obj.auth_data.attested_credential_data.credential_id.0.len())))
                                            }
                                            UncompressedPubKey::MlDsa65(_) => {
                                                // This won't overflow since `AttestationObject::parse_data` succeeded and `auth_idx`
                                                // is the start of the raw authenticator data which itself contains the raw Credential ID.
                                                Ok(Some((CoseAlgorithmIdentifier::Mldsa65, auth_idx,  auth_idx + att_obj.auth_data.attested_credential_data.credential_id.0.len())))
                                            }
                                            UncompressedPubKey::MlDsa44(_) => {
                                                // This won't overflow since `AttestationObject::parse_data` succeeded and `auth_idx`
                                                // is the start of the raw authenticator data which itself contains the raw Credential ID.
                                                Ok(Some((CoseAlgorithmIdentifier::Mldsa44, auth_idx,  auth_idx + att_obj.auth_data.attested_credential_data.credential_id.0.len())))
                                            }
                                            UncompressedPubKey::P384(_) => {
                                                // This won't overflow since `AttestationObject::parse_data` succeeded and `auth_idx`
                                                // is the start of the raw authenticator data which itself contains the raw Credential ID.
                                                Ok(Some((CoseAlgorithmIdentifier::Es384, auth_idx,  auth_idx + att_obj.auth_data.attested_credential_data.credential_id.0.len())))
                                            }
                                            UncompressedPubKey::Ed25519(_) | UncompressedPubKey::P256(_) | UncompressedPubKey::Rsa(_) => Err(Error::missing_field(PUBLIC_KEY)),
                                        }
                                    }),
                                    |&(ref attested_data, cred_id_start)| {
                                        match attested_data.credential_public_key {
                                            UncompressedPubKey::MlDsa87(_) => {
                                                // Overflow won't occur since this is correct. This is correct since we successfully parsed
                                                // `AttestedCredentialData` and calculated `cred_id_start` from it.
                                                Ok(Some((CoseAlgorithmIdentifier::Mldsa87, cred_id_start, cred_id_start + attested_data.credential_id.0.len())))
                                            }
                                            UncompressedPubKey::MlDsa65(_) => {
                                                // Overflow won't occur since this is correct. This is correct since we successfully parsed
                                                // `AttestedCredentialData` and calculated `cred_id_start` from it.
                                                Ok(Some((CoseAlgorithmIdentifier::Mldsa65, cred_id_start, cred_id_start + attested_data.credential_id.0.len())))
                                            }
                                            UncompressedPubKey::MlDsa44(_) => {
                                                // Overflow won't occur since this is correct. This is correct since we successfully parsed
                                                // `AttestedCredentialData` and calculated `cred_id_start` from it.
                                                Ok(Some((CoseAlgorithmIdentifier::Mldsa44, cred_id_start, cred_id_start + attested_data.credential_id.0.len())))
                                            }
                                            UncompressedPubKey::P384(_) => {
                                                // Overflow won't occur since this is correct. This is correct since we successfully parsed
                                                // `AttestedCredentialData` and calculated `cred_id_start` from it.
                                                Ok(Some((CoseAlgorithmIdentifier::Es384, cred_id_start, cred_id_start + attested_data.credential_id.0.len())))
                                            }
                                            UncompressedPubKey::Ed25519(_) | UncompressedPubKey::P256(_) | UncompressedPubKey::Rsa(_) => if flag { Err(Error::invalid_type(Unexpected::Other("null"), &format!("{PUBLIC_KEY} to be a base64url-encoded DER-encoded SubjectPublicKeyInfo").as_str())) } else { Err(Error::missing_field(PUBLIC_KEY)) },
                                        }
                                    }
                                )
                            }
                        },
                        |der| {
                            UncompressedPubKey::from_der(der.0.as_slice()).map_err(Error::custom).and_then(|key| {
                                attested_info.as_ref().map_or_else(
                                    || AttestationObject::parse_data(attestation_object.as_slice()).map_err(Error::custom).and_then(|(att_obj, auth_idx)| {
                                        if key == att_obj.auth_data.attested_credential_data.credential_public_key {
                                            let alg = match att_obj.auth_data.attested_credential_data.credential_public_key {
                                                UncompressedPubKey::MlDsa87(_) => CoseAlgorithmIdentifier::Mldsa87,
                                                UncompressedPubKey::MlDsa65(_) => CoseAlgorithmIdentifier::Mldsa65,
                                                UncompressedPubKey::MlDsa44(_) => CoseAlgorithmIdentifier::Mldsa44,
                                                UncompressedPubKey::Ed25519(_) => CoseAlgorithmIdentifier::Eddsa,
                                                UncompressedPubKey::P256(_) => CoseAlgorithmIdentifier::Es256,
                                                UncompressedPubKey::P384(_) => CoseAlgorithmIdentifier::Es384,
                                                UncompressedPubKey::Rsa(_) => CoseAlgorithmIdentifier::Rs256,
                                            };
                                            // This won't overflow since `AttestationObject::parse_data` succeeded and `auth_idx`
                                            // is the start of the raw authenticator data which itself contains the raw Credential ID.
                                            Ok(Some((alg, auth_idx, auth_idx+ att_obj.auth_data.attested_credential_data.credential_id.0.len())))
                                        } else {
                                            Err(Error::invalid_value(Unexpected::Bytes(der.0.as_slice()), &format!("DER-encoded public key to match the public key within the attestation object: {:?}", att_obj.auth_data.attested_credential_data.credential_public_key).as_str()))
                                        }
                                    }),
                                    |&(ref attested_data, cred_id_start)| {
                                        if key == attested_data.credential_public_key {
                                            let alg = match attested_data.credential_public_key {
                                                UncompressedPubKey::MlDsa87(_) => CoseAlgorithmIdentifier::Mldsa87,
                                                UncompressedPubKey::MlDsa65(_) => CoseAlgorithmIdentifier::Mldsa65,
                                                UncompressedPubKey::MlDsa44(_) => CoseAlgorithmIdentifier::Mldsa44,
                                                UncompressedPubKey::Ed25519(_) => CoseAlgorithmIdentifier::Eddsa,
                                                UncompressedPubKey::P256(_) => CoseAlgorithmIdentifier::Es256,
                                                UncompressedPubKey::P384(_) => CoseAlgorithmIdentifier::Es384,
                                                UncompressedPubKey::Rsa(_) => CoseAlgorithmIdentifier::Rs256,
                                            };
                                            // Overflow won't occur since this is correct. This is correct since we successfully parsed
                                            // `AttestedCredentialData` and calculated `cred_id_start` from it.
                                            Ok(Some((alg, cred_id_start, cred_id_start + attested_data.credential_id.0.len())))
                                        } else {
                                            Err(Error::invalid_value(Unexpected::Bytes(der.0.as_slice()), &format!("DER-encoded public key to match the public key within the attestation object: {:?}", attested_data.credential_public_key).as_str()))
                                        }
                                    }
                                )
                            })
                        }
                    ).and_then(|cred_key_alg_cred_info| {
                        key_alg.ok_or(false).and_then(|opt_alg| opt_alg.ok_or(true)).map_or_else(
                            |flag| {
                                if R {
                                    Ok(cred_key_alg_cred_info.map(|info| (info.1, info.2)))
                                } else if flag {
                                    Err(Error::invalid_type(Unexpected::Other("null"), &format!("{PUBLIC_KEY_ALGORITHM} to be a base64url-encoded DER-encoded SubjectPublicKeyInfo").as_str()))
                                } else {
                                    Err(Error::missing_field(PUBLIC_KEY_ALGORITHM))
                                }
                            },
                            |alg| {
                                cred_key_alg_cred_info.map_or_else(
                                    || AttestationObject::parse_data(attestation_object.as_slice()).map_err(Error::custom).and_then(|(att_obj, auth_idx)| {
                                        let att_obj_alg = match att_obj.auth_data.attested_credential_data.credential_public_key {
                                            UncompressedPubKey::MlDsa87(_) => CoseAlgorithmIdentifier::Mldsa87,
                                            UncompressedPubKey::MlDsa65(_) => CoseAlgorithmIdentifier::Mldsa65,
                                            UncompressedPubKey::MlDsa44(_) => CoseAlgorithmIdentifier::Mldsa44,
                                            UncompressedPubKey::Ed25519(_) => CoseAlgorithmIdentifier::Eddsa,
                                            UncompressedPubKey::P256(_) => CoseAlgorithmIdentifier::Es256,
                                            UncompressedPubKey::P384(_) => CoseAlgorithmIdentifier::Es384,
                                            UncompressedPubKey::Rsa(_) => CoseAlgorithmIdentifier::Rs256,
                                        };
                                        if alg == att_obj_alg {
                                            // This won't overflow since `AttestationObject::parse_data` succeeded and `auth_idx`
                                            // is the start of the raw authenticator data which itself contains the raw Credential ID.
                                            Ok(Some((auth_idx, auth_idx + att_obj.auth_data.attested_credential_data.credential_id.0.len())))
                                        } else {
                                            Err(Error::invalid_value(Unexpected::Other(format!("{alg:?}").as_str()), &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {att_obj_alg:?}").as_str()))
                                        }
                                    }),
                                    |(a, start, last)| if alg == a {
                                        Ok(Some((start, last)))
                                    } else {
                                        Err(Error::invalid_value(Unexpected::Other(format!("{alg:?}").as_str()), &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {a:?}").as_str()))
                                    },
                                )
                            }
                        ).map(|cred_info| AuthAttest{ attest: AuthenticatorAttestation::new(client_data_json, attestation_object, transports), cred_info, })
                    })
                })
            })
        }))
    }
}
/// `"clientDataJSON"`
const CLIENT_DATA_JSON: &str = "clientDataJSON";
/// `"attestationObject"`
const ATTESTATION_OBJECT: &str = "attestationObject";
/// `"authenticatorData"`
const AUTHENTICATOR_DATA: &str = "authenticatorData";
/// `"transports"`
const TRANSPORTS: &str = "transports";
/// `"publicKey"`
const PUBLIC_KEY: &str = "publicKey";
/// `"publicKeyAlgorithm"`
const PUBLIC_KEY_ALGORITHM: &str = "publicKeyAlgorithm";
/// Fields in `AuthenticatorAttestationResponseJSON`.
pub(super) const AUTH_ATTEST_FIELDS: &[&str; 6] = &[
    CLIENT_DATA_JSON,
    ATTESTATION_OBJECT,
    AUTHENTICATOR_DATA,
    TRANSPORTS,
    PUBLIC_KEY,
    PUBLIC_KEY_ALGORITHM,
];
impl<'de> Deserialize<'de> for AuthAttest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "AuthenticatorAttestation",
            AUTH_ATTEST_FIELDS,
            AuthenticatorAttestationVisitor::<false>,
        )
    }
}
impl<'de> Deserialize<'de> for AuthenticatorAttestation {
    /// Deserializes a `struct` based on
    /// [`AuthenticatorAttestationResponseJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorattestationresponsejson).
    ///
    /// Note unknown keys and duplicate keys are forbidden;
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-clientdatajson),
    /// [`authenticatorData`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-authenticatordata),
    /// [`publicKey`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-publickey)
    /// and
    /// [`attestationObject`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-attestationobject)
    /// are base64url-decoded;
    /// [`transports`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-transports)
    /// is deserialized via [`AuthTransports::deserialize`]; the decoded `publicKey` is parsed according to the
    /// applicable DER-encoded ASN.1 `SubjectPublicKeyInfo` schema;
    /// [`publicKeyAlgorithm`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-publickeyalgorithm)
    /// is deserialized according to
    /// [`CoseAlgorithmIdentifier`](https://www.w3.org/TR/webauthn-3/#typedefdef-cosealgorithmidentifier); all `required`
    /// fields in the `AuthenticatorAttestationResponseJSON` Web IDL `dictionary` exist (and must not be `null`); `publicKey`
    /// exists when Ed25519, P-256 with SHA-256, or RSASSA-PKCS1-v1_5 with SHA-256 is used (and must not be `null`)
    /// [per WebAuthn](https://www.w3.org/TR/webauthn-3/#sctn-public-key-easy); the `publicKeyAlgorithm` aligns
    /// with
    /// [`credentialPublicKey`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata-credentialpublickey)
    /// within
    /// [`attestedCredentialData`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata) within the
    /// decoded `authenticatorData`; the decoded `publicKey` is the same as `credentialPublicKey` within
    /// `attestedCredentialData` within the decoded `authenticatorData`; and the decoded `authenticatorData` is the
    /// same as [`authData`](https://www.w3.org/TR/webauthn-3/#attestation-object) within the decoded
    /// `attestationObject`.
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        AuthAttest::deserialize(deserializer).map(|val| val.attest)
    }
}
/// `Visitor` for `CredentialPropertiesOutput`.
///
/// Unknown fields are ignored iff `RELAXED`.
pub(super) struct CredentialPropertiesOutputVisitor<const RELAXED: bool>;
impl<'d, const R: bool> Visitor<'d> for CredentialPropertiesOutputVisitor<R> {
    type Value = CredentialPropertiesOutput;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialPropertiesOutput")
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'d>,
    {
        /// Allowed fields.
        enum Field<const IGNORE_UNKNOWN: bool> {
            /// `rk` field.
            Rk,
            /// Unknown field.
            Other,
        }
        impl<'e, const I: bool> Deserialize<'e> for Field<I> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'e>,
            {
                /// `Visitor` for `Field`.
                ///
                /// Unknown fields are ignored iff `IGNORE_UNKNOWN`.
                struct FieldVisitor<const IGNORE_UNKNOWN: bool>;
                impl<const IG: bool> Visitor<'_> for FieldVisitor<IG> {
                    type Value = Field<IG>;
                    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                        write!(formatter, "'{RK}'")
                    }
                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            RK => Ok(Field::Rk),
                            _ => {
                                if IG {
                                    Ok(Field::Other)
                                } else {
                                    Err(E::unknown_field(v, PROPS_FIELDS))
                                }
                            }
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }
        let mut rk = None;
        while let Some(key) = map.next_key::<Field<R>>()? {
            match key {
                Field::Rk => {
                    if rk.is_some() {
                        return Err(Error::duplicate_field(RK));
                    }
                    rk = map.next_value().map(Some)?;
                }
                Field::Other => map.next_value::<IgnoredAny>().map(|_| ())?,
            }
        }
        Ok(CredentialPropertiesOutput { rk: rk.flatten() })
    }
}
/// `"rk"`
const RK: &str = "rk";
/// `CredentialPropertiesOutput` fields.
pub(super) const PROPS_FIELDS: &[&str; 1] = &[RK];
impl<'de> Deserialize<'de> for CredentialPropertiesOutput {
    /// Deserializes a `struct` based on
    /// [`CredentialPropertiesOutput`](https://www.w3.org/TR/webauthn-3/#dictdef-credentialpropertiesoutput).
    ///
    /// Note unknown and duplicate keys are forbidden.
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "CredentialPropertiesOutput",
            PROPS_FIELDS,
            CredentialPropertiesOutputVisitor::<false>,
        )
    }
}
impl<'de> Deserialize<'de> for AuthenticationExtensionsPrfOutputs {
    /// Deserializes a `struct` based on
    /// [`AuthenticationExtensionsPRFOutputsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfoutputsjson).
    ///
    /// Note unknown and duplicate keys are forbidden;
    /// [`enabled`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-enabled)
    /// must exist (and not be `null`); and
    /// [`results`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-results) must not exist,
    /// be `null`, or be an
    /// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues)
    /// with no unknown or duplicate keys,
    /// [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first) must exist but be
    /// `null`, and
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second) can exist but
    /// must be `null` if so.
    #[inline]
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        AuthenticationExtensionsPrfOutputsHelper::<false, true, AuthenticationExtensionsPrfValues>::deserialize(deserializer).map(|val| Self {
            enabled: val.0.unwrap_or_else(|| {
                unreachable!(
                    "there is a bug in AuthenticationExtensionsPrfOutputsHelper::deserialize"
                )
            }),
        })
    }
}
/// `Visitor` for `ClientExtensionsOutputs`.
///
/// Unknown fields are ignored iff `RELAXED`.
pub(super) struct ClientExtensionsOutputsVisitor<const RELAXED: bool, PROPS, PRF>(
    pub PhantomData<fn() -> (PROPS, PRF)>,
);
impl<'d, const R: bool, C, P> Visitor<'d> for ClientExtensionsOutputsVisitor<R, C, P>
where
    C: for<'a> Deserialize<'a> + Into<CredentialPropertiesOutput>,
    P: for<'a> Deserialize<'a> + Into<AuthenticationExtensionsPrfOutputs>,
{
    type Value = ClientExtensionsOutputs;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientExtensionsOutputs")
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'d>,
    {
        /// Allowed fields.
        enum Field<const IGNORE_UNKNOWN: bool> {
            /// `credProps` field.
            CredProps,
            /// `prf` field.
            Prf,
            /// Unknown field.
            Other,
        }
        impl<'e, const I: bool> Deserialize<'e> for Field<I> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'e>,
            {
                /// `Visitor` for `Field`.
                ///
                /// Unknown fields are ignored iff `IGNORE_UNKNOWN`.
                struct FieldVisitor<const IGNORE_UNKNOWN: bool>;
                impl<const IG: bool> Visitor<'_> for FieldVisitor<IG> {
                    type Value = Field<IG>;
                    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                        write!(formatter, "'{CRED_PROPS}' or '{PRF}'")
                    }
                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            CRED_PROPS => Ok(Field::CredProps),
                            PRF => Ok(Field::Prf),
                            _ => {
                                if IG {
                                    Ok(Field::Other)
                                } else {
                                    Err(E::unknown_field(v, EXT_FIELDS))
                                }
                            }
                        }
                    }
                }
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }
        let mut cred_props = None;
        let mut prf = None;
        while let Some(key) = map.next_key::<Field<R>>()? {
            match key {
                Field::CredProps => {
                    if cred_props.is_some() {
                        return Err(Error::duplicate_field(CRED_PROPS));
                    }
                    cred_props = map.next_value::<Option<C>>().map(Some)?;
                }
                Field::Prf => {
                    if prf.is_some() {
                        return Err(Error::duplicate_field(PRF));
                    }
                    prf = map.next_value::<Option<P>>().map(Some)?;
                }
                Field::Other => map.next_value::<IgnoredAny>().map(|_| ())?,
            }
        }
        Ok(ClientExtensionsOutputs {
            cred_props: cred_props.flatten().map(Into::into),
            prf: prf.flatten().map(Into::into),
        })
    }
}
impl ClientExtensions for ClientExtensionsOutputs {
    fn empty() -> Self {
        Self {
            prf: None,
            cred_props: None,
        }
    }
}
/// `"credProps"`
const CRED_PROPS: &str = "credProps";
/// `"prf"`
const PRF: &str = "prf";
/// `AuthenticationExtensionsClientOutputsJSON` fields.
pub(super) const EXT_FIELDS: &[&str; 2] = &[CRED_PROPS, PRF];
impl<'de> Deserialize<'de> for ClientExtensionsOutputs {
    /// Deserializes a `struct` based on
    /// [`AuthenticationExtensionsClientOutputsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientoutputsjson).
    ///
    /// Note that unknown and duplicate keys are forbidden;
    /// [`credProps`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsclientoutputs-credprops) is
    /// `null` or deserialized via [`CredentialPropertiesOutput::deserialize`]; and
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsclientoutputs-prf) is `null`
    /// or deserialized via [`AuthenticationExtensionsPrfOutputs::deserialize`].
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "ClientExtensionsOutputs",
            EXT_FIELDS,
            ClientExtensionsOutputsVisitor::<
                false,
                CredentialPropertiesOutput,
                AuthenticationExtensionsPrfOutputs,
            >(PhantomData),
        )
    }
}
impl<'de> Deserialize<'de> for Registration {
    /// Deserializes a `struct` based on
    /// [`RegistrationResponseJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson).
    ///
    /// Note that unknown and duplicate keys are forbidden;
    /// [`id`](https://www.w3.org/TR/webauthn-3/#dom-registrationresponsejson-id) and
    /// [`rawId`](https://www.w3.org/TR/webauthn-3/#dom-registrationresponsejson-rawid) are deserialized
    /// via [`CredentialId::deserialize`];
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-registrationresponsejson-response) is deserialized
    /// via [`AuthenticatorAttestation::deserialize`];
    /// [`authenticatorAttachment`](https://www.w3.org/TR/webauthn-3/#dom-registrationresponsejson-authenticatorattachment)
    /// is `null` or deserialized via [`AuthenticatorAttachment::deserialize`];
    /// [`clientExtensionResults`](https://www.w3.org/TR/webauthn-3/#dom-registrationresponsejson-clientextensionresults)
    /// is deserialized via [`ClientExtensionsOutputs::deserialize`]; all `required` fields in the
    /// `RegistrationResponseJSON` Web IDL `dictionary` exist (and are not `null`);
    /// [`type`](https://www.w3.org/TR/webauthn-3/#dom-registrationresponsejson-type) is `"public-key"`;
    /// and the decoded `id`, decoded `rawId`, and
    /// [`credentialId`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata-credentialid) within
    /// [`attestedCredentialData`](https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata) within
    /// [`authData`](https://www.w3.org/TR/webauthn-3/#attestation-object) within the decoded
    /// [`attestationObject`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-attestationobject)
    /// are all the same.
    #[expect(clippy::unreachable, reason = "when there is a bug, we want to crash")]
    #[expect(clippy::indexing_slicing, reason = "comment justifies its correctness")]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        PublicKeyCredential::<false, true, AuthAttest, ClientExtensionsOutputs>::deserialize(deserializer).and_then(|cred| {
            let id = cred.id.unwrap_or_else(|| unreachable!("there is a bug in PublicKeyCredential::deserialize"));
            cred.response.cred_info.map_or_else(
                || AttestationObject::try_from(cred.response.attest.attestation_object()).map_err(Error::custom).and_then(|att_obj| {
                    if id.as_ref() == att_obj.auth_data.attested_credential_data.credential_id.as_ref() {
                        Ok(())
                    } else {
                        Err(Error::invalid_value(Unexpected::Bytes(id.as_ref()), &format!("id, rawId, and the credential id in the attested credential data to all match: {:?}", att_obj.auth_data.attested_credential_data.credential_id.0).as_str()))
                    }
                }),
                // `start` and `last` were calculated based on `cred.response.attest.attestation_object()`
                // and represent the starting and ending index of the `CredentialId`; therefore this is correct
                // let alone won't `panic`.
                |(start, last)| if *id.0 == cred.response.attest.attestation_object()[start..last] {
                    Ok(())
                } else {
                    Err(Error::invalid_value(Unexpected::Bytes(id.as_ref()), &format!("id, rawId, and the credential id in the attested credential data to all match: {:?}", &cred.response.attest.attestation_object()[start..last]).as_str()))
                },
            ).map(|()| Self { response: cred.response.attest, authenticator_attachment: cred.authenticator_attachment, client_extension_results: cred.client_extension_results, })
        })
    }
}
