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
        Ed25519PubKey, RsaPubKey, RsaPubKeyErr, UncompressedP256PubKey, UncompressedP384PubKey,
        UncompressedPubKey,
    };
    use core::fmt::{self, Display, Formatter};
    use p256::{
        NistP256,
        elliptic_curve::{Curve, generic_array::typenum::type_operators::ToInt as _},
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
        /// The DER-encoded `SubjectPublicKeyInfo` had an invalid length.
        Len,
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
                Self::Len => {
                    f.write_str("the DER-encoded SubjectPublicKeyInfo had an invalid length")
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
        #[expect(single_use_lifetimes, reason = "false positive")]
        fn from_der<'b: 'a>(der: &'b [u8]) -> Result<Self, SubjectPublicKeyInfoErr> {
            // The lengths of the three key types do not overlap.
            match der.len() {
                // The minimum modulus we support for RSA is 2048 bits which is 256 bytes;
                // thus clearly its encoding will be at least 256 which is greater than
                // all of the other values.
                ED25519_LEN => Ed25519PubKey::from_der(der).map(Self::Ed25519),
                P256_LEN => UncompressedP256PubKey::from_der(der).map(Self::P256),
                P384_LEN => UncompressedP384PubKey::from_der(der).map(Self::P384),
                256.. => RsaPubKey::from_der(der).map(Self::Rsa),
                _ => Err(SubjectPublicKeyInfoErr::Len),
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
                    if id == att_obj.auth_data.attested_credential_data.credential_id {
                        Ok(())
                    } else {
                        Err(Error::invalid_value(Unexpected::Bytes(id.as_ref()), &format!("id, rawId, and the credential id in the attested credential data to all match: {:?}", att_obj.auth_data.attested_credential_data.credential_id.0).as_str()))
                    }
                }),
                // `start` and `last` were calculated based on `cred.response.attest.attestation_object()`
                // and represent the starting and ending index of the `CredentialId`; therefore this is correct
                // let alone won't `panic`.
                |(start, last)| if id.0 == cred.response.attest.attestation_object()[start..last] {
                    Ok(())
                } else {
                    Err(Error::invalid_value(Unexpected::Bytes(id.as_ref()), &format!("id, rawId, and the credential id in the attested credential data to all match: {:?}", &cred.response.attest.attestation_object()[start..last]).as_str()))
                },
            ).map(|()| Self { response: cred.response.attest, authenticator_attachment: cred.authenticator_attachment, client_extension_results: cred.client_extension_results, })
        })
    }
}
#[cfg(test)]
mod tests {
    use super::{
        super::{
            ALG, AuthenticatorAttachment, EC2, EDDSA, ES256, ES384, Ed25519PubKey, KTY, OKP, RSA,
            Registration, RsaPubKey, UncompressedP256PubKey, UncompressedP384PubKey, cbor,
        },
        CoseAlgorithmIdentifier,
        spki::SubjectPublicKeyInfo,
    };
    use ed25519_dalek::{VerifyingKey, pkcs8::EncodePublicKey};
    use p256::{
        EncodedPoint as P256Pt, PublicKey as P256PubKey, SecretKey as P256Key,
        elliptic_curve::sec1::{FromEncodedPoint as _, ToEncodedPoint as _},
    };
    use p384::{EncodedPoint as P384Pt, PublicKey as P384PubKey, SecretKey as P384Key};
    use rsa::{
        BigUint, RsaPrivateKey,
        sha2::{Digest as _, Sha256},
        traits::PublicKeyParts,
    };
    use serde::de::{Error as _, Unexpected};
    use serde_json::Error;
    #[test]
    fn ed25519_spki() {
        assert!(
            Ed25519PubKey::from_der(
                VerifyingKey::from_bytes(&[1; 32])
                    .unwrap()
                    .to_public_key_der()
                    .unwrap()
                    .as_bytes()
            )
            .map_or(false, |k| k.0 == [1; 32])
        );
    }
    #[test]
    fn p256_spki() {
        let key = P256Key::from_bytes(
            &[
                137, 133, 36, 206, 163, 47, 255, 5, 76, 144, 163, 141, 40, 109, 108, 240, 246, 115,
                178, 237, 169, 68, 6, 129, 92, 21, 238, 127, 55, 158, 207, 95,
            ]
            .into(),
        )
        .unwrap()
        .public_key();
        let enc_key = key.to_encoded_point(false);
        assert!(
            UncompressedP256PubKey::from_der(key.to_public_key_der().unwrap().as_bytes()).map_or(
                false,
                |k| k.0 == enc_key.x().unwrap().as_slice()
                    && k.1 == enc_key.y().unwrap().as_slice()
            )
        );
    }
    #[test]
    fn p384_spki() {
        let key = P384Key::from_bytes(
            &[
                158, 99, 156, 49, 190, 211, 85, 167, 28, 2, 80, 57, 31, 22, 17, 38, 85, 78, 232,
                42, 45, 199, 154, 243, 136, 251, 84, 34, 5, 120, 208, 91, 61, 248, 64, 144, 87, 1,
                32, 86, 220, 68, 182, 11, 105, 223, 75, 70,
            ]
            .into(),
        )
        .unwrap()
        .public_key();
        let enc_key = key.to_encoded_point(false);
        assert!(
            UncompressedP384PubKey::from_der(key.to_public_key_der().unwrap().as_bytes()).map_or(
                false,
                |k| k.0 == enc_key.x().unwrap().as_slice()
                    && k.1 == enc_key.y().unwrap().as_slice()
            )
        );
    }
    #[test]
    fn rsa_spki() {
        let n = [
            111, 183, 124, 133, 38, 167, 70, 148, 44, 50, 30, 60, 121, 14, 38, 37, 96, 114, 107,
            195, 248, 64, 79, 36, 237, 140, 43, 27, 94, 74, 102, 152, 135, 102, 184, 150, 186, 206,
            185, 19, 165, 209, 48, 98, 98, 9, 3, 205, 208, 82, 250, 105, 132, 201, 73, 62, 60, 165,
            100, 128, 153, 9, 41, 118, 66, 95, 236, 214, 73, 135, 197, 68, 184, 10, 27, 116, 204,
            145, 50, 174, 58, 42, 183, 181, 119, 232, 126, 252, 217, 96, 162, 190, 103, 122, 64,
            87, 145, 45, 32, 207, 17, 239, 223, 3, 35, 14, 112, 119, 124, 141, 123, 208, 239, 105,
            81, 217, 151, 162, 190, 17, 88, 182, 176, 158, 81, 200, 42, 166, 133, 48, 23, 236, 55,
            117, 248, 233, 151, 203, 122, 155, 231, 46, 177, 20, 20, 151, 64, 222, 239, 226, 7, 21,
            254, 81, 202, 64, 232, 161, 235, 22, 51, 246, 207, 213, 0, 229, 138, 46, 222, 205, 157,
            108, 139, 253, 230, 80, 50, 2, 122, 212, 163, 100, 180, 114, 12, 113, 52, 56, 99, 188,
            42, 198, 212, 23, 182, 222, 56, 221, 200, 79, 96, 239, 221, 135, 10, 17, 106, 183, 56,
            104, 68, 94, 198, 196, 35, 200, 83, 204, 26, 185, 204, 212, 31, 183, 19, 111, 233, 13,
            72, 93, 53, 65, 111, 59, 242, 122, 160, 244, 162, 126, 38, 235, 156, 47, 88, 39, 132,
            153, 79, 0, 133, 78, 7, 218, 165, 241,
        ];
        let e = 65537u32;
        let d = [
            145, 79, 21, 97, 233, 3, 192, 194, 177, 68, 181, 80, 120, 197, 23, 44, 185, 74, 144, 0,
            132, 149, 139, 11, 16, 224, 4, 112, 236, 94, 238, 97, 121, 124, 213, 145, 24, 253, 168,
            35, 190, 205, 132, 115, 33, 201, 38, 253, 246, 180, 66, 155, 165, 46, 3, 254, 68, 108,
            154, 247, 246, 45, 187, 0, 204, 96, 185, 157, 249, 174, 158, 38, 62, 244, 183, 76, 102,
            6, 219, 92, 212, 138, 59, 147, 163, 219, 111, 39, 105, 21, 236, 196, 38, 255, 114, 247,
            82, 104, 113, 204, 29, 152, 209, 219, 48, 239, 74, 129, 19, 247, 33, 239, 119, 166,
            216, 152, 94, 138, 238, 164, 242, 129, 50, 150, 57, 20, 53, 224, 56, 241, 138, 97, 111,
            215, 107, 212, 195, 146, 108, 143, 0, 229, 181, 171, 73, 152, 105, 146, 25, 243, 242,
            140, 252, 248, 162, 247, 63, 168, 180, 20, 153, 120, 10, 248, 211, 1, 71, 127, 212,
            249, 237, 203, 202, 48, 26, 216, 226, 228, 186, 13, 204, 70, 255, 240, 89, 255, 59, 83,
            31, 253, 55, 43, 158, 90, 248, 83, 32, 159, 105, 57, 134, 34, 96, 18, 255, 245, 153,
            162, 60, 91, 99, 220, 51, 44, 85, 114, 67, 125, 202, 65, 217, 245, 40, 8, 81, 165, 142,
            24, 245, 127, 122, 247, 152, 212, 75, 45, 59, 90, 184, 234, 31, 147, 36, 8, 212, 45,
            50, 23, 3, 25, 253, 87, 227, 79, 119, 161,
        ];
        let p = BigUint::from_bytes_le(
            [
                215, 166, 5, 21, 11, 179, 41, 77, 198, 92, 165, 48, 77, 162, 42, 41, 206, 141, 60,
                69, 47, 164, 19, 92, 46, 72, 100, 238, 100, 53, 214, 197, 163, 185, 6, 140, 229,
                250, 195, 77, 8, 12, 5, 236, 178, 173, 86, 201, 43, 213, 165, 51, 108, 101, 161,
                99, 76, 240, 14, 234, 76, 197, 137, 53, 198, 168, 135, 205, 212, 198, 120, 29, 16,
                82, 98, 233, 236, 177, 12, 171, 141, 100, 107, 146, 33, 176, 125, 202, 172, 79,
                147, 179, 30, 62, 247, 206, 169, 19, 168, 114, 26, 73, 108, 178, 105, 84, 89, 191,
                168, 253, 228, 214, 54, 16, 212, 199, 111, 72, 3, 41, 247, 227, 165, 244, 32, 188,
                24, 247,
            ]
            .as_slice(),
        );
        let p_2 = BigUint::from_bytes_le(
            [
                41, 25, 198, 240, 134, 206, 121, 57, 11, 5, 134, 192, 212, 77, 229, 197, 14, 78,
                85, 212, 190, 114, 179, 188, 21, 171, 174, 12, 104, 74, 15, 164, 136, 173, 62, 177,
                141, 213, 93, 102, 147, 83, 59, 124, 146, 59, 175, 213, 55, 27, 25, 248, 154, 29,
                39, 85, 50, 235, 134, 60, 203, 106, 186, 195, 190, 185, 71, 169, 142, 236, 92, 11,
                250, 187, 198, 8, 201, 184, 120, 178, 227, 87, 63, 243, 89, 227, 234, 184, 28, 252,
                112, 211, 193, 69, 23, 92, 5, 72, 93, 53, 69, 159, 73, 160, 105, 244, 249, 94, 214,
                173, 9, 236, 4, 255, 129, 11, 224, 140, 252, 168, 57, 143, 176, 241, 60, 219, 90,
                250,
            ]
            .as_slice(),
        );
        let key = RsaPrivateKey::from_components(
            BigUint::from_bytes_le(n.as_slice()),
            e.into(),
            BigUint::from_bytes_le(d.as_slice()),
            vec![p, p_2],
        )
        .unwrap()
        .to_public_key();
        assert!(
            RsaPubKey::from_der(key.to_public_key_der().unwrap().as_bytes())
                .map_or(false, |k| k.0 == key.n().to_bytes_be()
                    && BigUint::from(k.1) == *key.e())
        );
    }
    #[test]
    fn eddsa_registration_deserialize_data_mismatch() {
        let c_data_json = serde_json::json!({}).to_string();
        let att_obj = [
            cbor::MAP_3,
            cbor::TEXT_3,
            b'f',
            b'm',
            b't',
            cbor::TEXT_4,
            b'n',
            b'o',
            b'n',
            b'e',
            cbor::TEXT_7,
            b'a',
            b't',
            b't',
            b'S',
            b't',
            b'm',
            b't',
            cbor::MAP_0,
            cbor::TEXT_8,
            b'a',
            b'u',
            b't',
            b'h',
            b'D',
            b'a',
            b't',
            b'a',
            cbor::BYTES_INFO_24,
            115,
            // `rpIdHash`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `flags`.
            0b0100_0101,
            // `signCount`.
            0,
            0,
            0,
            0,
            // `aaguid`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `credentialIdLength`.
            0,
            16,
            // `credentialId`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // Ed25519 COSE key.
            cbor::MAP_4,
            KTY,
            OKP,
            ALG,
            EDDSA,
            // `crv`.
            cbor::NEG_ONE,
            // `Ed25519`.
            cbor::SIX,
            // `x`.
            cbor::NEG_TWO,
            cbor::BYTES_INFO_24,
            32,
            // Compressed y-coordinate.
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
        ];
        let pub_key = VerifyingKey::from_bytes(&[1; 32])
            .unwrap()
            .to_public_key_der()
            .unwrap();
        let b64_cdata = base64url_nopad::encode(c_data_json.as_bytes());
        let b64_adata = base64url_nopad::encode(&att_obj[att_obj.len() - 113..]);
        let b64_key = base64url_nopad::encode(pub_key.as_bytes());
        let b64_aobj = base64url_nopad::encode(att_obj.as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": ["ble", "usb", "hybrid", "internal", "nfc", "smart-card"],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "authenticatorAttachment": "cross-platform",
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.response.client_data_json
                == c_data_json.as_bytes()
                && reg.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.response.transports.count() == 6
                && matches!(
                    reg.authenticator_attachment,
                    AuthenticatorAttachment::CrossPlatform
                )
                && reg.client_extension_results.cred_props.is_none()
                && reg.client_extension_results.prf.is_none())
        );
        // `id` and `rawId` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Bytes(
                base64url_nopad::decode("ABABABABABABABABABABAA".as_bytes())
                    .unwrap()
                    .as_slice(),
            ),
            &format!("id and rawId to match: CredentialId({:?})", [0; 16]).as_str(),
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "ABABABABABABABABABABAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // missing `id`.
        err = Error::missing_field("id").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `id`.
        err = Error::invalid_type(Unexpected::Other("null"), &"CredentialId")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": null,
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // missing `rawId`.
        err = Error::missing_field("rawId").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `rawId`.
        err = Error::invalid_type(Unexpected::Other("null"), &"CredentialId")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": null,
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `id` and the credential id in authenticator data mismatch.
        err = Error::invalid_value(
            Unexpected::Bytes(
                base64url_nopad
                    ::decode("ABABABABABABABABABABAA".as_bytes())
                    .unwrap()
                    .as_slice(),
            ),
            &format!("id, rawId, and the credential id in the attested credential data to all match: {:?}", [0; 16]).as_str(),
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "ABABABABABABABABABABAA",
                    "rawId": "ABABABABABABABABABABAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `authenticatorData` mismatches `authData` in attestation object.
        let mut bad_auth = [0; 113];
        bad_auth.copy_from_slice(&att_obj[att_obj.len() - 113..]);
        bad_auth[113 - 32..].copy_from_slice([0; 32].as_slice());
        err = Error::invalid_value(
            Unexpected::Bytes(bad_auth.as_slice()),
            &format!("authenticator data to match the authenticator data portion of attestation object: {:?}", &att_obj[att_obj.len() - bad_auth.len()..]).as_str(),
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": base64url_nopad::encode(bad_auth.as_slice()),
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `authenticatorData`.
        err = Error::missing_field("authenticatorData")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `authenticatorData`.
        err = Error::invalid_type(Unexpected::Other("null"), &"authenticatorData")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "transports": [],
                        "authenticatorData": null,
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `publicKeyAlgorithm` mismatch.
        err = Error::invalid_value(
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Es256).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Eddsa).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -7,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `publicKeyAlgorithm`.
        err = Error::missing_field("publicKeyAlgorithm")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `publicKeyAlgorithm`.
        err = Error::invalid_type(Unexpected::Other("null"), &"publicKeyAlgorithm")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": null,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `publicKey` mismatch.
        err = Error::invalid_value(
            Unexpected::Bytes([0; 32].as_slice()),
            &format!(
                "DER-encoded public key to match the public key within the attestation object: Ed25519(Ed25519PubKey({:?}))",
                &att_obj[att_obj.len() - 32..],
            )
            .as_str(),
        )
        .to_string().into_bytes();
        assert_eq!(serde_json::from_str::<Registration>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "transports": [],
                    "publicKey": base64url_nopad::encode(VerifyingKey::from_bytes(&[0; 32]).unwrap().to_public_key_der().unwrap().as_bytes()),
                    "publicKeyAlgorithm": -8,
                    "attestationObject": b64_aobj,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
            )
            .unwrap_err().to_string().into_bytes()[..err.len()],
            err
        );
        // Missing `publicKey` when using EdDSA, ES256, or RS256.
        err = Error::missing_field("publicKey").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `publicKey` when using EdDSA, ES256, or RS256.
        err = Error::invalid_type(Unexpected::Other("null"), &"publicKey")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": null,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `transports`.
        err = Error::missing_field("transports").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Duplicate `transports` are allowed.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": ["usb", "usb"],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.response.transports.count() == 1)
        );
        // `null` `transports`.
        err = Error::invalid_type(Unexpected::Other("null"), &"transports")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": null,
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Unknown `transports`.
        err = Error::invalid_value(
            Unexpected::Str("Usb"),
            &"'ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', or 'usb'",
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": ["Usb"],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `authenticatorAttachment`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "authenticatorAttachment": null,
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| matches!(
                reg.authenticator_attachment,
                AuthenticatorAttachment::None
            ))
        );
        // Unknown `authenticatorAttachment`.
        err = Error::invalid_value(
            Unexpected::Str("Platform"),
            &"'platform' or 'cross-platform'",
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "authenticatorAttachment": "Platform",
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `clientDataJSON`.
        err = Error::missing_field("clientDataJSON")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `clientDataJSON`.
        err = Error::invalid_type(Unexpected::Other("null"), &"base64url-encoded data")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": null,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `attestationObject`.
        err = Error::missing_field("attestationObject")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `attestationObject`.
        err = Error::invalid_type(
            Unexpected::Other("null"),
            &"base64url-encoded attestation object",
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": null,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `response`.
        err = Error::missing_field("response").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `response`.
        err = Error::invalid_type(Unexpected::Other("null"), &"AuthenticatorAttestation")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": null,
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Empty `response`.
        err = Error::missing_field("clientDataJSON")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {},
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `clientExtensionResults`.
        err = Error::missing_field("clientExtensionResults")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `clientExtensionResults`.
        err = Error::invalid_type(
            Unexpected::Other("null"),
            &"clientExtensionResults to be a map of allowed client extensions",
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": null,
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `type`.
        err = Error::missing_field("type").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `type`.
        err = Error::invalid_type(Unexpected::Other("null"), &"public-key")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": null
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Not exactly `public-type` `type`.
        err = Error::invalid_value(Unexpected::Str("Public-key"), &"public-key")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "Public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null`.
        err = Error::invalid_type(Unexpected::Other("null"), &"PublicKeyCredential")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(serde_json::json!(null).to_string().as_str())
                .unwrap_err()
                .to_string()
                .into_bytes()[..err.len()],
            err
        );
        // Empty.
        err = Error::missing_field("response").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(serde_json::json!({}).to_string().as_str())
                .unwrap_err()
                .to_string()
                .into_bytes()[..err.len()],
            err
        );
        // Unknown field in `response`.
        err = Error::unknown_field(
            "foo",
            [
                "clientDataJSON",
                "attestationObject",
                "authenticatorData",
                "transports",
                "publicKey",
                "publicKeyAlgorithm",
            ]
            .as_slice(),
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                        "foo": true,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Duplicate field in `response`.
        err = Error::duplicate_field("transports")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
                           \"authenticatorData\": \"{b64_adata}\",
                           \"transports\": [],
                           \"publicKey\": \"{b64_key}\",
                           \"publicKeyAlgorithm\": -8,
                           \"attestationObject\": \"{b64_aobj}\",
                           \"transports\": []
                       }},
                       \"clientExtensionResults\": {{}},
                       \"type\": \"public-key\"
                            
                     }}"
                )
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Unknown field in `PublicKeyCredential`.
        err = Error::unknown_field(
            "foo",
            [
                "id",
                "type",
                "rawId",
                "response",
                "authenticatorAttachment",
                "clientExtensionResults",
            ]
            .as_slice(),
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj
                    },
                    "clientExtensionResults": {},
                    "type": "public-key",
                    "foo": true,
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Duplicate field in `PublicKeyCredential`.
        err = Error::duplicate_field("id").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
                           \"authenticatorData\": \"{b64_adata}\",
                           \"transports\": [],
                           \"publicKey\": \"{b64_key}\",
                           \"publicKeyAlgorithm\": -8,
                           \"attestationObject\": \"{b64_aobj}\"
                       }},
                       \"clientExtensionResults\": {{}},
                       \"type\": \"public-key\"
                            
                     }}"
                )
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
    }
    #[test]
    fn client_extensions() {
        let c_data_json = serde_json::json!({}).to_string();
        let att_obj = [
            cbor::MAP_3,
            cbor::TEXT_3,
            b'f',
            b'm',
            b't',
            cbor::TEXT_4,
            b'n',
            b'o',
            b'n',
            b'e',
            cbor::TEXT_7,
            b'a',
            b't',
            b't',
            b'S',
            b't',
            b'm',
            b't',
            cbor::MAP_0,
            cbor::TEXT_8,
            b'a',
            b'u',
            b't',
            b'h',
            b'D',
            b'a',
            b't',
            b'a',
            cbor::BYTES_INFO_24,
            113,
            // `rpIdHash`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `flags`.
            0b0100_0101,
            // `signCount`.
            0,
            0,
            0,
            0,
            // `aaguid`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `credentialIdLength`.
            0,
            16,
            // `credentialId`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // Ed25519 COSE key.
            cbor::MAP_4,
            KTY,
            OKP,
            ALG,
            EDDSA,
            // `crv`.
            cbor::NEG_ONE,
            // `Ed25519`.
            cbor::SIX,
            // `x`.
            cbor::NEG_TWO,
            cbor::BYTES_INFO_24,
            32,
            // Compressed y-coordinate.
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
        ];
        let pub_key = VerifyingKey::from_bytes(&[1; 32])
            .unwrap()
            .to_public_key_der()
            .unwrap();
        let b64_cdata = base64url_nopad::encode(c_data_json.as_bytes());
        let b64_adata = base64url_nopad::encode(&att_obj[att_obj.len() - 113..]);
        let b64_key = base64url_nopad::encode(pub_key.as_bytes());
        let b64_aobj = base64url_nopad::encode(att_obj.as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.response.client_data_json
                == c_data_json.as_bytes()
                && reg.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.response.transports.is_empty()
                && matches!(reg.authenticator_attachment, AuthenticatorAttachment::None)
                && reg.client_extension_results.cred_props.is_none()
                && reg.client_extension_results.prf.is_none())
        );
        // `null` `credProps`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "credProps": null
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .is_none()
                && reg.client_extension_results.prf.is_none())
        );
        // `null` `prf`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": null
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .is_none()
                && reg.client_extension_results.prf.is_none())
        );
        // Unknown `clientExtensionResults`.
        let mut err = Error::unknown_field("CredProps", ["credProps", "prf"].as_slice())
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "CredProps": {
                            "rk": true
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Duplicate field.
        err = Error::duplicate_field("credProps").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
                           \"authenticatorData\": \"{b64_adata}\",
                           \"transports\": [],
                           \"publicKey\": \"{b64_key}\",
                           \"publicKeyAlgorithm\": -8,
                           \"attestationObject\": \"{b64_aobj}\"
                       }},
                       \"clientExtensionResults\": {{
                           \"credProps\": null,
                           \"credProps\": null
                       }},
                       \"type\": \"public-key\"
                     }}"
                )
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `rk`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "credProps": {
                            "rk": null
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .map_or(false, |props| props.rk.is_none())
                && reg.client_extension_results.prf.is_none())
        );
        // Missing `rk`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "credProps": {}
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .map_or(false, |props| props.rk.is_none())
                && reg.client_extension_results.prf.is_none())
        );
        // `true` rk`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "credProps": {
                            "rk": true
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .map_or(false, |props| props.rk.unwrap_or_default())
                && reg.client_extension_results.prf.is_none())
        );
        // `false` rk`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "credProps": {
                            "rk": false
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .map_or(false, |props| props.rk.map_or(false, |rk| !rk))
                && reg.client_extension_results.prf.is_none())
        );
        // Invalid `rk`.
        err = Error::invalid_type(Unexpected::Unsigned(3), &"a boolean")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "credProps": {
                            "rk": 3
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Unknown `credProps` field.
        err = Error::unknown_field("Rk", ["rk"].as_slice())
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "credProps": {
                            "Rk": true,
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Duplicate field in `credProps`.
        err = Error::duplicate_field("rk").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
                           \"authenticatorData\": \"{b64_adata}\",
                           \"transports\": [],
                           \"publicKey\": \"{b64_key}\",
                           \"publicKeyAlgorithm\": -8,
                           \"attestationObject\": \"{b64_aobj}\"
                       }},
                       \"clientExtensionResults\": {{
                           \"credProps\": {{
                               \"rk\": true,
                               \"rk\": true
                           }}
                       }},
                       \"type\": \"public-key\"
                     }}"
                )
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `enabled`.
        err = Error::invalid_type(Unexpected::Other("null"), &"a boolean")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": null
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `enabled`.
        err = Error::missing_field("enabled").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {}
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `true` `enabled`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": true
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .is_none()
                && reg
                    .client_extension_results
                    .prf
                    .map_or(false, |prf| prf.enabled))
        );
        // `false` `enabled`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": false,
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .is_none()
                && reg
                    .client_extension_results
                    .prf
                    .map_or(false, |prf| !prf.enabled))
        );
        // Invalid `enabled`.
        err = Error::invalid_type(Unexpected::Unsigned(3), &"a boolean")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": 3
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `results` with `enabled` `true`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": true,
                            "results": null,
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .is_none()
                && reg
                    .client_extension_results
                    .prf
                    .map_or(false, |prf| prf.enabled))
        );
        // `null` `results` with `enabled` `false`.
        err = Error::custom(
            "prf must not have 'results', including a null 'results', if 'enabled' is false",
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": false,
                            "results": null
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Duplicate field in `prf`.
        err = Error::duplicate_field("enabled").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
                           \"authenticatorData\": \"{b64_adata}\",
                           \"transports\": [],
                           \"publicKey\": \"{b64_key}\",
                           \"publicKeyAlgorithm\": -8,
                           \"attestationObject\": \"{b64_aobj}\"
                       }},
                       \"clientExtensionResults\": {{
                           \"prf\": {{
                               \"enabled\": true,
                               \"enabled\": true
                           }}
                       }},
                       \"type\": \"public-key\"
                     }}"
                )
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `first`.
        err = Error::missing_field("first").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": true,
                            "results": {},
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `first`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": true,
                            "results": {
                                "first": null
                            },
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .is_none()
                && reg
                    .client_extension_results
                    .prf
                    .map_or(false, |prf| prf.enabled))
        );
        // `null` `second`.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": true,
                            "results": {
                                "first": null,
                                "second": null
                            },
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg
                .client_extension_results
                .cred_props
                .is_none()
                && reg
                    .client_extension_results
                    .prf
                    .map_or(false, |prf| prf.enabled))
        );
        // Non-`null` `first`.
        err = Error::invalid_type(Unexpected::Option, &"null")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": true,
                            "results": {
                                "first": ""
                            },
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Non-`null` `second`.
        err = Error::invalid_type(Unexpected::Option, &"null")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": true,
                            "results": {
                                "first": null,
                                "second": ""
                            },
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Unknown `prf` field.
        err = Error::unknown_field("Results", ["enabled", "results"].as_slice())
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": true,
                            "Results": null
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Unknown `results` field.
        err = Error::unknown_field("Second", ["first", "second"].as_slice())
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {
                        "prf": {
                            "enabled": true,
                            "results": {
                                "first": null,
                                "Second": null
                            }
                        }
                    },
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Duplicate field in `results`.
        err = Error::duplicate_field("first").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                format!(
                    "{{
                       \"id\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"rawId\": \"AAAAAAAAAAAAAAAAAAAAAA\",
                       \"response\": {{
                           \"clientDataJSON\": \"{b64_cdata}\",
                           \"authenticatorData\": \"{b64_adata}\",
                           \"transports\": [],
                           \"publicKey\": \"{b64_key}\",
                           \"publicKeyAlgorithm\": -8,
                           \"attestationObject\": \"{b64_aobj}\"
                       }},
                       \"clientExtensionResults\": {{
                           \"prf\": {{
                               \"enabled\": true,
                               \"results\": {{
                                   \"first\": null,
                                   \"first\": null
                               }}
                           }}
                       }},
                       \"type\": \"public-key\"
                     }}"
                )
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
    }
    #[test]
    fn es256_registration_deserialize_data_mismatch() {
        let c_data_json = serde_json::json!({}).to_string();
        let mut att_obj = [
            cbor::MAP_3,
            cbor::TEXT_3,
            b'f',
            b'm',
            b't',
            cbor::TEXT_4,
            b'n',
            b'o',
            b'n',
            b'e',
            cbor::TEXT_7,
            b'a',
            b't',
            b't',
            b'S',
            b't',
            b'm',
            b't',
            cbor::MAP_0,
            cbor::TEXT_8,
            b'a',
            b'u',
            b't',
            b'h',
            b'D',
            b'a',
            b't',
            b'a',
            cbor::BYTES_INFO_24,
            148,
            // `rpIdHash`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `flags`.
            0b0100_0101,
            // `signCount`.
            0,
            0,
            0,
            0,
            // `aaguid`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `credentialIdLength`.
            0,
            16,
            // `credentialId`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // P-256 COSE key.
            cbor::MAP_5,
            KTY,
            EC2,
            ALG,
            ES256,
            // `crv`.
            cbor::NEG_ONE,
            // `P-256`.
            cbor::ONE,
            // `x`.
            cbor::NEG_TWO,
            cbor::BYTES_INFO_24,
            32,
            // x-coordinate. This will be overwritten later.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `y`.
            cbor::NEG_THREE,
            cbor::BYTES_INFO_24,
            32,
            // y-coordinate. This will be overwritten later.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let key = P256Key::from_bytes(
            &[
                137, 133, 36, 206, 163, 47, 255, 5, 76, 144, 163, 141, 40, 109, 108, 240, 246, 115,
                178, 237, 169, 68, 6, 129, 92, 21, 238, 127, 55, 158, 207, 95,
            ]
            .into(),
        )
        .unwrap()
        .public_key();
        let enc_key = key.to_encoded_point(false);
        let pub_key = key.to_public_key_der().unwrap();
        let att_obj_len = att_obj.len();
        att_obj[att_obj_len - 67..att_obj_len - 35]
            .copy_from_slice(enc_key.x().unwrap().as_slice());
        att_obj[att_obj_len - 32..].copy_from_slice(enc_key.y().unwrap().as_slice());
        let b64_cdata = base64url_nopad::encode(c_data_json.as_bytes());
        let b64_adata = base64url_nopad::encode(&att_obj[att_obj.len() - 148..]);
        let b64_key = base64url_nopad::encode(pub_key.as_bytes());
        let b64_aobj = base64url_nopad::encode(att_obj.as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -7,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.response.client_data_json
                == c_data_json.as_bytes()
                && reg.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.response.transports.is_empty()
                && matches!(reg.authenticator_attachment, AuthenticatorAttachment::None)
                && reg.client_extension_results.cred_props.is_none()
                && reg.client_extension_results.prf.is_none())
        );
        // `publicKeyAlgorithm` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Eddsa).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Es256).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `publicKeyAlgorithm`.
        err = Error::missing_field("publicKeyAlgorithm")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `publicKeyAlgorithm`.
        err = Error::invalid_type(Unexpected::Other("null"), &"publicKeyAlgorithm")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": null,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `publicKey` mismatch.
        let bad_pub_key = P256PubKey::from_encoded_point(&P256Pt::from_affine_coordinates(
            &[
                66, 71, 188, 41, 125, 2, 226, 44, 148, 62, 63, 190, 172, 64, 33, 214, 6, 37, 148,
                23, 240, 235, 203, 84, 112, 219, 232, 197, 54, 182, 17, 235,
            ]
            .into(),
            &[
                22, 172, 123, 13, 170, 242, 217, 248, 193, 209, 206, 163, 92, 4, 162, 168, 113, 63,
                2, 117, 16, 223, 239, 196, 109, 179, 10, 130, 43, 213, 205, 92,
            ]
            .into(),
            false,
        ))
        .unwrap();
        err = Error::invalid_value(
            Unexpected::Bytes([0; 32].as_slice()),
            &format!(
                "DER-encoded public key to match the public key within the attestation object: P256(UncompressedP256PubKey({:?}, {:?}))",
                &att_obj[att_obj.len() - 67..att_obj.len() - 35],
                &att_obj[att_obj.len() - 32..],
            )
            .as_str(),
        )
        .to_string().into_bytes();
        assert_eq!(serde_json::from_str::<Registration>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "transports": [],
                    "publicKey": base64url_nopad::encode(bad_pub_key.to_public_key_der().unwrap().as_bytes()),
                    "publicKeyAlgorithm": -7,
                    "attestationObject": b64_aobj,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
            )
            .unwrap_err().to_string().into_bytes()[..err.len()],
            err
        );
        // Missing `publicKey` when using EdDSA, ES256, or RS256.
        err = Error::missing_field("publicKey").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKeyAlgorithm": -7,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `publicKey` when using EdDSA, ES256, or RS256.
        err = Error::invalid_type(Unexpected::Other("null"), &"publicKey")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": null,
                        "publicKeyAlgorithm": -7,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
    }
    #[test]
    fn es384_registration_deserialize_data_mismatch() {
        let c_data_json = serde_json::json!({}).to_string();
        let mut att_obj = [
            cbor::MAP_3,
            cbor::TEXT_3,
            b'f',
            b'm',
            b't',
            cbor::TEXT_4,
            b'n',
            b'o',
            b'n',
            b'e',
            cbor::TEXT_7,
            b'a',
            b't',
            b't',
            b'S',
            b't',
            b'm',
            b't',
            cbor::MAP_0,
            cbor::TEXT_8,
            b'a',
            b'u',
            b't',
            b'h',
            b'D',
            b'a',
            b't',
            b'a',
            cbor::BYTES_INFO_24,
            181,
            // `rpIdHash`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `flags`.
            0b0100_0101,
            // `signCount`.
            0,
            0,
            0,
            0,
            // `aaguid`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `credentialIdLength`.
            0,
            16,
            // `credentialId`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // P-384 COSE key.
            cbor::MAP_5,
            KTY,
            EC2,
            ALG,
            cbor::NEG_INFO_24,
            ES384,
            // `crv`.
            cbor::NEG_ONE,
            // `P-384`.
            cbor::TWO,
            // `x`.
            cbor::NEG_TWO,
            cbor::BYTES_INFO_24,
            48,
            // x-coordinate. This will be overwritten later.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `y`.
            cbor::NEG_THREE,
            cbor::BYTES_INFO_24,
            48,
            // y-coordinate. This will be overwritten later.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let key = P384Key::from_bytes(
            &[
                158, 99, 156, 49, 190, 211, 85, 167, 28, 2, 80, 57, 31, 22, 17, 38, 85, 78, 232,
                42, 45, 199, 154, 243, 136, 251, 84, 34, 5, 120, 208, 91, 61, 248, 64, 144, 87, 1,
                32, 86, 220, 68, 182, 11, 105, 223, 75, 70,
            ]
            .into(),
        )
        .unwrap()
        .public_key();
        let enc_key = key.to_encoded_point(false);
        let pub_key = key.to_public_key_der().unwrap();
        let att_obj_len = att_obj.len();
        att_obj[att_obj_len - 99..att_obj_len - 51]
            .copy_from_slice(enc_key.x().unwrap().as_slice());
        att_obj[att_obj_len - 48..].copy_from_slice(enc_key.y().unwrap().as_slice());
        let b64_cdata = base64url_nopad::encode(c_data_json.as_bytes());
        let b64_adata = base64url_nopad::encode(&att_obj[att_obj.len() - 181..]);
        let b64_key = base64url_nopad::encode(pub_key.as_bytes());
        let b64_aobj = base64url_nopad::encode(att_obj.as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -35,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.response.client_data_json
                == c_data_json.as_bytes()
                && reg.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.response.transports.is_empty()
                && matches!(reg.authenticator_attachment, AuthenticatorAttachment::None)
                && reg.client_extension_results.cred_props.is_none()
                && reg.client_extension_results.prf.is_none())
        );
        // `publicKeyAlgorithm` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Es256).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Es384).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -7,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `publicKeyAlgorithm`.
        err = Error::missing_field("publicKeyAlgorithm")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `publicKeyAlgorithm`.
        err = Error::invalid_type(Unexpected::Other("null"), &"publicKeyAlgorithm")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": null,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `publicKey` mismatch.
        let bad_pub_key = P384PubKey::from_encoded_point(&P384Pt::from_affine_coordinates(
            &[
                192, 10, 27, 46, 66, 67, 80, 98, 33, 230, 156, 95, 1, 135, 150, 110, 64, 243, 22,
                118, 5, 255, 107, 44, 234, 111, 217, 105, 125, 114, 39, 7, 126, 2, 191, 111, 48,
                93, 234, 175, 18, 172, 59, 28, 97, 106, 178, 152,
            ]
            .into(),
            &[
                57, 36, 196, 12, 109, 129, 253, 115, 88, 154, 6, 43, 195, 85, 169, 5, 230, 51, 28,
                205, 142, 28, 150, 35, 24, 222, 170, 253, 14, 248, 84, 151, 109, 191, 152, 111,
                222, 70, 134, 247, 109, 171, 211, 33, 214, 217, 200, 111,
            ]
            .into(),
            false,
        ))
        .unwrap();
        err = Error::invalid_value(
            Unexpected::Bytes([0; 32].as_slice()),
            &format!(
                "DER-encoded public key to match the public key within the attestation object: P384(UncompressedP384PubKey({:?}, {:?}))",
                &att_obj[att_obj.len() - 99..att_obj.len() - 51],
                &att_obj[att_obj.len() - 48..],
            )
            .as_str(),
        )
        .to_string().into_bytes();
        assert_eq!(serde_json::from_str::<Registration>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "transports": [],
                    "publicKey": base64url_nopad::encode(bad_pub_key.to_public_key_der().unwrap().as_bytes()),
                    "publicKeyAlgorithm": -35,
                    "attestationObject": b64_aobj,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
            )
            .unwrap_err().to_string().into_bytes()[..err.len()],
            err
        );
        // Missing `publicKey` is allowed when not using EdDSA, ES256, or RS256.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKeyAlgorithm": -35,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .is_ok()
        );
        // `publicKeyAlgorithm` mismatch when `publicKey` does not exist.
        err = Error::invalid_value(
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Es256).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Es384).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKeyAlgorithm": -7,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `publicKey` is allowed when not using EdDSA, ES256, or RS256.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": null,
                        "publicKeyAlgorithm": -35,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .is_ok()
        );
        // `publicKeyAlgorithm` mismatch when `publicKey` is null.
        err = Error::invalid_value(
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Es256).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Es384).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": null,
                        "publicKeyAlgorithm": -7,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
    }
    #[test]
    fn rs256_registration_deserialize_data_mismatch() {
        let c_data_json = serde_json::json!({}).to_string();
        let mut att_obj = [
            cbor::MAP_3,
            cbor::TEXT_3,
            b'f',
            b'm',
            b't',
            cbor::TEXT_4,
            b'n',
            b'o',
            b'n',
            b'e',
            cbor::TEXT_7,
            b'a',
            b't',
            b't',
            b'S',
            b't',
            b'm',
            b't',
            cbor::MAP_0,
            cbor::TEXT_8,
            b'a',
            b'u',
            b't',
            b'h',
            b'D',
            b'a',
            b't',
            b'a',
            cbor::BYTES_INFO_25,
            1,
            87,
            // `rpIdHash`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `flags`.
            0b0100_0101,
            // `signCount`.
            0,
            0,
            0,
            0,
            // `aaguid`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `credentialIdLength`.
            0,
            16,
            // `credentialId`.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // RSA COSE key.
            cbor::MAP_4,
            KTY,
            RSA,
            ALG,
            cbor::NEG_INFO_25,
            // RS256.
            1,
            0,
            // `n`.
            cbor::NEG_ONE,
            cbor::BYTES_INFO_25,
            1,
            0,
            // n. This will be overwritten later.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // `e`.
            cbor::NEG_TWO,
            cbor::BYTES | 3,
            // e.
            1,
            0,
            1,
        ];
        let n = [
            111, 183, 124, 133, 38, 167, 70, 148, 44, 50, 30, 60, 121, 14, 38, 37, 96, 114, 107,
            195, 248, 64, 79, 36, 237, 140, 43, 27, 94, 74, 102, 152, 135, 102, 184, 150, 186, 206,
            185, 19, 165, 209, 48, 98, 98, 9, 3, 205, 208, 82, 250, 105, 132, 201, 73, 62, 60, 165,
            100, 128, 153, 9, 41, 118, 66, 95, 236, 214, 73, 135, 197, 68, 184, 10, 27, 116, 204,
            145, 50, 174, 58, 42, 183, 181, 119, 232, 126, 252, 217, 96, 162, 190, 103, 122, 64,
            87, 145, 45, 32, 207, 17, 239, 223, 3, 35, 14, 112, 119, 124, 141, 123, 208, 239, 105,
            81, 217, 151, 162, 190, 17, 88, 182, 176, 158, 81, 200, 42, 166, 133, 48, 23, 236, 55,
            117, 248, 233, 151, 203, 122, 155, 231, 46, 177, 20, 20, 151, 64, 222, 239, 226, 7, 21,
            254, 81, 202, 64, 232, 161, 235, 22, 51, 246, 207, 213, 0, 229, 138, 46, 222, 205, 157,
            108, 139, 253, 230, 80, 50, 2, 122, 212, 163, 100, 180, 114, 12, 113, 52, 56, 99, 188,
            42, 198, 212, 23, 182, 222, 56, 221, 200, 79, 96, 239, 221, 135, 10, 17, 106, 183, 56,
            104, 68, 94, 198, 196, 35, 200, 83, 204, 26, 185, 204, 212, 31, 183, 19, 111, 233, 13,
            72, 93, 53, 65, 111, 59, 242, 122, 160, 244, 162, 126, 38, 235, 156, 47, 88, 39, 132,
            153, 79, 0, 133, 78, 7, 218, 165, 241,
        ];
        let e = 65537u32;
        let d = [
            145, 79, 21, 97, 233, 3, 192, 194, 177, 68, 181, 80, 120, 197, 23, 44, 185, 74, 144, 0,
            132, 149, 139, 11, 16, 224, 4, 112, 236, 94, 238, 97, 121, 124, 213, 145, 24, 253, 168,
            35, 190, 205, 132, 115, 33, 201, 38, 253, 246, 180, 66, 155, 165, 46, 3, 254, 68, 108,
            154, 247, 246, 45, 187, 0, 204, 96, 185, 157, 249, 174, 158, 38, 62, 244, 183, 76, 102,
            6, 219, 92, 212, 138, 59, 147, 163, 219, 111, 39, 105, 21, 236, 196, 38, 255, 114, 247,
            82, 104, 113, 204, 29, 152, 209, 219, 48, 239, 74, 129, 19, 247, 33, 239, 119, 166,
            216, 152, 94, 138, 238, 164, 242, 129, 50, 150, 57, 20, 53, 224, 56, 241, 138, 97, 111,
            215, 107, 212, 195, 146, 108, 143, 0, 229, 181, 171, 73, 152, 105, 146, 25, 243, 242,
            140, 252, 248, 162, 247, 63, 168, 180, 20, 153, 120, 10, 248, 211, 1, 71, 127, 212,
            249, 237, 203, 202, 48, 26, 216, 226, 228, 186, 13, 204, 70, 255, 240, 89, 255, 59, 83,
            31, 253, 55, 43, 158, 90, 248, 83, 32, 159, 105, 57, 134, 34, 96, 18, 255, 245, 153,
            162, 60, 91, 99, 220, 51, 44, 85, 114, 67, 125, 202, 65, 217, 245, 40, 8, 81, 165, 142,
            24, 245, 127, 122, 247, 152, 212, 75, 45, 59, 90, 184, 234, 31, 147, 36, 8, 212, 45,
            50, 23, 3, 25, 253, 87, 227, 79, 119, 161,
        ];
        let p = BigUint::from_bytes_le(
            [
                215, 166, 5, 21, 11, 179, 41, 77, 198, 92, 165, 48, 77, 162, 42, 41, 206, 141, 60,
                69, 47, 164, 19, 92, 46, 72, 100, 238, 100, 53, 214, 197, 163, 185, 6, 140, 229,
                250, 195, 77, 8, 12, 5, 236, 178, 173, 86, 201, 43, 213, 165, 51, 108, 101, 161,
                99, 76, 240, 14, 234, 76, 197, 137, 53, 198, 168, 135, 205, 212, 198, 120, 29, 16,
                82, 98, 233, 236, 177, 12, 171, 141, 100, 107, 146, 33, 176, 125, 202, 172, 79,
                147, 179, 30, 62, 247, 206, 169, 19, 168, 114, 26, 73, 108, 178, 105, 84, 89, 191,
                168, 253, 228, 214, 54, 16, 212, 199, 111, 72, 3, 41, 247, 227, 165, 244, 32, 188,
                24, 247,
            ]
            .as_slice(),
        );
        let p_2 = BigUint::from_bytes_le(
            [
                41, 25, 198, 240, 134, 206, 121, 57, 11, 5, 134, 192, 212, 77, 229, 197, 14, 78,
                85, 212, 190, 114, 179, 188, 21, 171, 174, 12, 104, 74, 15, 164, 136, 173, 62, 177,
                141, 213, 93, 102, 147, 83, 59, 124, 146, 59, 175, 213, 55, 27, 25, 248, 154, 29,
                39, 85, 50, 235, 134, 60, 203, 106, 186, 195, 190, 185, 71, 169, 142, 236, 92, 11,
                250, 187, 198, 8, 201, 184, 120, 178, 227, 87, 63, 243, 89, 227, 234, 184, 28, 252,
                112, 211, 193, 69, 23, 92, 5, 72, 93, 53, 69, 159, 73, 160, 105, 244, 249, 94, 214,
                173, 9, 236, 4, 255, 129, 11, 224, 140, 252, 168, 57, 143, 176, 241, 60, 219, 90,
                250,
            ]
            .as_slice(),
        );
        let key = RsaPrivateKey::from_components(
            BigUint::from_bytes_le(n.as_slice()),
            e.into(),
            BigUint::from_bytes_le(d.as_slice()),
            vec![p, p_2],
        )
        .unwrap()
        .to_public_key();
        let pub_key = key.to_public_key_der().unwrap();
        let att_obj_len = att_obj.len();
        att_obj[att_obj_len - 261..att_obj_len - 5]
            .copy_from_slice(key.n().to_bytes_be().as_slice());
        let b64_cdata = base64url_nopad::encode(c_data_json.as_bytes());
        let b64_adata = base64url_nopad::encode(&att_obj[att_obj.len() - 343..]);
        let b64_key = base64url_nopad::encode(pub_key.as_bytes());
        let b64_aobj = base64url_nopad::encode(att_obj.as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -257,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.response.client_data_json
                == c_data_json.as_bytes()
                && reg.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.response.transports.is_empty()
                && matches!(reg.authenticator_attachment, AuthenticatorAttachment::None)
                && reg.client_extension_results.cred_props.is_none()
                && reg.client_extension_results.prf.is_none())
        );
        // `publicKeyAlgorithm` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Eddsa).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Rs256).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": -8,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Missing `publicKeyAlgorithm`.
        err = Error::missing_field("publicKeyAlgorithm")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `publicKeyAlgorithm`.
        err = Error::invalid_type(Unexpected::Other("null"), &"publicKeyAlgorithm")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": b64_key,
                        "publicKeyAlgorithm": null,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `publicKey` mismatch.
        let bad_pub_key = RsaPrivateKey::from_components(
            BigUint::from_bytes_le(
                [
                    175, 161, 161, 75, 52, 244, 72, 168, 29, 119, 33, 120, 3, 222, 231, 152, 222,
                    119, 112, 83, 221, 237, 74, 174, 79, 216, 147, 251, 245, 94, 234, 114, 254, 21,
                    17, 254, 8, 115, 75, 127, 150, 87, 59, 109, 230, 116, 85, 90, 11, 160, 63, 217,
                    9, 38, 187, 250, 226, 183, 38, 164, 182, 218, 22, 19, 58, 189, 83, 219, 11,
                    144, 15, 99, 151, 166, 46, 57, 17, 111, 189, 131, 142, 113, 85, 122, 188, 238,
                    52, 21, 116, 125, 102, 195, 182, 165, 29, 156, 213, 182, 125, 156, 88, 56, 221,
                    2, 98, 43, 210, 115, 32, 4, 105, 88, 181, 158, 207, 236, 162, 250, 253, 240,
                    72, 8, 253, 50, 220, 247, 76, 170, 143, 68, 225, 231, 113, 64, 244, 17, 138,
                    162, 233, 33, 2, 67, 11, 223, 188, 232, 152, 193, 20, 32, 243, 52, 64, 43, 2,
                    243, 8, 77, 150, 232, 109, 148, 95, 127, 55, 71, 162, 34, 54, 83, 135, 52, 172,
                    191, 32, 42, 106, 43, 211, 206, 100, 104, 110, 232, 5, 43, 120, 180, 166, 40,
                    144, 233, 239, 103, 134, 103, 255, 224, 138, 184, 208, 137, 127, 36, 189, 143,
                    248, 201, 2, 218, 51, 232, 96, 30, 83, 124, 109, 241, 23, 179, 247, 151, 238,
                    212, 204, 44, 43, 223, 148, 241, 172, 10, 235, 155, 94, 68, 116, 24, 116, 191,
                    86, 53, 127, 35, 133, 198, 204, 59, 76, 110, 16, 1, 15, 148, 135, 157,
                ]
                .as_slice(),
            ),
            65537u32.into(),
            BigUint::from_bytes_le(
                [
                    129, 93, 123, 251, 104, 29, 84, 203, 116, 100, 75, 237, 111, 160, 12, 100, 172,
                    76, 57, 178, 144, 235, 81, 61, 115, 243, 28, 40, 183, 22, 56, 150, 68, 38, 220,
                    62, 233, 110, 48, 174, 35, 197, 244, 109, 148, 109, 36, 69, 69, 82, 225, 113,
                    175, 6, 239, 27, 193, 101, 50, 239, 122, 102, 7, 46, 98, 79, 195, 116, 155,
                    158, 138, 147, 51, 93, 24, 237, 246, 82, 14, 109, 144, 250, 239, 93, 63, 214,
                    96, 130, 226, 134, 198, 145, 161, 11, 231, 97, 214, 180, 255, 95, 158, 88, 108,
                    254, 243, 177, 133, 184, 92, 95, 148, 88, 55, 124, 245, 244, 84, 86, 4, 121,
                    44, 231, 97, 176, 190, 29, 155, 40, 57, 69, 165, 80, 168, 9, 56, 43, 233, 6,
                    14, 157, 112, 223, 64, 88, 141, 7, 65, 23, 64, 208, 6, 83, 61, 8, 182, 248,
                    126, 84, 179, 163, 80, 238, 90, 133, 4, 14, 71, 177, 175, 27, 29, 151, 211,
                    108, 162, 195, 7, 157, 167, 86, 169, 3, 87, 235, 89, 158, 237, 216, 31, 243,
                    197, 62, 5, 84, 131, 230, 186, 248, 49, 12, 93, 244, 61, 135, 180, 17, 162,
                    241, 13, 115, 241, 138, 219, 98, 155, 166, 191, 63, 12, 37, 1, 165, 178, 84,
                    200, 72, 80, 41, 77, 136, 217, 141, 246, 209, 31, 243, 159, 71, 43, 246, 159,
                    182, 171, 116, 12, 3, 142, 235, 218, 164, 70, 90, 147, 238, 42, 75,
                ]
                .as_slice(),
            ),
            vec![
                BigUint::from_bytes_le(
                    [
                        215, 199, 110, 28, 64, 16, 16, 109, 106, 152, 150, 124, 52, 166, 121, 92,
                        242, 13, 0, 69, 7, 152, 72, 172, 118, 63, 156, 180, 140, 39, 53, 29, 197,
                        224, 177, 48, 41, 221, 102, 65, 17, 185, 55, 62, 219, 152, 227, 7, 78, 219,
                        14, 139, 71, 204, 144, 152, 14, 39, 247, 244, 165, 224, 234, 60, 213, 74,
                        237, 30, 102, 177, 242, 138, 168, 31, 122, 47, 206, 155, 225, 113, 103,
                        175, 152, 244, 27, 233, 112, 223, 248, 38, 215, 178, 20, 244, 8, 121, 26,
                        11, 70, 122, 16, 85, 167, 87, 64, 216, 228, 227, 173, 57, 250, 8, 221, 38,
                        12, 203, 212, 1, 112, 43, 72, 91, 225, 97, 228, 57, 154, 193,
                    ]
                    .as_slice(),
                ),
                BigUint::from_bytes_le(
                    [
                        233, 89, 204, 152, 31, 242, 8, 110, 38, 190, 111, 159, 105, 105, 45, 85,
                        15, 244, 30, 250, 174, 226, 219, 111, 107, 191, 196, 135, 17, 123, 186,
                        167, 85, 13, 120, 197, 159, 129, 78, 237, 152, 31, 230, 26, 229, 253, 197,
                        211, 105, 204, 126, 142, 250, 55, 26, 172, 65, 160, 45, 6, 99, 86, 66, 238,
                        107, 6, 98, 171, 93, 224, 201, 160, 31, 204, 82, 120, 228, 158, 238, 6,
                        190, 12, 150, 153, 239, 95, 57, 71, 100, 239, 235, 155, 73, 200, 5, 225,
                        127, 185, 46, 48, 243, 84, 33, 142, 17, 19, 20, 23, 215, 16, 114, 58, 211,
                        14, 73, 148, 168, 252, 159, 252, 125, 57, 101, 211, 188, 12, 77, 208,
                    ]
                    .as_slice(),
                ),
            ],
        )
        .unwrap()
        .to_public_key();
        err = Error::invalid_value(
            Unexpected::Bytes([0; 32].as_slice()),
            &format!(
                "DER-encoded public key to match the public key within the attestation object: Rsa(RsaPubKey({:?}, 65537))",
                &att_obj[att_obj.len() - 261..att_obj.len() - 5],
            )
            .as_str(),
        )
        .to_string().into_bytes();
        assert_eq!(serde_json::from_str::<Registration>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "transports": [],
                    "publicKey": base64url_nopad::encode(bad_pub_key.to_public_key_der().unwrap().as_bytes()),
                    "publicKeyAlgorithm": -257,
                    "attestationObject": b64_aobj,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            })
            .to_string()
            .as_str()
            )
            .unwrap_err().to_string().into_bytes()[..err.len()],
            err
        );
        // Missing `publicKey` when using EdDSA, ES256, or RS256.
        err = Error::missing_field("publicKey").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKeyAlgorithm": -257,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // `null` `publicKey` when using EdDSA, ES256, or RS256.
        err = Error::invalid_type(Unexpected::Other("null"), &"publicKey")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<Registration>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": b64_adata,
                        "transports": [],
                        "publicKey": null,
                        "publicKeyAlgorithm": -257,
                        "attestationObject": b64_aobj,
                    },
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
    }
}
