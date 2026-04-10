#[cfg(feature = "serde_relaxed")]
use super::super::SerdeJsonErr;
#[cfg(doc)]
use super::{
    super::super::{
        RegisteredCredential,
        request::{
            CredentialMediationRequirement, UserVerificationRequirement,
            register::{
                AuthenticatorSelectionCriteria, BackupReq, CredentialCreationOptions, Extension,
                PublicKeyCredentialCreationOptions, RegistrationServerState,
                RegistrationVerificationOptions,
            },
        },
    },
    Aaguid, Attestation, AttestationObject, AttestedCredentialData, AuthenticatorAttachment,
    AuthenticatorAttestation, AuthenticatorData, AuthenticatorExtensionOutput, Backup,
    ClientExtensionsOutputs, CollectedClientData, CompressedP256PubKey, CompressedP384PubKey,
    Ed25519PubKey, Ed25519Signature, Flag, MAX_RSA_N_BITS, MIN_RSA_E, MIN_RSA_N_BITS, Metadata,
    MlDsa44PubKey, MlDsa65PubKey, MlDsa87PubKey, PackedAttestation, RsaPubKey,
    UncompressedP256PubKey, UncompressedP384PubKey, UncompressedPubKey,
};
use super::{
    super::{
        super::{CredentialErr, request::register::CredProtect},
        AuthRespErr, AuthenticatorDataErr as AuthDataErr, CeremonyErr,
        error::{CollectedClientDataErr, CredentialIdErr},
    },
    CredentialProtectionPolicy, FourToSixtyThree,
};
use core::{
    convert::Infallible,
    error::Error,
    fmt::{self, Display, Formatter},
};
/// Error returned from [`MlDsa87PubKey::try_from`] when the `slice` is not 2592 bytes in length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlDsa87PubKeyErr;
impl Display for MlDsa87PubKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("the ML-DSA-87 public key is not 2592 bytes in length")
    }
}
impl Error for MlDsa87PubKeyErr {}
/// Error returned from [`MlDsa65PubKey::try_from`] when the `slice` is not 1952 bytes in length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlDsa65PubKeyErr;
impl Display for MlDsa65PubKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("the ML-DSA-65 public key is not 1952 bytes in length")
    }
}
impl Error for MlDsa65PubKeyErr {}
/// Error returned from [`MlDsa44PubKey::try_from`] when the `slice` is not 1312 bytes in length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlDsa44PubKeyErr;
impl Display for MlDsa44PubKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("the ML-DSA-44 public key is not 1312 bytes in length")
    }
}
impl Error for MlDsa44PubKeyErr {}
/// Error returned from [`Ed25519PubKey::try_from`] when the `slice` is not 32 bytes in length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed25519PubKeyErr;
impl Display for Ed25519PubKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("the Ed25519 public key is not 32 bytes in length")
    }
}
impl Error for Ed25519PubKeyErr {}
/// Error returned from [`UncompressedP256PubKey::try_from`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UncompressedP256PubKeyErr {
    /// Variant returned when the x-coordinate is not 32 bytes in length.
    X,
    /// Variant returned when the y-coordinate is not 32 bytes in length.
    Y,
}
impl Display for UncompressedP256PubKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::X => "the P-256 public key x-coordinate is not 32 bytes in length",
            Self::Y => "the P-256 public key y-coordinate is not 32 bytes in length",
        })
    }
}
impl Error for UncompressedP256PubKeyErr {}
/// Error returned from [`CompressedP256PubKey::try_from`] when the x-coordinate
/// is not exactly 32 bytes in length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompressedP256PubKeyErr;
impl Display for CompressedP256PubKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("the compressed P-256 public key x-coordinate is not 32 bytes in length")
    }
}
impl Error for CompressedP256PubKeyErr {}
/// Error returned from [`UncompressedP384PubKey::try_from`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UncompressedP384PubKeyErr {
    /// Variant returned when the x-coordinate is not 48 bytes in length.
    X,
    /// Variant returned when the y-coordinate is not 48 bytes in length.
    Y,
}
impl Display for UncompressedP384PubKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::X => "the P-384 public key x-coordinate is not 48 bytes in length",
            Self::Y => "the P-384 public key y-coordinate is not 48 bytes in length",
        })
    }
}
impl Error for UncompressedP384PubKeyErr {}
/// Error returned from [`CompressedP384PubKey::try_from`] when the x-coordinate
/// is not exactly 48 bytes in length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompressedP384PubKeyErr;
impl Display for CompressedP384PubKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("the compressed P-384 public key x-coordinate is not 48 bytes in length")
    }
}
impl Error for CompressedP384PubKeyErr {}
/// Error returned from [`RsaPubKey::try_from`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RsaPubKeyErr {
    /// Variant returned when the modulus has a leading 0.
    NLeading0,
    /// Variant returned when the modulus has fewer than [`MIN_RSA_N_BITS`] or more than
    /// [`MAX_RSA_N_BITS`].
    NSize,
    /// Variant returned when the modulus is even.
    NEven,
    /// Variant returned when the exponent is less than [`MIN_RSA_E`].
    ESize,
    /// Variant returned when the exponent is even.
    EEven,
}
impl Display for RsaPubKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::NLeading0 => "the RSA public key modulus had a leading 0",
            Self::NSize => {
                "the RSA public key modulus was less than 2048 bits or greater than 16384"
            }
            Self::NEven => "the RSA public key modulus was even",
            Self::ESize => "the RSA public key exponent was less than 3",
            Self::EEven => "the RSA public key exponent was even",
        })
    }
}
impl Error for RsaPubKeyErr {}
/// Error returned when an alleged public key is not valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PubKeyErr {
    /// Error when [`Ed25519PubKey`] is not valid.
    ///
    /// Note this means the underlying point is either not on the curve or is an element
    /// of the small-order subgroup.
    Ed25519,
    /// Error when [`UncompressedP256PubKey`] or [`CompressedP256PubKey`] is not valid.
    P256,
    /// Error when [`UncompressedP384PubKey`] or [`CompressedP384PubKey`] is not valid.
    P384,
}
impl Display for PubKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Ed25519 => "Ed25519 public key is invalid",
            Self::P256 => "P-256 public key is invalid",
            Self::P384 => "P-384 public key is invalid",
        })
    }
}
impl Error for PubKeyErr {}
/// Error returned from [`Ed25519Signature::try_from`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed25519SignatureErr;
impl Display for Ed25519SignatureErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("the Ed25519 signature is not 64 bytes in length")
    }
}
impl Error for Ed25519SignatureErr {}
/// Error returned from [`Aaguid::try_from`] when the slice is not exactly
/// 16 bytes in length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AaguidErr;
impl Display for AaguidErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("the AAGUID is not 16 bytes in length")
    }
}
impl Error for AaguidErr {}
/// Error returned in [`AuthenticatorDataErr::AuthenticatorExtension`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorExtensionOutputErr {
    /// The `slice` had an invalid length.
    Len,
    /// The first byte did not represent a map of one, two, or three key pairs.
    CborHeader,
    /// `credProtect` had an invalid value.
    CredProtectValue,
    /// `hmac-secret` had an invalid value.
    HmacSecretValue,
    /// `minPinLength` had an invalid value.
    MinPinLengthValue,
    /// `hmac-secret-mc` was not a byte string with additional info 24.
    HmacSecretMcType,
    /// `hmac-secret-mc` was not a byte string of length 48 or 80.
    HmacSecretMcValue,
    /// Fewer extensions existed than expected.
    Missing,
}
impl Display for AuthenticatorExtensionOutputErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Len => "CBOR authenticator extensions had an invalid length",
            Self::CborHeader => "CBOR authenticator extensions did not represent a map of one, two, or three key pairs",
            Self::CredProtectValue => "CBOR authenticator extension 'credProtect' had an invalid value",
            Self::HmacSecretValue => "CBOR authenticator extension 'hmac-secret' had an invalid value",
            Self::MinPinLengthValue => "CBOR authenticator extension 'minPinLength' had an invalid value",
            Self::HmacSecretMcType => "CBOR authenticator extension 'hmac-secret-mc' was not a byte string with additional info 24",
            Self::HmacSecretMcValue => "CBOR authenticator extension 'hmac-secret-mc' was not a byte string of length 48 or 80",
            Self::Missing => "CBOR authenticator extensions had fewer extensions than expected",
        })
    }
}
impl Error for AuthenticatorExtensionOutputErr {}
/// Error returned in [`AttestedCredentialDataErr::CoseKey`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoseKeyErr {
    /// The `slice` had an invalid length.
    Len,
    /// The COSE Key type was not `AKP`, `OKP`, `EC2`, or `RSA`.
    CoseKeyType,
    /// The `slice` was malformed and did not conform to an ML-DSA-87 public key encoded as a COSE Key per
    /// [Draft IETF COSE Dilithium 10](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-10).
    MlDsa87CoseEncoding,
    /// The `slice` was malformed and did not conform to an ML-DSA-65 public key encoded as a COSE Key per
    /// [Draft IETF COSE Dilithium 10](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-10).
    MlDsa65CoseEncoding,
    /// The `slice` was malformed and did not conform to an ML-DSA-44 public key encoded as a COSE Key per
    /// [Draft IETF COSE Dilithium 10](https://datatracker.ietf.org/doc/html/draft-ietf-cose-dilithium-10).
    MlDsa44CoseEncoding,
    /// The `slice` was malformed and did not conform to an Ed25519 public key encoded as a COSE Key per
    /// [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053).
    Ed25519CoseEncoding,
    /// The `slice` was malformed and did not conform to an ECDSA public key based on curve P-256 and SHA-256
    /// encoded as a COSE Key per [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and
    /// [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053).
    P256CoseEncoding,
    /// The `slice` was malformed and did not conform to an ECDSA public key based on curve P-384 and SHA-384
    /// encoded as a COSE Key per [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052) and
    /// [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053).
    P384CoseEncoding,
    /// The `slice` was malformed and did not conform to an RSASSA-PKCS1-v1.5 public key using SHA-256 encoded as a
    /// COSE Key per [RFC 8230](https://www.rfc-editor.org/rfc/rfc8230.html).
    RsaCoseEncoding,
    /// The RSA public key exponent is too large.
    RsaExponentTooLarge,
    /// The RSA public key was invalid.
    RsaPubKey(RsaPubKeyErr),
}
impl Display for CoseKeyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Len => f.write_str("COSE key data had an invalid length"),
            Self::CoseKeyType => f.write_str("COSE key type was not 'AKP', 'OKP', 'EC2', or 'RSA'"),
            Self::MlDsa87CoseEncoding => {
                f.write_str("ML-DSA-87 COSE key was not encoded correctly")
            }
            Self::MlDsa65CoseEncoding => {
                f.write_str("ML-DSA-65 COSE key was not encoded correctly")
            }
            Self::MlDsa44CoseEncoding => {
                f.write_str("ML-DSA-44 COSE key was not encoded correctly")
            }
            Self::Ed25519CoseEncoding => f.write_str("Ed25519 COSE key was not encoded correctly"),
            Self::P256CoseEncoding => {
                f.write_str("ECDSA with P-256 and SHA-256 COSE key was not encoded correctly")
            }
            Self::P384CoseEncoding => {
                f.write_str("ECDSA with P-384 and SHA-384 COSE key was not encoded correctly")
            }
            Self::RsaCoseEncoding => {
                f.write_str("RSASSA-PKCS1-v1.5 using SHA-256 COSE key was not encoded correctly")
            }
            Self::RsaExponentTooLarge => f.write_str("RSA public key exponent is too large"),
            Self::RsaPubKey(err) => err.fmt(f),
        }
    }
}
impl Error for CoseKeyErr {}
/// Error returned in [`AuthenticatorDataErr::AttestedCredential`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestedCredentialDataErr {
    /// The `slice` had an invalid length.
    Len,
    /// Error when the claimed credential ID length is not valid.
    CredentialId(CredentialIdErr),
    /// Error related to the credential public key.
    CoseKey(CoseKeyErr),
}
impl Display for AttestedCredentialDataErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Len => f.write_str("attested credential data had an invalid length"),
            Self::CredentialId(err) => err.fmt(f),
            Self::CoseKey(err) => err.fmt(f),
        }
    }
}
impl Error for AttestedCredentialDataErr {}
/// Error returned from [`AuthenticatorData::try_from`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatorDataErr {
    /// The `slice` had an invalid length.
    Len,
    /// Bit 1 in [`flags`](https://www.w3.org/TR/webauthn-3/#authdata-flags) is not 0.
    FlagsBit1Not0,
    /// Bit 5 in [`flags`](https://www.w3.org/TR/webauthn-3/#authdata-flags) is not 0.
    FlagsBit5Not0,
    /// [AT](https://www.w3.org/TR/webauthn-3/#authdata-flags-at) bit was 0.
    AttestedCredentialDataNotIncluded,
    /// [BE](https://www.w3.org/TR/webauthn-3/#authdata-flags-be) and
    /// [BS](https://www.w3.org/TR/webauthn-3/#authdata-flags-bs) bits were 0 and 1 respectively.
    BackupWithoutEligibility,
    /// Error returned when [`AttestedCredentialData`] is malformed.
    AttestedCredential(AttestedCredentialDataErr),
    /// Error returned when [`AuthenticatorExtensionOutput`] is malformed.
    AuthenticatorExtension(AuthenticatorExtensionOutputErr),
    /// [ED](https://www.w3.org/TR/webauthn-3/#authdata-flags-ed) bit was 0, but
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions) existed.
    NoExtensionBitWithData,
    /// [ED](https://www.w3.org/TR/webauthn-3/#authdata-flags-ed) bit was 1, but
    /// [`extensions`](https://www.w3.org/TR/webauthn-3/#authdata-extensions) did not exist.
    ExtensionBitWithoutData,
    /// There was data remaining that could not be deserialized.
    TrailingData,
}
impl Display for AuthenticatorDataErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Len => AuthDataErr::<
                Infallible,
                AttestedCredentialDataErr,
                AuthenticatorExtensionOutputErr,
            >::Len
                .fmt(f),
            Self::FlagsBit1Not0 => AuthDataErr::<
                Infallible,
                AttestedCredentialDataErr,
                AuthenticatorExtensionOutputErr,
            >::FlagsBit1Not0
                .fmt(f),
            Self::FlagsBit5Not0 => AuthDataErr::<
                Infallible,
                AttestedCredentialDataErr,
                AuthenticatorExtensionOutputErr,
            >::FlagsBit5Not0
                .fmt(f),
            Self::AttestedCredentialDataNotIncluded => {
                f.write_str("attested credential data was not included")
            }
            Self::BackupWithoutEligibility => AuthDataErr::<
                Infallible,
                AttestedCredentialDataErr,
                AuthenticatorExtensionOutputErr,
            >::BackupWithoutEligibility
                .fmt(f),
            Self::AttestedCredential(err) => err.fmt(f),
            Self::AuthenticatorExtension(err) => err.fmt(f),
            Self::NoExtensionBitWithData => AuthDataErr::<
                Infallible,
                AttestedCredentialDataErr,
                AuthenticatorExtensionOutputErr,
            >::NoExtensionBitWithData
                .fmt(f),
            Self::ExtensionBitWithoutData => AuthDataErr::<
                Infallible,
                AttestedCredentialDataErr,
                AuthenticatorExtensionOutputErr,
            >::ExtensionBitWithoutData
                .fmt(f),
            Self::TrailingData => AuthDataErr::<
                Infallible,
                AttestedCredentialDataErr,
                AuthenticatorExtensionOutputErr,
            >::TrailingData
                .fmt(f),
        }
    }
}
impl Error for AuthenticatorDataErr {}
/// Error returned in [`AttestationObjectErr::Attestation`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationErr {
    /// The `slice` had an invalid length.
    Len,
    /// The attestation format does not exist.
    MissingFormat,
    /// The attestation format is not supported.
    UnsupportedFormat,
    /// The attestation statement does not exist.
    MissingStatement,
    /// [None](https://www.w3.org/TR/webauthn-3/#sctn-none-attestation) has the wrong format.
    NoneFormat,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) was not a map of two or three key-value pairs.
    PackedFormat,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) did not have an algorithm.
    PackedFormatMissingAlg,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) had an unsupported algorithm.
    PackedFormatUnsupportedAlg,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) did not have a signature.
    PackedFormatMissingSig,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) ML-DSA-87 signature CBOR was invalid.
    PackedFormatCborMlDsa87Signature,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) ML-DSA-87 signature was invalid.
    PackedFormatMlDsa87,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) ML-DSA-65 signature CBOR was invalid.
    PackedFormatCborMlDsa65Signature,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) ML-DSA-65 signature was invalid.
    PackedFormatMlDsa65,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) ML-DSA-44 signature CBOR was invalid.
    PackedFormatCborMlDsa44Signature,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) ML-DSA-44 signature was invalid.
    PackedFormatMlDsa44,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) Ed25519 signature CBOR was invalid.
    PackedFormatCborEd25519Signature,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) P-256 signature CBOR was invalid.
    PackedFormatCborP256Signature,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) P-256 signature was invalid.
    PackedFormatP256,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) P-384 signature CBOR was invalid.
    PackedFormatCborP384Signature,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) P-384 signature was invalid.
    PackedFormatP384,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) RS256 signature CBOR was invalid.
    PackedFormatCborRs256Signature,
    /// [Packed](https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation) RS256 signature was invalid.
    PackedFormatRs256,
}
impl Display for AttestationErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::Len => "CBOR attestation had an invalid length",
            Self::MissingFormat => "CBOR attestation did not have an attestation format",
            Self::UnsupportedFormat => "CBOR attestation format is not supported",
            Self::MissingStatement => "CBOR attestation did not have an attestation statement",
            Self::NoneFormat => "CBOR attestation had the wrong format for the none attestation",
            Self::PackedFormat => "CBOR attestation had the wrong number of key-value pairs for the packed attestation",
            Self::PackedFormatMissingAlg => "CBOR attestation did not have an algorithm for the packed attestation",
            Self::PackedFormatUnsupportedAlg => "CBOR attestation had an unsupported algorithm for the packed attestation",
            Self::PackedFormatMissingSig => "CBOR attestation did not have a signature for the packed attestation",
            Self::PackedFormatCborMlDsa87Signature => "CBOR attestation ML-DSA-87 signature had the wrong CBOR format for the packed attestation",
            Self::PackedFormatMlDsa87 => "CBOR attestation ML-DSA-87 signature was invalid for the packed attestation",
            Self::PackedFormatCborMlDsa65Signature => "CBOR attestation ML-DSA-65 signature had the wrong CBOR format for the packed attestation",
            Self::PackedFormatMlDsa65 => "CBOR attestation ML-DSA-65 signature was invalid for the packed attestation",
            Self::PackedFormatCborMlDsa44Signature => "CBOR attestation ML-DSA-44 signature had the wrong CBOR format for the packed attestation",
            Self::PackedFormatMlDsa44 => "CBOR attestation ML-DSA-44 signature was invalid for the packed attestation",
            Self::PackedFormatCborEd25519Signature => "CBOR attestation Ed25519 signature had the wrong CBOR format for the packed attestation",
            Self::PackedFormatCborP256Signature => "CBOR attestation P-256 signature had the wrong CBOR format for the packed attestation",
            Self::PackedFormatP256 => "CBOR attestation P-256 signature was invalid for the packed attestation",
            Self::PackedFormatCborP384Signature => "CBOR attestation P-384 signature had the wrong CBOR format for the packed attestation",
            Self::PackedFormatP384 => "CBOR attestation P-384 signature was invalid for the packed attestation",
            Self::PackedFormatCborRs256Signature => "CBOR attestation RS256 signature had the wrong CBOR format for the packed attestation",
            Self::PackedFormatRs256 => "CBOR attestation RS256 signature was invalid for the packed attestation",
        })
    }
}
impl Error for AttestationErr {}
/// Error returned by [`AttestationObject::try_from`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttestationObjectErr {
    /// The `slice` had an invalid length.
    Len,
    /// The `slice` was not a CBOR map with three key-value pairs.
    NotAMapOf3,
    /// Error when [`PackedAttestation::signature`] does not match the type of
    /// [`AttestedCredentialData::credential_public_key`] when self attestation
    /// is used.
    SelfAttestationAlgorithmMismatch,
    /// The third key was not "authData".
    MissingAuthData,
    /// `authData` did not have a byte string data type.
    AuthDataType,
    /// `authData` length with additional info 24 or 25 did not have a conforming length.
    AuthDataLenInfo,
    /// Error related to the encoding of [`Attestation`].
    Attestation(AttestationErr),
    /// [`AuthenticatorData`] length did not match the length encoded in the CBOR data.
    CborAuthDataLenMismatch,
    /// Error from [`AuthenticatorData::try_from`].
    AuthData(AuthenticatorDataErr),
}
impl Display for AttestationObjectErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Len => f.write_str("CBOR attestation object had an invalid length"),
            Self::NotAMapOf3 => {
                f.write_str("CBOR attestation object was not a map of three key-value pairs")
            }
            Self::MissingAuthData => {
                f.write_str("CBOR attestation object did not have 'authData' as its third key")
            }
            Self::AuthDataType => {
                f.write_str("CBOR attestation object authenticator data invalid type")
            }
            Self::AuthDataLenInfo => f.write_str(
                "CBOR attestation object authenticator data had an invalid encoded length",
            ),
            Self::Attestation(err) => err.fmt(f),
            Self::CborAuthDataLenMismatch => f.write_str(
                "CBOR attestation object authenticator data length did not match the CBOR value",
            ),
            Self::AuthData(err) => err.fmt(f),
            Self::SelfAttestationAlgorithmMismatch => f.write_str("CBOR attestation object packed attestation contained a self attestation whose format did not match the type of the public key"),
        }
    }
}
impl Error for AttestationObjectErr {}
/// Error in [`RegCeremonyErr::Extension`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionErr {
    /// [`ClientExtensionsOutputs::cred_props`] was sent from the client but was not supposed to be.
    ForbiddenCredProps,
    /// [`ClientExtensionsOutputs::prf`] was sent from the client but was not supposed to be.
    ForbiddenPrf,
    /// [`AuthenticatorExtensionOutput::cred_protect`] was sent from the client but was not supposed to be.
    ForbiddenCredProtect,
    /// [`AuthenticatorExtensionOutput::hmac_secret`] was sent from the client but was not supposed to be.
    ForbiddenHmacSecret,
    /// [`AuthenticatorExtensionOutput::min_pin_length`] was sent from the client but was not supposed to be.
    ForbiddenMinPinLength,
    /// [`Extension::cred_props`] was requested, but the required response was not sent back.
    MissingCredProps,
    /// [`Extension::prf`] was requested, but the required response was not sent back.
    MissingPrf,
    /// [`Extension::cred_protect`] was requested, but the required response was not sent back.
    MissingCredProtect,
    /// [`Extension::min_pin_length`] was requested, but the required response was not sent back.
    MissingMinPinLength,
    /// [`Extension::cred_protect`] was requested with the first policy, but the second policy was sent back.
    InvalidCredProtectValue(CredProtect, CredentialProtectionPolicy),
    /// [`Extension::prf`] was requested, but
    /// [`enabled`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-enabled) was `false`.
    InvalidPrfValue,
    /// [`Extension::prf`] was requested, but
    /// [`hmac-secret`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hmac-secret-extension)
    /// was `false`.
    InvalidHmacSecretValue,
    /// [`Extension::min_pin_length`] was requested, but
    /// [`minPinLength`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-minpinlength-extension)
    /// was sent set to the second value which is strictly less than the required first value.
    InvalidMinPinLength(FourToSixtyThree, FourToSixtyThree),
}
impl Display for ExtensionErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ForbiddenCredProps => {
                f.write_str("credProps was sent from the client, but it is not allowed")
            }
            Self::ForbiddenPrf => {
                f.write_str("prf info was sent from the client, but it is not allowed")
            }
            Self::ForbiddenCredProtect => {
                f.write_str("credProtect was sent from the client, but it is not allowed")
            }
            Self::ForbiddenHmacSecret => {
                f.write_str("hmac-secret info was sent from the client, but it is not allowed")
            }
            Self::ForbiddenMinPinLength => {
                f.write_str("minPinLength info was sent from the client, but it is not allowed")
            }
            Self::MissingCredProps => f.write_str("credProps was not sent from the client"),
            Self::MissingPrf => f.write_str("prf was not sent from the client"),
            Self::MissingCredProtect => f.write_str("credProtect was not sent from the client"),
            Self::MissingMinPinLength => f.write_str("minPinLength was not sent from the client"),
            Self::InvalidCredProtectValue(sent, rec) => write!(
                f,
                "credProtect was sent with {sent}, but {rec} was received",
            ),
            Self::InvalidPrfValue => f.write_str("prf was false"),
            Self::InvalidHmacSecretValue => f.write_str("hmac-secret was false"),
            Self::InvalidMinPinLength(sent, rec) => write!(
                f,
                "minPinLength was sent, but {rec} is strictly smaller than the required {sent}"
            ),
        }
    }
}
impl Error for ExtensionErr {}
/// Error returned by [`RegistrationServerState::verify`].
#[derive(Debug)]
pub enum RegCeremonyErr {
    /// [`PublicKeyCredentialCreationOptions::timeout`] was exceeded.
    Timeout,
    /// [`AuthenticatorAttestation::client_data_json`] could not be parsed by
    /// [`CollectedClientData::from_client_data_json`].
    CollectedClientData(CollectedClientDataErr),
    /// [`AuthenticatorAttestation::client_data_json`] could not be parsed by
    /// [`CollectedClientData::from_client_data_json_relaxed`].
    #[cfg(feature = "serde_relaxed")]
    CollectedClientDataRelaxed(SerdeJsonErr),
    /// [`AuthenticatorAttestation::attestation_object`] could not be parsed into
    /// [`AttestationObject`].
    AttestationObject(AttestationObjectErr),
    /// [`UncompressedPubKey`] was not valid.
    PubKey(PubKeyErr),
    /// [`PackedAttestation::signature`] was not valid.
    AttestationSignature,
    /// [`CollectedClientData::origin`] does not match one of the values in
    /// [`RegistrationVerificationOptions::allowed_origins`].
    OriginMismatch,
    /// [`CollectedClientData::cross_origin`] was `true`, but
    /// [`RegistrationVerificationOptions::allowed_top_origins`] was `None`.
    CrossOrigin,
    /// [`CollectedClientData::top_origin`] does not match one of the values in
    /// [`RegistrationVerificationOptions::allowed_top_origins`].
    TopOriginMismatch,
    /// [`PublicKeyCredentialCreationOptions::challenge`] and [`CollectedClientData::challenge`] don't match.
    ChallengeMismatch,
    /// The SHA-256 hash of [`PublicKeyCredentialCreationOptions::rp_id`] does not match [`AuthenticatorData::rp_id_hash`].
    RpIdHashMismatch,
    /// [`Flag::user_present`] was `false` despite [`CredentialCreationOptions::mediation`]
    /// being something other than [`CredentialMediationRequirement::Conditional`].
    UserNotPresent,
    /// [`AuthenticatorSelectionCriteria::user_verification`] was set to [`UserVerificationRequirement::Required`],
    /// but [`Flag::user_verified`] was `false`.
    UserNotVerified,
    /// [`Backup::NotEligible`] was not sent back despite [`BackupReq::NotEligible`].
    BackupEligible,
    /// [`Backup::NotEligible`] was sent back despite [`BackupReq::Eligible`].
    BackupNotEligible,
    /// [`Backup::Eligible`] was not sent back despite [`BackupReq::EligibleNotExists`].
    BackupExists,
    /// [`Backup::Exists`] was not sent back despite [`BackupReq::Exists`].
    BackupDoesNotExist,
    /// [`AuthenticatorAttachment`] was not sent back despite being required.
    MissingAuthenticatorAttachment,
    /// [`AuthenticatorAttachment::Platform`] or [`AuthenticatorAttachment::CrossPlatform`] was sent
    /// but [`AuthenticatorAttachment`] was not the same.
    AuthenticatorAttachmentMismatch,
    /// Variant returned when there is an issue with [`Extension`]s.
    Extension(ExtensionErr),
    /// [`PublicKeyCredentialCreationOptions::pub_key_cred_params`] does not contain an algorithm associated with
    /// [`AttestedCredentialData::credential_public_key`].
    PublicKeyAlgorithmMismatch,
    /// Variant returned when [`RegisteredCredential`] cannot be created due to invalid state.
    Credential(CredentialErr),
}
impl Display for RegCeremonyErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Timeout => CeremonyErr::<AttestationObjectErr>::Timeout.fmt(f),
            Self::CollectedClientData(ref err) => write!(f, "clientDataJSON could not be parsed: {err}"),
            #[cfg(feature = "serde_relaxed")]
            Self::CollectedClientDataRelaxed(ref err) => write!(f, "clientDataJSON could not be parsed: {err}"),
            Self::AttestationObject(err) => err.fmt(f),
            Self::PubKey(err) => err.fmt(f),
            Self::AttestationSignature => AuthRespErr::<AttestationObjectErr>::Signature.fmt(f),
            Self::OriginMismatch => CeremonyErr::<AttestationObjectErr>::OriginMismatch.fmt(f),
            Self::CrossOrigin => CeremonyErr::<AttestationObjectErr>::CrossOrigin.fmt(f),
            Self::TopOriginMismatch => CeremonyErr::<AttestationObjectErr>::TopOriginMismatch.fmt(f),
            Self::BackupEligible => CeremonyErr::<AttestationObjectErr>::BackupEligible.fmt(f),
            Self::BackupNotEligible => CeremonyErr::<AttestationObjectErr>::BackupNotEligible.fmt(f),
            Self::BackupExists => CeremonyErr::<AttestationObjectErr>::BackupExists.fmt(f),
            Self::BackupDoesNotExist => CeremonyErr::<AttestationObjectErr>::BackupDoesNotExist.fmt(f),
            Self::ChallengeMismatch => CeremonyErr::<AttestationObjectErr>::ChallengeMismatch.fmt(f),
            Self::RpIdHashMismatch => CeremonyErr::<AttestationObjectErr>::RpIdHashMismatch.fmt(f),
            Self::UserNotPresent => f.write_str("user was not present despite mediation not being conditional"),
            Self::UserNotVerified => CeremonyErr::<AttestationObjectErr>::UserNotVerified.fmt(f),
            Self::MissingAuthenticatorAttachment => f.write_str("the authenticator attachment modality was not sent despite being required"),
            Self::AuthenticatorAttachmentMismatch => f.write_str("the kind of authenticator requested (e.g., platform) was not used"),
            Self::Extension(ext) => ext.fmt(f),
            Self::PublicKeyAlgorithmMismatch => f.write_str(
                "the allowed public key algorithms does not contain the algorithm sent from the client",
            ),
            Self::Credential(err) => err.fmt(f),
        }
    }
}
impl Error for RegCeremonyErr {}
