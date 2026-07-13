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
mod spki;
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
