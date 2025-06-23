#[cfg(doc)]
use super::super::{super::request::register::CoseAlgorithmIdentifier, Challenge, CredentialId};
use super::{
    super::{
        register::ser::{
            AUTH_ATTEST_FIELDS, AttObj, AuthenticatorAttestationVisitor,
            ClientExtensionsOutputsVisitor, EXT_FIELDS,
        },
        ser::{
            AuthenticationExtensionsPrfOutputsHelper, Base64DecodedVal, ClientExtensions,
            PublicKeyCredential, Type,
        },
        ser_relaxed::AuthenticationExtensionsPrfValuesRelaxed,
    },
    AttestationObject, AuthenticationExtensionsPrfOutputs, AuthenticatorAttachment,
    AuthenticatorAttestation, ClientExtensionsOutputs, CredentialPropertiesOutput, Registration,
    ser::{AuthAttest, CredentialPropertiesOutputVisitor, PROPS_FIELDS},
};
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
};
use serde::de::{Deserialize, Deserializer, Error, MapAccess, Unexpected, Visitor};
/// `newtype` around `CredentialPropertiesOutput` with a "relaxed" [`Self::deserialize`] implementation.
#[derive(Clone, Copy, Debug)]
pub struct CredentialPropertiesOutputRelaxed(pub CredentialPropertiesOutput);
impl From<CredentialPropertiesOutputRelaxed> for CredentialPropertiesOutput {
    #[inline]
    fn from(value: CredentialPropertiesOutputRelaxed) -> Self {
        value.0
    }
}
impl<'de> Deserialize<'de> for CredentialPropertiesOutputRelaxed {
    /// Same as [`CredentialPropertiesOutput::deserialize`] except unknown keys are ignored.
    ///
    /// Note that duplicate keys are still forbidden.
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_struct(
                "CredentialPropertiesOutputRelaxed",
                PROPS_FIELDS,
                CredentialPropertiesOutputVisitor::<true>,
            )
            .map(Self)
    }
}
/// `newtype` around `AuthenticationExtensionsPrfOutputs` with a "relaxed" [`Self::deserialize`] implementation.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticationExtensionsPrfOutputsRelaxed(AuthenticationExtensionsPrfOutputs);
impl From<AuthenticationExtensionsPrfOutputsRelaxed> for AuthenticationExtensionsPrfOutputs {
    #[inline]
    fn from(value: AuthenticationExtensionsPrfOutputsRelaxed) -> Self {
        value.0
    }
}
impl<'de> Deserialize<'de> for AuthenticationExtensionsPrfOutputsRelaxed {
    /// Same as [`AuthenticationExtensionsPrfOutputs::deserialize`] except unknown keys are ignored.
    ///
    /// Note that duplicate keys are still forbidden;
    /// [`enabled`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-enabled) must still exist
    /// (and not be `null`); and
    /// [`results`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfoutputs-results) must not exist,
    /// be `null`, or be an
    /// [`AuthenticationExtensionsPRFValues`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues)
    /// such that unknown keys are ignored, duplicate keys are forbidden,
    /// [`first`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-first) is not required but
    /// if it exists it must be `null`, and
    /// [`second`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfvalues-second) can exist but
    /// must be `null` if so.
    #[inline]
    #[expect(clippy::unreachable, reason = "we want to crash when there is a bug")]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        AuthenticationExtensionsPrfOutputsHelper::<
            true,
            true,
            AuthenticationExtensionsPrfValuesRelaxed,
        >::deserialize(deserializer)
        .map(|v| {
            Self(AuthenticationExtensionsPrfOutputs {
                enabled: v.0.unwrap_or_else(|| {
                    unreachable!(
                        "there is a bug in AuthenticationExtensionsPrfOutputsHelper::deserialize"
                    )
                }),
            })
        })
    }
}
/// `newtype` around `ClientExtensionsOutputs` with a "relaxed" [`Self::deserialize`] implementation.
#[derive(Clone, Copy, Debug)]
pub struct ClientExtensionsOutputsRelaxed(pub ClientExtensionsOutputs);
impl ClientExtensions for ClientExtensionsOutputsRelaxed {
    fn empty() -> Self {
        Self(ClientExtensionsOutputs::empty())
    }
}
impl<'de> Deserialize<'de> for ClientExtensionsOutputsRelaxed {
    /// Same as [`ClientExtensionsOutputs::deserialize`] except unknown keys are ignored,
    /// [`credProps`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsclientoutputs-credprops) is
    /// `null` or deserialized via [`CredentialPropertiesOutputRelaxed::deserialize`], and
    /// [`prf`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsclientoutputs-prf) is
    /// `null` or deserialized via [`AuthenticationExtensionsPrfOutputsRelaxed::deserialize`].
    ///
    /// Note that duplicate keys are still forbidden.
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_struct(
                "ClientExtensionsOutputsRelaxed",
                EXT_FIELDS,
                ClientExtensionsOutputsVisitor::<
                    true,
                    CredentialPropertiesOutputRelaxed,
                    AuthenticationExtensionsPrfOutputsRelaxed,
                >(PhantomData),
            )
            .map(Self)
    }
}
/// `newtype` around `AuthAttest` with a "relaxed" [`Self::deserialize`] implementation.
struct AuthAttestRelaxed(pub AuthAttest);
impl<'de> Deserialize<'de> for AuthAttestRelaxed {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_struct(
                "AuthenticatorAttestation",
                AUTH_ATTEST_FIELDS,
                AuthenticatorAttestationVisitor::<true>,
            )
            .map(Self)
    }
}
/// `newtype` around `AuthenticatorAttestation` with a "relaxed" [`Self::deserialize`] implementation.
#[derive(Debug)]
pub struct AuthenticatorAttestationRelaxed(pub AuthenticatorAttestation);
impl<'de> Deserialize<'de> for AuthenticatorAttestationRelaxed {
    /// Same as [`AuthenticatorAttestation::deserialize`] except unknown keys are ignored and only
    /// [`clientDataJSON`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-clientdatajson)
    /// and
    /// [`attestationObject`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-attestationobject)
    /// are required (and must not be `null`). For the other fields, they are allowed to not exist or be `null`.
    ///
    /// Note that duplicate keys are still forbidden, and data matching still applies when applicable.
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        AuthAttestRelaxed::deserialize(deserializer).map(|v| Self(v.0.attest))
    }
}
/// `newtype` around `Registration` with a "relaxed" [`Self::deserialize`] implementation.
#[derive(Debug)]
pub struct RegistrationRelaxed(pub Registration);
impl<'de> Deserialize<'de> for RegistrationRelaxed {
    /// Same as [`Registration::deserialize`] except unknown keys are ignored,
    /// [`response`](https://www.w3.org/TR/webauthn-3/#dom-registrationresponsejson-response) is deserialized
    /// via [`AuthenticatorAttestationRelaxed::deserialize`],
    /// [`clientExtensionResults`](https://www.w3.org/TR/webauthn-3/#dom-registrationresponsejson-clientextensionresults)
    /// is `null` or deserialized via [`ClientExtensionsOutputsRelaxed::deserialize`], and only `response` is required.
    /// `id`, `rawId`, and `type` are allowed to not exist. For the other fields, they are allowed to not exist or
    /// be `null`.
    ///
    /// Note that duplicate keys are still forbidden, and data matching still applies when applicable.
    #[expect(clippy::indexing_slicing, reason = "comment justifies its correctness")]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        PublicKeyCredential::<true, true, AuthAttestRelaxed, ClientExtensionsOutputsRelaxed>::deserialize(deserializer).and_then(|cred| {
            cred.id.map_or_else(|| Ok(()), |id| {
                cred.response.0.cred_info.map_or_else(
                    || AttestationObject::try_from(cred.response.0.attest.attestation_object()).map_err(Error::custom).and_then(|att_obj| {
                        if id == att_obj.auth_data.attested_credential_data.credential_id {
                            Ok(())
                        } else {
                            Err(Error::invalid_value(Unexpected::Bytes(id.as_ref()), &format!("id, rawId, and the credential id in the attested credential data to all match: {:?}", att_obj.auth_data.attested_credential_data.credential_id.0).as_str()))
                        }
                    }),
                    // `start` and `last` were calculated based on `cred.response.attest.attestation_object()`
                    // and represent the starting and ending index of the `CredentialId`; therefore this is correct
                    // let alone won't `panic`.
                    |(start, last)| if id.0 == cred.response.0.attest.attestation_object()[start..last] {
                        Ok(())
                    } else {
                        Err(Error::invalid_value(Unexpected::Bytes(id.as_ref()), &format!("id, rawId, and the credential id in the attested credential data to all match: {:?}", &cred.response.0.attest.attestation_object()[start..last]).as_str()))
                    }
                )
            }).map(|()| {
                Self(Registration { response: cred.response.0.attest, authenticator_attachment: cred.authenticator_attachment, client_extension_results: cred.client_extension_results.0 })
            })
        })
    }
}
/// `newtype` around `Registration` with a custom [`Self::deserialize`] implementation.
#[derive(Debug)]
pub struct CustomRegistration(pub Registration);
impl<'de> Deserialize<'de> for CustomRegistration {
    /// Despite the spec having a
    /// [pre-defined format](https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson) that clients
    /// can follow, the downside is the superfluous data it contains.
    ///
    /// There simply is no reason to send the [`CredentialId`] _four_ times. This redundant data puts RPs in
    /// a position where they either ignore the data or parse the data to ensure no contradictions exist
    /// (e.g., [FIDO conformance requires one to verify `id` and `rawId` exist and match](https://github.com/w3c/webauthn/issues/2119#issuecomment-2287875401)).
    ///
    /// While [`Registration::deserialize`] _strictly_ adheres to the JSON definition (e.g., it requires `publicKey`
    /// to exist and match with what is in both `authenticatorData` and `attestationObject` when the underlying
    /// algorithm is not [`CoseAlgorithmIdentifier::Es384`]), this implementation
    /// strictly disallows superfluous data. Specifically the following JSON is required to be sent where duplicate
    /// and unknown keys are disallowed:
    ///
    /// ```json
    /// {
    ///   "attestationObject": <base64url string>,
    ///   "authenticatorAttachment": null | "platform" | "cross-platform",
    ///   "clientDataJSON": <base64url string>,
    ///   "clientExtensionResults": <see ClientExtensionsOutputs::deserialize>,
    ///   "transports": <see AuthTransports::deserialize>,
    ///   "type": "public-key"
    /// }
    /// ```
    ///
    /// All of the above keys are required with the exceptions of `"authenticatorAttachment"` and `"type"`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::response::register::ser_relaxed::CustomRegistration;
    /// assert!(
    ///     // The below payload is technically valid, but `RegistrationServerState::verify` will fail
    ///     // since the attestationObject is not valid. This is true for `Registration::deserialize`
    ///     // as well since attestationObject parsing is always deferred.
    ///     serde_json::from_str::<CustomRegistration>(
    ///         r#"{
    ///             "transports": ["usb"],
    ///             "attestationObject": "AA",
    ///             "authenticatorAttachment": "cross-platform",
    ///             "clientExtensionResults": {},
    ///             "clientDataJSON": "AA",
    ///             "type": "public-key"
    ///         }"#
    ///     ).is_ok());
    /// ```
    #[expect(
        clippy::too_many_lines,
        reason = "want to hide; thus don't want to put in an outer scope"
    )]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `CustomRegistration`.
        struct CustomRegistrationVisitor;
        impl<'d> Visitor<'d> for CustomRegistrationVisitor {
            type Value = CustomRegistration;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("CustomRegistration")
            }
            #[expect(
                clippy::too_many_lines,
                reason = "want to hide; thus don't want to put in an outer scope"
            )]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Fields in the JSON.
                enum Field {
                    /// `attestationObject` key.
                    AttestationObject,
                    /// `authenticatorAttachment` key.
                    AuthenticatorAttachment,
                    /// `clientDataJSON` key.
                    ClientDataJson,
                    /// `clientExtensionResults` key.
                    ClientExtensionResults,
                    /// `transports` key.
                    Transports,
                    /// `type` key.
                    Type,
                }
                impl<'e> Deserialize<'e> for Field {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: Deserializer<'e>,
                    {
                        /// `Visitor` for `Field`.
                        struct FieldVisitor;
                        impl Visitor<'_> for FieldVisitor {
                            type Value = Field;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                write!(
                                    formatter,
                                    "'{ATTESTATION_OBJECT}', '{AUTHENTICATOR_ATTACHMENT}', '{CLIENT_DATA_JSON}', '{CLIENT_EXTENSION_RESULTS}', '{TRANSPORTS}', or '{TYPE}'"
                                )
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    ATTESTATION_OBJECT => Ok(Field::AttestationObject),
                                    AUTHENTICATOR_ATTACHMENT => Ok(Field::AuthenticatorAttachment),
                                    CLIENT_DATA_JSON => Ok(Field::ClientDataJson),
                                    CLIENT_EXTENSION_RESULTS => Ok(Field::ClientExtensionResults),
                                    TRANSPORTS => Ok(Field::Transports),
                                    TYPE => Ok(Field::Type),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                let mut attestation_object = None;
                let mut authenticator_attachment = None;
                let mut client_data_json = None;
                let mut ext = None;
                let mut transports = None;
                let mut typ = false;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::AttestationObject => {
                            if attestation_object.is_some() {
                                return Err(Error::duplicate_field(ATTESTATION_OBJECT));
                            }
                            attestation_object =
                                map.next_value::<AttObj>().map(|val| Some(val.0))?;
                        }
                        Field::AuthenticatorAttachment => {
                            if authenticator_attachment.is_some() {
                                return Err(Error::duplicate_field(AUTHENTICATOR_ATTACHMENT));
                            }
                            authenticator_attachment = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::ClientDataJson => {
                            if client_data_json.is_some() {
                                return Err(Error::duplicate_field(CLIENT_DATA_JSON));
                            }
                            client_data_json = map
                                .next_value::<Base64DecodedVal>()
                                .map(|val| Some(val.0))?;
                        }
                        Field::ClientExtensionResults => {
                            if ext.is_some() {
                                return Err(Error::duplicate_field(CLIENT_EXTENSION_RESULTS));
                            }
                            ext = map.next_value().map(Some)?;
                        }
                        Field::Transports => {
                            if transports.is_some() {
                                return Err(Error::duplicate_field(TRANSPORTS));
                            }
                            transports = map.next_value().map(Some)?;
                        }
                        Field::Type => {
                            if typ {
                                return Err(Error::duplicate_field(TYPE));
                            }
                            typ = map.next_value::<Type>().map(|_| true)?;
                        }
                    }
                }
                attestation_object
                    .ok_or_else(|| Error::missing_field(ATTESTATION_OBJECT))
                    .and_then(|att_obj| {
                        client_data_json
                            .ok_or_else(|| Error::missing_field(CLIENT_DATA_JSON))
                            .and_then(|c_data| {
                                ext.ok_or_else(|| Error::missing_field(CLIENT_EXTENSION_RESULTS))
                                    .and_then(|client_extension_results| {
                                        transports
                                            .ok_or_else(|| Error::missing_field(TRANSPORTS))
                                            .map(|trans| {
                                                CustomRegistration(Registration {
                                                    response: AuthenticatorAttestation::new(
                                                        c_data, att_obj, trans,
                                                    ),
                                                    authenticator_attachment:
                                                        authenticator_attachment.map_or(
                                                            AuthenticatorAttachment::None,
                                                            |auth_attach| {
                                                                auth_attach.unwrap_or(
                                                                    AuthenticatorAttachment::None,
                                                                )
                                                            },
                                                        ),
                                                    client_extension_results,
                                                })
                                            })
                                    })
                            })
                    })
            }
        }
        /// `attestationObject` key.
        const ATTESTATION_OBJECT: &str = "attestationObject";
        /// `authenticatorAttachment` key.
        const AUTHENTICATOR_ATTACHMENT: &str = "authenticatorAttachment";
        /// `clientDataJSON` key.
        const CLIENT_DATA_JSON: &str = "clientDataJSON";
        /// `clientExtensionResults` key.
        const CLIENT_EXTENSION_RESULTS: &str = "clientExtensionResults";
        /// `transports` key.
        const TRANSPORTS: &str = "transports";
        /// `type` key.
        const TYPE: &str = "type";
        /// Fields.
        const FIELDS: &[&str; 6] = &[
            ATTESTATION_OBJECT,
            AUTHENTICATOR_ATTACHMENT,
            CLIENT_DATA_JSON,
            CLIENT_EXTENSION_RESULTS,
            TRANSPORTS,
            TYPE,
        ];
        deserializer.deserialize_struct("CustomRegistration", FIELDS, CustomRegistrationVisitor)
    }
}
#[cfg(test)]
mod tests {
    use super::{
        super::{
            super::super::request::register::CoseAlgorithmIdentifier, ALG, AuthenticatorAttachment,
            EC2, EDDSA, ES256, ES384, KTY, OKP, RSA, cbor,
        },
        CustomRegistration, RegistrationRelaxed,
    };
    use data_encoding::BASE64URL_NOPAD;
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
        let b64_cdata = BASE64URL_NOPAD.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD.encode(&att_obj[att_obj.len() - 113..]);
        let b64_key = BASE64URL_NOPAD.encode(pub_key.as_bytes());
        let b64_aobj = BASE64URL_NOPAD.encode(att_obj.as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .map_or(false, |reg| reg.0.response.client_data_json
                == c_data_json.as_bytes()
                && reg.0.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.0.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.0.response.transports.count() == 6
                && matches!(
                    reg.0.authenticator_attachment,
                    AuthenticatorAttachment::CrossPlatform
                )
                && reg.0.client_extension_results.cred_props.is_none()
                && reg.0.client_extension_results.prf.is_none())
        );
        // `id` and `rawId` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Bytes(
                BASE64URL_NOPAD
                    .decode("ABABABABABABABABABABAA".as_bytes())
                    .unwrap()
                    .as_slice(),
            ),
            &format!("id and rawId to match: CredentialId({:?})", [0; 16]).as_str(),
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `id`.
        err = Error::invalid_type(Unexpected::Other("null"), &"CredentialId")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
                serde_json::json!({
                    "id": null,
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
        // Missing `rawId`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `rawId`.
        err = Error::invalid_type(Unexpected::Other("null"), &"CredentialId")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
                BASE64URL_NOPAD
                    .decode("ABABABABABABABABABABAA".as_bytes())
                    .unwrap()
                    .as_slice(),
            ),
            &format!("id, rawId, and the credential id in the attested credential data to all match: {:?}", [0; 16]).as_str(),
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
                serde_json::json!({
                    "id": "AAAAAAAAAAAAAAAAAAAAAA",
                    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                    "response": {
                        "clientDataJSON": b64_cdata,
                        "authenticatorData": BASE64URL_NOPAD.encode(bad_auth.as_slice()),
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null `authenticatorData`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `publicKeyAlgorithm` mismatch.
        err = Error::invalid_value(
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Es256).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Eddsa).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `publicKeyAlgorithm`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
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
        assert_eq!(serde_json::from_str::<RegistrationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "transports": [],
                    "publicKey": BASE64URL_NOPAD.encode(VerifyingKey::from_bytes(&[0; 32]).unwrap().to_public_key_der().unwrap().as_bytes()),
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
        // Missing `publicKey`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `publicKey`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Missing `transports`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Duplicate `transports` are allowed.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .map_or(false, |reg| reg.0.response.transports.count() == 1)
        );
        // `null` `transports`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Unknown `transports`.
        err = Error::invalid_value(
            Unexpected::Str("Usb"),
            &"'ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', or 'usb'",
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
                reg.0.authenticator_attachment,
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `clientExtensionResults`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Missing `type`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `type`.
        err = Error::invalid_type(Unexpected::Other("null"), &"public-key")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
                serde_json::json!(null).to_string().as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Empty.
        err = Error::missing_field("response").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(serde_json::json!({}).to_string().as_str())
                .unwrap_err()
                .to_string()
                .into_bytes()[..err.len()],
            err
        );
        // Unknown field in `response`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Duplicate field in `response`.
        err = Error::duplicate_field("transports")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Duplicate field in `PublicKeyCredential`.
        err = Error::duplicate_field("id").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        // Base case is correct.
        assert!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "attestationObject": b64_aobj,
                    "authenticatorAttachment": "cross-platform",
                    "clientDataJSON": b64_cdata,
                    "clientExtensionResults": {},
                    "transports": ["ble", "usb", "hybrid", "internal", "nfc", "smart-card"],
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.0.response.client_data_json
                == c_data_json.as_bytes()
                && reg.0.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.0.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.0.response.transports.count() == 6
                && matches!(
                    reg.0.authenticator_attachment,
                    AuthenticatorAttachment::CrossPlatform
                )
                && reg.0.client_extension_results.cred_props.is_none()
                && reg.0.client_extension_results.prf.is_none())
        );
        // Missing `transports`.
        err = Error::missing_field("transports").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "attestationObject": b64_aobj,
                    "authenticatorAttachment": "cross-platform",
                    "clientDataJSON": b64_cdata,
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
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "attestationObject": b64_aobj,
                    "authenticatorAttachment": "cross-platform",
                    "clientDataJSON": b64_cdata,
                    "clientExtensionResults": {},
                    "transports": ["usb", "usb"],
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.0.response.transports.count() == 1)
        );
        // `null` `transports`.
        err = Error::invalid_type(Unexpected::Other("null"), &"AuthTransports")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
                    "transports": null,
                    "attestationObject": b64_aobj,
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
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "attestationObject": b64_aobj,
                    "authenticatorAttachment": "cross-platform",
                    "clientDataJSON": b64_cdata,
                    "clientExtensionResults": {},
                    "transports": ["Usb"],
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
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "attestationObject": b64_aobj,
                    "authenticatorAttachment": null,
                    "clientDataJSON": b64_cdata,
                    "clientExtensionResults": {},
                    "transports": [],
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| matches!(
                reg.0.authenticator_attachment,
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
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "attestationObject": b64_aobj,
                    "authenticatorAttachment": "Platform",
                    "clientDataJSON": b64_cdata,
                    "clientExtensionResults": {},
                    "transports": [],
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
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "transports": [],
                    "attestationObject": b64_aobj,
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
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": null,
                    "transports": [],
                    "attestationObject": b64_aobj,
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
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
                    "transports": [],
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
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
                    "transports": [],
                    "attestationObject": null,
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
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
                    "transports": [],
                    "attestationObject": b64_aobj,
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
        err = Error::invalid_type(Unexpected::Other("null"), &"ClientExtensionsOutputs")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
                    "transports": [],
                    "attestationObject": b64_aobj,
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
        assert!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "attestationObject": b64_aobj,
                    "clientDataJSON": b64_cdata,
                    "clientExtensionResults": {},
                    "transports": []
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |_| true)
        );
        // `null` `type`.
        err = Error::invalid_type(Unexpected::Other("null"), &"public-key")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "attestationObject": b64_aobj,
                    "clientDataJSON": b64_cdata,
                    "clientExtensionResults": {},
                    "transports": [],
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
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
                    "transports": [],
                    "attestationObject": b64_aobj,
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
        err = Error::invalid_type(Unexpected::Other("null"), &"CustomRegistration")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!(null).to_string().as_str()
            )
            .unwrap_err()
            .to_string()
            .into_bytes()[..err.len()],
            err
        );
        // Empty.
        err = Error::missing_field("attestationObject")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomRegistration>(serde_json::json!({}).to_string().as_str())
                .unwrap_err()
                .to_string()
                .into_bytes()[..err.len()],
            err
        );
        // Unknown field.
        err = Error::unknown_field(
            "foo",
            [
                "attestationObject",
                "authenticatorAttachment",
                "clientDataJSON",
                "clientExtensionResults",
                "transports",
                "type",
            ]
            .as_slice(),
        )
        .to_string()
        .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
                    "transports": [],
                    "attestationObject": b64_aobj,
                    "foo": true,
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
        // Duplicate field.
        err = Error::duplicate_field("transports")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<CustomRegistration>(
                format!(
                    "{{
                       \"clientDataJSON\": \"{b64_cdata}\",
                       \"transports\": [],
                       \"attestationObject\": \"{b64_aobj}\",
                       \"transports\": []
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
        let b64_cdata = BASE64URL_NOPAD.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD.encode(&att_obj[att_obj.len() - 113..]);
        let b64_key = BASE64URL_NOPAD.encode(pub_key.as_bytes());
        let b64_aobj = BASE64URL_NOPAD.encode(att_obj.as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .map_or(false, |reg| reg.0.response.client_data_json
                == c_data_json.as_bytes()
                && reg.0.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.0.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.0.response.transports.is_empty()
                && matches!(
                    reg.0.authenticator_attachment,
                    AuthenticatorAttachment::None
                )
                && reg.0.client_extension_results.cred_props.is_none()
                && reg.0.client_extension_results.prf.is_none())
        );
        // `null` `credProps`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .is_none()
                && reg.0.client_extension_results.prf.is_none())
        );
        // `null` `prf`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .is_none()
                && reg.0.client_extension_results.prf.is_none())
        );
        // Unknown `clientExtensionResults`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Duplicate field.
        let mut err = Error::duplicate_field("credProps").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .map_or(false, |props| props.rk.is_none())
                && reg.0.client_extension_results.prf.is_none())
        );
        // Missing `rk`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .map_or(false, |props| props.rk.is_none())
                && reg.0.client_extension_results.prf.is_none())
        );
        // `true` rk`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .map_or(false, |props| props.rk.unwrap_or_default())
                && reg.0.client_extension_results.prf.is_none())
        );
        // `false` rk`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .map_or(false, |props| props.rk.map_or(false, |rk| !rk))
                && reg.0.client_extension_results.prf.is_none())
        );
        // Invalid `rk`.
        err = Error::invalid_type(Unexpected::Unsigned(3), &"a boolean")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Duplicate field in `credProps`.
        err = Error::duplicate_field("rk").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .is_none()
                && reg
                    .0
                    .client_extension_results
                    .prf
                    .map_or(false, |prf| prf.enabled))
        );
        // `false` `enabled`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .is_none()
                && reg
                    .0
                    .client_extension_results
                    .prf
                    .map_or(false, |prf| !prf.enabled))
        );
        // Invalid `enabled`.
        err = Error::invalid_type(Unexpected::Unsigned(3), &"a boolean")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .is_none()
                && reg
                    .0
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
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `first`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .is_none()
                && reg
                    .0
                    .client_extension_results
                    .prf
                    .map_or(false, |prf| prf.enabled))
        );
        // `null` `second`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
                .0
                .client_extension_results
                .cred_props
                .is_none()
                && reg
                    .0
                    .client_extension_results
                    .prf
                    .map_or(false, |prf| prf.enabled))
        );
        // Non-`null` `first`.
        err = Error::invalid_type(Unexpected::Option, &"null")
            .to_string()
            .into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            serde_json::from_str::<RegistrationRelaxed>(
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Unknown `results` field.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Duplicate field in `results`.
        err = Error::duplicate_field("first").to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        let b64_cdata = BASE64URL_NOPAD.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD.encode(&att_obj[att_obj.len() - 148..]);
        let b64_key = BASE64URL_NOPAD.encode(pub_key.as_bytes());
        let b64_aobj = BASE64URL_NOPAD.encode(att_obj.as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .map_or(false, |reg| reg.0.response.client_data_json
                == c_data_json.as_bytes()
                && reg.0.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.0.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.0.response.transports.is_empty()
                && matches!(
                    reg.0.authenticator_attachment,
                    AuthenticatorAttachment::None
                )
                && reg.0.client_extension_results.cred_props.is_none()
                && reg.0.client_extension_results.prf.is_none())
        );
        // `publicKeyAlgorithm` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Eddsa).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Es256).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `publicKeyAlgorithm`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
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
        assert_eq!(serde_json::from_str::<RegistrationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "transports": [],
                    "publicKey": BASE64URL_NOPAD.encode(bad_pub_key.to_public_key_der().unwrap().as_bytes()),
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
        // Missing `publicKey`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `publicKey`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Base case is valid.
        assert!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
                    "transports": [],
                    "attestationObject": b64_aobj,
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.0.response.client_data_json
                == c_data_json.as_bytes()
                && reg.0.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.0.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.0.response.transports.is_empty()
                && matches!(
                    reg.0.authenticator_attachment,
                    AuthenticatorAttachment::None
                )
                && reg.0.client_extension_results.cred_props.is_none()
                && reg.0.client_extension_results.prf.is_none())
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
        let b64_cdata = BASE64URL_NOPAD.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD.encode(&att_obj[att_obj.len() - 181..]);
        let b64_key = BASE64URL_NOPAD.encode(pub_key.as_bytes());
        let b64_aobj = BASE64URL_NOPAD.encode(att_obj.as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .map_or(false, |reg| reg.0.response.client_data_json
                == c_data_json.as_bytes()
                && reg.0.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.0.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.0.response.transports.is_empty()
                && matches!(
                    reg.0.authenticator_attachment,
                    AuthenticatorAttachment::None
                )
                && reg.0.client_extension_results.cred_props.is_none()
                && reg.0.client_extension_results.prf.is_none())
        );
        // `publicKeyAlgorithm` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Es256).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Es384).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `publicKeyAlgorithm`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
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
        assert_eq!(serde_json::from_str::<RegistrationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "transports": [],
                    "publicKey": BASE64URL_NOPAD.encode(bad_pub_key.to_public_key_der().unwrap().as_bytes()),
                    "publicKeyAlgorithm": -35,
                    "attestationObject": b64_aobj,
                },
                "clientExtensionResults": {},
                "type": "public-key"
            }).to_string().as_str()
        ).unwrap_err().to_string().into_bytes()[..err.len()], err);
        // Missing `publicKey`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Eddsa).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Es384).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        // `null` `publicKey`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Eddsa).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Es384).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        // Base case is valid.
        assert!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
                    "transports": [],
                    "attestationObject": b64_aobj,
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.0.response.client_data_json
                == c_data_json.as_bytes()
                && reg.0.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.0.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.0.response.transports.is_empty()
                && matches!(
                    reg.0.authenticator_attachment,
                    AuthenticatorAttachment::None
                )
                && reg.0.client_extension_results.cred_props.is_none()
                && reg.0.client_extension_results.prf.is_none())
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
        let b64_cdata = BASE64URL_NOPAD.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD.encode(&att_obj[att_obj.len() - 343..]);
        let b64_key = BASE64URL_NOPAD.encode(pub_key.as_bytes());
        let b64_aobj = BASE64URL_NOPAD.encode(att_obj.as_slice());
        // Base case is valid.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .map_or(false, |reg| reg.0.response.client_data_json
                == c_data_json.as_bytes()
                && reg.0.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.0.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.0.response.transports.is_empty()
                && matches!(
                    reg.0.authenticator_attachment,
                    AuthenticatorAttachment::None
                )
                && reg.0.client_extension_results.cred_props.is_none()
                && reg.0.client_extension_results.prf.is_none())
        );
        // `publicKeyAlgorithm` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Other(&format!("{:?}", CoseAlgorithmIdentifier::Eddsa).as_str()),
            &format!("public key algorithm to match the algorithm associated with the public key within the attestation object: {:?}", CoseAlgorithmIdentifier::Rs256).as_str()
        )
        .to_string().into_bytes();
        assert_eq!(
            serde_json::from_str::<RegistrationRelaxed>(
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
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `publicKeyAlgorithm`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
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
        assert_eq!(serde_json::from_str::<RegistrationRelaxed>(
            serde_json::json!({
                "id": "AAAAAAAAAAAAAAAAAAAAAA",
                "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
                "response": {
                    "clientDataJSON": b64_cdata,
                    "authenticatorData": b64_adata,
                    "transports": [],
                    "publicKey": BASE64URL_NOPAD.encode(bad_pub_key.to_public_key_der().unwrap().as_bytes()),
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
        // Missing `publicKey`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // `null` `publicKey`.
        assert!(
            serde_json::from_str::<RegistrationRelaxed>(
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
            .is_ok()
        );
        // Base case is valid.
        assert!(
            serde_json::from_str::<CustomRegistration>(
                serde_json::json!({
                    "clientDataJSON": b64_cdata,
                    "transports": [],
                    "attestationObject": b64_aobj,
                    "clientExtensionResults": {},
                    "type": "public-key"
                })
                .to_string()
                .as_str()
            )
            .map_or(false, |reg| reg.0.response.client_data_json
                == c_data_json.as_bytes()
                && reg.0.response.attestation_object_and_c_data_hash[..att_obj.len()]
                    == att_obj
                && reg.0.response.attestation_object_and_c_data_hash[att_obj.len()..]
                    == *Sha256::digest(c_data_json.as_bytes()).as_slice()
                && reg.0.response.transports.is_empty()
                && matches!(
                    reg.0.authenticator_attachment,
                    AuthenticatorAttachment::None
                )
                && reg.0.client_extension_results.cred_props.is_none()
                && reg.0.client_extension_results.prf.is_none())
        );
    }
}
