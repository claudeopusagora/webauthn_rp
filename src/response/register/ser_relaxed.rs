#[cfg(doc)]
use super::super::Challenge;
use super::{
    super::{
        register::ser::{
            AuthenticatorAttestationVisitor, ClientExtensionsOutputsVisitor, AUTH_ATTEST_FIELDS,
            EXT_FIELDS,
        },
        ser::{AuthenticationExtensionsPrfOutputsHelper, ClientExtensions, PublicKeyCredential},
        ser_relaxed::AuthenticationExtensionsPrfValuesRelaxed,
    },
    ser::{AuthAttest, CredentialPropertiesOutputVisitor, PROPS_FIELDS},
    AttestationObject, AuthenticationExtensionsPrfOutputs, AuthenticatorAttestation,
    ClientExtensionsOutputs, CredentialPropertiesOutput, Registration,
};
use core::marker::PhantomData;
#[cfg(doc)]
use data_encoding::BASE64URL_NOPAD;
use serde::de::{Deserialize, Deserializer, Error, Unexpected};
/// `newtype` around `CredentialPropertiesOutput` with a "relaxed" [`Self::deserialize`] implementation.
#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug)]
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
    /// For the other fields, they are allowed to not exist or be `null`.
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
#[cfg(test)]
mod tests {
    use super::{
        super::{
            super::{super::request::register::CoseAlgorithmIdentifier, BASE64URL_NOPAD_ENC},
            cbor, AuthenticatorAttachment, ALG, EC2, EDDSA, ES256, ES384, KTY, OKP, RSA,
        },
        RegistrationRelaxed,
    };
    use ed25519_dalek::{pkcs8::EncodePublicKey, VerifyingKey};
    use p256::{
        elliptic_curve::sec1::{FromEncodedPoint as _, ToEncodedPoint as _},
        EncodedPoint as P256Pt, PublicKey as P256PubKey, SecretKey as P256Key,
    };
    use p384::{EncodedPoint as P384Pt, PublicKey as P384PubKey, SecretKey as P384Key};
    use rsa::{
        sha2::{Digest as _, Sha256},
        traits::PublicKeyParts,
        BigUint, RsaPrivateKey,
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
        let b64_cdata = BASE64URL_NOPAD_ENC.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD_ENC.encode(&att_obj[att_obj.len() - 113..]);
        let b64_key = BASE64URL_NOPAD_ENC.encode(pub_key.as_bytes());
        let b64_aobj = BASE64URL_NOPAD_ENC.encode(att_obj.as_slice());
        // Base case is valid.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
        // `id` and `rawId` mismatch.
        let mut err = Error::invalid_value(
            Unexpected::Bytes(
                BASE64URL_NOPAD_ENC
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `id`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // Missing `rawId`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `rawId`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `id` and the credential id in authenticator data mismatch.
        err = Error::invalid_value(
            Unexpected::Bytes(
                BASE64URL_NOPAD_ENC
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
                        "authenticatorData": BASE64URL_NOPAD_ENC.encode(bad_auth.as_slice()),
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null `authenticatorData`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `publicKeyAlgorithm`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
                    "publicKey": BASE64URL_NOPAD_ENC.encode(VerifyingKey::from_bytes(&[0; 32]).unwrap().to_public_key_der().unwrap().as_bytes()),
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `publicKey`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // Missing `transports`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // Duplicate `transports` are allowed.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .map_or(false, |reg| reg.0.response.transports.count() == 1));
        // `null` `transports`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // Unknown `transports`.
        err = Error::invalid_value(
            Unexpected::Str("Usb"),
            &"'ble', 'hybrid', 'internal', 'nfc', 'smart-card', or 'usb'",
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        )));
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `clientExtensionResults`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // Missing `type`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `type`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
        let b64_cdata = BASE64URL_NOPAD_ENC.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD_ENC.encode(&att_obj[att_obj.len() - 113..]);
        let b64_key = BASE64URL_NOPAD_ENC.encode(pub_key.as_bytes());
        let b64_aobj = BASE64URL_NOPAD_ENC.encode(att_obj.as_slice());
        // Base case is valid.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
        // `null` `credProps`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
        // `null` `prf`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
        // Unknown `clientExtensionResults`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
        // Missing `rk`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
        // `true` rk`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
        // `false` rk`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
                .map_or(false, |prf| prf.enabled)));
        // `false` `enabled`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
                .map_or(false, |prf| !prf.enabled)));
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
                .map_or(false, |prf| prf.enabled)));
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `first`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
                .map_or(false, |prf| prf.enabled)));
        // `null` `second`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
                .map_or(false, |prf| prf.enabled)));
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // Unknown `results` field.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
        let b64_cdata = BASE64URL_NOPAD_ENC.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD_ENC.encode(&att_obj[att_obj.len() - 148..]);
        let b64_key = BASE64URL_NOPAD_ENC.encode(pub_key.as_bytes());
        let b64_aobj = BASE64URL_NOPAD_ENC.encode(att_obj.as_slice());
        // Base case is valid.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `publicKeyAlgorithm`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
                    "publicKey": BASE64URL_NOPAD_ENC.encode(bad_pub_key.to_public_key_der().unwrap().as_bytes()),
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `publicKey`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
        let b64_cdata = BASE64URL_NOPAD_ENC.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD_ENC.encode(&att_obj[att_obj.len() - 181..]);
        let b64_key = BASE64URL_NOPAD_ENC.encode(pub_key.as_bytes());
        let b64_aobj = BASE64URL_NOPAD_ENC.encode(att_obj.as_slice());
        // Base case is valid.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
        // `publicKeyAlgorithm` mismatch.
        let mut err = Error::invalid_value(
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `publicKeyAlgorithm`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
                    "publicKey": BASE64URL_NOPAD_ENC.encode(bad_pub_key.to_public_key_der().unwrap().as_bytes()),
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
        // Missing `publicKey`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
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
        let p = BigUint::from_slice(
            [
                352691927, 1294578443, 816143558, 690659917, 1161596366, 1544791087, 3999549486,
                3319149924, 2349250979, 1304689381, 3959753736, 3377900978, 866506027, 1671521644,
                3926847564, 898221388, 3448219846, 494454484, 3915534864, 2869735916, 2456511629,
                3397234721, 3012775852, 3472309790, 1923617705, 2993441050, 3210302569, 3605331368,
                3352563766, 688081007, 4104512503, 4145593376,
            ]
            .as_slice(),
        );
        let p_2 = BigUint::from_slice(
            [
                4039514409, 964284038, 3230008587, 3320139220, 3562360334, 3165876926, 212773653,
                2752465512, 2973674888, 1717425549, 2084262803, 3585031058, 4162394935, 1428626842,
                1015474994, 3283774155, 2840050110, 190639246, 147241978, 2994256073, 4081014755,
                3102401369, 3547397148, 1545029057, 895305733, 2689179461, 1593439337, 3960057302,
                193068804, 2835123424, 4054880057, 4200258364,
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
        let b64_cdata = BASE64URL_NOPAD_ENC.encode(c_data_json.as_bytes());
        let b64_adata = BASE64URL_NOPAD_ENC.encode(&att_obj[att_obj.len() - 343..]);
        let b64_key = BASE64URL_NOPAD_ENC.encode(pub_key.as_bytes());
        let b64_aobj = BASE64URL_NOPAD_ENC.encode(att_obj.as_slice());
        // Base case is valid.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
            && reg.0.client_extension_results.prf.is_none()));
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `publicKeyAlgorithm`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `publicKey` mismatch.
        let bad_pub_key = RsaPrivateKey::from_components(
            BigUint::from_slice(
                [
                    1268883887, 2823353396, 2015459101, 2565332483, 1399879646, 2924146141,
                    4220770383, 1927962357, 4262532606, 2135651080, 1832605590, 1515549926,
                    3644825611, 4206568969, 2754000866, 320264886, 3679698234, 1661964299,
                    959358615, 2210230033, 2052419982, 355790524, 3278273908, 2619188662,
                    2625484501, 48052312, 1943153506, 1483277344, 3973029557, 4043176610,
                    855443528, 2857170908, 3890300047, 301219953, 568959626, 3742057218,
                    3248023740, 888348692, 4077005632, 3902164232, 2136970349, 581060407,
                    881283894, 706789292, 3469945706, 3899549796, 3027774213, 3918538918,
                    1736861679, 3096109311, 612338128, 3388510141, 3895712258, 2085822048,
                    3004690797, 3572406263, 3744148684, 179106196, 1147050987, 3212056692,
                    595539286, 1003275909, 17854028, 2642908175,
                ]
                .as_slice(),
            ),
            65537u32.into(),
            BigUint::from_slice(
                [
                    4219166081, 3411287400, 3981141108, 1678549103, 2990099628, 1028778896,
                    672985971, 2520258231, 1054615108, 2922409705, 1844757795, 1160015252,
                    1910592069, 468649647, 4013057473, 772236922, 1958956898, 2475335323,
                    3977796915, 1829655286, 1576008336, 2187384383, 2445706978, 1642531745,
                    1610593494, 4268513438, 3095769587, 1486118748, 4109728823, 2030327380,
                    2959206188, 681254334, 1353008441, 725092776, 2634942185, 1480646512,
                    390137741, 1392955456, 4172679229, 2746438782, 2237328976, 2974223876,
                    2535267247, 3282201811, 1453825287, 3948348329, 3639451225, 1053160223,
                    3867366405, 204601530, 2268984413, 4053930420, 2331079437, 2795201243,
                    621559743, 1420993793, 693127368, 2379843661, 4078948854, 4130031519,
                    1957410463, 3951952652, 1514579162, 1261104787,
                ]
                .as_slice(),
            ),
            vec![
                BigUint::from_slice(
                    [
                        477022167, 1829769280, 2090244202, 1551476276, 1157631474, 2890438663,
                        3030138742, 490022796, 816963781, 1097260329, 1043839249, 132356315,
                        2333006670, 2559626311, 4109838094, 1022025893, 518867669, 2331160934,
                        796532648, 1910610894, 4103647079, 3748718875, 3000444664, 2030629908,
                        2051410714, 1470584080, 3823425600, 150616493, 3406571229, 728760788,
                        1642158920, 3248110052,
                    ]
                    .as_slice(),
                ),
                BigUint::from_slice(
                    [
                        2563529193, 1846080031, 2674900518, 1429039465, 4196332559, 1876681390,
                        2277818219, 2814016273, 3312979285, 3981345183, 451288984, 3552968165,
                        2390674537, 2887399418, 103653441, 3997324899, 2875328107, 2697584733,
                        2018692127, 116301540, 2576747710, 1194942447, 2615930724, 3775252553,
                        808368511, 2384549107, 387191569, 980553943, 2487815891, 4238343336,
                        3546626429, 3494710460,
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
                    "publicKey": BASE64URL_NOPAD_ENC.encode(bad_pub_key.to_public_key_der().unwrap().as_bytes()),
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
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
        // `null` `publicKey`.
        assert!(serde_json::from_str::<RegistrationRelaxed>(
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
        .is_ok());
    }
}
