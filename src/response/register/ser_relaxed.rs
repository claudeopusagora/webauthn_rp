#[cfg(test)]
mod tests;
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
                        if id.as_ref() == att_obj.auth_data.attested_credential_data.credential_id.as_ref() {
                            Ok(())
                        } else {
                            Err(Error::invalid_value(Unexpected::Bytes(id.as_ref()), &format!("id, rawId, and the credential id in the attested credential data to all match: {:?}", att_obj.auth_data.attested_credential_data.credential_id.0).as_str()))
                        }
                    }),
                    // `start` and `last` were calculated based on `cred.response.attest.attestation_object()`
                    // and represent the starting and ending index of the `CredentialId`; therefore this is correct
                    // let alone won't `panic`.
                    |(start, last)| if *id.0 == cred.response.0.attest.attestation_object()[start..last] {
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
