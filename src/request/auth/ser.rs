#[cfg(doc)]
use super::ExtensionReq;
use super::{
    super::{
        super::response::ser::Null,
        ser::{DEFAULT_RP_ID, PrfHelper},
    },
    AllowedCredential, AllowedCredentials, Challenge, CredentialMediationRequirement,
    Credentials as _, DiscoverableAuthenticationClientState, DiscoverableCredentialRequestOptions,
    Extension, FIVE_MINUTES, Hint, NonDiscoverableAuthenticationClientState,
    NonDiscoverableCredentialRequestOptions, PrfInput, PrfInputOwned,
    PublicKeyCredentialRequestOptions, RpId, UserVerificationRequirement,
};
use core::{
    fmt::{self, Formatter},
    num::NonZeroU32,
};
use serde::{
    de::{Deserialize, Deserializer, Error, MapAccess, Visitor},
    ser::{Serialize, SerializeMap as _, SerializeStruct as _, Serializer},
};
impl Serialize for PrfInputOwned {
    /// See [`PrfInput::serialize`]
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        PrfInput {
            first: self.first.as_slice(),
            second: self.second.as_deref(),
        }
        .serialize(serializer)
    }
}
impl Serialize for AllowedCredential {
    /// Serializes `self` to conform with
    /// [`PublicKeyCredentialDescriptorJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptorjson).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// # use webauthn_rp::{bin::Decode, response::bin::DecodeAuthTransportsErr};
    /// # use webauthn_rp::{
    /// #     request::{auth::AllowedCredential, PublicKeyCredentialDescriptor},
    /// #     response::{AuthTransports, CredentialId},
    /// # };
    /// /// Retrieves the `AuthTransports` associated with the unique `cred_id`
    /// /// from the database.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// fn get_transports(cred_id: CredentialId<&[u8]>) -> Result<AuthTransports, DecodeAuthTransportsErr> {
    ///     // ⋮
    /// #     AuthTransports::decode(32)
    /// }
    /// // `CredentialId::try_from` only exists when `custom` is enabled; and even then, it is
    /// // likely never needed since the `CredentialId` was originally sent from the client and is likely
    /// // stored in a database which would be fetched by `UserHandle` or `Authentication::raw_id`.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let id = CredentialId::try_from(vec![0; 16])?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports = get_transports((&id).into())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(
    ///     serde_json::to_string(&AllowedCredential::from(PublicKeyCredentialDescriptor {
    ///         id,
    ///         transports
    ///     })).unwrap(),
    ///     r#"{"type":"public-key","id":"AAAAAAAAAAAAAAAAAAAAAA","transports":["usb"]}"#
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.credential.serialize(serializer)
    }
}
impl Serialize for AllowedCredentials {
    /// Serializes `self` to conform with
    /// [`allowCredentials`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptionsjson-allowcredentials).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// # use webauthn_rp::{bin::Decode, response::bin::DecodeAuthTransportsErr};
    /// # use webauthn_rp::{
    /// #     request::{auth::AllowedCredentials, PublicKeyCredentialDescriptor, Credentials},
    /// #     response::{AuthTransports, CredentialId},
    /// # };
    /// /// Retrieves the `AuthTransports` associated with the unique `cred_id`
    /// /// from the database.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// fn get_transports(cred_id: CredentialId<&[u8]>) -> Result<AuthTransports, DecodeAuthTransportsErr> {
    ///     // ⋮
    /// #     AuthTransports::decode(32)
    /// }
    /// // `CredentialId::try_from` only exists when `custom` is enabled; and even then, it is
    /// // likely never needed since the `CredentialId` was originally sent from the client and is likely
    /// // stored in a database which would be fetched by `UserHandle` or `Authentication::raw_id`.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let id = CredentialId::try_from(vec![0; 16])?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports = get_transports((&id).into())?;
    /// let mut creds = AllowedCredentials::with_capacity(1);
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// creds.push(PublicKeyCredentialDescriptor { id, transports }.into());
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(
    ///     serde_json::to_string(&creds).unwrap(),
    ///     r#"[{"type":"public-key","id":"AAAAAAAAAAAAAAAAAAAAAA","transports":["usb"]}]"#
    /// );
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.creds.serialize(serializer)
    }
}
/// [`evalByCredential`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfinputs-evalbycredential).
struct PrfCreds<'a>(&'a AllowedCredentials);
impl Serialize for PrfCreds<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_map(Some(self.0.prf_count))
            .and_then(|mut ser| {
                self.0
                    .creds
                    .iter()
                    .try_fold((), |(), cred| {
                        cred.extension.prf.as_ref().map_or(Ok(()), |input| {
                            ser.serialize_entry(&cred.credential.id, input)
                        })
                    })
                    .and_then(|()| ser.end())
            })
    }
}
/// [`AuthenticationExtensionsPRFInputs`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfinputs).
struct PrfInputs<'a, 'b, 'c> {
    /// [`eval`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfinputs-eval).
    eval: Option<PrfInput<'a, 'b>>,
    /// [`evalByCredential`](https://www.w3.org/TR/webauthn-3/#dom-authenticationextensionsprfinputs-evalbycredential).
    eval_by_credential: PrfCreds<'c>,
}
impl Serialize for PrfInputs<'_, '_, '_> {
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "comment explains how overflow is not possible"
    )]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct(
                "PrfInputs",
                // The max is 1 + 1 = 2, so overflow is not an issue.
                usize::from(self.eval.is_some())
                    + usize::from(self.eval_by_credential.0.prf_count > 0),
            )
            .and_then(|mut ser| {
                self.eval
                    .map_or(Ok(()), |eval| ser.serialize_field("eval", &eval))
                    .and_then(|()| {
                        if self.eval_by_credential.0.prf_count == 0 {
                            Ok(())
                        } else {
                            ser.serialize_field("evalByCredential", &self.eval_by_credential)
                        }
                    })
                    .and_then(|()| ser.end())
            })
    }
}
/// Serializes `self` to conform with
/// [`AuthenticationExtensionsClientInputsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsclientinputsjson).
struct ExtensionHelper<'a, 'b, 'c> {
    /// [`extension`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptionsjson-extensions).
    extension: &'a Extension<'b, 'c>,
    /// [`extension`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptionsjson-extensions).
    ///
    /// Some extensions contain records, so we need both this and above.
    allow_credentials: &'a AllowedCredentials,
}
impl Serialize for ExtensionHelper<'_, '_, '_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ext_count =
            usize::from(self.extension.prf.is_some() || self.allow_credentials.prf_count > 0);
        serializer
            .serialize_struct("Extension", ext_count)
            .and_then(|mut ser| {
                if ext_count == 0 {
                    Ok(())
                } else {
                    ser.serialize_field(
                        "prf",
                        &PrfInputs {
                            eval: self.extension.prf.map(|prf| prf.0),
                            eval_by_credential: PrfCreds(self.allow_credentials),
                        },
                    )
                }
                .and_then(|()| ser.end())
            })
    }
}
/// `"challenge"`
const CHALLENGE: &str = "challenge";
/// `"timeout"`
const TIMEOUT: &str = "timeout";
/// `"rpId"`
const RP_ID: &str = "rpId";
/// `"allowCredentials"`
const ALLOW_CREDENTIALS: &str = "allowCredentials";
/// `"extensions"`
const EXTENSIONS: &str = "extensions";
/// `"hints"`
const HINTS: &str = "hints";
/// `"userVerification"`
const USER_VERIFICATION: &str = "userVerification";
/// Helper type that peforms the serialization for both [`DiscoverableAuthenticationClientState`] and
/// [`NonDiscoverableAuthenticationClientState`] and
struct AuthenticationClientState<'rp_id, 'prf_first, 'prf_second, 'opt, 'cred>(
    &'opt PublicKeyCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second>,
    &'cred AllowedCredentials,
);
impl Serialize for AuthenticationClientState<'_, '_, '_, '_, '_> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("PublicKeyCredentialRequestOptions", 7)
            .and_then(|mut ser| {
                ser.serialize_field(CHALLENGE, &self.0.challenge)
                    .and_then(|()| {
                        ser.serialize_field(TIMEOUT, &self.0.timeout)
                            .and_then(|()| {
                                ser.serialize_field(RP_ID, &self.0.rp_id).and_then(|()| {
                                    ser.serialize_field(ALLOW_CREDENTIALS, &self.1)
                                        .and_then(|()| {
                                            ser.serialize_field(
                                                USER_VERIFICATION,
                                                &self.0.user_verification,
                                            )
                                            .and_then(
                                                |()| {
                                                    ser.serialize_field(HINTS, &self.0.hints)
                                                        .and_then(|()| {
                                                            ser.serialize_field(
                                                                EXTENSIONS,
                                                                &ExtensionHelper {
                                                                    extension: &self.0.extensions,
                                                                    allow_credentials: self.1,
                                                                },
                                                            )
                                                            .and_then(|()| ser.end())
                                                        })
                                                },
                                            )
                                        })
                                })
                            })
                    })
            })
    }
}
/// `"mediation"`.
const MEDIATION: &str = "mediation";
/// `"publicKey"`.
const PUBLIC_KEY: &str = "publicKey";
impl Serialize for DiscoverableCredentialRequestOptions<'_, '_, '_> {
    /// Serializes `self` to conform with
    /// [`CredentialRequestOptions`](https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions).
    ///
    /// Note [`signal`](https://www.w3.org/TR/credential-management-1/#dom-credentialrequestoptions-signal)
    /// is not present, and [`publicKey`](https://www.w3.org/TR/credential-management-1/#sctn-cred-type-registry)
    /// is serialized to conform to
    /// [`PublicKeyCredentialRequestOptionsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptionsjson).
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("DiscoverableCredentialRequestOptions", 2)
            .and_then(|mut ser| {
                ser.serialize_field(MEDIATION, &self.mediation)
                    .and_then(|()| {
                        ser.serialize_field(
                            PUBLIC_KEY,
                            &AuthenticationClientState(
                                &self.public_key,
                                &AllowedCredentials::with_capacity(0),
                            ),
                        )
                        .and_then(|()| ser.end())
                    })
            })
    }
}
impl Serialize for NonDiscoverableCredentialRequestOptions<'_, '_, '_> {
    /// Serializes `self` to conform with
    /// [`CredentialRequestOptions`](https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions).
    ///
    /// Note [`signal`](https://www.w3.org/TR/credential-management-1/#dom-credentialrequestoptions-signal)
    /// is not present, and [`publicKey`](https://www.w3.org/TR/credential-management-1/#sctn-cred-type-registry)
    /// is serialized to conform to
    /// [`PublicKeyCredentialRequestOptionsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptionsjson).
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct("NonDiscoverableCredentialRequestOptions", 2)
            .and_then(|mut ser| {
                ser.serialize_field(MEDIATION, &self.mediation)
                    .and_then(|()| {
                        ser.serialize_field(
                            PUBLIC_KEY,
                            &AuthenticationClientState(&self.options, &self.allow_credentials),
                        )
                        .and_then(|()| ser.end())
                    })
            })
    }
}
impl Serialize for DiscoverableAuthenticationClientState<'_, '_, '_> {
    /// Serializes `self` according to [`DiscoverableCredentialRequestOptions::serialize`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::{
    /// #     request::{
    /// #         auth::{
    /// #             AllowedCredential, AllowedCredentials, CredentialSpecificExtension, Extension,
    /// #             PrfInputOwned, DiscoverableCredentialRequestOptions
    /// #         },
    /// #         AsciiDomain, ExtensionReq, Hint, PrfInput, RpId, PublicKeyCredentialDescriptor, Credentials, UserVerificationRequirement,
    /// #     },
    /// #     response::{AuthTransports, CredentialId},
    /// # };
    /// let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
    /// let mut options = DiscoverableCredentialRequestOptions::passkey(&rp_id);
    /// options.public_key.hints = Hint::SecurityKey;
    /// options.public_key.extensions = Extension {
    ///     prf: Some((PrfInput {
    ///         first: [0; 4].as_slice(),
    ///         second: None,
    ///     }, ExtensionReq::Require)),
    /// };
    /// let client_state = serde_json::to_string(&options.start_ceremony()?.1).unwrap();
    /// let json = serde_json::json!({
    ///     "mediation":"required",
    ///     "publicKey":{
    ///         "challenge":"AAAAAAAAAAAAAAAAAAAAAA",
    ///         "timeout":300000,
    ///         "rpId":"example.com",
    ///         "allowCredentials":[],
    ///         "userVerification":"required",
    ///         "hints":[
    ///             "security-key"
    ///         ],
    ///         "extensions":{
    ///             "prf":{
    ///                 "eval":{
    ///                     "first":"AAAAAA"
    ///                 },
    ///             }
    ///         }
    ///     }
    /// }).to_string();
    /// // Since `Challenge`s are randomly generated, we don't know what it will be; thus
    /// // we test the JSON string for everything except it.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(client_state.get(..50), json.get(..50));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(client_state.get(72..), json.get(72..));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}
impl Serialize for NonDiscoverableAuthenticationClientState<'_, '_, '_> {
    /// Serializes `self` according to [`NonDiscoverableCredentialRequestOptions::serialize`].
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// # use webauthn_rp::{bin::Decode, response::bin::DecodeAuthTransportsErr};
    /// # use webauthn_rp::{
    /// #     request::{
    /// #         auth::{
    /// #             AllowedCredential, AllowedCredentials, CredentialSpecificExtension, Extension,
    /// #             PrfInputOwned, NonDiscoverableCredentialRequestOptions
    /// #         },
    /// #         AsciiDomain, ExtensionReq, Hint, PrfInput, RpId, PublicKeyCredentialDescriptor, Credentials, UserVerificationRequirement,
    /// #     },
    /// #     response::{AuthTransports, CredentialId},
    /// # };
    /// /// Retrieves the `AuthTransports` associated with the unique `cred_id`
    /// /// from the database.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// fn get_transports(cred_id: CredentialId<&[u8]>) -> Result<AuthTransports, DecodeAuthTransportsErr> {
    ///     // ⋮
    /// #     AuthTransports::decode(32)
    /// }
    /// let mut creds = AllowedCredentials::with_capacity(1);
    /// // `CredentialId::try_from` only exists when `custom` is enabled; and even then, it is
    /// // likely never needed since the `CredentialId` was originally sent from the client and is likely
    /// // stored in a database which would be fetched by `UserHandle` or `Authentication::raw_id`.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let id = CredentialId::try_from(vec![0; 16])?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let transports = get_transports((&id).into())?;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// creds.push(AllowedCredential {
    ///     credential: PublicKeyCredentialDescriptor { id, transports },
    ///     extension: CredentialSpecificExtension {
    ///         prf: Some(PrfInputOwned {
    ///             first: vec![2; 6],
    ///             second: Some(vec![3; 2]),
    ///             ext_req: ExtensionReq::Require,
    ///         }),
    ///     },
    /// });
    /// let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let mut options = NonDiscoverableCredentialRequestOptions::second_factor(&rp_id, creds);
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let opts = &mut options.options;
    /// # #[cfg(not(all(feature = "bin", feature = "custom")))]
    /// # let mut opts = webauthn_rp::DiscoverableCredentialRequestOptions::passkey(&rp_id).public_key;
    /// opts.hints = Hint::SecurityKey;
    /// // This is actually useless since `CredentialSpecificExtension` takes priority
    /// // when the client receives the payload. We set it for illustration purposes only.
    /// // If `creds` contained an `AllowedCredential` that didn't set
    /// // `CredentialSpecificExtension::prf`, then this would be used for it.
    /// opts.extensions = Extension {
    ///     prf: Some((PrfInput {
    ///         first: [0; 4].as_slice(),
    ///         second: None,
    ///     }, ExtensionReq::Require)),
    /// };
    /// // Since we are requesting the PRF extension, we must require user verification; otherwise
    /// // `NonDiscoverableCredentialRequestOptions::start_ceremony` would error.
    /// opts.user_verification = UserVerificationRequirement::Required;
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// let client_state = serde_json::to_string(&options.start_ceremony()?.1).unwrap();
    /// let json = serde_json::json!({
    ///     "mediation":"required",
    ///     "publicKey":{
    ///         "challenge":"AAAAAAAAAAAAAAAAAAAAAA",
    ///         "timeout":300000,
    ///         "rpId":"example.com",
    ///         "allowCredentials":[
    ///             {
    ///                 "type":"public-key",
    ///                 "id":"AAAAAAAAAAAAAAAAAAAAAA",
    ///                 "transports":["usb"]
    ///             }
    ///         ],
    ///         "userVerification":"required",
    ///         "hints":[
    ///             "security-key"
    ///         ],
    ///         "extensions":{
    ///             "prf":{
    ///                 "eval":{
    ///                     "first":"AAAAAA"
    ///                 },
    ///                 "evalByCredential":{
    ///                     "AAAAAAAAAAAAAAAAAAAAAA":{
    ///                         "first":"AgICAgIC",
    ///                         "second":"AwM"
    ///                     }
    ///                 }
    ///             }
    ///         }
    ///     }
    /// }).to_string();
    /// // Since `Challenge`s are randomly generated, we don't know what it will be; thus
    /// // we test the JSON string for everything except it.
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(client_state.get(..50), json.get(..50));
    /// # #[cfg(all(feature = "bin", feature = "custom"))]
    /// assert_eq!(client_state.get(72..), json.get(72..));
    /// # Ok::<_, webauthn_rp::AggErr>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}
/// Similar to [`Extension`] except [`PrfInputOwned`] is used.
///
/// This is primarily useful to assist [`ClientCredentialRequestOptions::deserialize`].
#[derive(Debug, Default)]
pub struct ExtensionOwned {
    /// See [`Extension::prf`].
    pub prf: Option<PrfInputOwned>,
}
impl<'a: 'prf_first + 'prf_second, 'prf_first, 'prf_second> From<&'a ExtensionOwned>
    for Extension<'prf_first, 'prf_second>
{
    #[inline]
    fn from(value: &'a ExtensionOwned) -> Self {
        Self {
            prf: value.prf.as_ref().map(|input| {
                (
                    PrfInput {
                        first: input.first.as_slice(),
                        second: input.second.as_deref(),
                    },
                    input.ext_req,
                )
            }),
        }
    }
}
impl<'de> Deserialize<'de> for ExtensionOwned {
    /// Deserializes a `struct` according to the following pseudo-schema:
    ///
    /// ```json
    /// {
    ///   "prf": null | PRFJSON
    /// }
    /// // PRFJSON:
    /// {
    ///   "eval": PRFInputs
    /// }
    /// // PRFInputs:
    /// {
    ///   "first": <base64url-encoded string>,
    ///   "second": null | <base64url-encoded string>
    /// }
    /// ```
    ///
    /// where the only required fields are `"eval"` and `"first"`.
    ///
    /// All extensions are not required to have a response sent back; but _if_ a response is sent back, its value
    /// will be enforced.
    ///
    /// Unknown or duplicate fields lead to an error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::{ExtensionReq, auth::ser::ExtensionOwned};
    /// let ext = serde_json::from_str::<ExtensionOwned>(
    ///     r#"{"prf":{"eval":{"first":"","second":null}}}"#,
    /// )?;
    /// assert!(ext.prf.map_or(false, |prf| prf.first.is_empty()
    ///     && prf.second.is_none()
    ///     && matches!(prf.ext_req, ExtensionReq::Allow)));
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `ExtensionOwned`.
        struct ExtensionOwnedVisitor;
        impl<'d> Visitor<'d> for ExtensionOwnedVisitor {
            type Value = ExtensionOwned;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("ExtensionOwned")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Field for `ExtensionOwned`.
                struct Field;
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
                                write!(formatter, "'{PRF}'")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                if v == PRF {
                                    Ok(Field)
                                } else {
                                    Err(E::unknown_field(v, FIELDS))
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                map.next_key::<Field>().and_then(|opt_key| {
                    opt_key
                        .map_or_else(
                            || Ok(None),
                            |_k| {
                                map.next_value::<Option<PrfHelper>>().and_then(|prf| {
                                    map.next_key::<Field>().and_then(|opt_key2| {
                                        opt_key2.map_or_else(
                                            || Ok(prf.map(|val| val.0)),
                                            |_k2| Err(Error::duplicate_field(PRF)),
                                        )
                                    })
                                })
                            },
                        )
                        .map(|prf| ExtensionOwned { prf })
                })
            }
        }
        /// `"prf"`.
        const PRF: &str = "prf";
        /// Fields for `ExtensionOwned`.
        const FIELDS: &[&str; 1] = &[PRF];
        deserializer.deserialize_struct("ExtensionOwned", FIELDS, ExtensionOwnedVisitor)
    }
}
/// Similar to [`PublicKeyCredentialRequestOptions`] except the fields are based on owned data.
///
/// This is primarily useful to assist [`ClientCredentialRequestOptions::deserialize`],
#[derive(Debug)]
pub struct PublicKeyCredentialRequestOptionsOwned {
    /// See [`PublicKeyCredentialRequestOptions::rp_id`].
    pub rp_id: RpId,
    /// See [`PublicKeyCredentialRequestOptions::timeout`].
    pub timeout: NonZeroU32,
    /// See [`PublicKeyCredentialRequestOptions::user_verification`].
    pub user_verification: UserVerificationRequirement,
    /// See [`PublicKeyCredentialRequestOptions::hints`].
    pub hints: Hint,
    /// See [`PublicKeyCredentialRequestOptions::extensions`].
    pub extensions: ExtensionOwned,
}
impl PublicKeyCredentialRequestOptionsOwned {
    /// Creates a `PublicKeyCredentialRequestOptions` based on the contained data and randomly-generated
    /// [`Challenge`].
    #[inline]
    #[must_use]
    pub fn into_options(&self) -> PublicKeyCredentialRequestOptions<'_, '_, '_> {
        PublicKeyCredentialRequestOptions {
            rp_id: &self.rp_id,
            challenge: Challenge::new(),
            timeout: self.timeout,
            user_verification: self.user_verification,
            hints: self.hints,
            extensions: (&self.extensions).into(),
        }
    }
}
impl Default for PublicKeyCredentialRequestOptionsOwned {
    #[inline]
    fn default() -> Self {
        Self {
            rp_id: DEFAULT_RP_ID,
            timeout: FIVE_MINUTES,
            user_verification: UserVerificationRequirement::Preferred,
            hints: Hint::default(),
            extensions: ExtensionOwned::default(),
        }
    }
}
impl<'de> Deserialize<'de> for PublicKeyCredentialRequestOptionsOwned {
    /// Deserializes a `struct` based on
    /// [`PublicKeyCredentialRequestOptionsJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrequestoptionsjson).
    ///
    /// Note that none of the fields are required, and all are allowed to be `null`.
    ///
    /// If [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptionsjson-challenge)
    /// exists, it must be `null`. If
    /// [`allowCredentials`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptionsjson-allowcredentials)
    /// exists, it must be `null` or empty.
    ///
    /// If [`timeout`](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptionsjson-timeout) exists,
    /// it must be `null` or positive.
    ///
    /// In the event there is no RP ID defined, the value `"example.invalid"` will be used.
    ///
    /// For any field that does not exist or is `null`, the corresponding [`Default`] `impl` will be used. For
    /// `user_verification`, [`UserVerificationRequirement::Preferred`] will be used. For `timeout`,
    /// [`FIVE_MINUTES`] will be used.
    ///
    /// Unknown or duplicate fields lead to an error.
    #[expect(clippy::too_many_lines, reason = "131 lines is fine")]
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `PublicKeyCredentialRequestOptionsOwned`.
        struct PublicKeyCredentialRequestOptionsOwnedVisitor;
        impl<'d> Visitor<'d> for PublicKeyCredentialRequestOptionsOwnedVisitor {
            type Value = PublicKeyCredentialRequestOptionsOwned;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("PublicKeyCredentialRequestOptionsOwned")
            }
            #[expect(clippy::too_many_lines, reason = "104 lines is fine")]
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Field for `PublicKeyCredentialRequestOptionsOwned`.
                enum Field {
                    /// `rpId`.
                    RpId,
                    /// `userVerification`.
                    UserVerification,
                    /// `challenge`.
                    Challenge,
                    /// `timeout`.
                    Timeout,
                    /// `allowCredentials`.
                    AllowCredentials,
                    /// `hints`.
                    Hints,
                    /// `extensions`.
                    Extensions,
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
                                    "'{RP_ID}', '{USER_VERIFICATION}', '{CHALLENGE}', '{TIMEOUT}', '{ALLOW_CREDENTIALS}', '{HINTS}', or '{EXTENSIONS}'"
                                )
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    RP_ID => Ok(Field::RpId),
                                    USER_VERIFICATION => Ok(Field::UserVerification),
                                    CHALLENGE => Ok(Field::Challenge),
                                    TIMEOUT => Ok(Field::Timeout),
                                    ALLOW_CREDENTIALS => Ok(Field::AllowCredentials),
                                    HINTS => Ok(Field::Hints),
                                    EXTENSIONS => Ok(Field::Extensions),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                let mut rp = None;
                let mut user_veri = None;
                let mut chall = None;
                let mut time = None;
                let mut allow = None;
                let mut hint = None;
                let mut ext = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::RpId => {
                            if rp.is_some() {
                                return Err(Error::duplicate_field(RP_ID));
                            }
                            rp = map.next_value::<Option<RpId>>().map(Some)?;
                        }
                        Field::UserVerification => {
                            if user_veri.is_some() {
                                return Err(Error::duplicate_field(USER_VERIFICATION));
                            }
                            user_veri = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::Challenge => {
                            if chall.is_some() {
                                return Err(Error::duplicate_field(CHALLENGE));
                            }
                            chall = map.next_value::<Null>().map(Some)?;
                        }
                        Field::Timeout => {
                            if time.is_some() {
                                return Err(Error::duplicate_field(TIMEOUT));
                            }
                            time = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::AllowCredentials => {
                            if allow.is_some() {
                                return Err(Error::duplicate_field(ALLOW_CREDENTIALS));
                            }
                            allow = map.next_value::<Option<[(); 0]>>().map(Some)?;
                        }
                        Field::Hints => {
                            if hint.is_some() {
                                return Err(Error::duplicate_field(HINTS));
                            }
                            hint = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::Extensions => {
                            if ext.is_some() {
                                return Err(Error::duplicate_field(EXTENSIONS));
                            }
                            ext = map.next_value::<Option<_>>().map(Some)?;
                        }
                    }
                }
                Ok(PublicKeyCredentialRequestOptionsOwned {
                    rp_id: rp.flatten().unwrap_or(DEFAULT_RP_ID),
                    user_verification: user_veri
                        .flatten()
                        .unwrap_or(UserVerificationRequirement::Preferred),
                    timeout: time.flatten().unwrap_or(FIVE_MINUTES),
                    extensions: ext.flatten().unwrap_or_default(),
                    hints: hint.flatten().unwrap_or_default(),
                })
            }
        }
        /// Fields for `PublicKeyCredentialRequestOptionsOwned`.
        const FIELDS: &[&str; 7] = &[
            RP_ID,
            USER_VERIFICATION,
            CHALLENGE,
            TIMEOUT,
            ALLOW_CREDENTIALS,
            HINTS,
            EXTENSIONS,
        ];
        deserializer.deserialize_struct(
            "PublicKeyCredentialRequestOptionsOwned",
            FIELDS,
            PublicKeyCredentialRequestOptionsOwnedVisitor,
        )
    }
}
/// Deserializes client-supplied data to assist in the creation of [`DiscoverableCredentialRequestOptions`]
/// and [`NonDiscoverableCredentialRequestOptions`].
///
/// It's common to tailor an authentication ceremony based on a user's environment. The options that should be
/// used are then sent to the server. To facilitate this, [`Self::deserialize`] can be used to deserialize the data
/// sent from the client. Upon successful deserialization, [`Self::into_discoverable_options`] and
/// [`Self::into_non_discoverable_options`] can then be used to construct the
/// appropriate [`DiscoverableCredentialRequestOptions`] and [`NonDiscoverableCredentialRequestOptions`]
/// respectively.
///
/// Note one may want to change some of the [`Extension`] data since [`ExtensionReq::Allow`] is unconditionally
/// used. Read [`ExtensionOwned::deserialize`] for more information.
///
/// Additionally, one may want to change the value of [`PublicKeyCredentialRequestOptions::rp_id`] since
/// `"example.invalid"` is used in the event the RP ID was not supplied.
#[derive(Debug)]
pub struct ClientCredentialRequestOptions {
    /// See [`DiscoverableCredentialRequestOptions::mediation`] and
    /// [`NonDiscoverableCredentialRequestOptions::mediation`].
    pub mediation: CredentialMediationRequirement,
    /// See [`DiscoverableCredentialRequestOptions::public_key`] and
    /// See [`NonDiscoverableCredentialRequestOptions::options`].
    pub public_key: PublicKeyCredentialRequestOptionsOwned,
}
impl ClientCredentialRequestOptions {
    /// Creates a `DiscoverableCredentialRequestOptions` based on the contained data where
    /// [`DiscoverableCredentialRequestOptions::public_key`] is constructed via
    /// [`PublicKeyCredentialRequestOptionsOwned::into_options`].
    #[inline]
    #[must_use]
    pub fn into_discoverable_options(&self) -> DiscoverableCredentialRequestOptions<'_, '_, '_> {
        DiscoverableCredentialRequestOptions {
            mediation: self.mediation,
            public_key: self.public_key.into_options(),
        }
    }
    /// Creates a `NonDiscoverableCredentialRequestOptions` based on the contained data where
    /// [`NonDiscoverableCredentialRequestOptions::options`] is constructed via
    /// [`PublicKeyCredentialRequestOptionsOwned::into_options`].
    #[inline]
    #[must_use]
    pub fn into_non_discoverable_options(
        &self,
        allow_credentials: AllowedCredentials,
    ) -> NonDiscoverableCredentialRequestOptions<'_, '_, '_> {
        NonDiscoverableCredentialRequestOptions {
            mediation: self.mediation,
            options: self.public_key.into_options(),
            allow_credentials,
        }
    }
}
impl Default for ClientCredentialRequestOptions {
    #[inline]
    fn default() -> Self {
        Self {
            mediation: CredentialMediationRequirement::default(),
            public_key: PublicKeyCredentialRequestOptionsOwned::default(),
        }
    }
}
impl<'de> Deserialize<'de> for ClientCredentialRequestOptions {
    /// Deserializes a `struct` according to the following pseudo-schema:
    ///
    /// ```json
    /// {
    ///   "mediation": null | "required" | "conditional",
    ///   "publicKey": null | <PublicKeyCredentialRequestOptionsOwned>
    /// }
    /// ```
    ///
    /// where none of the fields are required and `"publicKey"` is deserialized according to
    /// [`PublicKeyCredentialRequestOptionsOwned::deserialize`]. If any field is missing or is `null`, then
    /// the corresponding [`Default`] `impl` will be used.
    ///
    /// Unknown or duplicate fields lead to an error.
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `ClientCredentialRequestOptions`.
        struct ClientCredentialRequestOptionsVisitor;
        impl<'d> Visitor<'d> for ClientCredentialRequestOptionsVisitor {
            type Value = ClientCredentialRequestOptions;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("ClientCredentialRequestOptions")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Field in `ClientCredentialRequestOptions`.
                enum Field {
                    /// `mediation`.
                    Mediation,
                    /// `publicKey`
                    PublicKey,
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
                                write!(formatter, "'{MEDIATION}' or '{PUBLIC_KEY}'")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    MEDIATION => Ok(Field::Mediation),
                                    PUBLIC_KEY => Ok(Field::PublicKey),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                let mut med = None;
                let mut key = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        Field::Mediation => {
                            if med.is_some() {
                                return Err(Error::duplicate_field(MEDIATION));
                            }
                            med = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::PublicKey => {
                            if key.is_some() {
                                return Err(Error::duplicate_field(PUBLIC_KEY));
                            }
                            key = map.next_value::<Option<_>>().map(Some)?;
                        }
                    }
                }
                Ok(ClientCredentialRequestOptions {
                    mediation: med.flatten().unwrap_or_default(),
                    public_key: key.flatten().unwrap_or_default(),
                })
            }
        }
        /// Fields for `ClientCredentialRequestOptions`.
        const FIELDS: &[&str; 2] = &[MEDIATION, PUBLIC_KEY];
        deserializer.deserialize_struct(
            "ClientCredentialRequestOptions",
            FIELDS,
            ClientCredentialRequestOptionsVisitor,
        )
    }
}
#[cfg(test)]
mod test {
    use super::{
        super::ExtensionReq, ClientCredentialRequestOptions, CredentialMediationRequirement,
        DEFAULT_RP_ID, ExtensionOwned, FIVE_MINUTES, Hint, NonZeroU32,
        PublicKeyCredentialRequestOptionsOwned, UserVerificationRequirement,
    };
    use serde_json::Error;
    #[test]
    fn client_options() -> Result<(), Error> {
        let mut err =
            serde_json::from_str::<ClientCredentialRequestOptions>(r#"{"bob":true}"#).unwrap_err();
        assert_eq!(
            err.to_string()[..56],
            *"unknown field `bob`, expected `mediation` or `publicKey`"
        );
        err = serde_json::from_str::<ClientCredentialRequestOptions>(
            r#"{"mediation":"required","mediation":"required"}"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string()[..27], *"duplicate field `mediation`");
        let mut options = serde_json::from_str::<ClientCredentialRequestOptions>(r#"{}"#)?;
        assert!(matches!(
            options.mediation,
            CredentialMediationRequirement::Required
        ));
        assert_eq!(options.public_key.rp_id, DEFAULT_RP_ID);
        assert_eq!(options.public_key.timeout, FIVE_MINUTES);
        assert!(matches!(
            options.public_key.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(matches!(options.public_key.hints, Hint::None));
        assert!(options.public_key.extensions.prf.is_none());
        options = serde_json::from_str::<ClientCredentialRequestOptions>(
            r#"{"mediation":null,"publicKey":null}"#,
        )?;
        assert!(matches!(
            options.mediation,
            CredentialMediationRequirement::Required
        ));
        assert_eq!(options.public_key.rp_id, DEFAULT_RP_ID);
        assert_eq!(options.public_key.timeout, FIVE_MINUTES);
        assert!(matches!(
            options.public_key.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(matches!(options.public_key.hints, Hint::None));
        assert!(options.public_key.extensions.prf.is_none());
        options = serde_json::from_str::<ClientCredentialRequestOptions>(r#"{"publicKey":{}}"#)?;
        assert_eq!(options.public_key.rp_id, DEFAULT_RP_ID);
        assert_eq!(options.public_key.timeout, FIVE_MINUTES);
        assert!(matches!(
            options.public_key.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(matches!(options.public_key.hints, Hint::None));
        assert!(options.public_key.extensions.prf.is_none());
        options = serde_json::from_str::<ClientCredentialRequestOptions>(
            r#"{"mediation":"conditional","publicKey":{"rpId":"example.com","timeout":300000,"allowCredentials":[],"userVerification":"required","extensions":{"prf":{"eval":{"first":"","second":""}}},"hints":["security-key"],"challenge":null}}"#,
        )?;
        assert!(matches!(
            options.mediation,
            CredentialMediationRequirement::Conditional
        ));
        assert_eq!(options.public_key.rp_id.as_ref(), "example.com");
        assert_eq!(options.public_key.timeout, FIVE_MINUTES);
        assert!(matches!(
            options.public_key.user_verification,
            UserVerificationRequirement::Required
        ));
        assert!(
            options
                .public_key
                .extensions
                .prf
                .map_or(false, |prf| prf.first.is_empty()
                    && prf.second.is_some_and(|p| p.is_empty())
                    && matches!(prf.ext_req, ExtensionReq::Allow))
        );
        Ok(())
    }
    #[test]
    fn key_options() -> Result<(), Error> {
        let mut err =
            serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(r#"{"bob":true}"#)
                .unwrap_err();
        assert_eq!(
            err.to_string()[..130],
            *"unknown field `bob`, expected one of `rpId`, `userVerification`, `challenge`, `timeout`, `allowCredentials`, `hints`, `extensions`"
        );
        err = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
            r#"{"rpId":"example.com","rpId":"example.com"}"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string()[..22], *"duplicate field `rpId`");
        err = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
            r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..41],
            *"invalid type: Option value, expected null"
        );
        err = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
            r#"{"allowCredentials":[{"type":"public-key","transports":["usb"],"id":"AAAAAAAAAAAAAAAAAAAAAA"}]}"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string()[..19], *"trailing characters");
        err = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(r#"{"timeout":0}"#)
            .unwrap_err();
        assert_eq!(
            err.to_string()[..50],
            *"invalid value: integer `0`, expected a nonzero u32"
        );
        err = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
            r#"{"timeout":4294967296}"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string()[..59],
            *"invalid value: integer `4294967296`, expected a nonzero u32"
        );
        let mut key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(r#"{}"#)?;
        assert_eq!(key.rp_id, DEFAULT_RP_ID);
        assert_eq!(key.timeout, FIVE_MINUTES);
        assert!(matches!(
            key.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(key.extensions.prf.is_none());
        assert!(matches!(key.hints, Hint::None));
        key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
            r#"{"rpId":null,"timeout":null,"allowCredentials":null,"userVerification":null,"extensions":null,"hints":null,"challenge":null}"#,
        )?;
        assert_eq!(key.rp_id, DEFAULT_RP_ID);
        assert_eq!(key.timeout, FIVE_MINUTES);
        assert!(matches!(
            key.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(key.extensions.prf.is_none());
        assert!(matches!(key.hints, Hint::None));
        key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
            r#"{"allowCredentials":[],"extensions":{},"hints":[]}"#,
        )?;
        assert!(matches!(
            key.user_verification,
            UserVerificationRequirement::Preferred
        ));
        assert!(matches!(key.hints, Hint::None));
        assert!(key.extensions.prf.is_none());
        key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
            r#"{"extensions":{"prf":null}}"#,
        )?;
        assert!(key.extensions.prf.is_none());
        key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
            r#"{"rpId":"example.com","timeout":300000,"allowCredentials":[],"userVerification":"required","extensions":{"prf":{"eval":{"first":"","second":""}}},"hints":["security-key"],"challenge":null}"#,
        )?;
        assert_eq!(key.rp_id.as_ref(), "example.com");
        assert_eq!(key.timeout, FIVE_MINUTES);
        assert!(matches!(
            key.user_verification,
            UserVerificationRequirement::Required
        ));
        assert!(matches!(key.hints, Hint::SecurityKey));
        assert!(key.extensions.prf.map_or(false, |prf| prf.first.is_empty()
            && prf.second.is_some_and(|p| p.is_empty())
            && matches!(prf.ext_req, ExtensionReq::Allow)));
        key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
            r#"{"timeout":4294967295}"#,
        )?;
        assert_eq!(key.timeout, NonZeroU32::MAX);
        Ok(())
    }
    #[test]
    fn extension() -> Result<(), Error> {
        let mut err = serde_json::from_str::<ExtensionOwned>(r#"{"bob":true}"#).unwrap_err();
        assert_eq!(
            err.to_string()[..35],
            *"unknown field `bob`, expected `prf`"
        );
        err = serde_json::from_str::<ExtensionOwned>(
            r#"{"prf":{"eval":{"first":"","second":""}},"prf":{"eval":{"first":"","second":""}}}"#,
        )
        .unwrap_err();
        assert_eq!(err.to_string()[..21], *"duplicate field `prf`");
        err = serde_json::from_str::<ExtensionOwned>(r#"{"prf":{"eval":{"first":null}}}"#)
            .unwrap_err();
        assert_eq!(
            err.to_string()[..51],
            *"invalid type: null, expected base64url-encoded data"
        );
        let mut ext =
            serde_json::from_str::<ExtensionOwned>(r#"{"prf":{"eval":{"first":"","second":""}}}"#)?;
        assert!(ext.prf.map_or(false, |prf| prf.first.is_empty()
            && prf.second.is_some_and(|v| v.is_empty())
            && matches!(prf.ext_req, ExtensionReq::Allow)));
        ext = serde_json::from_str::<ExtensionOwned>(r#"{"prf":null}"#)?;
        assert!(ext.prf.is_none());
        ext = serde_json::from_str::<ExtensionOwned>(r#"{}"#)?;
        assert!(ext.prf.is_none());
        Ok(())
    }
}
