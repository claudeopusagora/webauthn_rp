use super::{
    AllowedCredential, AllowedCredentials, Credentials as _, DiscoverableAuthenticationClientState,
    DiscoverableCredentialRequestOptions, Extension, NonDiscoverableAuthenticationClientState,
    NonDiscoverableCredentialRequestOptions, PrfInput, PrfInputOwned,
    PublicKeyCredentialRequestOptions,
};
use serde::ser::{Serialize, SerializeMap as _, SerializeStruct as _, Serializer};
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
                ser.serialize_field("challenge", &self.0.challenge)
                    .and_then(|()| {
                        ser.serialize_field("timeout", &self.0.timeout)
                            .and_then(|()| {
                                ser.serialize_field("rpId", &self.0.rp_id).and_then(|()| {
                                    ser.serialize_field("allowCredentials", &self.1).and_then(
                                        |()| {
                                            ser.serialize_field(
                                                "userVerification",
                                                &self.0.user_verification,
                                            )
                                            .and_then(
                                                |()| {
                                                    ser.serialize_field("hints", &self.0.hints)
                                                        .and_then(|()| {
                                                            ser.serialize_field(
                                                                "extensions",
                                                                &ExtensionHelper {
                                                                    extension: &self.0.extensions,
                                                                    allow_credentials: self.1,
                                                                },
                                                            )
                                                            .and_then(|()| ser.end())
                                                        })
                                                },
                                            )
                                        },
                                    )
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
