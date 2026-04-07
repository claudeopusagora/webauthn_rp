#[cfg(test)]
mod tests;
use super::{
    super::{super::response::ser::Null, ser::PrfHelper},
    AllowedCredential, AllowedCredentials, Challenge, CredentialMediationRequirement,
    CredentialUiMode, Credentials as _, DiscoverableAuthenticationClientState,
    DiscoverableCredentialRequestOptions, Extension, ExtensionReq, FIVE_MINUTES, Hints,
    NonDiscoverableAuthenticationClientState, NonDiscoverableCredentialRequestOptions, PrfInput,
    PrfInputOwned, PublicKeyCredentialRequestOptions, RpId, UserVerificationRequirement,
};
use core::{
    error::Error as E,
    fmt::{self, Display, Formatter},
    num::NonZeroU32,
};
use serde::{
    de::{Deserialize, Deserializer, Error, MapAccess, Unexpected, Visitor},
    ser::{Serialize, SerializeMap as _, SerializeStruct as _, Serializer},
};
/// `"immediate"`.
const IMMEDIATE: &str = "immediate";
impl Serialize for CredentialUiMode {
    /// Serializes `self` as a [`prim@str`] conforming with
    /// [`CredentialUiMode`](https://www.w3.org/TR/credential-management-1/#enumdef-credentialuimode).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::auth::CredentialUiMode;
    /// assert_eq!(
    ///     serde_json::to_string(&CredentialUiMode::Immediate)?,
    ///     r#""immediate""#
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(IMMEDIATE)
    }
}
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
    /// let id = CredentialId::try_from(vec![0; 16].into_boxed_slice())?;
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
    /// let id = CredentialId::try_from(vec![0; 16].into_boxed_slice())?;
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
/// `"uiMode"`.
const UI_MODE: &str = "uiMode";
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
    /// Additionally [`uiMode`](https://www.w3.org/TR/credential-management-1/#dom-credentialrequestoptions-uiMode)
    /// is not present iff [`Self::ui_mode`] is `None`.
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer
            .serialize_struct(
                "DiscoverableCredentialRequestOptions",
                if self.ui_mode.is_none() { 2 } else { 3 },
            )
            .and_then(|mut ser| {
                ser.serialize_field(MEDIATION, &self.mediation)
                    .and_then(|()| {
                        if self.ui_mode.is_none() {
                            Ok(())
                        } else {
                            ser.serialize_field(UI_MODE, &self.ui_mode)
                        }
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
            })
    }
}
impl Serialize for NonDiscoverableCredentialRequestOptions<'_, '_, '_> {
    /// Serializes `self` to conform with
    /// [`CredentialRequestOptions`](https://www.w3.org/TR/credential-management-1/#dictdef-credentialrequestoptions).
    ///
    /// Note [`signal`](https://www.w3.org/TR/credential-management-1/#dom-credentialrequestoptions-signal)
    /// and [`uiMode`](https://www.w3.org/TR/credential-management-1/#dom-credentialrequestoptions-uiMode)
    /// are not present, and [`publicKey`](https://www.w3.org/TR/credential-management-1/#sctn-cred-type-registry)
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
    /// #         AsciiDomain, ExtensionReq, Hints, PublicKeyCredentialHint, PrfInput, RpId, PublicKeyCredentialDescriptor, Credentials, UserVerificationRequirement,
    /// #     },
    /// #     response::{AuthTransports, CredentialId},
    /// # };
    /// let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
    /// let mut options = DiscoverableCredentialRequestOptions::passkey(&rp_id);
    /// options.public_key.hints = Hints::EMPTY.add(PublicKeyCredentialHint::SecurityKey);
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
    /// #         AsciiDomain, ExtensionReq, Hints, PublicKeyCredentialHint, PrfInput, RpId, PublicKeyCredentialDescriptor, Credentials, UserVerificationRequirement,
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
    /// let id = CredentialId::try_from(vec![0; 16].into_boxed_slice())?;
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
    /// opts.hints = Hints::EMPTY.add(PublicKeyCredentialHint::SecurityKey);
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
impl<'de> Deserialize<'de> for CredentialUiMode {
    /// Deserializes a [`prim@str`] based on
    /// [`CredentialUiMode`](https://www.w3.org/TR/credential-management-1/#enumdef-credentialuimode).
    ///
    /// # Examples
    ///
    /// ```
    /// # use webauthn_rp::request::auth::CredentialUiMode;
    /// assert_eq!(
    ///     serde_json::from_str::<CredentialUiMode>(r#""immediate""#)?,
    ///     CredentialUiMode::Immediate,
    /// );
    /// # Ok::<_, serde_json::Error>(())
    /// ```
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CredentialUiModeVisitor;
        impl Visitor<'_> for CredentialUiModeVisitor {
            type Value = CredentialUiMode;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                write!(formatter, "'{IMMEDIATE}'")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                if v == IMMEDIATE {
                    Ok(CredentialUiMode::Immediate)
                } else {
                    Err(E::invalid_value(
                        Unexpected::Str(v),
                        &format!("'{IMMEDIATE}'").as_str(),
                    ))
                }
            }
        }
        deserializer.deserialize_str(CredentialUiModeVisitor)
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
impl ExtensionOwned {
    /// Returns an `Extension` based on `self`.
    #[inline]
    #[must_use]
    pub fn as_extension(&self) -> Extension<'_, '_> {
        Extension {
            prf: self.prf.as_ref().map(|prf| {
                (
                    PrfInput {
                        first: &prf.first,
                        second: prf.second.as_deref(),
                    },
                    prf.ext_req,
                )
            }),
        }
    }
    /// Returns an `Extension` based on `self` and `prf`.
    ///
    /// Note `prf` is used _unconditionally_ regardless if [`Self::prf`] is `Some`.
    #[inline]
    #[must_use]
    pub const fn with_prf<'prf_first, 'prf_second>(
        &self,
        prf: (PrfInput<'prf_first, 'prf_second>, ExtensionReq),
    ) -> Extension<'prf_first, 'prf_second> {
        Extension { prf: Some(prf) }
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
/// Error returned by [`PublicKeyCredentialRequestOptionsOwned::as_options`] when
/// [`PublicKeyCredentialRequestOptionsOwned::rp_id`] is `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicKeyCredentialRequestOptionsOwnedErr;
impl Display for PublicKeyCredentialRequestOptionsOwnedErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("request options did not have an RP ID")
    }
}
impl E for PublicKeyCredentialRequestOptionsOwnedErr {}
/// Similar to [`PublicKeyCredentialRequestOptions`] except the fields are based on owned data, and
/// [`Self::rp_id`] is optional.
///
/// This is primarily useful to assist [`ClientCredentialRequestOptions::deserialize`],
#[derive(Debug)]
pub struct PublicKeyCredentialRequestOptionsOwned {
    /// See [`PublicKeyCredentialRequestOptions::rp_id`].
    pub rp_id: Option<RpId>,
    /// See [`PublicKeyCredentialRequestOptions::timeout`].
    pub timeout: NonZeroU32,
    /// See [`PublicKeyCredentialRequestOptions::user_verification`].
    pub user_verification: UserVerificationRequirement,
    /// See [`PublicKeyCredentialRequestOptions::hints`].
    pub hints: Hints,
    /// See [`PublicKeyCredentialRequestOptions::extensions`].
    pub extensions: ExtensionOwned,
}
impl PublicKeyCredentialRequestOptionsOwned {
    /// Returns a `PublicKeyCredentialRequestOptions` based on `self`.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::rp_id`] is `None`.
    #[inline]
    pub fn as_options(
        &self,
    ) -> Result<
        PublicKeyCredentialRequestOptions<'_, '_, '_>,
        PublicKeyCredentialRequestOptionsOwnedErr,
    > {
        self.rp_id
            .as_ref()
            .ok_or(PublicKeyCredentialRequestOptionsOwnedErr)
            .map(|rp_id| PublicKeyCredentialRequestOptions {
                challenge: Challenge::new(),
                timeout: self.timeout,
                rp_id,
                user_verification: self.user_verification,
                hints: self.hints,
                extensions: self.extensions.as_extension(),
            })
    }
    /// Returns a `PublicKeyCredentialRequestOptions` based on `self` and `rp_id`.
    ///
    /// Note `rp_id` is used _unconditionally_ regardless if [`Self::rp_id`] is `Some`.
    #[inline]
    #[must_use]
    pub fn with_rp_id<'rp_id>(
        &self,
        rp_id: &'rp_id RpId,
    ) -> PublicKeyCredentialRequestOptions<'rp_id, '_, '_> {
        PublicKeyCredentialRequestOptions {
            challenge: Challenge::new(),
            timeout: self.timeout,
            rp_id,
            user_verification: self.user_verification,
            hints: self.hints,
            extensions: self.extensions.as_extension(),
        }
    }
    /// Returns a `PublicKeyCredentialRequestOptions` based on `self`, `exclude_credentials`, and `extensions`.
    ///
    /// Note `extensions` is used _unconditionally_ regardless of what [`Self::extensions`] is.
    ///
    /// # Errors
    ///
    /// Errors iff [`Self::rp_id`] is `None`.
    #[inline]
    pub fn with_extensions<'prf_first, 'prf_second>(
        &self,
        extensions: Extension<'prf_first, 'prf_second>,
    ) -> Result<
        PublicKeyCredentialRequestOptions<'_, 'prf_first, 'prf_second>,
        PublicKeyCredentialRequestOptionsOwnedErr,
    > {
        self.rp_id
            .as_ref()
            .ok_or(PublicKeyCredentialRequestOptionsOwnedErr)
            .map(|rp_id| PublicKeyCredentialRequestOptions {
                challenge: Challenge::new(),
                timeout: self.timeout,
                rp_id,
                user_verification: self.user_verification,
                hints: self.hints,
                extensions,
            })
    }
    /// Returns a `PublicKeyCredentialRequestOptions` based on `self`, `rp_id`, and `extensions`.
    ///
    /// Note `rp_id` and `extensions` are used _unconditionally_ regardless if [`Self::rp_id`] is `Some` or what
    /// [`Self::extensions`] is.
    #[inline]
    #[must_use]
    pub fn with_rp_id_and_extensions<'rp_id, 'prf_first, 'prf_second>(
        &self,
        rp_id: &'rp_id RpId,
        extensions: Extension<'prf_first, 'prf_second>,
    ) -> PublicKeyCredentialRequestOptions<'rp_id, 'prf_first, 'prf_second> {
        PublicKeyCredentialRequestOptions {
            challenge: Challenge::new(),
            timeout: self.timeout,
            rp_id,
            user_verification: self.user_verification,
            hints: self.hints,
            extensions,
        }
    }
}
impl Default for PublicKeyCredentialRequestOptionsOwned {
    #[inline]
    fn default() -> Self {
        Self {
            rp_id: None,
            timeout: FIVE_MINUTES,
            user_verification: UserVerificationRequirement::Preferred,
            hints: Hints::default(),
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
    /// it must be `null` or positive. If `timeout` is missing or is `null`, then [`FIVE_MINUTES`] will be used.
    ///
    /// If `userVerification` is missing or is `null`, then [`UserVerificationRequirement::Required`] will be used.
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
                            rp = map.next_value::<Option<_>>().map(Some)?;
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
                    rp_id: rp.flatten(),
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
/// sent from the client.
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
    /// See [`DiscoverableCredentialRequestOptions::mediation`].
    pub ui_mode: Option<CredentialUiMode>,
    /// See [`DiscoverableCredentialRequestOptions::public_key`] and
    /// See [`NonDiscoverableCredentialRequestOptions::options`].
    pub public_key: PublicKeyCredentialRequestOptionsOwned,
}
impl<'de> Deserialize<'de> for ClientCredentialRequestOptions {
    /// Deserializes a `struct` according to the following pseudo-schema:
    ///
    /// ```json
    /// {
    ///   "mediation": null | "required" | "conditional",
    ///   "uiMode": null | "immediate",
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
                    /// `uiMode`.
                    UiMode,
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
                                write!(formatter, "'{MEDIATION}', '{UI_MODE}', or '{PUBLIC_KEY}'")
                            }
                            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                match v {
                                    MEDIATION => Ok(Field::Mediation),
                                    UI_MODE => Ok(Field::UiMode),
                                    PUBLIC_KEY => Ok(Field::PublicKey),
                                    _ => Err(E::unknown_field(v, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }
                let mut med = None;
                let mut ui = None;
                let mut key = None;
                while let Some(k) = map.next_key()? {
                    match k {
                        Field::Mediation => {
                            if med.is_some() {
                                return Err(Error::duplicate_field(MEDIATION));
                            }
                            med = map.next_value::<Option<_>>().map(Some)?;
                        }
                        Field::UiMode => {
                            if ui.is_some() {
                                return Err(Error::duplicate_field(UI_MODE));
                            }
                            ui = map.next_value().map(Some)?;
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
                    ui_mode: ui.flatten(),
                    public_key: key.flatten().unwrap_or_default(),
                })
            }
        }
        /// Fields for `ClientCredentialRequestOptions`.
        const FIELDS: &[&str; 3] = &[MEDIATION, UI_MODE, PUBLIC_KEY];
        deserializer.deserialize_struct(
            "ClientCredentialRequestOptions",
            FIELDS,
            ClientCredentialRequestOptionsVisitor,
        )
    }
}
