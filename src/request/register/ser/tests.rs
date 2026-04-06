use super::{
    AuthenticatorAttachment, AuthenticatorSelectionCriteria, ClientCredentialCreationOptions,
    CoseAlgorithmIdentifier, CoseAlgorithmIdentifiers, CredProtect, CredentialMediationRequirement,
    ExtensionInfo, ExtensionOwned, ExtensionReq, FIVE_MINUTES, FourToSixtyThree, NonZeroU32,
    PublicKeyCredentialCreationOptionsOwned, PublicKeyCredentialUserEntityOwned,
    ResidentKeyRequirement, UserVerificationRequirement,
};
use serde_json::Error;
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "OK in tests"
)]
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "a lot to test"
)]
#[test]
fn client_options() -> Result<(), Error> {
    let mut err =
        serde_json::from_str::<ClientCredentialCreationOptions<16>>(r#"{"bob":true}"#).unwrap_err();
    assert_eq!(
        err.to_string().get(..56),
        Some("unknown field `bob`, expected `mediation` or `publicKey`")
    );
    err = serde_json::from_str::<ClientCredentialCreationOptions<1>>(
        r#"{"mediation":"required","mediation":"required"}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..27),
        Some("duplicate field `mediation`")
    );
    let mut options = serde_json::from_str::<ClientCredentialCreationOptions<1>>("{}")?;
    assert!(matches!(
        options.mediation,
        CredentialMediationRequirement::Required
    ));
    assert!(options.public_key.rp_id.is_none());
    assert!(options.public_key.user.name.is_none());
    assert!(options.public_key.user.id.is_none());
    assert!(options.public_key.user.display_name.is_none());
    assert_eq!(
        options.public_key.pub_key_cred_params.0,
        CoseAlgorithmIdentifiers::ALL.0
    );
    assert_eq!(options.public_key.timeout, FIVE_MINUTES);
    assert_eq!(
        options
            .public_key
            .authenticator_selection
            .authenticator_attachment,
        AuthenticatorAttachment::None,
    );
    assert!(matches!(
        options.public_key.authenticator_selection.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    assert!(matches!(
        options.public_key.authenticator_selection.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert!(options.public_key.extensions.cred_props.is_none());
    assert!(matches!(
        options.public_key.extensions.cred_protect,
        CredProtect::None
    ));
    assert!(options.public_key.extensions.min_pin_length.is_none());
    assert!(options.public_key.extensions.prf.is_none());
    options = serde_json::from_str::<ClientCredentialCreationOptions<1>>(
        r#"{"mediation":null,"publicKey":null}"#,
    )?;
    assert!(matches!(
        options.mediation,
        CredentialMediationRequirement::Required
    ));
    assert!(options.public_key.rp_id.is_none());
    assert!(options.public_key.user.name.is_none());
    assert!(options.public_key.user.id.is_none());
    assert!(options.public_key.user.display_name.is_none());
    assert_eq!(
        options.public_key.pub_key_cred_params.0,
        CoseAlgorithmIdentifiers::ALL.0
    );
    assert_eq!(options.public_key.timeout, FIVE_MINUTES);
    assert_eq!(
        options
            .public_key
            .authenticator_selection
            .authenticator_attachment,
        AuthenticatorAttachment::None,
    );
    assert!(matches!(
        options.public_key.authenticator_selection.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    assert!(matches!(
        options.public_key.authenticator_selection.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert!(options.public_key.extensions.cred_props.is_none());
    assert!(matches!(
        options.public_key.extensions.cred_protect,
        CredProtect::None
    ));
    assert!(options.public_key.extensions.min_pin_length.is_none());
    assert!(options.public_key.extensions.prf.is_none());
    options = serde_json::from_str::<ClientCredentialCreationOptions<1>>(r#"{"publicKey":{}}"#)?;
    assert!(options.public_key.rp_id.is_none());
    assert!(options.public_key.user.name.is_none());
    assert!(options.public_key.user.id.is_none());
    assert!(options.public_key.user.display_name.is_none());
    assert_eq!(
        options.public_key.pub_key_cred_params.0,
        CoseAlgorithmIdentifiers::ALL.0
    );
    assert_eq!(options.public_key.timeout, FIVE_MINUTES);
    assert_eq!(
        options
            .public_key
            .authenticator_selection
            .authenticator_attachment,
        AuthenticatorAttachment::None,
    );
    assert!(matches!(
        options.public_key.authenticator_selection.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    assert!(matches!(
        options.public_key.authenticator_selection.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert!(options.public_key.extensions.cred_props.is_none());
    assert!(matches!(
        options.public_key.extensions.cred_protect,
        CredProtect::None
    ));
    assert!(options.public_key.extensions.min_pin_length.is_none());
    assert!(options.public_key.extensions.prf.is_none());
    options = serde_json::from_str::<ClientCredentialCreationOptions<1>>(
        r#"{"mediation":"conditional","publicKey":{"rp":{"name":"Example.com","id":"example.com"},"user":{"name":"bob","displayName":"Bob","id":"AQ"},"timeout":300000,"excludeCredentials":[],"attestation":"none","attestationFormats":["none"],"authenticatorSelection":{"authenticatorAttachment":"cross-platform","residentKey":"required","requireResidentKey":true,"userVerification":"required"},"extensions":{"credProps":true,"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"minPinLength":true,"prf":{"eval":{"first":"","second":""}}},"pubKeyCredParams":[{"type":"public-key","alg":-8}],"hints":["security-key"],"challenge":null}}"#,
    )?;
    assert!(matches!(
        options.mediation,
        CredentialMediationRequirement::Conditional
    ));
    assert!(
        options
            .public_key
            .rp_id
            .is_some_and(|val| val.as_ref() == "example.com")
    );
    assert!(options.public_key.user.name.is_some_and(|val| val == "bob"));
    assert!(
        options
            .public_key
            .user
            .display_name
            .is_some_and(|val| val == "Bob")
    );
    assert!(
        options
            .public_key
            .user
            .id
            .is_some_and(|val| val.as_ref() == [1; 1])
    );
    assert_eq!(
        options.public_key.pub_key_cred_params.0,
        CoseAlgorithmIdentifiers::ALL
            .remove(CoseAlgorithmIdentifier::Mldsa87)
            .remove(CoseAlgorithmIdentifier::Mldsa65)
            .remove(CoseAlgorithmIdentifier::Mldsa44)
            .remove(CoseAlgorithmIdentifier::Es256)
            .remove(CoseAlgorithmIdentifier::Es384)
            .remove(CoseAlgorithmIdentifier::Rs256)
            .0
    );
    assert_eq!(options.public_key.timeout, FIVE_MINUTES);
    assert_eq!(
        options
            .public_key
            .authenticator_selection
            .authenticator_attachment,
        AuthenticatorAttachment::CrossPlatform,
    );
    assert!(matches!(
        options.public_key.authenticator_selection.resident_key,
        ResidentKeyRequirement::Required
    ));
    assert!(matches!(
        options.public_key.authenticator_selection.user_verification,
        UserVerificationRequirement::Required
    ));
    assert!(
        options
            .public_key
            .extensions
            .cred_props
            .is_some_and(|req| matches!(req, ExtensionReq::Allow))
    );
    assert!(
        matches!(options.public_key.extensions.cred_protect, CredProtect::UserVerificationRequired(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
    );
    assert!(
        options
            .public_key
            .extensions
            .min_pin_length
            .is_some_and(|min| min.0 == FourToSixtyThree::Four
                && matches!(min.1, ExtensionInfo::AllowEnforceValue))
    );
    assert!(
        options
            .public_key
            .extensions
            .prf
            .is_some_and(|prf| prf.first.is_empty()
                && prf.second.is_some_and(|p| p.is_empty())
                && matches!(prf.ext_req, ExtensionReq::Allow))
    );
    Ok(())
}
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "OK in tests"
)]
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "a lot to test"
)]
#[test]
fn key_options() -> Result<(), Error> {
    let mut err =
        serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<16>>(r#"{"bob":true}"#)
            .unwrap_err();
    assert_eq!(
        err.to_string().get(..201),
        Some(
            "unknown field `bob`, expected one of `rp`, `user`, `challenge`, `pubKeyCredParams`, `timeout`, `excludeCredentials`, `authenticatorSelection`, `hints`, `extensions`, `attestation`, `attestationFormats`"
        )
    );
    err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"attestation":"none","attestation":"none"}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..29),
        Some("duplicate field `attestation`")
    );
    err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..41),
        Some("invalid type: Option value, expected null")
    );
    err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"excludeCredentials":[{"type":"public-key","transports":["usb"],"id":"AAAAAAAAAAAAAAAAAAAAAA"}]}"#,
    )
    .unwrap_err();
    assert_eq!(err.to_string().get(..19), Some("trailing characters"));
    err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"attestation":"foo"}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..27),
        Some("invalid value: string \"foo\"")
    );
    err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"attestationFormats":["none","none"]}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..96),
        Some(
            "attestationFormats must be an empty sequence or contain exactly one string whose value is 'none'"
        )
    );
    err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"attestationFormats":["foo"]}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..42),
        Some("invalid value: string \"foo\", expected none")
    );
    err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(r#"{"timeout":0}"#)
        .unwrap_err();
    assert_eq!(
        err.to_string().get(..50),
        Some("invalid value: integer `0`, expected a nonzero u32")
    );
    err = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"timeout":4294967296}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..59),
        Some("invalid value: integer `4294967296`, expected a nonzero u32")
    );
    let mut key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>("{}")?;
    assert!(key.rp_id.is_none());
    assert!(key.user.name.is_none());
    assert!(key.user.id.is_none());
    assert!(key.user.display_name.is_none());
    assert_eq!(key.pub_key_cred_params.0, CoseAlgorithmIdentifiers::ALL.0);
    assert_eq!(key.timeout, FIVE_MINUTES);
    assert_eq!(
        key.authenticator_selection.authenticator_attachment,
        AuthenticatorAttachment::None,
    );
    assert!(matches!(
        key.authenticator_selection.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    assert!(matches!(
        key.authenticator_selection.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert!(key.extensions.cred_props.is_none());
    assert!(matches!(key.extensions.cred_protect, CredProtect::None));
    assert!(key.extensions.min_pin_length.is_none());
    assert!(key.extensions.prf.is_none());
    key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"rp":null,"user":null,"timeout":null,"excludeCredentials":null,"attestation":null,"attestationFormats":null,"authenticatorSelection":null,"extensions":null,"pubKeyCredParams":null,"hints":null,"challenge":null}"#,
    )?;
    assert!(key.rp_id.is_none());
    assert!(key.user.name.is_none());
    assert!(key.user.id.is_none());
    assert!(key.user.display_name.is_none());
    assert_eq!(key.pub_key_cred_params.0, CoseAlgorithmIdentifiers::ALL.0);
    assert_eq!(key.timeout, FIVE_MINUTES);
    assert_eq!(
        key.authenticator_selection.authenticator_attachment,
        AuthenticatorAttachment::None,
    );
    assert!(matches!(
        key.authenticator_selection.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    assert!(matches!(
        key.authenticator_selection.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert!(key.extensions.cred_props.is_none());
    assert!(matches!(key.extensions.cred_protect, CredProtect::None));
    assert!(key.extensions.min_pin_length.is_none());
    assert!(key.extensions.prf.is_none());
    key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"rp":{},"user":{},"excludeCredentials":[],"attestationFormats":[],"authenticatorSelection":{},"extensions":{},"pubKeyCredParams":[],"hints":[]}"#,
    )?;
    assert!(key.rp_id.is_none());
    assert!(key.user.name.is_none());
    assert!(key.user.id.is_none());
    assert!(key.user.display_name.is_none());
    assert_eq!(key.pub_key_cred_params.0, CoseAlgorithmIdentifiers::ALL.0);
    assert_eq!(
        key.authenticator_selection.authenticator_attachment,
        AuthenticatorAttachment::None,
    );
    assert!(matches!(
        key.authenticator_selection.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    assert!(matches!(
        key.authenticator_selection.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert!(key.extensions.cred_props.is_none());
    assert!(matches!(key.extensions.cred_protect, CredProtect::None));
    assert!(key.extensions.min_pin_length.is_none());
    assert!(key.extensions.prf.is_none());
    key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"rp":{"name":null,"id":null},"user":{"name":null,"id":null,"displayName":null},"authenticatorSelection":{"residentKey":null,"requireResidentKey":null,"userVerification":null,"authenticatorAttachment":null},"extensions":{"credProps":null,"credentialProtectionPolicy":null,"enforceCredentialProtectionPolicy":null,"minPinLength":null,"prf":null}}"#,
    )?;
    assert!(key.rp_id.is_none());
    assert!(key.user.name.is_none());
    assert!(key.user.id.is_none());
    assert!(key.user.display_name.is_none());
    assert_eq!(key.pub_key_cred_params.0, CoseAlgorithmIdentifiers::ALL.0);
    assert_eq!(
        key.authenticator_selection.authenticator_attachment,
        AuthenticatorAttachment::None,
    );
    assert!(matches!(
        key.authenticator_selection.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    assert!(matches!(
        key.authenticator_selection.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert!(key.extensions.cred_props.is_none());
    assert!(matches!(key.extensions.cred_protect, CredProtect::None));
    assert!(key.extensions.min_pin_length.is_none());
    assert!(key.extensions.prf.is_none());
    key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"rp":{"name":"Example.com","id":"example.com"},"user":{"name":"bob","displayName":"Bob","id":"AQ"},"timeout":300000,"excludeCredentials":[],"attestation":"none","attestationFormats":["none"],"authenticatorSelection":{"authenticatorAttachment":"cross-platform","residentKey":"required","requireResidentKey":true,"userVerification":"required"},"extensions":{"credProps":true,"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"minPinLength":true,"prf":{"eval":{"first":"","second":""}}},"pubKeyCredParams":[{"type":"public-key","alg":-8}],"hints":["security-key"],"challenge":null}"#,
    )?;
    assert!(key.rp_id.is_some_and(|val| val.as_ref() == "example.com"));
    assert!(key.user.name.is_some_and(|val| val == "bob"));
    assert!(key.user.display_name.is_some_and(|val| val == "Bob"));
    assert!(key.user.id.is_some_and(|val| val.as_ref() == [1; 1]));
    assert_eq!(
        key.pub_key_cred_params.0,
        CoseAlgorithmIdentifiers::ALL
            .remove(CoseAlgorithmIdentifier::Mldsa87)
            .remove(CoseAlgorithmIdentifier::Mldsa65)
            .remove(CoseAlgorithmIdentifier::Mldsa44)
            .remove(CoseAlgorithmIdentifier::Es256)
            .remove(CoseAlgorithmIdentifier::Es384)
            .remove(CoseAlgorithmIdentifier::Rs256)
            .0
    );
    assert_eq!(key.timeout, FIVE_MINUTES);
    assert_eq!(
        key.authenticator_selection.authenticator_attachment,
        AuthenticatorAttachment::CrossPlatform,
    );
    assert!(matches!(
        key.authenticator_selection.resident_key,
        ResidentKeyRequirement::Required
    ));
    assert!(matches!(
        key.authenticator_selection.user_verification,
        UserVerificationRequirement::Required
    ));
    assert!(
        key.extensions
            .cred_props
            .is_some_and(|req| matches!(req, ExtensionReq::Allow))
    );
    assert!(
        matches!(key.extensions.cred_protect, CredProtect::UserVerificationRequired(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
    );
    assert!(
        key.extensions
            .min_pin_length
            .is_some_and(|min| min.0 == FourToSixtyThree::Four
                && matches!(min.1, ExtensionInfo::AllowEnforceValue))
    );
    assert!(key.extensions.prf.is_some_and(|prf| prf.first.is_empty()
        && prf.second.is_some_and(|p| p.is_empty())
        && matches!(prf.ext_req, ExtensionReq::Allow)));
    key = serde_json::from_str::<PublicKeyCredentialCreationOptionsOwned<1>>(
        r#"{"timeout":4294967295}"#,
    )?;
    assert_eq!(key.timeout, NonZeroU32::MAX);
    Ok(())
}
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "OK in tests"
)]
#[expect(clippy::cognitive_complexity, reason = "a lot to test")]
#[test]
fn extension() -> Result<(), Error> {
    let mut err = serde_json::from_str::<ExtensionOwned>(r#"{"bob":true}"#).unwrap_err();
    assert_eq!(
        err.to_string().get(..138),
        Some(
            "unknown field `bob`, expected one of `credProps`, `credentialProtectionPolicy`, `enforceCredentialProtectionPolicy`, `minPinLength`, `prf`"
        )
    );
    err = serde_json::from_str::<ExtensionOwned>(r#"{"credProps":true,"credProps":true}"#)
        .unwrap_err();
    assert_eq!(
        err.to_string().get(..27),
        Some("duplicate field `credProps`")
    );
    err = serde_json::from_str::<ExtensionOwned>(r#"{"enforceCredentialProtectionPolicy":null}"#)
        .unwrap_err();
    assert_eq!(
        err.to_string().get(..84),
        Some(
            "'enforceCredentialProtectionPolicy' must not exist when 'credentialProtectionPolicy'"
        )
    );
    err = serde_json::from_str::<ExtensionOwned>(
        r#"{"enforceCredentialProtectionPolicy":false,"credentialProtectionPolicy":null}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..103),
        Some(
            "'enforceCredentialProtectionPolicy' must be null or not exist when 'credentialProtectionPolicy' is null"
        )
    );
    let mut ext = serde_json::from_str::<ExtensionOwned>(
        r#"{"credProps":true,"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"minPinLength":true,"prf":{"eval":{"first":"","second":""}}}"#,
    )?;
    assert!(
        ext.cred_props
            .is_some_and(|props| matches!(props, ExtensionReq::Allow))
    );
    assert!(
        matches!(ext.cred_protect, CredProtect::UserVerificationRequired(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
    );
    assert!(
        ext.min_pin_length
            .is_some_and(|min| min.0 == FourToSixtyThree::Four
                && matches!(min.1, ExtensionInfo::AllowEnforceValue))
    );
    assert!(ext.prf.is_some_and(|prf| prf.first.is_empty()
        && prf.second.is_some_and(|v| v.is_empty())
        && matches!(prf.ext_req, ExtensionReq::Allow)));
    ext = serde_json::from_str::<ExtensionOwned>(
        r#"{"credProps":null,"credentialProtectionPolicy":null,"enforceCredentialProtectionPolicy":null,"minPinLength":null,"prf":null}"#,
    )?;
    assert!(ext.cred_props.is_none());
    assert!(matches!(ext.cred_protect, CredProtect::None));
    assert!(ext.min_pin_length.is_none());
    assert!(ext.prf.is_none());
    ext = serde_json::from_str::<ExtensionOwned>("{}")?;
    assert!(ext.cred_props.is_none());
    assert!(matches!(ext.cred_protect, CredProtect::None));
    assert!(ext.min_pin_length.is_none());
    assert!(ext.prf.is_none());
    ext = serde_json::from_str::<ExtensionOwned>(r#"{"credentialProtectionPolicy":null}"#)?;
    assert!(matches!(ext.cred_protect, CredProtect::None));
    ext = serde_json::from_str::<ExtensionOwned>(
        r#"{"credentialProtectionPolicy":"userVerificationOptional"}"#,
    )?;
    assert!(
        matches!(ext.cred_protect, CredProtect::UserVerificationOptional(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
    );
    ext = serde_json::from_str::<ExtensionOwned>(
        r#"{"credentialProtectionPolicy":"userVerificationOptionalWithCredentialIDList","enforceCredentialProtectionPolicy":null}"#,
    )?;
    assert!(
        matches!(ext.cred_protect, CredProtect::UserVerificationOptionalWithCredentialIdList(enforce, info) if !enforce && matches!(info, ExtensionInfo::AllowEnforceValue))
    );
    Ok(())
}
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "OK in tests"
)]
#[test]
fn user_entity() -> Result<(), Error> {
    let mut err = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<16>>(r#"{"bob":true}"#)
        .unwrap_err();
    assert_eq!(
        err.to_string().get(..64),
        Some("unknown field `bob`, expected one of `id`, `name`, `displayName`")
    );
    err = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<1>>(
        r#"{"name":"bob","name":"bob"}"#,
    )
    .unwrap_err();
    assert_eq!(err.to_string().get(..22), Some("duplicate field `name`"));
    let mut user = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<1>>(
        r#"{"id":"AQ","name":"bob","displayName":"Bob"}"#,
    )?;
    assert!(
        user.id
            .is_some_and(|val| val.as_slice() == [1; 1].as_slice())
    );
    assert!(user.name.is_some_and(|val| val == "bob"));
    assert!(user.display_name.is_some_and(|val| val == "Bob"));
    user = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<1>>(
        r#"{"id":null,"name":null,"displayName":null}"#,
    )?;
    assert!(user.name.is_none());
    assert!(user.display_name.is_none());
    assert!(user.id.is_none());
    user = serde_json::from_str::<PublicKeyCredentialUserEntityOwned<1>>("{}")?;
    assert!(user.name.is_none());
    assert!(user.display_name.is_none());
    assert!(user.id.is_none());
    Ok(())
}
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "OK in tests"
)]
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "a lot to test"
)]
#[test]
fn auth_crit() -> Result<(), Error> {
    let mut err = serde_json::from_str::<AuthenticatorSelectionCriteria>("null").unwrap_err();
    assert_eq!(
        err.to_string().get(..59),
        Some("invalid type: null, expected AuthenticatorSelectionCriteria")
    );
    err = serde_json::from_str::<AuthenticatorSelectionCriteria>(
        r#"{"residentKey":"required","requireResidentKey":false}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..62),
        Some("'residentKey' is 'required', but 'requireResidentKey' is false")
    );
    err = serde_json::from_str::<AuthenticatorSelectionCriteria>(
        r#"{"residentKey":"preferred","requireResidentKey":true}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..65),
        Some("'residentKey' is not 'required', but 'requireResidentKey' is true")
    );
    err = serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"residentKey":"prefered"}"#)
        .unwrap_err();
    assert_eq!(
        err.to_string().get(..84),
        Some(
            "invalid value: string \"prefered\", expected 'required', 'discouraged', or 'preferred'"
        )
    );
    err = serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"bob":true}"#).unwrap_err();
    assert_eq!(
        err.to_string().get(..119),
        Some(
            "unknown field `bob`, expected one of `authenticatorAttachment`, `residentKey`, `requireResidentKey`, `userVerification`"
        )
    );
    err = serde_json::from_str::<AuthenticatorSelectionCriteria>(
        r#"{"requireResidentKey":true,"requireResidentKey":true}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..36),
        Some("duplicate field `requireResidentKey`")
    );
    let mut crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
        r#"{"authenticatorAttachment":"platform","residentKey":"required","requireResidentKey":true,"userVerification":"required"}"#,
    )?;
    assert_eq!(
        crit.authenticator_attachment,
        AuthenticatorAttachment::Platform,
    );
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Required
    ));
    assert!(matches!(
        crit.user_verification,
        UserVerificationRequirement::Required
    ));
    crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
        r#"{"authenticatorAttachment":null,"residentKey":null,"requireResidentKey":null,"userVerification":null}"#,
    )?;
    assert_eq!(crit.authenticator_attachment, AuthenticatorAttachment::None,);
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    assert!(matches!(
        crit.user_verification,
        UserVerificationRequirement::Preferred
    ));
    crit = serde_json::from_str::<AuthenticatorSelectionCriteria>("{}")?;
    assert_eq!(crit.authenticator_attachment, AuthenticatorAttachment::None,);
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    assert!(matches!(
        crit.user_verification,
        UserVerificationRequirement::Preferred
    ));
    crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
        r#"{"residentKey":"preferred","requireResidentKey":false}"#,
    )?;
    assert_eq!(crit.authenticator_attachment, AuthenticatorAttachment::None,);
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Preferred
    ));
    assert!(matches!(
        crit.user_verification,
        UserVerificationRequirement::Preferred
    ));
    crit =
        serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"residentKey":"preferred"}"#)?;
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Preferred
    ));
    crit =
        serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"requireResidentKey":true}"#)?;
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Required
    ));
    crit =
        serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"requireResidentKey":false}"#)?;
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"residentKey":"required"}"#)?;
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Required
    ));
    crit =
        serde_json::from_str::<AuthenticatorSelectionCriteria>(r#"{"residentKey":"discouraged"}"#)?;
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
        r#"{"residentKey":"discouraged","requireResidentKey":null}"#,
    )?;
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
        r#"{"residentKey":"required","requireResidentKey":null}"#,
    )?;
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Required
    ));
    crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
        r#"{"residentKey":null,"requireResidentKey":true}"#,
    )?;
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Required
    ));
    crit = serde_json::from_str::<AuthenticatorSelectionCriteria>(
        r#"{"residentKey":null,"requireResidentKey":false}"#,
    )?;
    assert!(matches!(
        crit.resident_key,
        ResidentKeyRequirement::Discouraged
    ));
    Ok(())
}
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "OK in tests"
)]
#[test]
fn cose_algs() -> Result<(), Error> {
    let mut err = serde_json::from_str::<CoseAlgorithmIdentifiers>("null").unwrap_err();
    assert_eq!(
        err.to_string().get(..53),
        Some("invalid type: null, expected CoseAlgorithmIdentifiers")
    );
    err = serde_json::from_str::<CoseAlgorithmIdentifiers>("[null]").unwrap_err();
    assert_eq!(
        err.to_string().get(..37),
        Some("invalid type: null, expected PubParam")
    );
    err = serde_json::from_str::<CoseAlgorithmIdentifiers>("[{}]").unwrap_err();
    assert_eq!(err.to_string().get(..19), Some("missing field `alg`"));
    err = serde_json::from_str::<CoseAlgorithmIdentifiers>(
        r#"[{"type":"public-key","alg":-7,"foo":true}]"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..45),
        Some("unknown field `foo`, expected `type` or `alg`")
    );
    err = serde_json::from_str::<CoseAlgorithmIdentifiers>(
        r#"[{"type":"public-key","alg":-7,"alg":-7}]"#,
    )
    .unwrap_err();
    assert_eq!(err.to_string().get(..21), Some("duplicate field `alg`"));
    err = serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"[{"type":"public-key","alg":null}]"#)
        .unwrap_err();
    assert_eq!(
        err.to_string().get(..52),
        Some("invalid type: null, expected CoseAlgorithmIdentifier")
    );
    err = serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"[{"type":null,"alg":-8}]"#)
        .unwrap_err();
    assert_eq!(
        err.to_string().get(..39),
        Some("invalid type: null, expected public-key")
    );
    err = serde_json::from_str::<CoseAlgorithmIdentifiers>(r#"[{"type":"public-key","alg":-6}]"#)
        .unwrap_err();
    assert_eq!(
        err.to_string().get(..73),
        Some("invalid value: integer `-6`, expected -50, -49, -48, -8, -7, -35, or -257")
    );
    err = serde_json::from_str::<CoseAlgorithmIdentifiers>(
        r#"[{"type":"public-key","alg":-7},{"type":"public-key","alg":-7}]"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..49),
        Some("pubKeyCredParams contained duplicate Es256 values")
    );
    err = serde_json::from_str::<CoseAlgorithmIdentifiers>(
        r#"[{"type":"public-key","alg":-7},{"type":"public-key","alg":-8}]"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..79),
        Some("pubKeyCredParams contained Eddsa, but it was preceded by Es256, Es384, or Rs256")
    );
    let mut alg = serde_json::from_str::<CoseAlgorithmIdentifiers>(
        r#"[{"type":"public-key","alg":-8},{"alg":-7}]"#,
    )?;
    assert!(alg.contains(CoseAlgorithmIdentifier::Eddsa));
    assert!(alg.contains(CoseAlgorithmIdentifier::Es256));
    assert!(!alg.contains(CoseAlgorithmIdentifier::Mldsa87));
    assert!(!alg.contains(CoseAlgorithmIdentifier::Mldsa65));
    assert!(!alg.contains(CoseAlgorithmIdentifier::Mldsa44));
    assert!(!alg.contains(CoseAlgorithmIdentifier::Es384));
    assert!(!alg.contains(CoseAlgorithmIdentifier::Rs256));
    alg = serde_json::from_str::<CoseAlgorithmIdentifiers>("[]")?;
    assert!(alg.contains(CoseAlgorithmIdentifier::Mldsa87));
    assert!(alg.contains(CoseAlgorithmIdentifier::Mldsa65));
    assert!(alg.contains(CoseAlgorithmIdentifier::Mldsa44));
    assert!(alg.contains(CoseAlgorithmIdentifier::Eddsa));
    assert!(alg.contains(CoseAlgorithmIdentifier::Es256));
    assert!(alg.contains(CoseAlgorithmIdentifier::Es384));
    assert!(alg.contains(CoseAlgorithmIdentifier::Rs256));
    Ok(())
}
