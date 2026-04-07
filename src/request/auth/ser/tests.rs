use super::{
    super::{super::PublicKeyCredentialHint, ExtensionReq},
    ClientCredentialRequestOptions, CredentialMediationRequirement, CredentialUiMode,
    ExtensionOwned, FIVE_MINUTES, Hints, NonZeroU32, PublicKeyCredentialRequestOptionsOwned,
    UserVerificationRequirement,
};
use serde_json::Error;
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    reason = "OK in tests"
)]
#[expect(clippy::cognitive_complexity, reason = "a lot to test")]
#[test]
fn client_options() -> Result<(), Error> {
    let mut err =
        serde_json::from_str::<ClientCredentialRequestOptions>(r#"{"bob":true}"#).unwrap_err();
    assert_eq!(
        err.to_string().get(..71),
        Some("unknown field `bob`, expected one of `mediation`, `uiMode`, `publicKey`")
    );
    err = serde_json::from_str::<ClientCredentialRequestOptions>(
        r#"{"mediation":"required","mediation":"required"}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..27),
        Some("duplicate field `mediation`")
    );
    let mut options = serde_json::from_str::<ClientCredentialRequestOptions>("{}")?;
    assert!(matches!(
        options.mediation,
        CredentialMediationRequirement::Required
    ));
    assert!(options.ui_mode.is_none());
    assert!(options.public_key.rp_id.is_none());
    assert_eq!(options.public_key.timeout, FIVE_MINUTES);
    assert!(matches!(
        options.public_key.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert_eq!(options.public_key.hints, Hints::EMPTY);
    assert!(options.public_key.extensions.prf.is_none());
    options = serde_json::from_str::<ClientCredentialRequestOptions>(
        r#"{"mediation":null,"uiMode":null,"publicKey":null}"#,
    )?;
    assert!(matches!(
        options.mediation,
        CredentialMediationRequirement::Required
    ));
    assert!(options.ui_mode.is_none());
    assert!(options.public_key.rp_id.is_none());
    assert_eq!(options.public_key.timeout, FIVE_MINUTES);
    assert!(matches!(
        options.public_key.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert_eq!(options.public_key.hints, Hints::EMPTY);
    assert!(options.public_key.extensions.prf.is_none());
    options = serde_json::from_str::<ClientCredentialRequestOptions>(r#"{"publicKey":{}}"#)?;
    assert!(options.public_key.rp_id.is_none());
    assert_eq!(options.public_key.timeout, FIVE_MINUTES);
    assert!(matches!(
        options.public_key.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert_eq!(options.public_key.hints, Hints::EMPTY);
    assert!(options.public_key.extensions.prf.is_none());
    options = serde_json::from_str::<ClientCredentialRequestOptions>(
        r#"{"mediation":"conditional","uiMode":"immediate","publicKey":{"rpId":"example.com","timeout":300000,"allowCredentials":[],"userVerification":"required","extensions":{"prf":{"eval":{"first":"","second":""}}},"hints":["security-key"],"challenge":null}}"#,
    )?;
    assert!(matches!(
        options.mediation,
        CredentialMediationRequirement::Conditional
    ));
    assert_eq!(options.ui_mode, Some(CredentialUiMode::Immediate));
    assert!(
        options
            .public_key
            .rp_id
            .is_some_and(|val| val.as_ref() == "example.com")
    );
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
#[expect(clippy::cognitive_complexity, reason = "a lot to test")]
#[test]
fn key_options() -> Result<(), Error> {
    let mut err = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(r#"{"bob":true}"#)
        .unwrap_err();
    assert_eq!(
        err.to_string().get(..130),
        Some(
            "unknown field `bob`, expected one of `rpId`, `userVerification`, `challenge`, `timeout`, `allowCredentials`, `hints`, `extensions`"
        )
    );
    err = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
        r#"{"rpId":"example.com","rpId":"example.com"}"#,
    )
    .unwrap_err();
    assert_eq!(err.to_string().get(..22), Some("duplicate field `rpId`"));
    err = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
        r#"{"challenge":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
    )
    .unwrap_err();
    assert_eq!(
        err.to_string().get(..41),
        Some("invalid type: Option value, expected null")
    );
    err = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
        r#"{"allowCredentials":[{"type":"public-key","transports":["usb"],"id":"AAAAAAAAAAAAAAAAAAAAAA"}]}"#,
    )
    .unwrap_err();
    assert_eq!(err.to_string().get(..19), Some("trailing characters"));
    err = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(r#"{"timeout":0}"#)
        .unwrap_err();
    assert_eq!(
        err.to_string().get(..50),
        Some("invalid value: integer `0`, expected a nonzero u32")
    );
    err =
        serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(r#"{"timeout":4294967296}"#)
            .unwrap_err();
    assert_eq!(
        err.to_string().get(..59),
        Some("invalid value: integer `4294967296`, expected a nonzero u32")
    );
    let mut key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>("{}")?;
    assert!(key.rp_id.is_none());
    assert_eq!(key.timeout, FIVE_MINUTES);
    assert!(matches!(
        key.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert!(key.extensions.prf.is_none());
    assert_eq!(key.hints, Hints::EMPTY);
    key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
        r#"{"rpId":null,"timeout":null,"allowCredentials":null,"userVerification":null,"extensions":null,"hints":null,"challenge":null}"#,
    )?;
    assert!(key.rp_id.is_none());
    assert_eq!(key.timeout, FIVE_MINUTES);
    assert!(matches!(
        key.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert!(key.extensions.prf.is_none());
    assert_eq!(key.hints, Hints::EMPTY);
    key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
        r#"{"allowCredentials":[],"extensions":{},"hints":[]}"#,
    )?;
    assert!(matches!(
        key.user_verification,
        UserVerificationRequirement::Preferred
    ));
    assert_eq!(key.hints, Hints::EMPTY);
    assert!(key.extensions.prf.is_none());
    key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
        r#"{"extensions":{"prf":null}}"#,
    )?;
    assert!(key.extensions.prf.is_none());
    key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
        r#"{"rpId":"example.com","timeout":300000,"allowCredentials":[],"userVerification":"required","extensions":{"prf":{"eval":{"first":"","second":""}}},"hints":["security-key"],"challenge":null}"#,
    )?;
    assert!(key.rp_id.is_some_and(|val| val.as_ref() == "example.com"));
    assert_eq!(key.timeout, FIVE_MINUTES);
    assert!(matches!(
        key.user_verification,
        UserVerificationRequirement::Required
    ));
    assert_eq!(
        key.hints,
        Hints::EMPTY.add(PublicKeyCredentialHint::SecurityKey)
    );
    assert!(key.extensions.prf.is_some_and(|prf| prf.first.is_empty()
        && prf.second.is_some_and(|p| p.is_empty())
        && matches!(prf.ext_req, ExtensionReq::Allow)));
    key = serde_json::from_str::<PublicKeyCredentialRequestOptionsOwned>(
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
#[test]
fn extension() -> Result<(), Error> {
    let mut err = serde_json::from_str::<ExtensionOwned>(r#"{"bob":true}"#).unwrap_err();
    assert_eq!(
        err.to_string().get(..35),
        Some("unknown field `bob`, expected `prf`")
    );
    err = serde_json::from_str::<ExtensionOwned>(
        r#"{"prf":{"eval":{"first":"","second":""}},"prf":{"eval":{"first":"","second":""}}}"#,
    )
    .unwrap_err();
    assert_eq!(err.to_string().get(..21), Some("duplicate field `prf`"));
    err = serde_json::from_str::<ExtensionOwned>(r#"{"prf":{"eval":{"first":null}}}"#).unwrap_err();
    assert_eq!(
        err.to_string().get(..51),
        Some("invalid type: null, expected base64url-encoded data")
    );
    let mut ext =
        serde_json::from_str::<ExtensionOwned>(r#"{"prf":{"eval":{"first":"","second":""}}}"#)?;
    assert!(ext.prf.is_some_and(|prf| prf.first.is_empty()
        && prf.second.is_some_and(|v| v.is_empty())
        && matches!(prf.ext_req, ExtensionReq::Allow)));
    ext = serde_json::from_str::<ExtensionOwned>(r#"{"prf":null}"#)?;
    assert!(ext.prf.is_none());
    ext = serde_json::from_str::<ExtensionOwned>("{}")?;
    assert!(ext.prf.is_none());
    Ok(())
}
