#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
use super::{
    super::super::{
        AuthenticatedCredential, DynamicState, StaticState, UserHandle,
        response::{
            Backup,
            auth::{DiscoverableAuthenticatorAssertion, HmacSecret},
            register::{
                AuthenticationExtensionsPrfOutputs, AuthenticatorExtensionOutputStaticState,
                ClientExtensionsOutputsStaticState, CompressedPubKeyOwned,
                CredentialProtectionPolicy, Ed25519PubKey,
            },
        },
    },
    AuthCeremonyErr, AuthenticationVerificationOptions, AuthenticatorAttachment,
    AuthenticatorAttachmentEnforcement, BackupStateReq, DiscoverableAuthentication, ExtensionErr,
    OneOrTwo, PrfInput, SignatureCounterEnforcement,
};
#[cfg(all(
    feature = "custom",
    any(
        feature = "serializable_server_state",
        not(any(feature = "bin", feature = "serde"))
    )
))]
use super::{
    super::{super::AggErr, Challenge, CredentialId, RpId, UserVerificationRequirement},
    DiscoverableCredentialRequestOptions, ExtensionReq,
};
#[cfg(all(feature = "custom", feature = "serializable_server_state"))]
use super::{
    super::{
        super::bin::{Decode as _, Encode as _},
        AsciiDomain, AuthTransports,
    },
    AllowedCredential, AllowedCredentials, CredentialSpecificExtension, Credentials as _,
    DiscoverableAuthenticationServerState, Extension, NonDiscoverableAuthenticationServerState,
    NonDiscoverableCredentialRequestOptions, PrfInputOwned, PublicKeyCredentialDescriptor,
};
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
use ed25519_dalek::{Signer as _, SigningKey};
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
use rsa::sha2::{Digest as _, Sha256};
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_BYTES: u8 = 0b010_00000;
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_TEXT: u8 = 0b011_00000;
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_MAP: u8 = 0b101_00000;
#[expect(clippy::panic_in_result_fn, reason = "OK in tests")]
#[test]
#[cfg(all(feature = "custom", feature = "serializable_server_state"))]
fn eddsa_auth_ser() -> Result<(), AggErr> {
    let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
    let mut creds = AllowedCredentials::with_capacity(1);
    _ = creds.push(AllowedCredential {
        credential: PublicKeyCredentialDescriptor {
            id: CredentialId::try_from(vec![0; 16].into_boxed_slice())?,
            transports: AuthTransports::NONE,
        },
        extension: CredentialSpecificExtension {
            prf: Some(PrfInputOwned {
                first: Vec::new(),
                second: Some(Vec::new()),
                ext_req: ExtensionReq::Require,
            }),
        },
    });
    let mut opts = NonDiscoverableCredentialRequestOptions::second_factor(&rp_id, creds);
    opts.options.user_verification = UserVerificationRequirement::Required;
    opts.options.challenge = Challenge(0);
    opts.options.extensions = Extension { prf: None };
    let server = opts.start_ceremony()?.0;
    let enc_data = server.encode()?;
    assert_eq!(enc_data.capacity(), 16 + 2 + 1 + 1 + 12 + 2 + 128 + 1);
    assert_eq!(enc_data.len(), 16 + 2 + 1 + 1 + 12 + 2 + 16 + 2);
    assert!(
        server.is_eq(&NonDiscoverableAuthenticationServerState::decode(
            enc_data.as_slice()
        )?)
    );
    let mut opts_2 = DiscoverableCredentialRequestOptions::passkey(&rp_id);
    opts_2.public_key.challenge = Challenge(0);
    opts_2.public_key.extensions = Extension { prf: None };
    let server_2 = opts_2.start_ceremony()?.0;
    let enc_data_2 = server_2
        .encode()
        .map_err(AggErr::EncodeDiscoverableAuthenticationServerState)?;
    assert_eq!(enc_data_2.capacity(), enc_data_2.len());
    assert_eq!(enc_data_2.len(), 16 + 1 + 1 + 12);
    assert!(
        server_2.is_eq(&DiscoverableAuthenticationServerState::decode(
            enc_data_2.as_slice()
        )?)
    );
    Ok(())
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[derive(Clone, Copy)]
struct TestResponseOptions {
    user_verified: bool,
    hmac: HmacSecret,
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[derive(Clone, Copy)]
enum PrfCredOptions {
    None,
    FalseNoHmac,
    FalseHmacFalse,
    TrueNoHmac,
    TrueHmacTrue,
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[derive(Clone, Copy)]
struct TestCredOptions {
    cred_protect: CredentialProtectionPolicy,
    prf: PrfCredOptions,
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[derive(Clone, Copy)]
enum PrfUvOptions {
    /// `true` iff `UserVerificationRequirement::Required` should be used; otherwise
    /// `UserVerificationRequirement::Preferred` is used.
    None(bool),
    Prf((PrfInput<'static, 'static>, ExtensionReq)),
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[derive(Clone, Copy)]
struct TestRequestOptions {
    error_unsolicited: bool,
    prf_uv: PrfUvOptions,
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[derive(Clone, Copy)]
struct TestOptions {
    request: TestRequestOptions,
    response: TestResponseOptions,
    cred: TestCredOptions,
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
fn generate_client_data_json() -> Vec<u8> {
    let mut json = Vec::with_capacity(256);
    json.extend_from_slice(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice());
    json
}
#[expect(clippy::indexing_slicing, reason = "comments justify correctness")]
#[expect(clippy::too_many_lines, reason = "a lot to test")]
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
fn generate_authenticator_data_public_key_sig(
    opts: TestResponseOptions,
) -> (Vec<u8>, CompressedPubKeyOwned, Vec<u8>) {
    let mut authenticator_data = Vec::with_capacity(256);
    authenticator_data.extend_from_slice(
        [
            // RP ID HASH.
            // This will be overwritten later.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // FLAGS.
            // UP, UV, AT, and ED (right-to-left).
            0b0000_0001
                | if opts.user_verified {
                    0b0000_0100
                } else {
                    0b0000_0000
                }
                | if matches!(opts.hmac, HmacSecret::None) {
                    0
                } else {
                    0b1000_0000
                },
            // COUNTER.
            // 0 as 32-bit big endian.
            0,
            0,
            0,
            0,
        ]
        .as_slice(),
    );
    authenticator_data[..32].copy_from_slice(&Sha256::digest(b"example.com"));
    match opts.hmac {
        HmacSecret::None => {}
        HmacSecret::One => {
            authenticator_data.extend_from_slice(
                [
                    CBOR_MAP | 1,
                    // CBOR text of length 11.
                    CBOR_TEXT | 11,
                    b'h',
                    b'm',
                    b'a',
                    b'c',
                    b'-',
                    b's',
                    b'e',
                    b'c',
                    b'r',
                    b'e',
                    b't',
                    CBOR_BYTES | 24,
                    48,
                ]
                .as_slice(),
            );
            authenticator_data.extend_from_slice([0; 48].as_slice());
        }
        HmacSecret::Two => {
            authenticator_data.extend_from_slice(
                [
                    CBOR_MAP | 1,
                    // CBOR text of length 11.
                    CBOR_TEXT | 11,
                    b'h',
                    b'm',
                    b'a',
                    b'c',
                    b'-',
                    b's',
                    b'e',
                    b'c',
                    b'r',
                    b'e',
                    b't',
                    CBOR_BYTES | 24,
                    80,
                ]
                .as_slice(),
            );
            authenticator_data.extend_from_slice([0; 80].as_slice());
        }
    }
    let len = authenticator_data.len();
    authenticator_data.extend_from_slice(&Sha256::digest(generate_client_data_json().as_slice()));
    let sig_key = SigningKey::from_bytes(&[0; 32]);
    let sig = sig_key.sign(authenticator_data.as_slice()).to_vec();
    authenticator_data.truncate(len);
    (
        authenticator_data,
        CompressedPubKeyOwned::Ed25519(Ed25519PubKey::from(sig_key.verifying_key().to_bytes())),
        sig,
    )
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
fn validate(options: TestOptions) -> Result<(), AggErr> {
    let rp_id = RpId::Domain("example.com".to_owned().try_into()?);
    let user = UserHandle::from([0; 1]);
    let (authenticator_data, credential_public_key, signature) =
        generate_authenticator_data_public_key_sig(options.response);
    let credential_id = CredentialId::try_from(vec![0; 16].into_boxed_slice())?;
    let authentication = DiscoverableAuthentication::new(
        credential_id.clone(),
        DiscoverableAuthenticatorAssertion::new(
            generate_client_data_json(),
            authenticator_data,
            signature,
            user,
        ),
        AuthenticatorAttachment::None,
    );
    let auth_opts = AuthenticationVerificationOptions::<'static, 'static, &str, &str> {
        allowed_origins: [].as_slice(),
        allowed_top_origins: None,
        auth_attachment_enforcement: AuthenticatorAttachmentEnforcement::Update(false),
        backup_state_requirement: BackupStateReq::None,
        error_on_unsolicited_extensions: options.request.error_unsolicited,
        sig_counter_enforcement: SignatureCounterEnforcement::Fail,
        update_uv: false,
        #[cfg(feature = "serde_relaxed")]
        client_data_json_relaxed: false,
    };
    let mut opts = DiscoverableCredentialRequestOptions::passkey(&rp_id);
    opts.public_key.challenge = Challenge(0);
    opts.public_key.user_verification = UserVerificationRequirement::Preferred;
    match options.request.prf_uv {
        PrfUvOptions::None(required) => {
            if required {
                opts.public_key.user_verification = UserVerificationRequirement::Required;
            }
        }
        PrfUvOptions::Prf(input) => {
            opts.public_key.user_verification = UserVerificationRequirement::Required;
            opts.public_key.extensions.prf = Some(input);
        }
    }
    let mut cred = AuthenticatedCredential::new(
        (&credential_id).into(),
        &user,
        StaticState {
            credential_public_key,
            extensions: AuthenticatorExtensionOutputStaticState {
                cred_protect: options.cred.cred_protect,
                hmac_secret: match options.cred.prf {
                    PrfCredOptions::None
                    | PrfCredOptions::FalseNoHmac
                    | PrfCredOptions::TrueNoHmac => None,
                    PrfCredOptions::FalseHmacFalse => Some(false),
                    PrfCredOptions::TrueHmacTrue => Some(true),
                },
            },
            client_extension_results: ClientExtensionsOutputsStaticState {
                prf: match options.cred.prf {
                    PrfCredOptions::None => None,
                    PrfCredOptions::FalseNoHmac | PrfCredOptions::FalseHmacFalse => {
                        Some(AuthenticationExtensionsPrfOutputs { enabled: false })
                    }
                    PrfCredOptions::TrueNoHmac | PrfCredOptions::TrueHmacTrue => {
                        Some(AuthenticationExtensionsPrfOutputs { enabled: true })
                    }
                },
            },
        },
        DynamicState {
            user_verified: true,
            backup: Backup::NotEligible,
            sign_count: 0,
            authenticator_attachment: AuthenticatorAttachment::None,
        },
    )?;
    opts.start_ceremony()?
        .0
        .verify(&rp_id, &authentication, &mut cred, &auth_opts)
        .map_err(AggErr::AuthCeremony)
        .map(|_| ())
}
/// Test all, and only, possible `UserNotVerified` errors.
/// 4 * 5 * 3 * 2 * 5 = 600 tests.
/// We ignore this due to how long it takes (around 4 seconds or so).
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[ignore = "slow"]
#[test]
fn uv_required_err() {
    const ALL_CRED_PROTECT_OPTIONS: [CredentialProtectionPolicy; 4] = [
        CredentialProtectionPolicy::None,
        CredentialProtectionPolicy::UserVerificationOptional,
        CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
        CredentialProtectionPolicy::UserVerificationRequired,
    ];
    const ALL_PRF_CRED_OPTIONS: [PrfCredOptions; 5] = [
        PrfCredOptions::None,
        PrfCredOptions::FalseNoHmac,
        PrfCredOptions::FalseHmacFalse,
        PrfCredOptions::TrueNoHmac,
        PrfCredOptions::TrueHmacTrue,
    ];
    const ALL_HMAC_OPTIONS: [HmacSecret; 3] = [HmacSecret::None, HmacSecret::One, HmacSecret::Two];
    const ALL_UNSOLICIT_OPTIONS: [bool; 2] = [false, true];
    const ALL_NOT_FALSE_PRF_UV_OPTIONS: [PrfUvOptions; 5] = [
        PrfUvOptions::None(true),
        PrfUvOptions::Prf((
            PrfInput {
                first: [].as_slice(),
                second: None,
            },
            ExtensionReq::Require,
        )),
        PrfUvOptions::Prf((
            PrfInput {
                first: [].as_slice(),
                second: None,
            },
            ExtensionReq::Allow,
        )),
        PrfUvOptions::Prf((
            PrfInput {
                first: [].as_slice(),
                second: Some([].as_slice()),
            },
            ExtensionReq::Require,
        )),
        PrfUvOptions::Prf((
            PrfInput {
                first: [].as_slice(),
                second: Some([].as_slice()),
            },
            ExtensionReq::Allow,
        )),
    ];
    for cred_protect in ALL_CRED_PROTECT_OPTIONS {
        for prf in ALL_PRF_CRED_OPTIONS {
            for hmac in ALL_HMAC_OPTIONS {
                for error_unsolicited in ALL_UNSOLICIT_OPTIONS {
                    for prf_uv in ALL_NOT_FALSE_PRF_UV_OPTIONS {
                        assert!(validate(TestOptions {
                            request: TestRequestOptions {
                                error_unsolicited,
                                prf_uv,
                            },
                            response: TestResponseOptions {
                                user_verified: false,
                                hmac,
                            },
                            cred: TestCredOptions { cred_protect, prf, },
                        }).is_err_and(|err| matches!(err, AggErr::AuthCeremony(auth_err) if matches!(auth_err, AuthCeremonyErr::UserNotVerified))));
                    }
                }
            }
        }
    }
}
/// Test all, and only, possible `UserNotVerified` errors.
/// 4 * 5 * 2 * 2 = 80 tests.
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[test]
fn forbidden_hmac() {
    const ALL_CRED_PROTECT_OPTIONS: [CredentialProtectionPolicy; 4] = [
        CredentialProtectionPolicy::None,
        CredentialProtectionPolicy::UserVerificationOptional,
        CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
        CredentialProtectionPolicy::UserVerificationRequired,
    ];
    const ALL_PRF_CRED_OPTIONS: [PrfCredOptions; 5] = [
        PrfCredOptions::None,
        PrfCredOptions::FalseNoHmac,
        PrfCredOptions::FalseHmacFalse,
        PrfCredOptions::TrueNoHmac,
        PrfCredOptions::TrueHmacTrue,
    ];
    const ALL_HMAC_OPTIONS: [HmacSecret; 2] = [HmacSecret::One, HmacSecret::Two];
    const ALL_UV_OPTIONS: [bool; 2] = [false, true];
    for cred_protect in ALL_CRED_PROTECT_OPTIONS {
        for prf in ALL_PRF_CRED_OPTIONS {
            for hmac in ALL_HMAC_OPTIONS {
                for user_verified in ALL_UV_OPTIONS {
                    assert!(validate(TestOptions {
                        request: TestRequestOptions {
                            error_unsolicited: true,
                            prf_uv: PrfUvOptions::None(false),
                        },
                        response: TestResponseOptions {
                            user_verified,
                            hmac,
                        },
                        cred: TestCredOptions { cred_protect, prf, },
                    }).is_err_and(|err| matches!(err, AggErr::AuthCeremony(auth_err) if matches!(auth_err, AuthCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::ForbiddenHmacSecret)))));
                }
            }
        }
    }
}
#[expect(clippy::panic_in_result_fn, reason = "OK in tests")]
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[test]
fn prf() -> Result<(), AggErr> {
    let mut opts = TestOptions {
        request: TestRequestOptions {
            error_unsolicited: false,
            prf_uv: PrfUvOptions::Prf((
                PrfInput {
                    first: [].as_slice(),
                    second: None,
                },
                ExtensionReq::Allow,
            )),
        },
        response: TestResponseOptions {
            user_verified: true,
            hmac: HmacSecret::None,
        },
        cred: TestCredOptions {
            cred_protect: CredentialProtectionPolicy::None,
            prf: PrfCredOptions::None,
        },
    };
    validate(opts)?;
    opts.request.prf_uv = PrfUvOptions::Prf((
        PrfInput {
            first: [].as_slice(),
            second: None,
        },
        ExtensionReq::Require,
    ));
    opts.cred.prf = PrfCredOptions::TrueHmacTrue;
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::AuthCeremony(auth_err) if matches!(auth_err, AuthCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::MissingHmacSecret)))));
    opts.response.hmac = HmacSecret::One;
    opts.request.prf_uv = PrfUvOptions::Prf((
        PrfInput {
            first: [].as_slice(),
            second: None,
        },
        ExtensionReq::Allow,
    ));
    opts.cred.prf = PrfCredOptions::TrueNoHmac;
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::AuthCeremony(auth_err) if matches!(auth_err, AuthCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::HmacSecretForNonHmacSecretCredential)))));
    opts.response.hmac = HmacSecret::Two;
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::AuthCeremony(auth_err) if matches!(auth_err, AuthCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::InvalidHmacSecretValue(OneOrTwo::One, OneOrTwo::Two))))));
    opts.response.hmac = HmacSecret::One;
    opts.cred.prf = PrfCredOptions::FalseNoHmac;
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::AuthCeremony(auth_err) if matches!(auth_err, AuthCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::HmacSecretForNonHmacSecretCredential)))));
    opts.response.user_verified = false;
    opts.request.prf_uv = PrfUvOptions::None(false);
    opts.cred.prf = PrfCredOptions::TrueHmacTrue;
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::AuthCeremony(auth_err) if matches!(auth_err, AuthCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::UserNotVerifiedHmacSecret)))));
    Ok(())
}
