#[cfg(all(
    feature = "custom",
    any(
        feature = "serializable_server_state",
        not(any(feature = "bin", feature = "serde"))
    )
))]
use super::{
    super::{super::AggErr, ExtensionInfo},
    Challenge, CredProtect, CredentialCreationOptions, FourToSixtyThree, PrfInput,
    PublicKeyCredentialUserEntity, RpId, UserHandle,
};
#[cfg(all(feature = "custom", feature = "serializable_server_state"))]
use super::{
    super::{
        super::bin::{Decode as _, Encode as _},
        AsciiDomain,
    },
    Extension, RegistrationServerState,
};
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
use super::{
    super::{
        super::{
            CredentialErr,
            response::register::{
                AuthenticationExtensionsPrfOutputs, AuthenticatorAttestation,
                ClientExtensionsOutputs, CredentialPropertiesOutput, CredentialProtectionPolicy,
                HmacSecret,
            },
        },
        AuthTransports,
    },
    AuthenticatorAttachment, BackupReq, ExtensionErr, ExtensionReq, RegCeremonyErr, Registration,
    RegistrationVerificationOptions, UserVerificationRequirement,
};
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
use rsa::sha2::{Digest as _, Sha256};
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_UINT: u8 = 0b000_00000;
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_NEG: u8 = 0b001_00000;
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_BYTES: u8 = 0b010_00000;
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_TEXT: u8 = 0b011_00000;
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_MAP: u8 = 0b101_00000;
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_SIMPLE: u8 = 0b111_00000;
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_FALSE: u8 = CBOR_SIMPLE | 20;
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
const CBOR_TRUE: u8 = CBOR_SIMPLE | 21;
#[expect(clippy::panic_in_result_fn, reason = "OK in tests")]
#[test]
#[cfg(all(feature = "custom", feature = "serializable_server_state"))]
fn eddsa_reg_ser() -> Result<(), AggErr> {
    let rp_id = RpId::Domain(AsciiDomain::try_from("example.com".to_owned())?);
    let id = UserHandle::from([0; 1]);
    let mut opts = CredentialCreationOptions::passkey(
        &rp_id,
        PublicKeyCredentialUserEntity {
            name: "foo",
            id: &id,
            display_name: "",
        },
        Vec::new(),
    );
    opts.public_key.challenge = Challenge(0);
    opts.public_key.extensions = Extension {
        cred_props: None,
        cred_protect: CredProtect::UserVerificationRequired(
            false,
            ExtensionInfo::RequireEnforceValue,
        ),
        min_pin_length: Some((FourToSixtyThree::Ten, ExtensionInfo::RequireEnforceValue)),
        prf: Some((
            PrfInput {
                first: [0].as_slice(),
                second: None,
            },
            ExtensionInfo::RequireEnforceValue,
        )),
    };
    let server = opts.start_ceremony()?.0;
    let enc_data = server
        .encode()
        .map_err(AggErr::EncodeRegistrationServerState)?;
    assert_eq!(enc_data.capacity(), enc_data.len());
    assert_eq!(enc_data.len(), 1 + 16 + 1 + 3 + (1 + 3 + 3 + 2) + 12 + 1);
    assert!(server.is_eq(&RegistrationServerState::decode(enc_data.as_slice())?));
    Ok(())
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[derive(Clone, Copy)]
struct TestResponseOptions {
    user_verified: bool,
    cred_protect: CredentialProtectionPolicy,
    prf: Option<bool>,
    hmac: HmacSecret,
    min_pin: Option<FourToSixtyThree>,
    #[expect(clippy::option_option, reason = "fine")]
    cred_props: Option<Option<bool>>,
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[derive(Clone, Copy)]
enum PrfUvOptions {
    /// `true` iff `UserVerificationRequirement::Required` should be used; otherwise
    /// `UserVerificationRequirement::Preferred` is used.
    None(bool),
    Prf(ExtensionInfo),
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[derive(Clone, Copy)]
struct TestRequestOptions {
    error_unsolicited: bool,
    protect: CredProtect,
    prf_uv: PrfUvOptions,
    props: Option<ExtensionReq>,
    pin: Option<(FourToSixtyThree, ExtensionInfo)>,
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
#[derive(Clone, Copy)]
struct TestOptions {
    request: TestRequestOptions,
    response: TestResponseOptions,
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
fn generate_client_data_json() -> Vec<u8> {
    let mut json = Vec::with_capacity(256);
    json.extend_from_slice(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice());
    json
}
#[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "comments justify correctness"
)]
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "a lot to test"
)]
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
fn generate_attestation_object(options: TestResponseOptions) -> Vec<u8> {
    let mut attestation_object = Vec::with_capacity(256);
    attestation_object.extend_from_slice(
        [
            CBOR_MAP | 3,
            CBOR_TEXT | 3,
            b'f',
            b'm',
            b't',
            CBOR_TEXT | 4,
            b'n',
            b'o',
            b'n',
            b'e',
            CBOR_TEXT | 7,
            b'a',
            b't',
            b't',
            b'S',
            b't',
            b'm',
            b't',
            CBOR_MAP,
            CBOR_TEXT | 8,
            b'a',
            b'u',
            b't',
            b'h',
            b'D',
            b'a',
            b't',
            b'a',
            CBOR_BYTES | 24,
            // Length.
            // Addition won't overflow.
            113 + if matches!(options.cred_protect, CredentialProtectionPolicy::None) {
                if matches!(options.hmac, HmacSecret::None) {
                    options.min_pin.map_or(0, |_| 15)
                } else {
                    14 + options.min_pin.map_or(0, |_| 14)
                        + match options.hmac {
                            HmacSecret::None => unreachable!("bug"),
                            HmacSecret::NotEnabled | HmacSecret::Enabled => 0,
                            HmacSecret::One => 65,
                            HmacSecret::Two => 97,
                        }
                }
            } else {
                14 + if matches!(options.hmac, HmacSecret::None) {
                    0
                } else {
                    13
                } + options.min_pin.map_or(0, |_| 14)
                    + match options.hmac {
                        HmacSecret::None | HmacSecret::NotEnabled | HmacSecret::Enabled => 0,
                        HmacSecret::One => 65,
                        HmacSecret::Two => 97,
                    }
            },
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
            0b0100_0001
                | if options.user_verified {
                    0b0000_0100
                } else {
                    0b0000_0000
                }
                | if matches!(options.cred_protect, CredentialProtectionPolicy::None)
                    && matches!(options.hmac, HmacSecret::None)
                    && options.min_pin.is_none()
                {
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
            // AAGUID.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            // L.
            // CREDENTIAL ID length is 16 as 16-bit big endian.
            0,
            16,
            // CREDENTIAL ID.
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            CBOR_MAP | 4,
            // COSE kty.
            CBOR_UINT | 1,
            // COSE OKP.
            CBOR_UINT | 1,
            // COSE alg.
            CBOR_UINT | 3,
            // COSE Eddsa.
            CBOR_NEG | 7,
            // COSE OKP crv.
            CBOR_NEG,
            // COSE Ed25519.
            CBOR_UINT | 6,
            // COSE OKP x.
            CBOR_NEG | 1,
            CBOR_BYTES | 24,
            // Length is 32.
            32,
            // Compressed-y coordinate.
            59,
            106,
            39,
            188,
            206,
            182,
            164,
            45,
            98,
            163,
            168,
            208,
            42,
            111,
            13,
            115,
            101,
            50,
            21,
            119,
            29,
            226,
            67,
            166,
            58,
            192,
            72,
            161,
            139,
            89,
            218,
            41,
        ]
        .as_slice(),
    );
    attestation_object[30..62].copy_from_slice(&Sha256::digest(b"example.com"));
    if matches!(options.cred_protect, CredentialProtectionPolicy::None) {
        if matches!(options.hmac, HmacSecret::None) {
            if options.min_pin.is_some() {
                attestation_object.push(CBOR_MAP | 1);
            }
        } else if options.min_pin.is_some() {
            attestation_object.push(
                // Addition won't overflow.
                CBOR_MAP
                    | (2 + u8::from(matches!(options.hmac, HmacSecret::One | HmacSecret::Two))),
            );
        } else {
            attestation_object.push(
                // Addition won't overflow.
                CBOR_MAP
                    | (1 + u8::from(matches!(options.hmac, HmacSecret::One | HmacSecret::Two))),
            );
        }
    } else {
        attestation_object.extend_from_slice(
            [
                // Addition won't overflow.
                CBOR_MAP
                    | (1 + match options.hmac {
                        HmacSecret::None => 0,
                        HmacSecret::NotEnabled | HmacSecret::Enabled => 1,
                        HmacSecret::One | HmacSecret::Two => 2,
                    } + u8::from(options.min_pin.is_some())),
                // CBOR text of length 11.
                CBOR_TEXT | 11,
                b'c',
                b'r',
                b'e',
                b'd',
                b'P',
                b'r',
                b'o',
                b't',
                b'e',
                b'c',
                b't',
                // Addition won't overflow.
                match options.cred_protect {
                    CredentialProtectionPolicy::None => unreachable!("bug"),
                    CredentialProtectionPolicy::UserVerificationOptional => 1,
                    CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList => 2,
                    CredentialProtectionPolicy::UserVerificationRequired => 3,
                },
            ]
            .as_slice(),
        );
    }
    if !matches!(options.hmac, HmacSecret::None) {
        attestation_object.extend_from_slice(
            [
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
                if matches!(options.hmac, HmacSecret::NotEnabled) {
                    CBOR_FALSE
                } else {
                    CBOR_TRUE
                },
            ]
            .as_slice(),
        );
    }
    _ = options.min_pin.map(|p| {
        assert!(p <= FourToSixtyThree::TwentyThree, "bug");
        attestation_object.extend_from_slice(
            [
                // CBOR text of length 12.
                CBOR_TEXT | 12,
                b'm',
                b'i',
                b'n',
                b'P',
                b'i',
                b'n',
                b'L',
                b'e',
                b'n',
                b'g',
                b't',
                b'h',
                CBOR_UINT | p.into_u8(),
            ]
            .as_slice(),
        );
    });
    if matches!(options.hmac, HmacSecret::One | HmacSecret::Two) {
        attestation_object.extend_from_slice(
            [
                // CBOR text of length 14.
                CBOR_TEXT | 14,
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
                b'-',
                b'm',
                b'c',
                CBOR_BYTES | 24,
            ]
            .as_slice(),
        );
        if matches!(options.hmac, HmacSecret::One) {
            attestation_object.push(48);
            attestation_object.extend_from_slice([1; 48].as_slice());
        } else {
            attestation_object.push(80);
            attestation_object.extend_from_slice([1; 80].as_slice());
        }
    }
    attestation_object
}
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
fn validate(options: TestOptions) -> Result<(), AggErr> {
    let rp_id = RpId::Domain("example.com".to_owned().try_into()?);
    let registration = Registration::new(
        AuthenticatorAttestation::new(
            generate_client_data_json(),
            generate_attestation_object(options.response),
            AuthTransports::NONE,
        ),
        AuthenticatorAttachment::None,
        ClientExtensionsOutputs {
            cred_props: options
                .response
                .cred_props
                .map(|rk| CredentialPropertiesOutput { rk }),
            prf: options
                .response
                .prf
                .map(|enabled| AuthenticationExtensionsPrfOutputs { enabled }),
        },
    );
    let reg_opts = RegistrationVerificationOptions::<'static, 'static, &str, &str> {
        allowed_origins: [].as_slice(),
        allowed_top_origins: None,
        backup_requirement: BackupReq::None,
        error_on_unsolicited_extensions: options.request.error_unsolicited,
        require_authenticator_attachment: false,
        #[cfg(feature = "serde_relaxed")]
        client_data_json_relaxed: false,
    };
    let user = UserHandle::from([0; 1]);
    let mut opts = CredentialCreationOptions::passkey(
        &rp_id,
        PublicKeyCredentialUserEntity {
            id: &user,
            name: "",
            display_name: "",
        },
        Vec::new(),
    );
    opts.public_key.challenge = Challenge(0);
    opts.public_key.authenticator_selection.user_verification =
        UserVerificationRequirement::Preferred;
    match options.request.prf_uv {
        PrfUvOptions::None(required) => {
            if required
                || matches!(
                    options.request.protect,
                    CredProtect::UserVerificationRequired(_, _)
                )
            {
                opts.public_key.authenticator_selection.user_verification =
                    UserVerificationRequirement::Required;
            }
        }
        PrfUvOptions::Prf(info) => {
            opts.public_key.authenticator_selection.user_verification =
                UserVerificationRequirement::Required;
            opts.public_key.extensions.prf = Some((
                PrfInput {
                    first: [0].as_slice(),
                    second: None,
                },
                info,
            ));
        }
    }
    opts.public_key.extensions.cred_protect = options.request.protect;
    opts.public_key.extensions.cred_props = options.request.props;
    opts.public_key.extensions.min_pin_length = options.request.pin;
    opts.start_ceremony()?
        .0
        .verify(&rp_id, &registration, &reg_opts)
        .map_err(AggErr::RegCeremony)
        .map(|_| ())
}
/// Test all, and only, possible `UserNotVerified` errors.
/// 4 * 3 * 5 * 2 * 13 * 5 * 3 * 5 * 4 * 4 = 1,872,000 tests.
/// We ignore this due to how long it takes (around 30 seconds or so).
#[expect(clippy::too_many_lines, reason = "a lot to test")]
#[test]
#[ignore = "slow"]
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
fn uv_required_err() {
    const ALL_CRED_PROTECTION_OPTIONS: [CredentialProtectionPolicy; 4] = [
        CredentialProtectionPolicy::None,
        CredentialProtectionPolicy::UserVerificationOptional,
        CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
        CredentialProtectionPolicy::UserVerificationRequired,
    ];
    const ALL_PRF_OPTIONS: [Option<bool>; 3] = [None, Some(false), Some(true)];
    const ALL_HMAC_OPTIONS: [HmacSecret; 5] = [
        HmacSecret::None,
        HmacSecret::NotEnabled,
        HmacSecret::Enabled,
        HmacSecret::One,
        HmacSecret::Two,
    ];
    const ALL_UNSOLICIT_OPTIONS: [bool; 2] = [false, true];
    const ALL_CRED_PROTECT_OPTIONS: [CredProtect; 13] = [
        CredProtect::None,
        CredProtect::UserVerificationOptional(false, ExtensionInfo::RequireEnforceValue),
        CredProtect::UserVerificationOptional(true, ExtensionInfo::RequireDontEnforceValue),
        CredProtect::UserVerificationOptional(false, ExtensionInfo::AllowEnforceValue),
        CredProtect::UserVerificationOptional(true, ExtensionInfo::AllowDontEnforceValue),
        CredProtect::UserVerificationOptionalWithCredentialIdList(
            false,
            ExtensionInfo::RequireEnforceValue,
        ),
        CredProtect::UserVerificationOptionalWithCredentialIdList(
            true,
            ExtensionInfo::RequireDontEnforceValue,
        ),
        CredProtect::UserVerificationOptionalWithCredentialIdList(
            false,
            ExtensionInfo::AllowEnforceValue,
        ),
        CredProtect::UserVerificationOptionalWithCredentialIdList(
            true,
            ExtensionInfo::AllowDontEnforceValue,
        ),
        CredProtect::UserVerificationRequired(false, ExtensionInfo::RequireEnforceValue),
        CredProtect::UserVerificationRequired(true, ExtensionInfo::RequireDontEnforceValue),
        CredProtect::UserVerificationRequired(false, ExtensionInfo::AllowEnforceValue),
        CredProtect::UserVerificationRequired(true, ExtensionInfo::AllowDontEnforceValue),
    ];
    const ALL_NOT_FALSE_PRF_UV_OPTIONS: [PrfUvOptions; 5] = [
        PrfUvOptions::None(true),
        PrfUvOptions::Prf(ExtensionInfo::RequireEnforceValue),
        PrfUvOptions::Prf(ExtensionInfo::RequireDontEnforceValue),
        PrfUvOptions::Prf(ExtensionInfo::AllowEnforceValue),
        PrfUvOptions::Prf(ExtensionInfo::AllowDontEnforceValue),
    ];
    const ALL_PROPS_OPTIONS: [Option<ExtensionReq>; 3] =
        [None, Some(ExtensionReq::Require), Some(ExtensionReq::Allow)];
    const ALL_PIN_OPTIONS: [Option<(FourToSixtyThree, ExtensionInfo)>; 5] = [
        None,
        Some((FourToSixtyThree::Five, ExtensionInfo::RequireEnforceValue)),
        Some((
            FourToSixtyThree::Five,
            ExtensionInfo::RequireDontEnforceValue,
        )),
        Some((FourToSixtyThree::Five, ExtensionInfo::AllowEnforceValue)),
        Some((FourToSixtyThree::Five, ExtensionInfo::AllowDontEnforceValue)),
    ];
    #[expect(clippy::option_option, reason = "fine")]
    const ALL_CRED_PROPS_OPTIONS: [Option<Option<bool>>; 4] =
        [None, Some(None), Some(Some(false)), Some(Some(true))];
    const ALL_MIN_PIN_OPTIONS: [Option<FourToSixtyThree>; 4] = [
        None,
        Some(FourToSixtyThree::Four),
        Some(FourToSixtyThree::Five),
        Some(FourToSixtyThree::Six),
    ];
    for cred_protect in ALL_CRED_PROTECTION_OPTIONS {
        for prf in ALL_PRF_OPTIONS {
            for hmac in ALL_HMAC_OPTIONS {
                for cred_props in ALL_CRED_PROPS_OPTIONS {
                    for min_pin in ALL_MIN_PIN_OPTIONS {
                        for error_unsolicited in ALL_UNSOLICIT_OPTIONS {
                            for protect in ALL_CRED_PROTECT_OPTIONS {
                                for prf_uv in ALL_NOT_FALSE_PRF_UV_OPTIONS {
                                    for props in ALL_PROPS_OPTIONS {
                                        for pin in ALL_PIN_OPTIONS {
                                            assert!(validate(TestOptions {
                                                request: TestRequestOptions {
                                                    error_unsolicited,
                                                    protect,
                                                    prf_uv,
                                                    props,
                                                    pin,
                                                },
                                                response: TestResponseOptions {
                                                    user_verified: false,
                                                    hmac,
                                                    cred_protect,
                                                    prf,
                                                    min_pin,
                                                    cred_props,
                                                },
                                            }).is_err_and(|err| matches!(err, AggErr::RegCeremony(reg_err) if matches!(reg_err, RegCeremonyErr::UserNotVerified))));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
/// Test all, and only, possible `ForbiddenCredProps` errors.
/// 4 * 3 * 5 * 2 * 13 * 6 * 5 * 3 * 4 = 561,600
/// -
/// 4 * 3 * 5 * 4 * 6 * 5 * 3 * 4 = 86,400
/// -
/// 4 * 3 * 5 * 13 * 5 * 5 * 3 * 4 = 234,000
/// +
/// 4 * 3 * 5 * 4 * 5 * 5 * 3 * 4 = 72,000
/// =
/// 313,200 total tests.
/// We ignore this due to how long it takes (around 6 seconds or so).
#[expect(clippy::too_many_lines, reason = "a lot to test")]
#[test]
#[ignore = "slow"]
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
fn forbidden_cred_props() {
    const ALL_CRED_PROTECTION_OPTIONS: [CredentialProtectionPolicy; 4] = [
        CredentialProtectionPolicy::None,
        CredentialProtectionPolicy::UserVerificationOptional,
        CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
        CredentialProtectionPolicy::UserVerificationRequired,
    ];
    const ALL_PRF_OPTIONS: [Option<bool>; 3] = [None, Some(false), Some(true)];
    const ALL_HMAC_OPTIONS: [HmacSecret; 5] = [
        HmacSecret::None,
        HmacSecret::NotEnabled,
        HmacSecret::Enabled,
        HmacSecret::One,
        HmacSecret::Two,
    ];
    const ALL_UV_OPTIONS: [bool; 2] = [false, true];
    const ALL_CRED_PROTECT_OPTIONS: [CredProtect; 13] = [
        CredProtect::None,
        CredProtect::UserVerificationOptional(false, ExtensionInfo::RequireEnforceValue),
        CredProtect::UserVerificationOptional(true, ExtensionInfo::RequireDontEnforceValue),
        CredProtect::UserVerificationOptional(false, ExtensionInfo::AllowEnforceValue),
        CredProtect::UserVerificationOptional(true, ExtensionInfo::AllowDontEnforceValue),
        CredProtect::UserVerificationOptionalWithCredentialIdList(
            false,
            ExtensionInfo::RequireEnforceValue,
        ),
        CredProtect::UserVerificationOptionalWithCredentialIdList(
            true,
            ExtensionInfo::RequireDontEnforceValue,
        ),
        CredProtect::UserVerificationOptionalWithCredentialIdList(
            false,
            ExtensionInfo::AllowEnforceValue,
        ),
        CredProtect::UserVerificationOptionalWithCredentialIdList(
            true,
            ExtensionInfo::AllowDontEnforceValue,
        ),
        CredProtect::UserVerificationRequired(false, ExtensionInfo::RequireEnforceValue),
        CredProtect::UserVerificationRequired(true, ExtensionInfo::RequireDontEnforceValue),
        CredProtect::UserVerificationRequired(false, ExtensionInfo::AllowEnforceValue),
        CredProtect::UserVerificationRequired(true, ExtensionInfo::AllowDontEnforceValue),
    ];
    const ALL_PRF_UV_OPTIONS: [PrfUvOptions; 6] = [
        PrfUvOptions::None(false),
        PrfUvOptions::None(true),
        PrfUvOptions::Prf(ExtensionInfo::RequireEnforceValue),
        PrfUvOptions::Prf(ExtensionInfo::RequireDontEnforceValue),
        PrfUvOptions::Prf(ExtensionInfo::AllowEnforceValue),
        PrfUvOptions::Prf(ExtensionInfo::AllowDontEnforceValue),
    ];
    const ALL_PIN_OPTIONS: [Option<(FourToSixtyThree, ExtensionInfo)>; 5] = [
        None,
        Some((FourToSixtyThree::Five, ExtensionInfo::RequireEnforceValue)),
        Some((
            FourToSixtyThree::Five,
            ExtensionInfo::RequireDontEnforceValue,
        )),
        Some((FourToSixtyThree::Five, ExtensionInfo::AllowEnforceValue)),
        Some((FourToSixtyThree::Five, ExtensionInfo::AllowDontEnforceValue)),
    ];
    #[expect(clippy::option_option, reason = "fine")]
    const ALL_NON_EMPTY_CRED_PROPS_OPTIONS: [Option<Option<bool>>; 3] =
        [Some(None), Some(Some(false)), Some(Some(true))];
    const ALL_MIN_PIN_OPTIONS: [Option<FourToSixtyThree>; 4] = [
        None,
        Some(FourToSixtyThree::Four),
        Some(FourToSixtyThree::Five),
        Some(FourToSixtyThree::Six),
    ];
    for cred_protect in ALL_CRED_PROTECTION_OPTIONS {
        for prf in ALL_PRF_OPTIONS {
            for hmac in ALL_HMAC_OPTIONS {
                for cred_props in ALL_NON_EMPTY_CRED_PROPS_OPTIONS {
                    for min_pin in ALL_MIN_PIN_OPTIONS {
                        for user_verified in ALL_UV_OPTIONS {
                            for protect in ALL_CRED_PROTECT_OPTIONS {
                                for prf_uv in ALL_PRF_UV_OPTIONS {
                                    for pin in ALL_PIN_OPTIONS {
                                        if user_verified
                                            || (!matches!(
                                                protect,
                                                CredProtect::UserVerificationRequired(_, _)
                                            ) && matches!(prf_uv, PrfUvOptions::None(uv) if !uv))
                                        {
                                            assert!(validate(TestOptions {
                                                request: TestRequestOptions {
                                                    error_unsolicited: true,
                                                    protect,
                                                    prf_uv,
                                                    props: None,
                                                    pin,
                                                },
                                                response: TestResponseOptions {
                                                    user_verified,
                                                    cred_protect,
                                                    prf,
                                                    hmac,
                                                    min_pin,
                                                    cred_props,
                                                },
                                            }).is_err_and(|err| matches!(err, AggErr::RegCeremony(reg_err) if matches!(reg_err, RegCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::ForbiddenCredProps)))));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
#[expect(clippy::panic_in_result_fn, reason = "OK in tests")]
#[test]
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
fn prf() -> Result<(), AggErr> {
    let mut opts = TestOptions {
        request: TestRequestOptions {
            error_unsolicited: false,
            protect: CredProtect::None,
            prf_uv: PrfUvOptions::Prf(ExtensionInfo::RequireEnforceValue),
            props: None,
            pin: None,
        },
        response: TestResponseOptions {
            user_verified: true,
            hmac: HmacSecret::None,
            cred_protect: CredentialProtectionPolicy::None,
            prf: Some(true),
            min_pin: None,
            cred_props: None,
        },
    };
    validate(opts)?;
    opts.response.prf = Some(false);
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::InvalidPrfValue)))));
    opts.response.hmac = HmacSecret::NotEnabled;
    opts.response.prf = Some(true);
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::InvalidHmacSecretValue)))));
    opts.request.prf_uv = PrfUvOptions::Prf(ExtensionInfo::AllowDontEnforceValue);
    opts.response.hmac = HmacSecret::Enabled;
    opts.response.prf = None;
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Credential(cred_err) if matches!(cred_err, CredentialErr::HmacSecretWithoutPrf)))));
    opts.response.hmac = HmacSecret::NotEnabled;
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Credential(cred_err) if matches!(cred_err, CredentialErr::HmacSecretWithoutPrf)))));
    opts.response.prf = Some(true);
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Credential(cred_err) if matches!(cred_err, CredentialErr::PrfWithoutHmacSecret)))));
    opts.response.prf = Some(false);
    validate(opts)?;
    opts.request.prf_uv = PrfUvOptions::None(false);
    opts.response.user_verified = false;
    opts.response.hmac = HmacSecret::Enabled;
    opts.response.prf = Some(true);
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Credential(cred_err) if matches!(cred_err, CredentialErr::PrfWithoutUserVerified)))));
    opts.response.prf = None;
    opts.response.hmac = HmacSecret::None;
    validate(opts)?;
    Ok(())
}
#[expect(clippy::panic_in_result_fn, reason = "OK in tests")]
#[test]
#[cfg(all(feature = "custom", not(any(feature = "bin", feature = "serde"))))]
fn cred_protect() -> Result<(), AggErr> {
    let mut opts = TestOptions {
        request: TestRequestOptions {
            error_unsolicited: false,
            protect: CredProtect::UserVerificationRequired(
                false,
                ExtensionInfo::RequireEnforceValue,
            ),
            prf_uv: PrfUvOptions::None(false),
            props: None,
            pin: None,
        },
        response: TestResponseOptions {
            user_verified: true,
            hmac: HmacSecret::None,
            cred_protect: CredentialProtectionPolicy::UserVerificationRequired,
            prf: None,
            min_pin: None,
            cred_props: None,
        },
    };
    validate(opts)?;
    opts.response.cred_protect =
        CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Extension(ext_err) if matches!(ext_err, ExtensionErr::InvalidCredProtectValue(CredProtect::UserVerificationRequired(false, ExtensionInfo::RequireEnforceValue), CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList))))));
    opts.request.protect =
        CredProtect::UserVerificationOptional(true, ExtensionInfo::RequireEnforceValue);
    opts.response.user_verified = false;
    opts.response.cred_protect = CredentialProtectionPolicy::UserVerificationRequired;
    assert!(validate(opts).is_err_and(|e| matches!(e, AggErr::RegCeremony(err) if matches!(err, RegCeremonyErr::Credential(cred_err) if matches!(cred_err, CredentialErr::CredProtectUserVerificationRequiredWithoutUserVerified)))));
    Ok(())
}
