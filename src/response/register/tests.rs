use super::{
    super::{
        super::{
            AggErr,
            request::{AsciiDomain, RpId},
        },
        auth::{AuthenticatorData, NonDiscoverableAuthenticatorAssertion},
    },
    AttestationFormat, AttestationObject, AuthDataContainer as _, AuthExtOutput as _,
    AuthTransports, AuthenticatorAttestation, AuthenticatorExtensionOutput,
    AuthenticatorExtensionOutputErr, Backup, CborSuccess, CredentialProtectionPolicy,
    FourToSixtyThree, FromCbor as _, HmacSecret, Sig, UncompressedPubKey,
    cbor::{
        BYTES, BYTES_INFO_24, MAP_1, MAP_2, MAP_3, MAP_4, SIMPLE_FALSE, SIMPLE_TRUE, TEXT_11,
        TEXT_12, TEXT_14,
    },
};
use ed25519_dalek::Verifier as _;
use p256::ecdsa::{DerSignature as P256Sig, SigningKey as P256Key};
use rsa::sha2::{Digest as _, Sha256};
#[expect(clippy::panic, reason = "OK in tests")]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::missing_asserts_for_indexing,
    reason = "comments justifies correctness"
)]
fn hex_decode<const N: usize>(input: &[u8; N]) -> Vec<u8> {
    /// Value to subtract from a lowercase hex digit.
    const LOWER_OFFSET: u8 = b'a' - 10;
    assert_eq!(
        N & 1,
        0,
        "hex_decode must be passed a reference to an array of even length"
    );
    let mut data = Vec::with_capacity(N >> 1);
    input.chunks_exact(2).fold((), |(), byte| {
        // `byte.len() == 2`.
        let mut hex = byte[0];
        let val = match hex {
            // `Won't underflow`.
            b'0'..=b'9' => hex - b'0',
            // `Won't underflow`.
            b'a'..=b'f' => hex - LOWER_OFFSET,
            _ => panic!("hex_decode must be passed a valid lowercase hexadecimal array"),
        } << 4u8;
        // `byte.len() == 2`.
        hex = byte[1];
        data.push(
            val | match hex {
                // `Won't underflow`.
                b'0'..=b'9' => hex - b'0',
                // `Won't underflow`.
                b'a'..=b'f' => hex - LOWER_OFFSET,
                _ => panic!("hex_decode must be passed a valid lowercase hexadecimal array"),
            },
        );
    });
    data
}
/// <https://pr-preview.s3.amazonaws.com/w3c/webauthn/pull/2209.html#sctn-test-vectors-none-es256>
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_in_result,
    clippy::unwrap_used,
    reason = "OK in tests"
)]
#[test]
fn es256_test_vector() -> Result<(), AggErr> {
    let rp_id = RpId::Domain(AsciiDomain::try_from("example.org".to_owned())?);
    let credential_private_key =
        hex_decode(b"6e68e7a58484a3264f66b77f5d6dc5bc36a47085b615c9727ab334e8c369c2ee");
    let aaguid = hex_decode(b"8446ccb9ab1db374750b2367ff6f3a1f");
    let credential_id =
        hex_decode(b"f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4");
    let client_data_json = hex_decode(b"7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c4535513d3d227d");
    let attestation_object = hex_decode(b"a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220");
    let key = *P256Key::from_slice(credential_private_key.as_slice())
        .unwrap()
        .verifying_key();
    let enc_key = key.to_sec1_point(false);
    let auth_attest =
        AuthenticatorAttestation::new(client_data_json, attestation_object, AuthTransports(0));
    let att_obj =
        AttestationObject::from_data(auth_attest.attestation_object_and_c_data_hash.as_slice())?;
    assert_eq!(
        aaguid,
        att_obj.data.auth_data.attested_credential_data.aaguid.0
    );
    assert_eq!(
        credential_id,
        att_obj
            .data
            .auth_data
            .attested_credential_data
            .credential_id
            .0
    );
    assert!(
        matches!(att_obj.data.auth_data.attested_credential_data.credential_public_key, UncompressedPubKey::P256(pub_key) if **enc_key.x().unwrap() == *pub_key.0 && **enc_key.y().unwrap() == *pub_key.1)
    );
    assert_eq!(
        *att_obj.data.auth_data.rp_id_hash,
        *Sha256::digest(rp_id.as_ref())
    );
    assert!(att_obj.data.auth_data.flags.user_present);
    assert!(matches!(att_obj.data.attestation, AttestationFormat::None));
    let authenticator_data =
        hex_decode(b"bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000");
    let client_data_json_2 = hex_decode(b"7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d");
    let signature = hex_decode(b"3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87");
    let auth_assertion = NonDiscoverableAuthenticatorAssertion::<1>::without_user(
        client_data_json_2,
        authenticator_data,
        signature,
    );
    let auth_data = AuthenticatorData::try_from(auth_assertion.authenticator_data())?;
    assert_eq!(*auth_data.rp_id_hash(), *Sha256::digest(rp_id.as_ref()));
    assert!(auth_data.flags().user_present);
    assert!(match att_obj.data.auth_data.flags.backup {
        Backup::NotEligible => matches!(auth_data.flags().backup, Backup::NotEligible),
        Backup::Eligible => !matches!(auth_data.flags().backup, Backup::NotEligible),
        Backup::Exists => matches!(auth_data.flags().backup, Backup::Exists),
    });
    let sig = P256Sig::from_bytes(auth_assertion.signature()).unwrap();
    let mut msg = auth_assertion.authenticator_data().to_owned();
    msg.extend_from_slice(&Sha256::digest(auth_assertion.client_data_json()));
    key.verify(msg.as_slice(), &sig).unwrap();
    Ok(())
}
/// <https://pr-preview.s3.amazonaws.com/w3c/webauthn/pull/2209.html#sctn-test-vectors-packed-self-es256>
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_in_result,
    clippy::unwrap_used,
    reason = "OK in tests"
)]
#[expect(clippy::indexing_slicing, reason = "comment justifies correctness")]
#[test]
fn es256_self_attest_test_vector() -> Result<(), AggErr> {
    let rp_id = RpId::Domain(AsciiDomain::try_from("example.org".to_owned())?);
    let credential_private_key =
        hex_decode(b"b4bbfa5d68e1693b6ef5a19a0e60ef7ee2cbcac81f7fec7006ac3a21e0c5116a");
    let aaguid = hex_decode(b"df850e09db6afbdfab51697791506cfc");
    let credential_id =
        hex_decode(b"455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c");
    let client_data_json = hex_decode(b"7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f3078594856673d3d227d");
    let attestation_object = hex_decode(b"a363666d74667061636b65646761747453746d74a263616c67266373696758483046022100ae045923ded832b844cae4d5fc864277c0dc114ad713e271af0f0d371bd3ac540221009077a088ed51a673951ad3ba2673d5029bab65b64f4ea67b234321f86fcfac5d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2");
    let key = *P256Key::from_slice(credential_private_key.as_slice())
        .unwrap()
        .verifying_key();
    let enc_key = key.to_sec1_point(false);
    let auth_attest =
        AuthenticatorAttestation::new(client_data_json, attestation_object, AuthTransports(0));
    let (att_obj, auth_idx) = AttestationObject::parse_data(auth_attest.attestation_object())?;
    assert_eq!(aaguid, att_obj.auth_data.attested_credential_data.aaguid.0);
    assert_eq!(
        credential_id,
        att_obj.auth_data.attested_credential_data.credential_id.0
    );
    assert!(
        matches!(att_obj.auth_data.attested_credential_data.credential_public_key, UncompressedPubKey::P256(pub_key) if **enc_key.x().unwrap() == *pub_key.0 && **enc_key.y().unwrap() == *pub_key.1)
    );
    assert_eq!(
        *att_obj.auth_data.rp_id_hash,
        *Sha256::digest(rp_id.as_ref())
    );
    assert!(att_obj.auth_data.flags.user_present);
    assert!(match att_obj.attestation {
        AttestationFormat::None => false,
        AttestationFormat::Packed(attest) => {
            match attest.signature {
                Sig::MlDsa87(_)
                | Sig::MlDsa65(_)
                | Sig::MlDsa44(_)
                | Sig::Ed25519(_)
                | Sig::P384(_)
                | Sig::Rs256(_) => false,
                Sig::P256(sig) => {
                    let s = P256Sig::from_bytes(sig).unwrap();
                    key.verify(
                        // Won't `panic` since `auth_idx` is returned from `AttestationObject::parse_data`.
                        &auth_attest.attestation_object_and_c_data_hash[auth_idx..],
                        &s,
                    )
                    .is_ok()
                }
            }
        }
    });
    let authenticator_data =
        hex_decode(b"bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50900000000");
    let client_data_json_2 = hex_decode(b"7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a225248696843784e534e493352594d45314f7731476d3132786e726b634a5f6666707637546e2d4a71386773222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a206754623533727a36456853576f6d58477a696d4331513d3d227d");
    let signature = hex_decode(b"3044022076691be76a8618976d9803c4cdc9b97d34a7af37e3bdc894a2bf54f040ffae850220448033a015296ffb09a762efd0d719a55346941e17e91ebf64c60d439d0b9744");
    let auth_assertion = NonDiscoverableAuthenticatorAssertion::<1>::without_user(
        client_data_json_2,
        authenticator_data,
        signature,
    );
    let auth_data = AuthenticatorData::try_from(auth_assertion.authenticator_data())?;
    assert_eq!(*auth_data.rp_id_hash(), *Sha256::digest(rp_id.as_ref()));
    assert!(auth_data.flags().user_present);
    assert!(match att_obj.auth_data.flags.backup {
        Backup::NotEligible => matches!(auth_data.flags().backup, Backup::NotEligible),
        Backup::Eligible | Backup::Exists =>
            !matches!(auth_data.flags().backup, Backup::NotEligible),
    });
    let sig = P256Sig::from_bytes(auth_assertion.signature()).unwrap();
    let mut msg = auth_assertion.authenticator_data().to_owned();
    msg.extend_from_slice(&Sha256::digest(auth_assertion.client_data_json()));
    key.verify(msg.as_slice(), &sig).unwrap();
    Ok(())
}
struct AuthExtOptions<'a> {
    cred_protect: Option<u8>,
    hmac_secret: Option<bool>,
    min_pin_length: Option<u8>,
    hmac_secret_mc: Option<&'a [u8]>,
}
#[expect(
    clippy::panic,
    clippy::unreachable,
    reason = "want to crash when there is a bug"
)]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "comments justify correctness"
)]
fn generate_auth_extensions(opts: &AuthExtOptions<'_>) -> Vec<u8> {
    // Maxes at 4, so addition is clearly free from overflow.
    let map_len = u8::from(opts.cred_protect.is_some())
        + u8::from(opts.hmac_secret.is_some())
        + u8::from(opts.min_pin_length.is_some())
        + u8::from(opts.hmac_secret_mc.is_some());
    let header = match map_len {
        0 => return Vec::new(),
        1 => MAP_1,
        2 => MAP_2,
        3 => MAP_3,
        4 => MAP_4,
        _ => unreachable!("bug"),
    };
    let mut cbor = Vec::with_capacity(128);
    cbor.push(header);
    if let Some(protect) = opts.cred_protect {
        cbor.push(TEXT_11);
        cbor.extend_from_slice(b"credProtect".as_slice());
        if protect >= 24 {
            cbor.push(24);
        }
        cbor.push(protect);
    }
    if let Some(hmac) = opts.hmac_secret {
        cbor.push(TEXT_11);
        cbor.extend_from_slice(b"hmac-secret".as_slice());
        cbor.push(if hmac { SIMPLE_TRUE } else { SIMPLE_FALSE });
    }
    if let Some(pin) = opts.min_pin_length {
        cbor.push(TEXT_12);
        cbor.extend_from_slice(b"minPinLength".as_slice());
        if pin >= 24 {
            cbor.push(24);
        }
        cbor.push(pin);
    }
    if let Some(mc) = opts.hmac_secret_mc {
        cbor.push(TEXT_14);
        cbor.extend_from_slice(b"hmac-secret-mc".as_slice());
        match mc.len() {
            len @ ..=23 => {
                // `as` is clearly OK.
                cbor.push(BYTES | len as u8);
            }
            len @ 24..=255 => {
                cbor.push(BYTES_INFO_24);
                // `as` is clearly OK.
                cbor.push(len as u8);
            }
            _ => panic!(
                "AuthExtOptions does not allow hmac_secret_mc to have length greater than 255"
            ),
        }
        cbor.extend_from_slice(mc);
    }
    cbor
}
#[expect(clippy::panic_in_result_fn, reason = "not a problem for a test")]
#[expect(clippy::shadow_unrelated, reason = "struct destructuring is prefered")]
#[expect(clippy::too_many_lines, reason = "a lot to test")]
#[test]
fn auth_ext() -> Result<(), AuthenticatorExtensionOutputErr> {
    let mut opts = generate_auth_extensions(&AuthExtOptions {
        cred_protect: None,
        hmac_secret: None,
        min_pin_length: None,
        hmac_secret_mc: None,
    });
    let CborSuccess { value, remaining } =
        AuthenticatorExtensionOutput::from_cbor(opts.as_slice())?;
    assert!(remaining.is_empty());
    assert!(value.missing());
    opts = generate_auth_extensions(&AuthExtOptions {
        cred_protect: None,
        hmac_secret: None,
        min_pin_length: None,
        hmac_secret_mc: Some([0; 48].as_slice()),
    });
    assert!(
        AuthenticatorExtensionOutput::from_cbor(opts.as_slice()).map_or_else(
            |e| matches!(e, AuthenticatorExtensionOutputErr::Missing),
            |_| false,
        )
    );
    opts = generate_auth_extensions(&AuthExtOptions {
        cred_protect: None,
        hmac_secret: Some(true),
        min_pin_length: None,
        hmac_secret_mc: Some([0; 48].as_slice()),
    });
    let CborSuccess { value, remaining } =
        AuthenticatorExtensionOutput::from_cbor(opts.as_slice())?;
    assert!(remaining.is_empty());
    assert!(
        matches!(value.cred_protect, CredentialProtectionPolicy::None)
            && matches!(value.hmac_secret, HmacSecret::One)
            && value.min_pin_length.is_none()
    );
    opts = generate_auth_extensions(&AuthExtOptions {
        cred_protect: None,
        hmac_secret: Some(false),
        min_pin_length: None,
        hmac_secret_mc: Some([0; 48].as_slice()),
    });
    assert!(
        AuthenticatorExtensionOutput::from_cbor(opts.as_slice()).map_or_else(
            |e| matches!(e, AuthenticatorExtensionOutputErr::Missing),
            |_| false,
        )
    );
    opts = generate_auth_extensions(&AuthExtOptions {
        cred_protect: None,
        hmac_secret: Some(true),
        min_pin_length: None,
        hmac_secret_mc: Some([0; 49].as_slice()),
    });
    assert!(
        AuthenticatorExtensionOutput::from_cbor(opts.as_slice()).map_or_else(
            |e| matches!(e, AuthenticatorExtensionOutputErr::HmacSecretMcValue),
            |_| false,
        )
    );
    opts = generate_auth_extensions(&AuthExtOptions {
        cred_protect: None,
        hmac_secret: Some(true),
        min_pin_length: None,
        hmac_secret_mc: Some([0; 23].as_slice()),
    });
    assert!(
        AuthenticatorExtensionOutput::from_cbor(opts.as_slice()).map_or_else(
            |e| matches!(e, AuthenticatorExtensionOutputErr::HmacSecretMcType),
            |_| false,
        )
    );
    opts = generate_auth_extensions(&AuthExtOptions {
        cred_protect: Some(1),
        hmac_secret: Some(true),
        min_pin_length: Some(5),
        hmac_secret_mc: Some([0; 48].as_slice()),
    });
    let CborSuccess { value, remaining } =
        AuthenticatorExtensionOutput::from_cbor(opts.as_slice())?;
    assert!(remaining.is_empty());
    assert!(
        matches!(
            value.cred_protect,
            CredentialProtectionPolicy::UserVerificationOptional
        ) && matches!(value.hmac_secret, HmacSecret::One)
            && value
                .min_pin_length
                .is_some_and(|pin| pin == FourToSixtyThree::Five)
    );
    opts = generate_auth_extensions(&AuthExtOptions {
        cred_protect: Some(0),
        hmac_secret: None,
        min_pin_length: None,
        hmac_secret_mc: None,
    });
    assert!(
        AuthenticatorExtensionOutput::from_cbor(opts.as_slice()).map_or_else(
            |e| matches!(e, AuthenticatorExtensionOutputErr::CredProtectValue),
            |_| false,
        )
    );
    opts = generate_auth_extensions(&AuthExtOptions {
        cred_protect: None,
        hmac_secret: None,
        min_pin_length: Some(3),
        hmac_secret_mc: None,
    });
    assert!(
        AuthenticatorExtensionOutput::from_cbor(opts.as_slice()).map_or_else(
            |e| matches!(e, AuthenticatorExtensionOutputErr::MinPinLengthValue),
            |_| false,
        )
    );
    opts = generate_auth_extensions(&AuthExtOptions {
        cred_protect: None,
        hmac_secret: None,
        min_pin_length: Some(64),
        hmac_secret_mc: None,
    });
    assert!(
        AuthenticatorExtensionOutput::from_cbor(opts.as_slice()).map_or_else(
            |e| matches!(e, AuthenticatorExtensionOutputErr::MinPinLengthValue),
            |_| false,
        )
    );
    Ok(())
}
