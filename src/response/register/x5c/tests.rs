//! Tests of the Agora fork's `packed_x5c` pass-through, with and without the feature. Fork-owned: the upstream
//! files only carry the `mod` hook.
//!
//! The two real `YubiKey` attestation objects (`YUBIKEY_5`, `YUBIKEY_BIO`) are from Yubico's
//! `java-webauthn-server` test suite (`webauthn-server-core/src/test/scala/com/yubico/webauthn/test/RealExamples.scala`,
//! commit fd1c04294ebf82468ca4ac97da7a1dc9a49ec74c): `YubiKey5` and `YubikeyBio_5_5_4`. Both leaf certificates
//! chain to `CN=Yubico U2F Root CA Serial 457200631` (`openssl verify`, 2026-10-29); that check belongs to the
//! caller and is not repeated here. They are used under this licence:
//!
//! ```text
//! Copyright (c) 2014-2018, Yubico AB
//! All rights reserved.
//!
//! Redistribution and use in source and binary forms, with or without
//! modification, are permitted provided that the following conditions are met:
//!
//! 1. Redistributions of source code must retain the above copyright notice, this
//!    list of conditions and the following disclaimer.
//!
//! 2. Redistributions in binary form must reproduce the above copyright notice,
//!    this list of conditions and the following disclaimer in the documentation
//!    and/or other materials provided with the distribution.
//!
//! THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//! ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//! WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//! DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
//! ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//! (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//! LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//! ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//! (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//! SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! ```
/// `YubiKey5`: a `YubiKey` 5 (U2F root), RP ID `example.com`, flags UP and AT.
const YUBIKEY_5: &[u8] = b"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgCrcg9FJhbV35puNRlN36gSO9_YNWweirVdB2n3Ojez0CIQDOvSCusMldIS57ittkKJ9cne9RYQS6a--ivsKFYWrAIWN4NWOBWQLAMIICvDCCAaSgAwIBAgIEA63wEjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbTELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEmMCQGA1UEAwwdWXViaWNvIFUyRiBFRSBTZXJpYWwgNjE3MzA4MzQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQZnoecFi233DnuSkKgRhalswn-ygkvdr4JSPltbpXK5MxlzVSgWc-9x8mzGysdbBhEecLAYfQYqpVLWWosHPoXo2wwajAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuNzATBgsrBgEEAYLlHAIBAQQEAwIEMDAhBgsrBgEEAYLlHAEBBAQSBBD6K5ncnjlCV4-SSjDSPEEYMAwGA1UdEwEB_wQCMAAwDQYJKoZIhvcNAQELBQADggEBACjrs2f-0djw4onryp_22AdXxg6a5XyxcoybHDjKu72E2SN9qDGsIZSfDy38DDFr_bF1s25joiu7WA6tylKA0HmEDloeJXJiWjv7h2Az2_siqWnJOLic4XE1lAChJS2XAqkSk9VFGelg3SLOiifrBet-ebdQwAL-2QFrcR7JrXRQG9kUy76O2VcSgbdPROsHfOYeywarhalyVSZ-6OOYK_Q_DLIaOC0jXrnkzm2ymMQFQlBAIysrYeEM1wxiFbwDt-lAcbcOEtHEf5ZlWi75nUzlWn8bSx_5FO4TbZ5hIEcUiGRpiIBEMRZlOIm4ZIbZycn_vJOFRTVps0V0S4ygtDdoYXV0aERhdGFYxKN5pvbur7mlXjeMEYA04nUeaC-rny0wqxPSElWGzhlHQQAAAAv6K5ncnjlCV4-SSjDSPEEYAED94RxjDuKGTpu5usg0Vcee9gqqhDVGw1__eyvx3YUhH7gba6zYjbwI1e1CZa78jZq8167iUIHbM_kNbyXIHSNhpQECAyYgASFYIIIyZu4ct876xj7sKSV90mbX0PpGLuRIRGu6IxnWUhD9Ilggw2qT1jtmMhn-X9raOZxqjWkzfdF8aJqFpvp3QXI-vNY";
/// Without `packed_x5c`, a packed statement with an `x5c` chain is refused, as upstream.
#[cfg(not(feature = "packed_x5c"))]
#[expect(clippy::unwrap_used, reason = "OK in tests")]
#[test]
fn packed_x5c_is_refused_without_the_feature() {
    use super::{
        AttestationObject,
        error::{AttestationErr, AttestationObjectErr},
    };
    let object = base64url_nopad::decode(YUBIKEY_5).unwrap();
    assert_eq!(
        AttestationObject::try_from(object.as_slice()).map(|_| ()),
        Err(AttestationObjectErr::Attestation(
            AttestationErr::PackedFormat
        ))
    );
}
/// With `packed_x5c`.
#[cfg(feature = "packed_x5c")]
mod with_feature {
    use super::{
        super::{
            super::super::AggErr, AttestationFormat, AttestationObject, AuthTransports,
            AuthenticatorAttestation, PackedAttestation, PackedX5c, Sig, X5c,
            error::AttestationErr,
        },
        YUBIKEY_5,
    };
    use base64url_nopad::decode;
    use p256::ecdsa::{
        DerSignature as P256Sig, VerifyingKey as P256VerKey, signature::Verifier as _,
    };
    use rsa::sha2::{Digest as _, Sha256};
    /// The client data JSON `YUBIKEY_5` was signed over.
    const YUBIKEY_5_CLIENT_DATA: &[u8] = br#"{"type": "webauthn.create", "clientExtensions": {}, "challenge": "Y2hhbGxlbmdl", "origin": "https://example.com"}"#;
    /// SHA-256 of the `YUBIKEY_5` leaf (`CN=Yubico U2F EE Serial 61730834`).
    const YUBIKEY_5_LEAF_SHA256: [u8; 32] = [
        0xd7, 0x23, 0xea, 0xeb, 0x32, 0xc8, 0xb5, 0x07, 0x1c, 0x18, 0xe2, 0xac, 0x0d, 0x9a, 0xb6,
        0xcb, 0xb3, 0x05, 0x70, 0x0f, 0x9d, 0x45, 0xc6, 0x1a, 0x09, 0xd4, 0x83, 0x09, 0x71, 0x59,
        0x78, 0x50,
    ];
    /// AAGUID of `YUBIKEY_5`: fa2b99dc-9e39-4257-8f92-4a30d23c4118 (FIDO MDS: "`YubiKey` 5 Series with NFC").
    const YUBIKEY_5_AAGUID: [u8; 16] = [
        0xfa, 0x2b, 0x99, 0xdc, 0x9e, 0x39, 0x42, 0x57, 0x8f, 0x92, 0x4a, 0x30, 0xd2, 0x3c, 0x41,
        0x18,
    ];
    /// `YubikeyBio_5_5_4`: a `YubiKey` Bio, firmware 5.5.4 (U2F root), RP ID `demo.yubico.com`, flags UP, UV and AT.
    const YUBIKEY_BIO: &[u8] = b"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEYwRAIgGSqwfT67zXQVsgBU_TvN1MGbZkR5KEyzzMMbS9cJQJsCIDZJ90wxLjNnpzNZ-Ns64cmgwixb0CJcXdfVM35EBgm0Y3g1Y4FZAt0wggLZMIIBwaADAgECAgkAtcaOPpfL6PYwDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMG8xCzAJBgNVBAYTAlNFMRIwEAYDVQQKDAlZdWJpY28gQUIxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDEwNDk1NDQzNzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQXmY7aJqXBb5wsBbCAeJFdFa3Fzz8VU1qdJxUCgPf2MNcoMnikaKg0yp_bakKjCNIqmsb75RhUzS5UQHwVOAe0o4GBMH8wEwYKKwYBBAGCxAoNAQQFBAMFBQQwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjkwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQ2FItn1dbSGaIqbqZ-gLzWzAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQB9yNliBCNlTGBrhYTTqHJm73KjMszL24buZcvifix-GRYk7D8I0_BQ20mQ_CITqqGTr5cvxjIKVw_2ed-326hITlhaWiwwEnwuI5afqwd72ObWczklHNvoV-uWtM9YVfk9H7VZqtQTMb3m8O-UWmkCGxLdqTprgTUSF_Tmk6KPyF1S6es6RJvk9vxyJ0T_EFkr9yAPlDzqtc9hEAUEPP5xpzEWRYon6T12AUW6wQwlkiA8q4gFIQfTGks1JX6ob_1nTvigO3EYB4wP3EIAJ-0HkpprKKDl4mRv_7b_BPuANq4jMr_9YkYs8XrmuUHdF0PwRzYPN4KtovuG0YdFA0ObaGF1dGhEYXRhWMTEbO-CrRtUZHdZHQCLCHWew-bS7LTzlHS_6mlpkl0Dt0UAAAAB2FItn1dbSGaIqbqZ-gLzWwBAvPVBBCgvthNO8DNbim45zueAndDzuMAQDBXL_bVsH9uXfKkrza7ya2DM_xka1hYW-K2d97qNRJmoAeetc5haaKUBAgMmIAEhWCDqr-a3QuoQk4VqspgOfHlkS2Rk-NpsHL5Rs4rbxE2DQiJYICjaw5BRuZKz5CPZRjiDJFOq51wbOrUggICGmC88-ZXq";
    /// The client data JSON `YUBIKEY_BIO` was signed over.
    const YUBIKEY_BIO_CLIENT_DATA: &[u8] = br#"{"type":"webauthn.create","challenge":"rrHBh7CMrdIXLM30Pd8VuRX7M_qUyyTJBX4T7lN5EQE","origin":"https://demo.yubico.com","crossOrigin":false}"#;
    /// SHA-256 of the `YUBIKEY_BIO` leaf (`CN=Yubico U2F EE Serial 1049544373`).
    const YUBIKEY_BIO_LEAF_SHA256: [u8; 32] = [
        0x55, 0x5e, 0x1c, 0x1d, 0xa5, 0xe9, 0xa2, 0xcc, 0x44, 0xda, 0xed, 0x7f, 0x40, 0xe5, 0x9e,
        0x28, 0x94, 0xe4, 0x1f, 0xaa, 0x56, 0x79, 0x3c, 0x5a, 0xde, 0x76, 0xe3, 0x79, 0xc9, 0x65,
        0x81, 0x8b,
    ];
    /// AAGUID of `YUBIKEY_BIO`: d8522d9f-575b-4866-88a9-ba99fa02f35b (FIDO MDS: "`YubiKey` Bio Series - FIDO Edition").
    const YUBIKEY_BIO_AAGUID: [u8; 16] = [
        0xd8, 0x52, 0x2d, 0x9f, 0x57, 0x5b, 0x48, 0x66, 0x88, 0xa9, 0xba, 0x99, 0xfa, 0x02, 0xf3,
        0x5b,
    ];
    /// DER prefix of a P-256 `SubjectPublicKeyInfo` up to the uncompressed point.
    const P256_SPKI_PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    /// The P-256 key of a certificate, found by its `SubjectPublicKeyInfo` prefix. A test shortcut, not X.509
    /// parsing: the caller's verifier parses the certificate properly.
    #[expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "OK in tests")]
    fn leaf_key(cert: &[u8]) -> P256VerKey {
        let start = cert
            .windows(P256_SPKI_PREFIX.len())
            .position(|w| w == P256_SPKI_PREFIX)
            .unwrap()
            .checked_add(P256_SPKI_PREFIX.len())
            .unwrap();
        P256VerKey::from_sec1_bytes(&cert[start..start.checked_add(65).unwrap()]).unwrap()
    }
    /// `attestation_object` (base64url) and `client_data_json` as an `AuthenticatorAttestation`.
    #[expect(clippy::unwrap_used, reason = "OK in tests")]
    fn attestation(attestation_object: &[u8], client_data_json: &[u8]) -> AuthenticatorAttestation {
        AuthenticatorAttestation::new(
            client_data_json.to_vec(),
            decode(attestation_object).unwrap(),
            AuthTransports(0),
        )
    }
    /// Checks what `packed_x5c` hands over for a real attestation, and that the caller can verify its signature.
    #[expect(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::unwrap_in_result,
        clippy::unwrap_used,
        reason = "OK in tests"
    )]
    fn check_real(
        attestation_object: &[u8],
        client_data_json: &[u8],
        leaf_sha256: [u8; 32],
        aaguid: [u8; 16],
    ) -> Result<(), AggErr> {
        let attest = attestation(attestation_object, client_data_json);
        let x5c: PackedX5c<'_> = attest.packed_x5c()?.unwrap();
        assert_eq!(x5c.x5c.len(), 1);
        assert!(!x5c.x5c.is_empty());
        assert_eq!(x5c.x5c.certificates().count(), 1);
        let leaf = x5c.x5c.attestation_certificate();
        assert_eq!(*Sha256::digest(leaf), leaf_sha256);
        assert_eq!(x5c.aaguid.data(), aaguid);
        // The signed data is the authenticator data followed by the client data hash.
        let raw = decode(attestation_object).unwrap();
        let auth_data = AttestationObject::try_from(raw.as_slice())?;
        assert_eq!(
            auth_data
                .auth_data()
                .attested_credential_data()
                .aaguid
                .data(),
            aaguid
        );
        let (signed_auth_data, hash) = x5c
            .signed_data
            .split_at(x5c.signed_data.len().checked_sub(32).unwrap());
        assert_eq!(*hash, *Sha256::digest(client_data_json));
        assert!(raw.ends_with(signed_auth_data));
        // A caller holding the leaf's key can verify the signature over exactly these bytes.
        let Sig::P256(sig) = x5c.signature else {
            panic!("YubiKeys sign attestations with ES256")
        };
        leaf_key(leaf)
            .verify(x5c.signed_data, &P256Sig::from_bytes(sig).unwrap())
            .unwrap();
        Ok(())
    }
    #[test]
    fn yubikey_5_packed_x5c_is_passed_through() -> Result<(), AggErr> {
        check_real(
            YUBIKEY_5,
            YUBIKEY_5_CLIENT_DATA,
            YUBIKEY_5_LEAF_SHA256,
            YUBIKEY_5_AAGUID,
        )
    }
    #[test]
    fn yubikey_bio_packed_x5c_is_passed_through() -> Result<(), AggErr> {
        check_real(
            YUBIKEY_BIO,
            YUBIKEY_BIO_CLIENT_DATA,
            YUBIKEY_BIO_LEAF_SHA256,
            YUBIKEY_BIO_AAGUID,
        )
    }
    /// Nothing in the statement is checked by the parser: a tampered signature still parses, and so does the
    /// statement when the client data changes. Only the caller's own verification can tell.
    #[expect(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::unwrap_in_result,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "OK in tests"
    )]
    #[test]
    fn nothing_is_verified() -> Result<(), AggErr> {
        let attest = attestation(YUBIKEY_5, br#"{"type":"webauthn.create"}"#);
        let x5c = attest.packed_x5c()?.unwrap();
        let Sig::P256(sig) = x5c.signature else {
            panic!("YubiKeys sign attestations with ES256")
        };
        let leaf = leaf_key(x5c.x5c.attestation_certificate());
        assert!(
            leaf.verify(x5c.signed_data, &P256Sig::from_bytes(sig).unwrap())
                .is_err()
        );
        // Not the credential key's signature: self attestation would fail the algorithm check if it were taken
        // as one, so the ceremony must see `none`.
        let mut object = decode(YUBIKEY_5).unwrap();
        let parsed = AttestationObject::try_from(object.as_slice())?;
        assert!(matches!(
            parsed.attestation(),
            AttestationFormat::Packed(PackedAttestation {
                signature: Sig::P256(_),
                x5c: Some(_)
            })
        ));
        assert!(matches!(
            parsed.attestation().self_attestation(),
            AttestationFormat::None
        ));
        // Flip a byte inside the leaf certificate: still parses, untouched by the library.
        object[200] ^= 1;
        _ = AttestationObject::try_from(object.as_slice()).unwrap();
        Ok(())
    }
    #[expect(clippy::panic_in_result_fn, reason = "OK in tests")]
    #[test]
    fn other_attestations_have_no_x5c() -> Result<(), AggErr> {
        // WebAuthn's `none` ES256 test vector (see `es256_test_vector`).
        let none = AuthenticatorAttestation::new(
            Vec::new(),
            decode(b"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikv6vDdDKViwYzYNOtZGHJxHNa5_jt1GWSpeDwFFKy5LVZAAAAAIRGzLmrHbN0dQsjZ_9vOh8AIPkfOR20ybL94OpwGJy6P7Y_V5umEiszrZT_PsMwCEvkpQECAyYgASFYIK_voW-XypstI-uGzLZAmNINuQhWBi6ySco6m2cvJt9hIlggkwpWuHovymYzSwNFir-Hlxd8EsxujXMpCvLiZkeWuSA").map_err(|_e| AggErr::AttestationObject(super::super::error::AttestationObjectErr::Len))?,
            AuthTransports(0),
        );
        assert!(none.packed_x5c()?.is_none());
        Ok(())
    }
    /// The CBOR framing of `x5c` is checked; its contents are not.
    #[test]
    fn x5c_framing() {
        /// `"x5c"` followed by `rest`.
        fn x5c(rest: &[u8]) -> Vec<u8> {
            let mut v = vec![0x63, b'x', b'5', b'c'];
            v.extend_from_slice(rest);
            v
        }
        let ok = |rest: &[u8]| {
            X5c::from_cbor(x5c(rest).as_slice()).map(|s| (s.value.len(), s.remaining.len()))
        };
        // One certificate of one byte, then one trailing byte left for the caller.
        assert_eq!(ok(&[0x81, 0x41, 0xaa, 0xff]), Ok((1, 1)));
        // Two certificates, lengths encoded in one and two extra bytes.
        let mut two = vec![0x82, 0x58, 24];
        two.extend_from_slice(&[1; 24]);
        two.extend_from_slice(&[0x59, 1, 0]);
        two.extend_from_slice(&[2; 256]);
        assert_eq!(ok(&two), Ok((2, 0)));
        let two_cbor = x5c(&two);
        let chain = X5c::from_cbor(two_cbor.as_slice()).map(|s| s.value);
        assert_eq!(
            chain.map(|c| c.certificates().map(<[u8]>::len).collect::<Vec<_>>()),
            Ok(vec![24, 256])
        );
        let err = Err(AttestationErr::PackedFormatX5c);
        // Wrong key.
        assert_eq!(
            X5c::from_cbor(&[0x63, b'x', b'5', b'd', 0x81, 0x41, 0])
                .map(|s| (s.value.len(), s.remaining.len())),
            err
        );
        // Empty array; not an array; more than 23 entries.
        assert_eq!(ok(&[0x80]), err);
        assert_eq!(ok(&[0x41, 0]), err);
        assert_eq!(ok(&[0x98, 24]), err);
        // An entry that is not a byte string, an empty one, a short one.
        assert_eq!(ok(&[0x81, 0x61, b'a']), err);
        assert_eq!(ok(&[0x81, 0x40]), err);
        assert_eq!(ok(&[0x81, 0x42, 0]), err);
        // Non-canonical lengths.
        assert_eq!(ok(&[0x81, 0x58, 1, 0]), err);
        assert_eq!(ok(&[0x81, 0x59, 0, 1, 0]), err);
        // Lengths of four or more bytes are refused.
        assert_eq!(ok(&[0x81, 0x5a, 0, 1, 0, 0]), err);
    }
    /// Runs a registration ceremony for `challenge` whose response is the real `YUBIKEY_5` attestation object with
    /// fresh client data for that challenge: the statement's signature, made over the original client data, no
    /// longer verifies, and the ceremony must succeed anyway, recording `none`.
    #[cfg(feature = "custom")]
    #[expect(
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::unwrap_in_result,
        clippy::unwrap_used,
        reason = "OK in tests"
    )]
    fn ceremony(challenge: super::super::super::super::request::Challenge) -> Result<(), AggErr> {
        use super::super::{
            super::{
                super::request::{
                    RpId,
                    register::{
                        CredProtect, CredentialCreationOptions, PublicKeyCredentialUserEntity,
                        RegistrationVerificationOptions, UserHandle,
                    },
                },
                AuthenticatorAttachment,
            },
            Attestation, ClientExtensionsOutputs, Registration,
        };
        let rp_id = RpId::from_static_domain("example.com").unwrap();
        let id = UserHandle::from([0]);
        let mut opts = CredentialCreationOptions::second_factor(
            &rp_id,
            PublicKeyCredentialUserEntity {
                name: "foo",
                id: &id,
                display_name: "",
            },
            Vec::new(),
        );
        opts.public_key.extensions.cred_protect = CredProtect::None;
        opts.public_key.extensions.cred_props = None;
        let encoded = base64url_nopad::encode(challenge.as_array().as_slice());
        opts.public_key.challenge = challenge;
        let client_data_json = format!(
            r#"{{"type":"webauthn.create","challenge":"{encoded}","origin":"https://example.com","crossOrigin":false}}"#
        )
        .into_bytes();
        let registration = Registration::new(
            AuthenticatorAttestation::new(
                client_data_json,
                decode(YUBIKEY_5).unwrap(),
                AuthTransports(0),
            ),
            AuthenticatorAttachment::None,
            ClientExtensionsOutputs {
                cred_props: None,
                prf: None,
            },
        );
        let credential = opts.start_ceremony()?.0.verify(
            &rp_id,
            &registration,
            &RegistrationVerificationOptions::<&str, &str>::default(),
        )?;
        assert_eq!(credential.metadata().attestation, Attestation::None);
        assert_eq!(credential.metadata().aaguid.data(), YUBIKEY_5_AAGUID);
        // The statement reaches the caller, and its signature fails the caller's check.
        let x5c = registration.response().packed_x5c()?.unwrap();
        let Sig::P256(sig) = x5c.signature else {
            panic!("YubiKeys sign attestations with ES256")
        };
        assert!(
            leaf_key(x5c.x5c.attestation_certificate())
                .verify(x5c.signed_data, &P256Sig::from_bytes(sig).unwrap())
                .is_err()
        );
        Ok(())
    }
    #[cfg(feature = "custom")]
    #[test]
    fn the_ceremony_records_none_for_an_unverified_x5c() -> Result<(), AggErr> {
        ceremony(super::super::super::super::request::Challenge::new())
    }
    /// Both Agora patches together: a derived challenge completes a ceremony like a random one.
    #[cfg(all(feature = "custom", feature = "derived_challenge"))]
    #[test]
    fn a_derived_challenge_completes_a_ceremony() -> Result<(), AggErr> {
        let digest = Sha256::digest(b"agora/portal-approval/v1\n");
        let mut bytes = [0; 16];
        bytes.copy_from_slice(digest.get(..16).unwrap_or_default());
        ceremony(super::super::super::super::request::Challenge::derived(
            bytes,
        ))
    }
}
