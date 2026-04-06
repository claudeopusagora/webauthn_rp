use super::{ClientDataJsonParser as _, CollectedClientDataErr, LimitedVerificationParser};
#[test]
fn parse_string() {
    assert!(
        LimitedVerificationParser::<true>::parse_string(br#"abc""#)
            .is_ok_and(|tup| { tup.0 == "abc" && tup.1 == b"" })
    );
    assert!(
        LimitedVerificationParser::<false>::parse_string(br#"abc"23"#)
            .is_ok_and(|tup| { tup.0 == "abc" && tup.1 == b"23" })
    );
    assert!(
        LimitedVerificationParser::<true>::parse_string(br#"ab\"c"23"#)
            .is_ok_and(|tup| { tup.0 == r#"ab"c"# && tup.1 == b"23" })
    );
    assert!(
        LimitedVerificationParser::<false>::parse_string(br#"ab\\c"23"#)
            .is_ok_and(|tup| { tup.0 == r"ab\c" && tup.1 == b"23" })
    );
    assert!(
        LimitedVerificationParser::<true>::parse_string(br#"ab\u001fc"23"#)
            .is_ok_and(|tup| { tup.0 == "ab\u{001f}c" && tup.1 == b"23" })
    );
    assert!(
        LimitedVerificationParser::<false>::parse_string(br#"ab\u000dc"23"#)
            .is_ok_and(|tup| { tup.0 == "ab\u{000d}c" && tup.1 == b"23" })
    );
    assert!(
        LimitedVerificationParser::<true>::parse_string(b"\\\\\\\\\\\\a\\\\\\\\a\\\\\"")
            .is_ok_and(|tup| { tup.0 == "\\\\\\a\\\\a\\" && tup.1.is_empty() })
    );
    assert!(
        LimitedVerificationParser::<false>::parse_string(b"\\\\\\\\\\a\\\\\\\\a\\\\\"")
            .is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidEscapedString),)
    );
    assert!(
        LimitedVerificationParser::<true>::parse_string(br#"ab\u0020c"23"#)
            .is_err_and(|err| matches!(err, CollectedClientDataErr::InvalidEscapedString),)
    );
    assert!(
        LimitedVerificationParser::<false>::parse_string(br#"ab\ac"23"#)
            .is_err_and(|err| matches!(err, CollectedClientDataErr::InvalidEscapedString),)
    );
    assert!(
        LimitedVerificationParser::<true>::parse_string(br#"ab\""#)
            .is_err_and(|err| matches!(err, CollectedClientDataErr::InvalidObject),)
    );
    assert!(
        LimitedVerificationParser::<false>::parse_string(br#"ab\u001Fc"23"#)
            .is_err_and(|err| matches!(err, CollectedClientDataErr::InvalidEscapedString),)
    );
    assert!(
        LimitedVerificationParser::<true>::parse_string([0, b'"'].as_slice())
            .is_err_and(|err| matches!(err, CollectedClientDataErr::InvalidEscapedString),)
    );
    assert!(
        LimitedVerificationParser::<false>::parse_string([b'a', 255, b'"'].as_slice())
            .is_err_and(|err| matches!(err, CollectedClientDataErr::Utf8(_)))
    );
    assert!(
        LimitedVerificationParser::<true>::parse_string([b'a', b'"', 255].as_slice())
            .is_ok_and(|tup| tup.0 == "a" && tup.1 == [255])
    );
    assert!(
        LimitedVerificationParser::<false>::parse_string(br#"""#)
            .is_ok_and(|tup| tup.0.is_empty() && tup.1.is_empty())
    );
}
#[expect(clippy::cognitive_complexity, reason = "a lot of things to test")]
#[test]
fn c_data_json() {
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://example.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false,{}}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://example.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":true}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://example.com" && val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":true,"topOrigin":"bob"}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://example.com" && val.cross_origin && val.top_origin.is_some_and(|v| v == "bob")));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":true,"topOrigin":"bob",a}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://example.com" && val.cross_origin && val.top_origin.is_some_and(|v| v == "bob")));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":true,"topOrigin":"bob"a}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidObject)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false,"topOrigin":""}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::TopOriginWithoutCrossOrigin)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false,"topOrigin":""}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::Challenge)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"","crossOrigin":false}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0.is_empty() && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::Type)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create", "challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::ChallengeKey)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::OriginKey)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\\e.com","crossOrigin":false}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://exampl\\e.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\"e.com","crossOrigin":false}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://exampl\"e.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\u0013e.com","crossOrigin":false}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://exampl\u{0013}e.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\3e.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidEscapedString)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\e.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidEscapedString)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\u0020.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidEscapedString)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\u000A.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidEscapedString)));
    assert!(
        LimitedVerificationParser::<true>::parse([].as_slice())
            .is_err_and(|e| matches!(e, CollectedClientDataErr::Len))
    );
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"abc","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidStart)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidObject)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","crossOrigin":false,"origin":"example.com"}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::OriginKey)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","topOrigin":"bob","crossOrigin":true}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::CrossOriginKey)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":"abc"}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::CrossOrigin)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":true"a}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidObject)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":true","topOrigin":"https://abc.com"a}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidObject)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://example.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<false>::parse(b"{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"origin\":\"https://example.com\",\"crossOrigin\":false,\xff}".as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://example.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":true}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://example.com" && val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":true,"topOrigin":"bob"}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://example.com" && val.cross_origin && val.top_origin.is_some_and(|v| v == "bob")));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false,"topOrigin":""}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::TopOriginWithoutCrossOrigin)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false,"topOrigin":""}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::Challenge)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"","crossOrigin":false}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0.is_empty() && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::Type)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get", "challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::ChallengeKey)));
    assert!(
        LimitedVerificationParser::<false>::parse(
            br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","crossOrigin":false}"#
                .as_slice()
        )
        .is_err_and(|e| matches!(e, CollectedClientDataErr::OriginKey))
    );
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\\e.com","crossOrigin":false}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://exampl\\e.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\"e.com","crossOrigin":false}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://exampl\"e.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\u0013e.com","crossOrigin":false}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://exampl\u{0013}e.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\3e.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidEscapedString)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\e.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidEscapedString)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\u0020.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidEscapedString)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://exampl\u000A.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidEscapedString)));
    assert!(
        LimitedVerificationParser::<false>::parse([].as_slice())
            .is_err_and(|e| matches!(e, CollectedClientDataErr::Len))
    );
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"abc","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidStart)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidObject)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","crossOrigin":false,"origin":"example.com"}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::OriginKey)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","topOrigin":"bob","crossOrigin":true}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::CrossOriginKey)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":"abc"}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::CrossOrigin)));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":true"a}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::InvalidObject)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":true,"topOrigin":"https://example.com"}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::TopOriginSameAsOrigin)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create","challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false,"foo":true}"#.as_slice()).is_ok_and(|val| val.challenge.0 == 0 && val.origin.0 == "https://example.com" && !val.cross_origin && val.top_origin.is_none()));
    assert!(LimitedVerificationParser::<false>::parse(br#"{"type":"webauthn.get","challengE":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossOrigin":false,"foo":true}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::ChallengeKey)));
    assert!(LimitedVerificationParser::<true>::parse(br#"{"type":"webauthn.create"challenge":"AAAAAAAAAAAAAAAAAAAAAA","origin":"https://example.com","crossorigin":false,"foo":true}"#.as_slice()).is_err_and(|e| matches!(e, CollectedClientDataErr::ChallengeKey)));
}
#[test]
fn c_data_challenge() {
    assert!(
        LimitedVerificationParser::<false>::get_sent_challenge([].as_slice())
            .is_err_and(|e| matches!(e, CollectedClientDataErr::Len))
    );
    assert!(
        LimitedVerificationParser::<true>::get_sent_challenge([].as_slice())
            .is_err_and(|e| matches!(e, CollectedClientDataErr::Len))
    );
    assert!(
        LimitedVerificationParser::<true>::get_sent_challenge(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBB"
        )
        .is_err_and(|e| matches!(e, CollectedClientDataErr::Challenge))
    );
    assert!(
        LimitedVerificationParser::<false>::get_sent_challenge(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBB"
        )
        .is_err_and(|e| matches!(e, CollectedClientDataErr::Challenge))
    );
    assert!(
        LimitedVerificationParser::<true>::get_sent_challenge(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_slice()
        )
        .is_ok_and(|c| c.0 == 0)
    );
    assert!(
        LimitedVerificationParser::<false>::get_sent_challenge(
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_slice()
        )
        .is_ok_and(|c| c.0 == 0)
    );
}
