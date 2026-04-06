use super::{ClientDataJsonParser as _, Cow, RelaxedClientDataJsonParser};
use serde::de::{Error as _, Unexpected};
use serde_json::Error;
#[expect(clippy::unwrap_used, reason = "OK in tests")]
#[expect(clippy::little_endian_bytes, reason = "comments justify correctness")]
#[expect(clippy::too_many_lines, reason = "a lot to test")]
#[test]
fn relaxed_client_data_json() {
    // Base case is correct.
    let mut input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert!(
        RelaxedClientDataJsonParser::<true>::parse(input.as_bytes()).is_ok_and(|c| {
            c.cross_origin
                && c.challenge.0
                // challenges are sent little-endian
                    == u128::from_le_bytes([
                        0, 16, 1, 0, 16, 1, 0, 16, 1, 0, 16, 1, 0, 16, 1, 0,
                    ])
                && matches!(c.origin.0, Cow::Borrowed(o) if o == "https://example.com")
                && c.top_origin
                    .is_some_and(|t| matches!(t.0, Cow::Borrowed(o) if o == "https://example.org"))
        })
    );
    // Base case is correct.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert!(
        RelaxedClientDataJsonParser::<false>::parse(input.as_bytes()).is_ok_and(|c| {
            c.cross_origin
                && c.challenge.0
                // challenges are sent little-endian
                    == u128::from_le_bytes([
                        0, 16, 1, 0, 16, 1, 0, 16, 1, 0, 16, 1, 0, 16, 1, 0,
                    ])
                && matches!(c.origin.0, Cow::Borrowed(o) if o == "https://example.com")
                && c.top_origin
                    .is_some_and(|t| matches!(t.0, Cow::Borrowed(o) if o == "https://example.org"))
        })
    );
    // Unknown keys are allowed.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org",
        "foo": true
    })
    .to_string();
    drop(RelaxedClientDataJsonParser::<true>::parse(input.as_bytes()).unwrap());
    // Duplicate keys are forbidden.
    let mut input_str = "{
        \"challenge\": \"ABABABABABABABABABABAA\",
        \"type\": \"webauthn.create\",
        \"origin\": \"https://example.com\",
        \"crossOrigin\": true,
        \"topOrigin\": \"https://example.org\",
        \"crossOrigin\": true
    }";
    let mut err = Error::duplicate_field("crossOrigin")
        .to_string()
        .into_bytes();
    assert_eq!(
        RelaxedClientDataJsonParser::<true>::parse(input_str.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `crossOrigin`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": null,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert!(
        RelaxedClientDataJsonParser::<true>::parse(input.as_bytes()).is_ok_and(|c| !c.cross_origin)
    );
    // Missing `crossOrigin`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert!(
        RelaxedClientDataJsonParser::<true>::parse(input.as_bytes()).is_ok_and(|c| !c.cross_origin)
    );
    // `null` `topOrigin`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": null
    })
    .to_string();
    assert!(
        RelaxedClientDataJsonParser::<true>::parse(input.as_bytes())
            .is_ok_and(|c| c.top_origin.is_none())
    );
    // Missing `topOrigin`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
    })
    .to_string();
    assert!(
        RelaxedClientDataJsonParser::<true>::parse(input.as_bytes())
            .is_ok_and(|c| c.top_origin.is_none())
    );
    // `null` `challenge`.
    err = Error::invalid_type(
        Unexpected::Other("null"),
        &"base64 encoding of the 16-byte challenge in a URL safe way without padding",
    )
    .to_string()
    .into_bytes();
    input = serde_json::json!({
        "challenge": null,
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert_eq!(
        RelaxedClientDataJsonParser::<true>::parse(input.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `challenge`.
    err = Error::missing_field("challenge").to_string().into_bytes();
    input = serde_json::json!({
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert_eq!(
        RelaxedClientDataJsonParser::<true>::parse(input.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `type`.
    err = Error::invalid_type(
        Unexpected::Other("null"),
        &"'webauthn.create' or 'webauthn.get'",
    )
    .to_string()
    .into_bytes();
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": null,
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert_eq!(
        RelaxedClientDataJsonParser::<true>::parse(input.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `type`.
    err = Error::missing_field("type").to_string().into_bytes();
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert_eq!(
        RelaxedClientDataJsonParser::<true>::parse(input.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `origin`.
    err = Error::invalid_type(Unexpected::Other("null"), &"OriginWrapper")
        .to_string()
        .into_bytes();
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "origin": null,
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert_eq!(
        RelaxedClientDataJsonParser::<false>::parse(input.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `origin`.
    err = Error::missing_field("origin").to_string().into_bytes();
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert_eq!(
        RelaxedClientDataJsonParser::<false>::parse(input.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // Mismatched `type`.
    err = Error::invalid_value(Unexpected::Str("webauthn.create"), &"webauthn.get")
        .to_string()
        .into_bytes();
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert_eq!(
        RelaxedClientDataJsonParser::<false>::parse(input.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // Mismatched `type`.
    err = Error::invalid_value(Unexpected::Str("webauthn.get"), &"webauthn.create")
        .to_string()
        .into_bytes();
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert_eq!(
        RelaxedClientDataJsonParser::<true>::parse(input.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // `crossOrigin` can be `false` even when `topOrigin` exists.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "origin": "https://example.com",
        "crossOrigin": false,
        "topOrigin": "https://example.org"
    })
    .to_string();
    drop(RelaxedClientDataJsonParser::<false>::parse(input.as_bytes()).unwrap());
    // `crossOrigin` can be `true` even when `topOrigin` does not exist.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "origin": "https://example.com",
        "crossOrigin": true,
    })
    .to_string();
    drop(RelaxedClientDataJsonParser::<false>::parse(input.as_bytes()).unwrap());
    // BOM is removed.
    input_str = "\u{feff}{
        \"challenge\": \"ABABABABABABABABABABAA\",
        \"type\": \"webauthn.create\",
        \"origin\": \"https://example.com\",
        \"crossOrigin\": true,
        \"topOrigin\": \"https://example.org\"
    }";
    drop(RelaxedClientDataJsonParser::<true>::parse(input_str.as_bytes()).unwrap());
    // Invalid Unicode is replaced.
    let mut input_bytes = b"{
        \"challenge\": \"ABABABABABABABABABABAA\",
        \"type\": \"webauthn.create\",
        \"origin\": \"https://\xffexample.com\",
        \"crossOrigin\": true,
        \"topOrigin\": \"https://example.org\"
    }"
    .as_slice();
    assert!(
        RelaxedClientDataJsonParser::<true>::parse(input_bytes).is_ok_and(|c| {
            matches!(c.origin.0, Cow::Owned(o) if o == "https://\u{fffd}example.com")
        })
    );
    // Escape characters are de-escaped.
    input_bytes = b"{
        \"challenge\": \"ABABABABABABABABABABAA\",
        \"type\": \"webauthn\\u002ecreate\",
        \"origin\": \"https://examp\\\\le.com\",
        \"crossOrigin\": true,
        \"topOrigin\": \"https://example.org\"
    }";
    assert!(
        RelaxedClientDataJsonParser::<true>::parse(input_bytes)
            .is_ok_and(|c| { matches!(c.origin.0, Cow::Owned(o) if o == "https://examp\\le.com") })
    );
}
#[expect(clippy::unwrap_used, reason = "OK in tests")]
#[expect(clippy::little_endian_bytes, reason = "comments justify correctness")]
#[expect(clippy::too_many_lines, reason = "a lot to test")]
#[test]
fn relaxed_challenge() {
    // Base case is correct.
    let mut input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert!(
        RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes()).is_ok_and(|c| {
            // `Challenges` are sent in little-endian.
            c.0 == u128::from_le_bytes([0, 16, 1, 0, 16, 1, 0, 16, 1, 0, 16, 1, 0, 16, 1, 0])
        })
    );
    // Base case is correct.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert!(
        RelaxedClientDataJsonParser::<false>::get_sent_challenge(input.as_bytes()).is_ok_and(|c| {
            // `Challenges` are sent in little-endian.
            c.0 == u128::from_le_bytes([0, 16, 1, 0, 16, 1, 0, 16, 1, 0, 16, 1, 0, 16, 1, 0])
        })
    );
    // Unknown keys are allowed.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org",
        "foo": true
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes()).unwrap();
    // Duplicate keys are ignored.
    let mut input_str = "{
        \"challenge\": \"ABABABABABABABABABABAA\",
        \"type\": \"webauthn.create\",
        \"origin\": \"https://example.com\",
        \"crossOrigin\": true,
        \"topOrigin\": \"https://example.org\",
        \"crossOrigin\": true
    }";
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input_str.as_bytes()).unwrap();
    // `null` `crossOrigin`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": null,
        "topOrigin": "https://example.org"
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes()).unwrap();
    // Missing `crossOrigin`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "topOrigin": "https://example.org"
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes()).unwrap();
    // `null` `topOrigin`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": null
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes()).unwrap();
    // Missing `topOrigin`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes()).unwrap();
    // `null` `challenge`.
    let mut err = Error::invalid_type(
        Unexpected::Other("null"),
        &"base64 encoding of the 16-byte challenge in a URL safe way without padding",
    )
    .to_string()
    .into_bytes();
    input = serde_json::json!({
        "challenge": null,
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert_eq!(
        RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // Missing `challenge`.
    err = Error::missing_field("challenge").to_string().into_bytes();
    input = serde_json::json!({
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    assert_eq!(
        RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes())
            .unwrap_err()
            .to_string()
            .into_bytes()
            .get(..err.len()),
        Some(err.as_slice())
    );
    // `null` `type`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": null,
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes()).unwrap();
    // Missing `type`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes()).unwrap();
    // `null` `origin`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "origin": null,
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<false>::get_sent_challenge(input.as_bytes()).unwrap();
    // Missing `origin`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<false>::get_sent_challenge(input.as_bytes()).unwrap();
    // Mismatched `type`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.create",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<false>::get_sent_challenge(input.as_bytes()).unwrap();
    // Mismatched `type`.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "origin": "https://example.com",
        "crossOrigin": true,
        "topOrigin": "https://example.org"
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input.as_bytes()).unwrap();
    // `crossOrigin` can be `false` even when `topOrigin` exists.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "origin": "https://example.com",
        "crossOrigin": false,
        "topOrigin": "https://example.org"
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<false>::get_sent_challenge(input.as_bytes()).unwrap();
    // `crossOrigin` can be `true` even when `topOrigin` does not exist.
    input = serde_json::json!({
        "challenge": "ABABABABABABABABABABAA",
        "type": "webauthn.get",
        "origin": "https://example.com",
        "crossOrigin": true,
    })
    .to_string();
    _ = RelaxedClientDataJsonParser::<false>::get_sent_challenge(input.as_bytes()).unwrap();
    // BOM is removed.
    input_str = "\u{feff}{
        \"challenge\": \"ABABABABABABABABABABAA\",
        \"type\": \"webauthn.create\",
        \"origin\": \"https://example.com\",
        \"crossOrigin\": true,
        \"topOrigin\": \"https://example.org\"
    }";
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input_str.as_bytes()).unwrap();
    // Invalid Unicode is replaced.
    let mut input_bytes = b"{
        \"challenge\": \"ABABABABABABABABABABAA\",
        \"type\": \"webauthn.create\",
        \"origin\": \"https://\xffexample.com\",
        \"crossOrigin\": true,
        \"topOrigin\": \"https://example.org\"
    }"
    .as_slice();
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input_bytes).unwrap();
    // Escape characters are de-escaped.
    input_bytes = b"{
        \"challenge\": \"ABABABABABABABABABABAA\",
        \"type\": \"webauthn\\u002ecreate\",
        \"origin\": \"https://examp\\\\le.com\",
        \"crossOrigin\": true,
        \"topOrigin\": \"https://example.org\"
    }";
    _ = RelaxedClientDataJsonParser::<true>::get_sent_challenge(input_bytes).unwrap();
}
