//! Tests of the Agora fork's `derived_challenge` feature. Fork-owned: `request.rs` only carries the `mod` hook.
use super::{super::response::SentChallenge, Challenge};
/// The derived bytes are what the client receives and sends back.
#[cfg(feature = "serde")]
#[expect(clippy::unwrap_used, reason = "OK in tests")]
#[test]
fn derived_challenge_is_sent_as_given() {
    let bytes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xff];
    let challenge = Challenge::derived(bytes);
    assert_eq!(challenge.as_array(), bytes);
    let json = serde_json::to_string(&challenge).unwrap();
    assert_eq!(
        json,
        format!("\"{}\"", base64url_nopad::encode(bytes.as_slice()))
    );
    let sent: SentChallenge = serde_json::from_str(&json).unwrap();
    assert_eq!(sent, SentChallenge::from_challenge(challenge));
    assert_eq!(sent, SentChallenge::from_array(bytes));
}
/// Equal inputs give equal challenges: the server state of a repeated derivation is a duplicate key.
#[test]
fn a_repeated_derivation_is_the_same_challenge() {
    assert_eq!(
        SentChallenge::from_challenge(Challenge::derived([9; 16])),
        SentChallenge::from_challenge(Challenge::derived([9; 16]))
    );
}
