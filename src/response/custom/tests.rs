use super::{AuthTransports, AuthenticatorTransport};
#[test]
fn iter_all() {
    let mut iter = AuthTransports::ALL.into_iter();
    assert_eq!(iter.len(), 6);
    assert!(
        iter.next()
            .is_some_and(|tran| matches!(tran, AuthenticatorTransport::Ble))
    );
    assert_eq!(iter.len(), 5);
    assert!(
        iter.next()
            .is_some_and(|tran| matches!(tran, AuthenticatorTransport::Hybrid))
    );
    assert_eq!(iter.len(), 4);
    assert!(
        iter.next_back()
            .is_some_and(|tran| matches!(tran, AuthenticatorTransport::Usb))
    );
    assert_eq!(iter.len(), 3);
    assert!(
        iter.next()
            .is_some_and(|tran| matches!(tran, AuthenticatorTransport::Internal))
    );
    assert_eq!(iter.len(), 2);
    assert!(
        iter.next_back()
            .is_some_and(|tran| matches!(tran, AuthenticatorTransport::SmartCard))
    );
    assert_eq!(iter.len(), 1);
    assert!(
        iter.next()
            .is_some_and(|tran| matches!(tran, AuthenticatorTransport::Nfc))
    );
    assert_eq!(iter.len(), 0);
    assert!(iter.next().is_none());
}
