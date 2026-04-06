use super::{Equivalent, Insert, InsertRemoveExpired, MaxLenHashSet, TimedCeremony};
use core::hash::{Hash, Hasher};
#[cfg(not(feature = "serializable_server_state"))]
use std::time::Instant;
#[cfg(feature = "serializable_server_state")]
use std::time::SystemTime;
#[derive(Clone, Copy)]
struct Ceremony {
    id: usize,
    #[cfg(not(feature = "serializable_server_state"))]
    exp: Instant,
    #[cfg(feature = "serializable_server_state")]
    exp: SystemTime,
}
impl Default for Ceremony {
    fn default() -> Self {
        Self {
            id: 0,
            #[cfg(not(feature = "serializable_server_state"))]
            exp: Instant::now(),
            #[cfg(feature = "serializable_server_state")]
            exp: SystemTime::now(),
        }
    }
}
impl PartialEq for Ceremony {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for Ceremony {}
impl Hash for Ceremony {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
impl TimedCeremony for Ceremony {
    #[cfg(not(feature = "serializable_server_state"))]
    fn expiration(&self) -> Instant {
        self.exp
    }
    #[cfg(feature = "serializable_server_state")]
    fn expiration(&self) -> SystemTime {
        self.exp
    }
}
impl Equivalent<Ceremony> for usize {
    #[inline]
    fn equivalent(&self, key: &Ceremony) -> bool {
        *self == key.id
    }
}
#[test]
fn hash_set_insert_removed() {
    const REQ_MAX_LEN: usize = 8;
    let mut set = MaxLenHashSet::new(REQ_MAX_LEN);
    let cap = set.as_ref().capacity();
    let max_len = set.max_len();
    assert_eq!(cap >> 1u8, max_len);
    assert!(max_len >= REQ_MAX_LEN);
    let mut cer = Ceremony::default();
    for i in 0..max_len {
        assert!(set.as_ref().capacity() <= cap);
        cer.id = i;
        assert_eq!(set.insert(cer), Insert::Success);
    }
    assert!(set.as_ref().capacity() <= cap);
    assert_eq!(set.as_ref().len(), max_len);
    for i in 0..max_len {
        assert!(set.as_ref().contains(&i));
    }
    cer.id = cap;
    assert_eq!(set.insert_remove_expired(cer), InsertRemoveExpired::Success);
    assert!(set.as_ref().capacity() <= cap);
    assert_eq!(set.as_ref().len(), max_len);
    let mut counter = 0;
    for i in 0..max_len {
        counter += usize::from(set.as_ref().contains(&i));
    }
    assert_eq!(counter, max_len - 1);
    assert!(set.as_ref().contains(&(max_len - 1)));
}
