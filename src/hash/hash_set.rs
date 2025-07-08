use super::{super::request::TimedCeremony, BuildIdentityHasher};
#[cfg(doc)]
use core::hash::Hasher;
use core::hash::{BuildHasher, Hash};
use hashbrown::{
    Equivalent,
    hash_set::{Drain, Entry, ExtractIf, HashSet},
};
#[cfg(not(feature = "serializable_server_state"))]
use std::time::Instant;
#[cfg(feature = "serializable_server_state")]
use std::time::SystemTime;
/// `newtype` around [`HashSet`] that has maximum [`HashSet::capacity`].
///
/// This is useful in situations when the underlying values are expected to be removed, and one wants to ensure the
/// set does not grow unbounded. When `T` is a [`TimedCeremony`], helper methods (e.g.,
/// [`Self::insert_remove_all_expired`]) are provided that will automatically remove expired values. Note the
/// intended use case is for `T` to be based on a server-side randomly generated value; thus the default [`Hasher`]
/// is [`BuildIdentityHasher`]. In the event this is not true, one MUST use a more appropriate `Hasher`.
///
/// Only the mutable methods of `HashSet` are re-defined in order to ensure the capacity never grows. For all
/// other methods, first call [`Self::as_ref`] or [`Self::into`].
///
/// [`Self::into`]: struct.FixedCapHashSet.html#impl-Into<U>-for-T
#[derive(Debug)]
pub struct FixedCapHashSet<T, S = BuildIdentityHasher>(HashSet<T, S>);
impl<T> FixedCapHashSet<T, BuildIdentityHasher> {
    /// [`HashSet::with_capacity_and_hasher`] using `capacity` and `BuildIdentityHasher`.
    #[inline]
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self(HashSet::with_capacity_and_hasher(
            capacity,
            BuildIdentityHasher,
        ))
    }
}
impl<T, S> FixedCapHashSet<T, S> {
    /// [`HashSet::clear`].
    #[inline]
    pub fn clear(&mut self) {
        self.0.clear();
    }
    /// [`HashSet::drain`].
    #[inline]
    pub fn drain(&mut self) -> Drain<'_, T> {
        self.0.drain()
    }
    /// [`HashSet::extract_if`].
    #[inline]
    pub fn extract_if<F: FnMut(&T) -> bool>(&mut self, f: F) -> ExtractIf<'_, T, F> {
        self.0.extract_if(f)
    }
    /// [`HashSet::with_capacity_and_hasher`].
    #[inline]
    #[must_use]
    pub fn with_hasher(capacity: usize, hasher: S) -> Self {
        Self(HashSet::with_capacity_and_hasher(capacity, hasher))
    }
    /// [`HashSet::retain`].
    #[inline]
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, f: F) {
        self.0.retain(f);
    }
}
impl<T: TimedCeremony, S> FixedCapHashSet<T, S> {
    /// Removes all expired ceremonies.
    #[inline]
    pub fn remove_expired_ceremonies(&mut self) {
        // Even though it's more accurate to check the current `Instant` for each ceremony, we elect to capture
        // the `Instant` we begin iteration for performance reasons. It's unlikely an appreciable amount of
        // additional ceremonies would be removed.
        #[cfg(not(feature = "serializable_server_state"))]
        let now = Instant::now();
        #[cfg(feature = "serializable_server_state")]
        let now = SystemTime::now();
        self.retain(|v| v.expiration() >= now);
    }
}
impl<T: Eq + Hash, S: BuildHasher> FixedCapHashSet<T, S> {
    /// [`HashSet::get_or_insert`].
    ///
    /// `None` is returned iff [`HashSet::len`] `==` [`HashSet::capacity`] and `value` does not already exist in the
    /// set.
    #[inline]
    pub fn get_or_insert(&mut self, value: T) -> Option<&T> {
        if self.0.len() == self.0.capacity() {
            self.0.get(&value)
        } else {
            Some(self.0.get_or_insert(value))
        }
    }
    /// [`HashSet::get_or_insert_with`].
    ///
    /// `None` is returned iff [`HashSet::len`] `==` [`HashSet::capacity`] and `value` does not already exist in the
    /// set.
    #[inline]
    pub fn get_or_insert_with<Q: Equivalent<T> + Hash + ?Sized, F: FnOnce(&Q) -> T>(
        &mut self,
        value: &Q,
        f: F,
    ) -> Option<&T> {
        if self.0.len() == self.0.capacity() {
            self.0.get(value)
        } else {
            Some(self.0.get_or_insert_with(value, f))
        }
    }
    /// [`HashSet::remove`].
    #[inline]
    pub fn remove<Q: Equivalent<T> + Hash + ?Sized>(&mut self, value: &Q) -> bool {
        self.0.remove(value)
    }
    /// [`HashSet::take`].
    #[inline]
    pub fn take<Q: Equivalent<T> + Hash + ?Sized>(&mut self, value: &Q) -> Option<T> {
        self.0.take(value)
    }
    /// [`HashSet::insert`].
    ///
    /// `None` is returned iff [`HashSet::len`] `==` [`HashSet::capacity`] and `value` does not already exist in the
    /// set.
    #[inline]
    pub fn insert(&mut self, value: T) -> Option<bool> {
        let full = self.0.len() == self.0.capacity();
        if let Entry::Vacant(ent) = self.0.entry(value) {
            if full {
                None
            } else {
                _ = ent.insert();
                Some(true)
            }
        } else {
            Some(false)
        }
    }
    /// [`HashSet::replace`].
    ///
    /// `None` is returned iff [`HashSet::len`] `==` [`HashSet::capacity`] and `value` does not already exist in the
    /// set.
    #[inline]
    pub fn replace(&mut self, value: T) -> Option<Option<T>> {
        // Ideally we would use the Entry API to avoid searching multiple times, but one can't while also using
        // `replace` since there is no `OccupiedEntry::replace`.
        if self.0.contains(&value) {
            Some(self.0.replace(value))
        } else if self.0.len() == self.0.capacity() {
            None
        } else {
            _ = self.0.insert(value);
            Some(None)
        }
    }
    /// [`HashSet::entry`].
    ///
    /// `None` is returned iff [`HashSet::len`] `==` [`HashSet::capacity`] and `value` does not already exist in the
    /// set.
    #[inline]
    pub fn entry(&mut self, value: T) -> Option<Entry<'_, T, S>> {
        let full = self.0.len() == self.0.capacity();
        match self.0.entry(value) {
            ent @ Entry::Occupied(_) => Some(ent),
            ent @ Entry::Vacant(_) => {
                if full {
                    None
                } else {
                    Some(ent)
                }
            }
        }
    }
}
impl<T: Eq + Hash + TimedCeremony, S: BuildHasher> FixedCapHashSet<T, S> {
    /// [`Self::insert`] except the first expired ceremony is removed in the event there is no available capacity.
    #[inline]
    pub fn insert_remove_expired(&mut self, value: T) -> Option<bool> {
        if self.0.len() == self.0.capacity() {
            #[cfg(not(feature = "serializable_server_state"))]
            let now = Instant::now();
            #[cfg(feature = "serializable_server_state")]
            let now = SystemTime::now();
            if self.0.extract_if(|v| v.expiration() < now).next().is_some() {
                Some(self.0.insert(value))
            } else {
                self.0.contains(&value).then_some(false)
            }
        } else {
            Some(self.0.insert(value))
        }
    }
    /// [`Self::insert`] except all expired ceremones are removed in the event there is no available capacity.
    #[inline]
    pub fn insert_remove_all_expired(&mut self, value: T) -> Option<bool> {
        if self.0.len() == self.0.capacity() {
            self.remove_expired_ceremonies();
        }
        if self.0.len() == self.0.capacity() {
            self.0.contains(&value).then_some(false)
        } else {
            Some(self.0.insert(value))
        }
    }
    /// [`Self::entry`] except the first expired ceremony is removed in the event there is no available capacity.
    #[inline]
    pub fn entry_remove_expired(&mut self, value: T) -> Option<Entry<'_, T, S>> {
        if self.0.len() == self.0.capacity() {
            #[cfg(not(feature = "serializable_server_state"))]
            let now = Instant::now();
            #[cfg(feature = "serializable_server_state")]
            let now = SystemTime::now();
            if self.0.extract_if(|v| v.expiration() < now).next().is_some() {
                Some(self.0.entry(value))
            } else if let ent @ Entry::Occupied(_) = self.0.entry(value) {
                Some(ent)
            } else {
                None
            }
        } else {
            Some(self.0.entry(value))
        }
    }
    /// [`Self::entry`] except all expired ceremones are removed in the event there is no available capacity.
    #[inline]
    pub fn entry_remove_all_expired(&mut self, value: T) -> Option<Entry<'_, T, S>> {
        if self.0.len() == self.0.capacity() {
            self.remove_expired_ceremonies();
        }
        if self.0.len() == self.0.capacity() {
            if let ent @ Entry::Occupied(_) = self.0.entry(value) {
                Some(ent)
            } else {
                None
            }
        } else {
            Some(self.0.entry(value))
        }
    }
}
impl<T, S> AsRef<HashSet<T, S>> for FixedCapHashSet<T, S> {
    #[inline]
    fn as_ref(&self) -> &HashSet<T, S> {
        &self.0
    }
}
impl<T, S> From<FixedCapHashSet<T, S>> for HashSet<T, S> {
    #[inline]
    fn from(value: FixedCapHashSet<T, S>) -> Self {
        value.0
    }
}
impl<T, S> From<HashSet<T, S>> for FixedCapHashSet<T, S> {
    #[inline]
    fn from(value: HashSet<T, S>) -> Self {
        Self(value)
    }
}
#[cfg(test)]
mod tests {
    use super::{Equivalent, FixedCapHashSet, TimedCeremony};
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
        fn equivalent(&self, key: &Ceremony) -> bool {
            *self == key.id
        }
    }
    #[test]
    fn hash_set_insert_removed() {
        let mut set = FixedCapHashSet::new(8);
        let cap = set.as_ref().capacity();
        let mut cer = Ceremony::default();
        for i in 0..cap {
            assert_eq!(set.as_ref().capacity(), cap);
            cer.id = i;
            assert_eq!(set.insert(cer), Some(true));
        }
        assert_eq!(set.as_ref().capacity(), cap);
        assert_eq!(set.as_ref().len(), cap);
        for i in 0..cap {
            assert!(set.as_ref().contains(&i));
        }
        cer.id = cap;
        assert_eq!(set.insert_remove_expired(cer), Some(true));
        assert_eq!(set.as_ref().capacity(), cap);
        assert_eq!(set.as_ref().len(), cap);
        let mut counter = 0;
        for i in 0..cap {
            counter += usize::from(set.as_ref().contains(&i));
        }
        assert_eq!(counter, cap - 1);
        assert!(set.as_ref().contains(&cap));
    }
}
