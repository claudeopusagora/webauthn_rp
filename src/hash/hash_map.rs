use super::{super::request::TimedCeremony, BuildIdentityHasher};
#[cfg(doc)]
use core::hash::Hasher;
use core::hash::{BuildHasher, Hash};
use hashbrown::{
    Equivalent, TryReserveError,
    hash_map::{Drain, Entry, EntryRef, ExtractIf, HashMap, IterMut, OccupiedError, ValuesMut},
};
#[cfg(not(feature = "serializable_server_state"))]
use std::time::Instant;
#[cfg(feature = "serializable_server_state")]
use std::time::SystemTime;
/// [`HashMap`] that has maximum [`HashMap::capacity`] and length and allocates exactly once.
///
/// Note due to how `HashMap` removes entries, it's possible to insert an entry after removing an entry and cause
/// a new allocation. To avoid this, we ensure that the allocated capacity is at least twice the size of
/// the requested maximum length.
///
/// This is useful in situations when the underlying entries are expected to be removed, and one wants to ensure the
/// map does not grow unbounded. When `K` is a [`TimedCeremony`], helper methods (e.g.,
/// [`Self::insert_remove_all_expired`]) are provided that will automatically remove expired entries. Note the
/// intended use case is for `K` to be based on a server-side randomly generated value; thus the default [`Hasher`]
/// is [`BuildIdentityHasher`]. In the event this is not true, one MUST use a more appropriate `Hasher`.
///
/// Only the mutable methods of `HashMap` are re-defined in order to ensure [`Self::max_len`] is never exceeded.
/// For all other methods, first call [`Self::as_ref`] or [`Self::into`].
///
/// [`Self::into`]: struct.MaxLenHashMap.html#impl-Into<U>-for-T
#[derive(Debug)]
pub struct MaxLenHashMap<K, V, S = BuildIdentityHasher>(HashMap<K, V, S>, usize);
impl<K, V> MaxLenHashMap<K, V, BuildIdentityHasher> {
    /// [`HashMap::with_capacity_and_hasher`] using `2 * max_len` and `BuildIdentityHasher`.
    ///
    /// Note since the actual capacity allocated may exceed the requested capacity, [`Self::max_len`] may exceed
    /// `max_len`.
    ///
    /// # Panics
    ///
    /// `panic`s if `max_len > usize::MAX / 2`. Note since [`HashMap::with_capacity_and_hasher`] `panic`s
    /// for much smaller values than `usize::MAX / 2`—even when `K` and `V` are zero-sized types (ZSTs)—this is not
    /// an additional `panic` than what would already occur. The only difference is the message reported.
    #[inline]
    #[must_use]
    pub fn new(max_len: usize) -> Self {
        Self::with_hasher(max_len, BuildIdentityHasher)
    }
}
impl<K, V, S> MaxLenHashMap<K, V, S> {
    /// Capacity we allocate.
    ///
    /// # Errors
    ///
    /// Errors iff `max_len > usize::MAX / 2`.
    const fn requested_capacity(max_len: usize) -> Result<usize, TryReserveError> {
        if max_len <= usize::MAX >> 1u8 {
            Ok(max_len << 1u8)
        } else {
            Err(TryReserveError::CapacityOverflow)
        }
    }
    /// Returns the immutable maximum length allowed by `self`.
    #[inline]
    pub const fn max_len(&self) -> usize {
        self.1
    }
    /// [`HashMap::values_mut`].
    #[inline]
    pub fn values_mut(&mut self) -> ValuesMut<'_, K, V> {
        self.0.values_mut()
    }
    /// [`HashMap::iter_mut`].
    #[expect(
        clippy::iter_without_into_iter,
        reason = "re-export all mutable methods of HashMap"
    )]
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, K, V> {
        self.0.iter_mut()
    }
    /// [`HashMap::clear`].
    #[inline]
    pub fn clear(&mut self) {
        self.0.clear();
    }
    /// [`HashMap::drain`].
    #[inline]
    pub fn drain(&mut self) -> Drain<'_, K, V> {
        self.0.drain()
    }
    /// [`HashMap::extract_if`].
    #[inline]
    pub fn extract_if<F: FnMut(&K, &mut V) -> bool>(&mut self, f: F) -> ExtractIf<'_, K, V, F> {
        self.0.extract_if(f)
    }
    /// [`HashMap::with_capacity_and_hasher`] using `2 * max_len` and `hasher`.
    ///
    /// Note since the actual capacity allocated may exceed the requested capacity, [`Self::max_len`] may exceed
    /// `max_len`.
    ///
    /// # Panics
    ///
    /// `panic`s if `max_len > usize::MAX / 2`. Note since [`HashMap::with_capacity_and_hasher`] `panic`s
    /// for much smaller values than `usize::MAX / 2`—even when `K` and `V` are zero-sized types (ZSTs)—this is not
    /// an additional `panic` than what would already occur. The only difference is the message reported.
    #[expect(
        clippy::expect_used,
        reason = "purpose of this function is to panic if the hash map cannot be allocated"
    )]
    #[inline]
    #[must_use]
    pub fn with_hasher(max_len: usize, hasher: S) -> Self {
        let map = HashMap::with_capacity_and_hasher(Self::requested_capacity(max_len).expect("HashMap::with_hasher must be passed a maximum length that does not exceed usize::MAX / 2"), hasher);
        let len = map.capacity() >> 1u8;
        Self(map, len)
    }
    /// [`HashMap::retain`].
    #[inline]
    pub fn retain<F: FnMut(&K, &mut V) -> bool>(&mut self, f: F) {
        self.0.retain(f);
    }
}
impl<K: TimedCeremony, V, S> MaxLenHashMap<K, V, S> {
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
        self.retain(|v, _| v.expiration() >= now);
    }
    /// Removes the first encountered expired ceremony.
    #[inline]
    pub fn remove_first_expired_ceremony(&mut self) {
        #[cfg(not(feature = "serializable_server_state"))]
        let now = Instant::now();
        #[cfg(feature = "serializable_server_state")]
        let now = SystemTime::now();
        drop(self.0.extract_if(|k, _| k.expiration() < now).next());
    }
}
impl<K: Eq + Hash, V, S: BuildHasher> MaxLenHashMap<K, V, S> {
    /// [`HashMap::with_hasher`] using `hasher` followed by [`HashMap::try_reserve`] using `2 * max_len`.
    ///
    /// Note since the actual capacity allocated may exceed the requested capacity, [`Self::max_len`] may exceed
    /// `max_len`.
    ///
    /// # Errors
    ///
    /// Errors iff `max_len > usize::MAX / 2` or [`HashMap::try_reserve`] does.
    #[inline]
    pub fn try_with_hasher(max_len: usize, hasher: S) -> Result<Self, TryReserveError> {
        Self::requested_capacity(max_len).and_then(|additional| {
            let mut set = HashMap::with_hasher(hasher);
            set.try_reserve(additional).map(|()| {
                let len = set.capacity() >> 1u8;
                Self(set, len)
            })
        })
    }
    /// [`HashMap::get_mut`].
    #[inline]
    pub fn get_mut<Q: Equivalent<K> + Hash + ?Sized>(&mut self, k: &Q) -> Option<&mut V> {
        self.0.get_mut(k)
    }
    /// [`HashMap::get_key_value_mut`].
    #[inline]
    pub fn get_key_value_mut<Q: Equivalent<K> + Hash + ?Sized>(
        &mut self,
        k: &Q,
    ) -> Option<(&K, &mut V)> {
        self.0.get_key_value_mut(k)
    }
    /// [`HashMap::get_disjoint_mut`].
    #[inline]
    pub fn get_disjoint_mut<Q: Equivalent<K> + Hash + ?Sized, const N: usize>(
        &mut self,
        ks: [&Q; N],
    ) -> [Option<&mut V>; N] {
        self.0.get_disjoint_mut(ks)
    }
    /// [`HashMap::get_disjoint_key_value_mut`].
    #[inline]
    pub fn get_disjoint_key_value_mut<Q: Equivalent<K> + Hash + ?Sized, const N: usize>(
        &mut self,
        ks: [&Q; N],
    ) -> [Option<(&K, &mut V)>; N] {
        self.0.get_disjoint_key_value_mut(ks)
    }
    /// [`HashMap::remove`].
    #[inline]
    pub fn remove<Q: Equivalent<K> + Hash + ?Sized>(&mut self, k: &Q) -> Option<V> {
        self.0.remove(k)
    }
    /// [`HashMap::remove_entry`].
    #[inline]
    pub fn remove_entry<Q: Equivalent<K> + Hash + ?Sized>(&mut self, k: &Q) -> Option<(K, V)> {
        self.0.remove_entry(k)
    }
    /// [`HashMap::try_insert`].
    ///
    /// `Ok(None)` is returned iff [`HashMap::len`] `==` [`Self::max_len`] and `key` does not already exist in
    /// the map.
    ///
    /// # Errors
    ///
    /// Errors iff [`HashMap::insert`] does.
    #[inline]
    pub fn try_insert(
        &mut self,
        key: K,
        value: V,
    ) -> Result<Option<&mut V>, OccupiedError<'_, K, V, S>> {
        let full = self.0.len() == self.1;
        match self.0.entry(key) {
            Entry::Occupied(entry) => Err(OccupiedError { entry, value }),
            Entry::Vacant(ent) => {
                if full {
                    Ok(None)
                } else {
                    Ok(Some(ent.insert(value)))
                }
            }
        }
    }
    /// [`HashMap::insert`].
    ///
    /// `None` is returned iff [`HashMap::len`] `==` [`Self::max_len`] and `key` does not already exist in the
    /// map.
    #[inline]
    pub fn insert(&mut self, k: K, v: V) -> Option<Option<V>> {
        let full = self.0.len() == self.1;
        match self.0.entry(k) {
            Entry::Occupied(mut ent) => Some(Some(ent.insert(v))),
            Entry::Vacant(ent) => {
                if full {
                    None
                } else {
                    _ = ent.insert(v);
                    Some(None)
                }
            }
        }
    }
    /// [`HashMap::entry`].
    ///
    /// `None` is returned iff [`HashMap::len`] `==` [`Self::max_len`] and `key` does not already exist in the
    /// map.
    #[inline]
    pub fn entry(&mut self, key: K) -> Option<Entry<'_, K, V, S>> {
        let full = self.0.len() == self.1;
        match self.0.entry(key) {
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
    /// [`HashMap::entry_ref`].
    ///
    /// `None` is returned iff [`HashMap::len`] `==` [`Self::max_len`] and `key` does not already exist in the
    /// map.
    #[inline]
    pub fn entry_ref<'a, 'b, Q: Equivalent<K> + Hash + ?Sized>(
        &'a mut self,
        key: &'b Q,
    ) -> Option<EntryRef<'a, 'b, K, Q, V, S>> {
        let full = self.0.len() == self.1;
        match self.0.entry_ref(key) {
            ent @ EntryRef::Occupied(_) => Some(ent),
            ent @ EntryRef::Vacant(_) => {
                if full {
                    None
                } else {
                    Some(ent)
                }
            }
        }
    }
}
impl<K: Eq + Hash + TimedCeremony, V, S: BuildHasher> MaxLenHashMap<K, V, S> {
    /// [`Self::insert`] except the first encountered expired ceremony is removed in the event [`Self::max_len`]
    /// entries have been added.
    #[inline]
    pub fn insert_remove_expired(&mut self, k: K, v: V) -> Option<Option<V>> {
        if self.0.len() == self.1 {
            #[cfg(not(feature = "serializable_server_state"))]
            let now = Instant::now();
            #[cfg(feature = "serializable_server_state")]
            let now = SystemTime::now();
            if self
                .0
                .extract_if(|exp, _| exp.expiration() < now)
                .next()
                .is_some()
            {
                Some(self.0.insert(k, v))
            } else if let Entry::Occupied(mut ent) = self.0.entry(k) {
                Some(Some(ent.insert(v)))
            } else {
                None
            }
        } else {
            Some(self.0.insert(k, v))
        }
    }
    /// [`Self::insert`] except all expired ceremonies are removed in the event [`Self::max_len`] entries have
    /// been added.
    #[inline]
    pub fn insert_remove_all_expired(&mut self, k: K, v: V) -> Option<Option<V>> {
        if self.0.len() == self.1 {
            self.remove_expired_ceremonies();
        }
        if self.0.len() == self.1 {
            if let Entry::Occupied(mut ent) = self.0.entry(k) {
                Some(Some(ent.insert(v)))
            } else {
                None
            }
        } else {
            Some(self.0.insert(k, v))
        }
    }
    /// [`Self::entry`] except the first encountered expired ceremony is removed in the event [`Self::max_len`]
    /// entries have been added.
    #[inline]
    pub fn entry_remove_expired(&mut self, key: K) -> Option<Entry<'_, K, V, S>> {
        if self.0.len() == self.1 {
            #[cfg(not(feature = "serializable_server_state"))]
            let now = Instant::now();
            #[cfg(feature = "serializable_server_state")]
            let now = SystemTime::now();
            if self
                .0
                .extract_if(|v, _| v.expiration() < now)
                .next()
                .is_some()
            {
                Some(self.0.entry(key))
            } else if let ent @ Entry::Occupied(_) = self.0.entry(key) {
                Some(ent)
            } else {
                None
            }
        } else {
            Some(self.0.entry(key))
        }
    }
    /// [`Self::entry`] except all expired ceremonies are removed in the event [`Self::max_len`] entries have
    /// been added.
    #[inline]
    pub fn entry_remove_all_expired(&mut self, key: K) -> Option<Entry<'_, K, V, S>> {
        if self.0.len() == self.1 {
            self.remove_expired_ceremonies();
        }
        if self.0.len() == self.1 {
            if let ent @ Entry::Occupied(_) = self.0.entry(key) {
                Some(ent)
            } else {
                None
            }
        } else {
            Some(self.0.entry(key))
        }
    }
    /// [`Self::entry_ref`] except the first encoutered expired ceremony is removed in the event [`Self::max_len`]
    /// entries have been added.
    #[inline]
    pub fn entry_ref_remove_expired<'a, 'b, Q: Equivalent<K> + Hash + ?Sized>(
        &'a mut self,
        key: &'b Q,
    ) -> Option<EntryRef<'a, 'b, K, Q, V, S>> {
        if self.0.len() == self.1 {
            #[cfg(not(feature = "serializable_server_state"))]
            let now = Instant::now();
            #[cfg(feature = "serializable_server_state")]
            let now = SystemTime::now();
            if self
                .0
                .extract_if(|v, _| v.expiration() < now)
                .next()
                .is_some()
            {
                Some(self.0.entry_ref(key))
            } else if let ent @ EntryRef::Occupied(_) = self.0.entry_ref(key) {
                Some(ent)
            } else {
                None
            }
        } else {
            Some(self.0.entry_ref(key))
        }
    }
    /// [`Self::entry_ref`] except all expired ceremonies are removed in the event [`Self::max_len`] entries have
    /// been added.
    #[inline]
    pub fn entry_ref_remove_all_expired<'a, 'b, Q: Equivalent<K> + Hash + ?Sized>(
        &'a mut self,
        key: &'b Q,
    ) -> Option<EntryRef<'a, 'b, K, Q, V, S>> {
        if self.0.len() == self.1 {
            self.remove_expired_ceremonies();
        }
        if self.0.len() == self.1 {
            if let ent @ EntryRef::Occupied(_) = self.0.entry_ref(key) {
                Some(ent)
            } else {
                None
            }
        } else {
            Some(self.0.entry_ref(key))
        }
    }
}
impl<K, V, S> AsRef<HashMap<K, V, S>> for MaxLenHashMap<K, V, S> {
    #[inline]
    fn as_ref(&self) -> &HashMap<K, V, S> {
        &self.0
    }
}
impl<K, V, S> From<MaxLenHashMap<K, V, S>> for HashMap<K, V, S> {
    #[inline]
    fn from(value: MaxLenHashMap<K, V, S>) -> Self {
        value.0
    }
}
