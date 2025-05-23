use super::{super::request::TimedCeremony, BuildIdentityHasher};
#[cfg(doc)]
use core::hash::Hasher;
use core::hash::{BuildHasher, Hash};
use hashbrown::{
    Equivalent,
    hash_map::{Drain, Entry, EntryRef, ExtractIf, HashMap, IterMut, OccupiedError, ValuesMut},
};
#[cfg(not(feature = "serializable_server_state"))]
use std::time::Instant;
#[cfg(feature = "serializable_server_state")]
use std::time::SystemTime;
/// `newtype` around [`HashMap`] that has maximum [`HashMap::capacity`].
///
/// This is useful in situations when the underlying entries are expected to be removed, and one wants to ensure the
/// map does not grow unbounded. When `K` is a [`TimedCeremony`], helper methods (e.g.,
/// [`Self::insert_remove_all_expired`]) are provided that will automatically remove expired entries. Note the
/// intended use case is for `K` to be based on a server-side randomly generated value; thus the default [`Hasher`]
/// is [`BuildIdentityHasher`]. In the event this is not true, one MUST use a more appropriate `Hasher`.
///
/// Only the mutable methods of `HashMap` are re-defined in order to ensure the capacity never grows. For all
/// other methods, first call [`Self::as_ref`] or [`Self::into`].
///
/// [`Self::into`]: struct.FixedCapHashMap.html#impl-Into<U>-for-T
#[derive(Debug)]
pub struct FixedCapHashMap<K, V, S = BuildIdentityHasher>(HashMap<K, V, S>);
impl<K, V> FixedCapHashMap<K, V, BuildIdentityHasher> {
    /// [`HashMap::with_capacity_and_hasher`] using `capacity` and `BuildIdentityHasher`.
    #[inline]
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self(HashMap::with_capacity_and_hasher(
            capacity,
            BuildIdentityHasher,
        ))
    }
}
impl<K, V, S> FixedCapHashMap<K, V, S> {
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
    /// [`HashMap::with_capacity_and_hasher`].
    #[inline]
    #[must_use]
    pub fn with_hasher(capacity: usize, hasher: S) -> Self {
        Self(HashMap::with_capacity_and_hasher(capacity, hasher))
    }
    /// [`HashMap::retain`].
    #[inline]
    pub fn retain<F: FnMut(&K, &mut V) -> bool>(&mut self, f: F) {
        self.0.retain(f);
    }
}
impl<K: TimedCeremony, V, S> FixedCapHashMap<K, V, S> {
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
}
impl<K: Eq + Hash, V, S: BuildHasher> FixedCapHashMap<K, V, S> {
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
    /// [`HashMap::get_many_mut`].
    #[inline]
    pub fn get_many_mut<Q: Equivalent<K> + Hash + ?Sized, const N: usize>(
        &mut self,
        ks: [&Q; N],
    ) -> [Option<&mut V>; N] {
        self.0.get_many_mut(ks)
    }
    /// [`HashMap::get_many_key_value_mut`].
    #[inline]
    pub fn get_many_key_value_mut<Q: Equivalent<K> + Hash + ?Sized, const N: usize>(
        &mut self,
        ks: [&Q; N],
    ) -> [Option<(&K, &mut V)>; N] {
        self.0.get_many_key_value_mut(ks)
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
    /// `Ok(None)` is returned iff [`HashMap::len`] `==` [`HashMap::capacity`] and `key` does not already exist in
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
        let full = self.0.len() == self.0.capacity();
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
    /// `None` is returned iff [`HashMap::len`] `==` [`HashMap::capacity`] and `key` does not already exist in the
    /// map.
    #[inline]
    pub fn insert(&mut self, k: K, v: V) -> Option<Option<V>> {
        let full = self.0.len() == self.0.capacity();
        match self.0.entry(k) {
            Entry::Occupied(mut ent) => Some(Some(ent.insert(v))),
            Entry::Vacant(ent) => {
                if full {
                    None
                } else {
                    ent.insert(v);
                    Some(None)
                }
            }
        }
    }
    /// [`HashMap::entry`].
    ///
    /// `None` is returned iff [`HashMap::len`] `==` [`HashMap::capacity`] and `key` does not already exist in the
    /// map.
    #[inline]
    pub fn entry(&mut self, key: K) -> Option<Entry<'_, K, V, S>> {
        let full = self.0.len() == self.0.capacity();
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
    /// `None` is returned iff [`HashMap::len`] `==` [`HashMap::capacity`] and `key` does not already exist in the
    /// map.
    #[inline]
    pub fn entry_ref<'a, 'b, Q: Equivalent<K> + Hash + ?Sized>(
        &'a mut self,
        key: &'b Q,
    ) -> Option<EntryRef<'a, 'b, K, Q, V, S>> {
        let full = self.0.len() == self.0.capacity();
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
impl<K: Eq + Hash + TimedCeremony, V, S: BuildHasher> FixedCapHashMap<K, V, S> {
    /// [`Self::insert`] except the first expired ceremony is removed in the event there is no available capacity.
    #[inline]
    pub fn insert_remove_expired(&mut self, k: K, v: V) -> Option<Option<V>> {
        if self.0.len() == self.0.capacity() {
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
    /// [`Self::insert`] except all expired ceremones are removed in the event there is no available capacity.
    #[inline]
    pub fn insert_remove_all_expired(&mut self, k: K, v: V) -> Option<Option<V>> {
        if self.0.len() == self.0.capacity() {
            self.remove_expired_ceremonies();
        }
        if self.0.len() == self.0.capacity() {
            if let Entry::Occupied(mut ent) = self.0.entry(k) {
                Some(Some(ent.insert(v)))
            } else {
                None
            }
        } else {
            Some(self.0.insert(k, v))
        }
    }
    /// [`Self::entry`] except the first expired ceremony is removed in the event there is no available capacity.
    #[inline]
    pub fn entry_remove_expired(&mut self, key: K) -> Option<Entry<'_, K, V, S>> {
        if self.0.len() == self.0.capacity() {
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
    /// [`Self::entry`] except all expired ceremones are removed in the event there is no available capacity.
    #[inline]
    pub fn entry_remove_all_expired(&mut self, key: K) -> Option<Entry<'_, K, V, S>> {
        if self.0.len() == self.0.capacity() {
            self.remove_expired_ceremonies();
        }
        if self.0.len() == self.0.capacity() {
            if let ent @ Entry::Occupied(_) = self.0.entry(key) {
                Some(ent)
            } else {
                None
            }
        } else {
            Some(self.0.entry(key))
        }
    }
    /// [`Self::entry_ref`] except the first expired ceremony is removed in the event there is no available capacity.
    #[inline]
    pub fn entry_ref_remove_expired<'a, 'b, Q: Equivalent<K> + Hash + ?Sized>(
        &'a mut self,
        key: &'b Q,
    ) -> Option<EntryRef<'a, 'b, K, Q, V, S>> {
        if self.0.len() == self.0.capacity() {
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
    /// [`Self::entry_ref`] except all expired ceremones are removed in the event there is no available capacity.
    #[inline]
    pub fn entry_ref_remove_all_expired<'a, 'b, Q: Equivalent<K> + Hash + ?Sized>(
        &'a mut self,
        key: &'b Q,
    ) -> Option<EntryRef<'a, 'b, K, Q, V, S>> {
        if self.0.len() == self.0.capacity() {
            self.remove_expired_ceremonies();
        }
        if self.0.len() == self.0.capacity() {
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
impl<K, V, S> AsRef<HashMap<K, V, S>> for FixedCapHashMap<K, V, S> {
    #[inline]
    fn as_ref(&self) -> &HashMap<K, V, S> {
        &self.0
    }
}
impl<K, V, S> From<FixedCapHashMap<K, V, S>> for HashMap<K, V, S> {
    #[inline]
    fn from(value: FixedCapHashMap<K, V, S>) -> Self {
        value.0
    }
}
impl<K, V, S> From<HashMap<K, V, S>> for FixedCapHashMap<K, V, S> {
    #[inline]
    fn from(value: HashMap<K, V, S>) -> Self {
        Self(value)
    }
}
