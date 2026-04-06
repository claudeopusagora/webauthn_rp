#[cfg(test)]
mod tests;
use super::{super::request::TimedCeremony, BuildIdentityHasher};
#[cfg(doc)]
use core::hash::Hasher;
use core::hash::{BuildHasher, Hash};
use hashbrown::{
    Equivalent, TryReserveError,
    hash_map::{Drain, Entry, EntryRef, ExtractIf, HashMap, IterMut, OccupiedError, ValuesMut},
};
#[cfg(any(doc, not(feature = "serializable_server_state")))]
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
    ///
    /// `None` is returned iff at least one expired ceremony was removed; otherwise returns the earliest
    /// expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is returned instead.
    #[cfg_attr(docsrs, doc(auto_cfg = false))]
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    #[inline]
    pub fn remove_expired_ceremonies(&mut self) -> Option<Instant> {
        // Even though it's more accurate to check the current `Instant` for each ceremony, we elect to capture
        // the `Instant` we begin iteration for performance reasons. It's unlikely an appreciable amount of
        // additional ceremonies would be removed.
        let now = Instant::now();
        let mut some = true;
        let mut expiry_min = None;
        self.retain(|k, _| {
            let expiry = k.expiration();
            if expiry >= now {
                match expiry_min {
                    None => expiry_min = Some(expiry),
                    Some(ref mut e) if expiry < *e => *e = expiry,
                    _ => {}
                }
                true
            } else {
                some = false;
                false
            }
        });
        if some { expiry_min } else { None }
    }
    /// Removes all expired ceremonies.
    ///
    /// `None` is returned iff at least one expired ceremony was removed; otherwise returns the earliest
    /// expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is returned instead.
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    #[inline]
    pub fn remove_expired_ceremonies(&mut self) -> Option<SystemTime> {
        // Even though it's more accurate to check the current `SystemTime` for each ceremony, we elect to capture
        // the `SystemTime` we begin iteration for performance reasons. It's unlikely an appreciable amount of
        // additional ceremonies would be removed.
        let now = SystemTime::now();
        let mut some = true;
        let mut expiry_min = None;
        self.retain(|k, _| {
            let expiry = k.expiration();
            if expiry >= now {
                match expiry_min {
                    None => expiry_min = Some(expiry),
                    Some(ref mut e) if expiry < *e => *e = expiry,
                    _ => {}
                }
                true
            } else {
                some = false;
                false
            }
        });
        if some { expiry_min } else { None }
    }
    /// Removes the first encountered expired ceremony.
    ///
    /// `None` is returned iff an expired ceremony was removed; otherwise returns the earliest
    /// expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is returned instead.
    #[cfg_attr(docsrs, doc(auto_cfg = false))]
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    #[inline]
    pub fn remove_first_expired_ceremony(&mut self) -> Option<Instant> {
        // Even though it's more accurate to check the current `Instant` for each ceremony, we elect to capture
        // the `Instant` we begin iteration for performance reasons. It's unlikely an appreciable amount of
        // additional ceremonies would be removed.
        let now = Instant::now();
        let mut expiry_min = None;
        self.0
            .extract_if(|k, _| {
                let expiry = k.expiration();
                if expiry < now {
                    true
                } else {
                    match expiry_min {
                        None => expiry_min = Some(expiry),
                        Some(ref mut e) if expiry < *e => *e = expiry,
                        _ => {}
                    }
                    false
                }
            })
            .next()
            .map_or(expiry_min, |_| None)
    }
    /// Removes the first encountered expired ceremony.
    ///
    /// `None` is returned iff an expired ceremony was removed; otherwise returns the earliest
    /// expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is returned instead.
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    #[inline]
    pub fn remove_first_expired_ceremony(&mut self) -> Option<SystemTime> {
        // Even though it's more accurate to check the current `SystemTime` for each ceremony, we elect to capture
        // the `SystemTime` we begin iteration for performance reasons. It's unlikely an appreciable amount of
        // additional ceremonies would be removed.
        let now = SystemTime::now();
        let mut expiry_min = None;
        self.0
            .extract_if(|k, _| {
                let expiry = k.expiration();
                if expiry < now {
                    true
                } else {
                    match expiry_min {
                        None => expiry_min = Some(expiry),
                        Some(ref mut e) if expiry < *e => *e = expiry,
                        _ => {}
                    }
                    false
                }
            })
            .next()
            .map_or(expiry_min, |_| None)
    }
}
/// Signifies the consequences of [`MaxLenHashMap::insert`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Insert<V> {
    /// The entry was successfully inserted.
    Success,
    /// The value replaced the contained value.
    Previous(V),
    /// The key does not exist, but there was no available capacity to insert the entry.
    CapacityFull,
}
/// Error returned from [`MaxLenHashMap::try_insert`].
#[derive(Debug)]
pub enum FullCapOccupiedErr<'a, K, V, S> {
    /// Error when the key already exists.
    Occupied(OccupiedError<'a, K, V, S>),
    /// Error when there is no available capacity and the key does not exist.
    CapacityFull,
}
/// Error returned from [`MaxLenHashMap::try_insert_remove_expired`] and
/// [`MaxLenHashMap::try_insert_remove_all_expired`].
#[derive(Debug)]
pub enum FullCapRemoveExpiredOccupiedErr<'a, K, V, S> {
    /// Error when the key already exists.
    Occupied(OccupiedError<'a, K, V, S>),
    /// Error when there was is no available capacity to insert the entry and no expired
    /// [`TimedCeremony`]s could be removed.
    ///
    /// The contained `Instant` is the earliest expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is contained instead.
    #[cfg_attr(docsrs, doc(auto_cfg = false))]
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    CapacityFull(Instant),
    /// Error when there was is no available capacity to insert the entry and no expired
    /// [`TimedCeremony`]s could be removed.
    ///
    /// The contained `Instant` is the earliest expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is contained instead.
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    CapacityFull(SystemTime),
}
/// Signifies the consequences of [`MaxLenHashMap::insert_remove_expired`] and
/// [`MaxLenHashMap::insert_remove_all_expired`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertRemoveExpired<V> {
    /// The entry was successfully inserted.
    Success,
    /// The value replaced the contained value.
    Previous(V),
    /// The key does not exist, but there was no available capacity to insert the entry and no expired
    /// [`TimedCeremony`]s could be removed.
    ///
    /// The contained `Instant` is the earliest expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is contained instead.
    #[cfg_attr(docsrs, doc(auto_cfg = false))]
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    CapacityFull(Instant),
    /// The value does not exist, but there was no available capacity to insert it and no expired
    /// [`TimedCeremony`]s that could be removed.
    ///
    /// The contained `Instant` is the earliest expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is contained instead.
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    CapacityFull(SystemTime),
}
/// Signifies the consequences of [`MaxLenHashMap::entry`] and [`MaxLenHashMap::entry_ref`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryStatus<E> {
    /// The entry was successfully grabbed.
    Success(E),
    /// The capacity was full, and there was no value where the entry would be.
    CapacityFull,
}
/// Signifies the consequences of [`MaxLenHashMap::entry_remove_expired`] and
/// [`MaxLenHashMap::entry_remove_all_expired`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryStatusRemoveExpired<E> {
    /// The entry was successfully grabbed.
    Success(E),
    /// The capacity was full, and there was no value where the entry would be.
    ///
    /// The contained `Instant` is the earliest expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is contained instead.
    #[cfg_attr(docsrs, doc(auto_cfg = false))]
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    CapacityFull(Instant),
    /// The capacity was full, and there was no value where the entry would be.
    ///
    /// The contained `Instant` is the earliest expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is contained instead.
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    CapacityFull(SystemTime),
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
    /// # Errors
    ///
    /// Errors iff [`HashMap::try_insert`] does or there is no available capacity to insert the entry.
    #[inline]
    pub fn try_insert(
        &mut self,
        key: K,
        value: V,
    ) -> Result<&mut V, FullCapOccupiedErr<'_, K, V, S>> {
        let full = self.0.len() == self.1;
        match self.0.entry(key) {
            Entry::Occupied(entry) => {
                Err(FullCapOccupiedErr::Occupied(OccupiedError { entry, value }))
            }
            Entry::Vacant(ent) => {
                if full {
                    Err(FullCapOccupiedErr::CapacityFull)
                } else {
                    Ok(ent.insert(value))
                }
            }
        }
    }
    /// [`HashMap::insert`].
    #[inline]
    pub fn insert(&mut self, k: K, v: V) -> Insert<V> {
        let full = self.0.len() == self.1;
        match self.0.entry(k) {
            Entry::Occupied(mut ent) => Insert::Previous(ent.insert(v)),
            Entry::Vacant(ent) => {
                if full {
                    Insert::CapacityFull
                } else {
                    _ = ent.insert(v);
                    Insert::Success
                }
            }
        }
    }
    /// [`HashMap::entry`].
    #[inline]
    pub fn entry(&mut self, key: K) -> EntryStatus<Entry<'_, K, V, S>> {
        let full = self.0.len() == self.1;
        match self.0.entry(key) {
            ent @ Entry::Occupied(_) => EntryStatus::Success(ent),
            ent @ Entry::Vacant(_) => {
                if full {
                    EntryStatus::CapacityFull
                } else {
                    EntryStatus::Success(ent)
                }
            }
        }
    }
    /// [`HashMap::entry_ref`].
    #[inline]
    pub fn entry_ref<'a, 'b, Q: Equivalent<K> + Hash + ?Sized>(
        &'a mut self,
        key: &'b Q,
    ) -> EntryStatus<EntryRef<'a, 'b, K, Q, V, S>> {
        let full = self.0.len() == self.1;
        match self.0.entry_ref(key) {
            ent @ EntryRef::Occupied(_) => EntryStatus::Success(ent),
            ent @ EntryRef::Vacant(_) => {
                if full {
                    EntryStatus::CapacityFull
                } else {
                    EntryStatus::Success(ent)
                }
            }
        }
    }
}
impl<K: Eq + Hash + TimedCeremony, V, S: BuildHasher> MaxLenHashMap<K, V, S> {
    /// [`Self::try_insert`] except the first encountered expired ceremony is removed in the event [`Self::max_len`]
    /// entries have been added.
    ///
    /// # Errors
    ///
    /// Errors iff [`HashMap::try_insert`] does after removing the first expired ceremony.
    #[inline]
    pub fn try_insert_remove_expired(
        &mut self,
        key: K,
        value: V,
    ) -> Result<&mut V, FullCapRemoveExpiredOccupiedErr<'_, K, V, S>> {
        if self.0.len() == self.1 {
            match self.remove_first_expired_ceremony() {
                None => self
                    .0
                    .try_insert(key, value)
                    .map_err(FullCapRemoveExpiredOccupiedErr::Occupied),
                Some(exp) => {
                    if let Entry::Occupied(entry) = self.0.entry(key) {
                        Err(FullCapRemoveExpiredOccupiedErr::Occupied(OccupiedError {
                            entry,
                            value,
                        }))
                    } else {
                        Err(FullCapRemoveExpiredOccupiedErr::CapacityFull(exp))
                    }
                }
            }
        } else {
            self.0
                .try_insert(key, value)
                .map_err(FullCapRemoveExpiredOccupiedErr::Occupied)
        }
    }
    /// [`Self::try_insert`] except all expired ceremonies are removed in the event [`Self::max_len`] entries have
    /// been added.
    ///
    /// # Errors
    ///
    /// Errors iff [`HashMap::try_insert`] does after removing all expired ceremonies.
    #[inline]
    pub fn try_insert_remove_all_expired(
        &mut self,
        key: K,
        value: V,
    ) -> Result<&mut V, FullCapRemoveExpiredOccupiedErr<'_, K, V, S>> {
        if self.0.len() == self.1 {
            match self.remove_expired_ceremonies() {
                None => self
                    .0
                    .try_insert(key, value)
                    .map_err(FullCapRemoveExpiredOccupiedErr::Occupied),
                Some(exp) => {
                    if let Entry::Occupied(entry) = self.0.entry(key) {
                        Err(FullCapRemoveExpiredOccupiedErr::Occupied(OccupiedError {
                            entry,
                            value,
                        }))
                    } else {
                        Err(FullCapRemoveExpiredOccupiedErr::CapacityFull(exp))
                    }
                }
            }
        } else {
            self.0
                .try_insert(key, value)
                .map_err(FullCapRemoveExpiredOccupiedErr::Occupied)
        }
    }
    /// [`Self::insert`] except the first encountered expired ceremony is removed in the event [`Self::max_len`]
    /// entries have been added.
    #[inline]
    pub fn insert_remove_expired(&mut self, k: K, v: V) -> InsertRemoveExpired<V> {
        if self.0.len() == self.1 {
            match self.remove_first_expired_ceremony() {
                None => self.0.insert(k, v).map_or_else(
                    || InsertRemoveExpired::Success,
                    InsertRemoveExpired::Previous,
                ),
                Some(exp) => {
                    if let Entry::Occupied(mut ent) = self.0.entry(k) {
                        InsertRemoveExpired::Previous(ent.insert(v))
                    } else {
                        InsertRemoveExpired::CapacityFull(exp)
                    }
                }
            }
        } else {
            self.0.insert(k, v).map_or_else(
                || InsertRemoveExpired::Success,
                InsertRemoveExpired::Previous,
            )
        }
    }
    /// [`Self::insert`] except all expired ceremonies are removed in the event [`Self::max_len`] entries have
    /// been added.
    #[inline]
    pub fn insert_remove_all_expired(&mut self, k: K, v: V) -> InsertRemoveExpired<V> {
        if self.0.len() == self.1 {
            match self.remove_expired_ceremonies() {
                None => self.0.insert(k, v).map_or_else(
                    || InsertRemoveExpired::Success,
                    InsertRemoveExpired::Previous,
                ),
                Some(exp) => {
                    if let Entry::Occupied(mut ent) = self.0.entry(k) {
                        InsertRemoveExpired::Previous(ent.insert(v))
                    } else {
                        InsertRemoveExpired::CapacityFull(exp)
                    }
                }
            }
        } else {
            self.0.insert(k, v).map_or_else(
                || InsertRemoveExpired::Success,
                InsertRemoveExpired::Previous,
            )
        }
    }
    /// [`Self::entry`] except the first encountered expired ceremony is removed in the event [`Self::max_len`]
    /// entries have been added.
    #[inline]
    pub fn entry_remove_expired(&mut self, key: K) -> EntryStatusRemoveExpired<Entry<'_, K, V, S>> {
        if self.0.len() == self.1 {
            match self.remove_first_expired_ceremony() {
                None => EntryStatusRemoveExpired::Success(self.0.entry(key)),
                Some(exp) => {
                    if let ent @ Entry::Occupied(_) = self.0.entry(key) {
                        EntryStatusRemoveExpired::Success(ent)
                    } else {
                        EntryStatusRemoveExpired::CapacityFull(exp)
                    }
                }
            }
        } else {
            EntryStatusRemoveExpired::Success(self.0.entry(key))
        }
    }
    /// [`Self::entry`] except all expired ceremonies are removed in the event [`Self::max_len`] entries have
    /// been added.
    #[inline]
    pub fn entry_remove_all_expired(
        &mut self,
        key: K,
    ) -> EntryStatusRemoveExpired<Entry<'_, K, V, S>> {
        if self.0.len() == self.1 {
            match self.remove_expired_ceremonies() {
                None => EntryStatusRemoveExpired::Success(self.0.entry(key)),
                Some(exp) => {
                    if let ent @ Entry::Occupied(_) = self.0.entry(key) {
                        EntryStatusRemoveExpired::Success(ent)
                    } else {
                        EntryStatusRemoveExpired::CapacityFull(exp)
                    }
                }
            }
        } else {
            EntryStatusRemoveExpired::Success(self.0.entry(key))
        }
    }
    /// [`Self::entry_ref`] except the first encoutered expired ceremony is removed in the event [`Self::max_len`]
    /// entries have been added.
    #[inline]
    pub fn entry_ref_remove_expired<'a, 'b, Q: Equivalent<K> + Hash + ?Sized>(
        &'a mut self,
        key: &'b Q,
    ) -> EntryStatusRemoveExpired<EntryRef<'a, 'b, K, Q, V, S>> {
        if self.0.len() == self.1 {
            match self.remove_first_expired_ceremony() {
                None => EntryStatusRemoveExpired::Success(self.0.entry_ref(key)),
                Some(exp) => {
                    if let ent @ EntryRef::Occupied(_) = self.0.entry_ref(key) {
                        EntryStatusRemoveExpired::Success(ent)
                    } else {
                        EntryStatusRemoveExpired::CapacityFull(exp)
                    }
                }
            }
        } else {
            EntryStatusRemoveExpired::Success(self.0.entry_ref(key))
        }
    }
    /// [`Self::entry_ref`] except all expired ceremonies are removed in the event [`Self::max_len`] entries have
    /// been added.
    #[inline]
    pub fn entry_ref_remove_all_expired<'a, 'b, Q: Equivalent<K> + Hash + ?Sized>(
        &'a mut self,
        key: &'b Q,
    ) -> EntryStatusRemoveExpired<EntryRef<'a, 'b, K, Q, V, S>> {
        if self.0.len() == self.1 {
            match self.remove_expired_ceremonies() {
                None => EntryStatusRemoveExpired::Success(self.0.entry_ref(key)),
                Some(exp) => {
                    if let ent @ EntryRef::Occupied(_) = self.0.entry_ref(key) {
                        EntryStatusRemoveExpired::Success(ent)
                    } else {
                        EntryStatusRemoveExpired::CapacityFull(exp)
                    }
                }
            }
        } else {
            EntryStatusRemoveExpired::Success(self.0.entry_ref(key))
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
