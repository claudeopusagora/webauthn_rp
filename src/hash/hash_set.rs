#[cfg(test)]
mod tests;
use super::{super::request::TimedCeremony, BuildIdentityHasher};
#[cfg(doc)]
use core::hash::Hasher;
use core::hash::{BuildHasher, Hash};
use hashbrown::{
    Equivalent, TryReserveError,
    hash_set::{Drain, Entry, ExtractIf, HashSet},
};
#[cfg(any(doc, not(feature = "serializable_server_state")))]
use std::time::Instant;
#[cfg(feature = "serializable_server_state")]
use std::time::SystemTime;
/// [`HashSet`] that has maximum [`HashSet::capacity`] and length and allocates exactly once.
///
/// Note due to how `HashSet` removes values, it's possible to insert a value after removing a value and cause
/// a new allocation. To avoid this, we ensure that the allocated capacity is at least twice the size of
/// the requested maximum length.
///
/// This is useful in situations when the underlying values are expected to be removed, and one wants to ensure the
/// set does not grow unbounded. When `T` is a [`TimedCeremony`], helper methods (e.g.,
/// [`Self::insert_remove_all_expired`]) are provided that will automatically remove expired values. Note the
/// intended use case is for `T` to be based on a server-side randomly generated value; thus the default [`Hasher`]
/// is [`BuildIdentityHasher`]. In the event this is not true, one MUST use a more appropriate `Hasher`.
///
/// Only the mutable methods of `HashSet` are re-defined in order to ensure [`Self::max_len`] is never exceeded.
/// For all other methods, first call [`Self::as_ref`] or [`Self::into`].
///
/// [`Self::into`]: struct.MaxLenHashSet.html#impl-Into<U>-for-T
#[derive(Debug)]
pub struct MaxLenHashSet<T, S = BuildIdentityHasher>(HashSet<T, S>, usize);
impl<T> MaxLenHashSet<T, BuildIdentityHasher> {
    /// [`HashSet::with_capacity_and_hasher`] using `2 * max_len` and `BuildIdentityHasher`.
    ///
    /// Note since the actual capacity allocated may exceed the requested capacity, [`Self::max_len`] may exceed
    /// `max_len`.
    ///
    /// # Panics
    ///
    /// `panic`s if `max_len > usize::MAX / 2`. Note since [`HashSet::with_capacity_and_hasher`] `panic`s
    /// for much smaller values than `usize::MAX / 2`—even when `T` is a zero-sized type (ZST)—this is not an
    /// additional `panic` than what would already occur. The only difference is the message reported.
    #[inline]
    #[must_use]
    pub fn new(max_len: usize) -> Self {
        Self::with_hasher(max_len, BuildIdentityHasher)
    }
}
impl<T, S> MaxLenHashSet<T, S> {
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
    /// [`HashSet::with_capacity_and_hasher`] using `2 * max_len` and `hasher`.
    ///
    /// Note since the actual capacity allocated may exceed the requested capacity, [`Self::max_len`] may exceed
    /// `max_len`.
    ///
    /// # Panics
    ///
    /// `panic`s if `max_len > usize::MAX / 2`. Note since [`HashSet::with_capacity_and_hasher`] `panic`s
    /// for much smaller values than `usize::MAX / 2`—even when `T` is a zero-sized type (ZST)—this is not an
    /// additional `panic` than what would already occur. The only difference is the message reported.
    #[expect(
        clippy::expect_used,
        reason = "purpose of this function is to panic if the hash set cannot be allocated"
    )]
    #[inline]
    #[must_use]
    pub fn with_hasher(max_len: usize, hasher: S) -> Self {
        let set = HashSet::with_capacity_and_hasher(Self::requested_capacity(max_len).expect("HashSet::with_hasher must be passed a maximum length that does not exceed usize::MAX / 2"), hasher);
        let len = set.capacity() >> 1u8;
        Self(set, len)
    }
    /// [`HashSet::retain`].
    #[inline]
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, f: F) {
        self.0.retain(f);
    }
}
impl<T: TimedCeremony, S> MaxLenHashSet<T, S> {
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
        self.retain(|v| {
            let expiry = v.expiration();
            if expiry >= now {
                match expiry_min {
                    None => expiry_min = Some(expiry),
                    Some(ref mut e) if expiry < *e => *e = expiry,
                    _ => (),
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
        self.retain(|v| {
            let expiry = v.expiration();
            if expiry >= now {
                match expiry_min {
                    None => expiry_min = Some(expiry),
                    Some(ref mut e) if expiry < *e => *e = expiry,
                    _ => (),
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
            .extract_if(|v| {
                let expiry = v.expiration();
                if expiry < now {
                    true
                } else {
                    match expiry_min {
                        None => expiry_min = Some(expiry),
                        Some(ref mut e) if expiry < *e => *e = expiry,
                        _ => (),
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
            .extract_if(|v| {
                let expiry = v.expiration();
                if expiry < now {
                    true
                } else {
                    match expiry_min {
                        None => expiry_min = Some(expiry),
                        Some(ref mut e) if expiry < *e => *e = expiry,
                        _ => (),
                    }
                    false
                }
            })
            .next()
            .map_or(expiry_min, |_| None)
    }
}
/// Signifies the consequences of [`MaxLenHashSet::insert`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Insert {
    /// The value was successfully inserted.
    Success,
    /// The value was not inserted since it already existed.
    Duplicate,
    /// The value does not exist, but there was no available capacity to insert it.
    CapacityFull,
}
/// Signifies the consequences of [`MaxLenHashSet::replace`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Replace<T> {
    /// The value was inserted.
    Insert,
    /// The value replaced the contained value.
    Previous(T),
    /// The value does not exist, but there was no available capacity to insert it.
    CapacityFull,
}
/// Signifies the consequences of [`MaxLenHashSet::insert_remove_expired`] and
/// [`MaxLenHashSet::insert_remove_all_expired`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertRemoveExpired {
    /// The value was successfully inserted.
    Success,
    /// The value was not inserted since it already existed.
    Duplicate,
    /// The value does not exist, but there was no available capacity to insert it and no expired
    /// [`TimedCeremony`]s that could be removed.
    ///
    /// The contained `Instant` is the earliest expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is contained instead.
    #[cfg_attr(docsrs, doc(auto_cfg = false))]
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    CapacityFull(Instant),
    /// The value does not exist, but there was no available capacity to insert it and no expired
    /// [`TimedCeremony`]s could be removed.
    ///
    /// The contained `Instant` is the earliest expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is contained instead.
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    CapacityFull(SystemTime),
}
/// Signifies the consequences of [`MaxLenHashSet::entry`].
#[derive(Debug)]
pub enum EntryStatus<'a, T, S> {
    /// The `Entry` was successfully grabbed.
    Success(Entry<'a, T, S>),
    /// The capacity was full, and there was no value where the `Entry` would be.
    CapacityFull,
}
/// Signifies the consequences of [`MaxLenHashSet::entry_remove_expired`] and
/// [`MaxLenHashSet::entry_remove_all_expired`].
#[derive(Debug)]
pub enum EntryStatusRemoveExpired<'a, T, S> {
    /// The `Entry` was successfully grabbed.
    Success(Entry<'a, T, S>),
    /// The capacity was full, and there was no value where the `Entry` would be.
    ///
    /// The contained `Instant` is the earliest expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is contained instead.
    #[cfg_attr(docsrs, doc(auto_cfg = false))]
    #[cfg(any(doc, not(feature = "serializable_server_state")))]
    CapacityFull(Instant),
    /// The capacity was full, and there was no value where the `Entry` would be.
    ///
    /// The contained `Instant` is the earliest expiration.
    ///
    /// Note when `serializable_server_state` is enabled, [`SystemTime`] is contained instead.
    #[cfg(all(not(doc), feature = "serializable_server_state"))]
    CapacityFull(SystemTime),
}
impl<T: Eq + Hash, S: BuildHasher> MaxLenHashSet<T, S> {
    /// [`HashSet::with_hasher`] using `hasher` followed by [`HashSet::try_reserve`] using `2 * max_len`.
    ///
    /// Note since the actual capacity allocated may exceed the requested capacity, [`Self::max_len`] may exceed
    /// `max_len`.
    ///
    /// # Errors
    ///
    /// Errors iff `max_len > usize::MAX / 2` or [`HashSet::try_reserve`] does.
    #[inline]
    pub fn try_with_hasher(max_len: usize, hasher: S) -> Result<Self, TryReserveError> {
        Self::requested_capacity(max_len).and_then(|additional| {
            let mut set = HashSet::with_hasher(hasher);
            set.try_reserve(additional).map(|()| {
                let len = set.capacity() >> 1u8;
                Self(set, len)
            })
        })
    }
    /// [`HashSet::get_or_insert`].
    ///
    /// `None` is returned iff [`HashSet::len`] `==` [`Self::max_len`] and `value` does not already exist in the
    /// set.
    #[inline]
    pub fn get_or_insert(&mut self, value: T) -> Option<&T> {
        if self.0.len() == self.1 {
            self.0.get(&value)
        } else {
            Some(self.0.get_or_insert(value))
        }
    }
    /// [`HashSet::get_or_insert_with`].
    ///
    /// `None` is returned iff [`HashSet::len`] `==` [`Self::max_len`] and `value` does not already exist in the
    /// set.
    #[inline]
    pub fn get_or_insert_with<Q: Equivalent<T> + Hash + ?Sized, F: FnOnce(&Q) -> T>(
        &mut self,
        value: &Q,
        f: F,
    ) -> Option<&T> {
        if self.0.len() == self.1 {
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
    #[inline]
    pub fn insert(&mut self, value: T) -> Insert {
        let full = self.0.len() == self.1;
        if let Entry::Vacant(ent) = self.0.entry(value) {
            if full {
                Insert::CapacityFull
            } else {
                _ = ent.insert();
                Insert::Success
            }
        } else {
            Insert::Duplicate
        }
    }
    /// [`HashSet::replace`].
    #[expect(clippy::unreachable, reason = "want to crash when there is a bug")]
    #[inline]
    pub fn replace(&mut self, value: T) -> Replace<T> {
        // Ideally we would use the Entry API to avoid searching multiple times, but one can't while also using
        // `replace` since there is no `OccupiedEntry::replace`.
        if self.0.contains(&value) {
            Replace::Previous(
                self.0
                    .replace(value)
                    .unwrap_or_else(|| unreachable!("there is a bug in HashSet::replace")),
            )
        } else if self.0.len() == self.1 {
            Replace::CapacityFull
        } else {
            _ = self.0.insert(value);
            Replace::Insert
        }
    }
    /// [`HashSet::entry`].
    #[inline]
    pub fn entry(&mut self, value: T) -> EntryStatus<'_, T, S> {
        let full = self.0.len() == self.1;
        match self.0.entry(value) {
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
}
impl<T: Eq + Hash + TimedCeremony, S: BuildHasher> MaxLenHashSet<T, S> {
    /// [`Self::insert`] except the first encountered expired ceremony is removed in the event [`Self::max_len`]
    /// items have been added.
    #[inline]
    pub fn insert_remove_expired(&mut self, value: T) -> InsertRemoveExpired {
        if self.0.len() == self.1 {
            match self.remove_first_expired_ceremony() {
                None => {
                    if self.0.insert(value) {
                        InsertRemoveExpired::Success
                    } else {
                        InsertRemoveExpired::Duplicate
                    }
                }
                Some(exp) => {
                    if self.0.contains(&value) {
                        InsertRemoveExpired::Duplicate
                    } else {
                        InsertRemoveExpired::CapacityFull(exp)
                    }
                }
            }
        } else if self.0.insert(value) {
            InsertRemoveExpired::Success
        } else {
            InsertRemoveExpired::Duplicate
        }
    }
    /// [`Self::insert`] except all expired ceremones are removed in the event [`Self::max_len`] items have
    /// been added.
    #[inline]
    pub fn insert_remove_all_expired(&mut self, value: T) -> InsertRemoveExpired {
        if self.0.len() == self.1 {
            match self.remove_expired_ceremonies() {
                None => {
                    if self.0.insert(value) {
                        InsertRemoveExpired::Success
                    } else {
                        InsertRemoveExpired::Duplicate
                    }
                }
                Some(exp) => {
                    if self.0.contains(&value) {
                        InsertRemoveExpired::Duplicate
                    } else {
                        InsertRemoveExpired::CapacityFull(exp)
                    }
                }
            }
        } else if self.0.insert(value) {
            InsertRemoveExpired::Success
        } else {
            InsertRemoveExpired::Duplicate
        }
    }
    /// [`Self::entry`] except the first encountered expired ceremony is removed in the event [`Self::max_len`]
    /// items have been added.
    #[inline]
    pub fn entry_remove_expired(&mut self, value: T) -> EntryStatusRemoveExpired<'_, T, S> {
        if self.0.len() == self.1 {
            match self.remove_first_expired_ceremony() {
                None => EntryStatusRemoveExpired::Success(self.0.entry(value)),
                Some(exp) => {
                    if let ent @ Entry::Occupied(_) = self.0.entry(value) {
                        EntryStatusRemoveExpired::Success(ent)
                    } else {
                        EntryStatusRemoveExpired::CapacityFull(exp)
                    }
                }
            }
        } else {
            EntryStatusRemoveExpired::Success(self.0.entry(value))
        }
    }
    /// [`Self::entry`] except all expired ceremones are removed in the event [`Self::max_len`] items have
    /// been added.
    #[inline]
    pub fn entry_remove_all_expired(&mut self, value: T) -> EntryStatusRemoveExpired<'_, T, S> {
        if self.0.len() == self.1 {
            match self.remove_expired_ceremonies() {
                None => EntryStatusRemoveExpired::Success(self.0.entry(value)),
                Some(exp) => {
                    if let ent @ Entry::Occupied(_) = self.0.entry(value) {
                        EntryStatusRemoveExpired::Success(ent)
                    } else {
                        EntryStatusRemoveExpired::CapacityFull(exp)
                    }
                }
            }
        } else {
            EntryStatusRemoveExpired::Success(self.0.entry(value))
        }
    }
}
impl<T, S> AsRef<HashSet<T, S>> for MaxLenHashSet<T, S> {
    #[inline]
    fn as_ref(&self) -> &HashSet<T, S> {
        &self.0
    }
}
impl<T, S> From<MaxLenHashSet<T, S>> for HashSet<T, S> {
    #[inline]
    fn from(value: MaxLenHashSet<T, S>) -> Self {
        value.0
    }
}
