#[cfg(doc)]
use super::{
    hash::hash_set::MaxLenHashSet,
    request::{
        Challenge,
        auth::{
            DiscoverableAuthenticationServerState, DiscoverableCredentialRequestOptions,
            NonDiscoverableAuthenticationServerState, NonDiscoverableCredentialRequestOptions,
        },
        register::{CredentialCreationOptions, RegistrationServerState},
    },
};
use core::hash::{BuildHasher, Hasher};
pub use hashbrown;
/// Hash map with an immutable maximum length that allocates exactly once.
pub mod hash_map;
/// Hash set with an immutable maximum length that allocates exactly once.
pub mod hash_set;
/// [`Hasher`] whose `write_*` methods simply store up to 64 bits of the passed argument _as is_ overwriting
/// any previous state.
///
/// This is designed to only be used indirectly via a hash map whose keys are randomly generated on the server
/// based on at least 64 bits—the size of the integer returned from [`Self::finish`]—of entropy.
/// This makes this `Hasher` usable (and ideal) in only the most niche circumstances.
///
/// [`RegistrationServerState`], [`DiscoverableAuthenticationServerState`], and
/// [`NonDiscoverableAuthenticationServerState`] implement [`Hash`] by simply writing the
/// contained [`Challenge`]; thus when they are stored in a hashed collection (e.g., [`MaxLenHashSet`]), one can
/// optimize without fear by using this `Hasher` since `Challenge`s are immutable and can only ever be created on
/// the server via [`Challenge::new`] (and equivalently [`Challenge::default`]). `RegistrationServerState`,
/// `DiscoverableAuthenticationServerState`, and `NonDiscoverableAuthenticationServerState` are also immutable and
/// only constructable via [`CredentialCreationOptions::start_ceremony`],
/// [`DiscoverableCredentialRequestOptions::start_ceremony`], and
/// [`NonDiscoverableCredentialRequestOptions::start_ceremony`] respectively. Since `Challenge` is already based on
/// a random `u128`, other `Hasher`s will be slower and likely produce lower-quality hashes (and never
/// higher quality).
#[derive(Clone, Copy, Debug, Default)]
pub struct IdentityHasher(u64);
// Note it is _not_ required for `write_*` methods to do the same thing as other `write_*` methods
// (e.g., `Self::write_u64` may not be the same thing as 8 calls to `Self::write_u8`).
impl Hasher for IdentityHasher {
    /// Returns `0` if no `write_*` calls have been made; otherwise returns the result of the most recent
    /// `write_*` call.
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }
    /// Writes `i` to `self`.
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.0 = i;
    }
    /// Sign-extends `i` to a [`u64`] before redirecting to [`Self::write_u64`].
    #[expect(
        clippy::as_conversions,
        clippy::cast_sign_loss,
        reason = "we simply need to convert into a u64 in a deterministic way"
    )]
    #[inline]
    fn write_i8(&mut self, i: i8) {
        self.write_u64(i as u64);
    }
    /// Sign-extends `i` to a [`u64`] before redirecting to [`Self::write_u64`].
    #[expect(
        clippy::as_conversions,
        clippy::cast_sign_loss,
        reason = "we simply need to convert into a u64 in a deterministic way"
    )]
    #[inline]
    fn write_i16(&mut self, i: i16) {
        self.write_u64(i as u64);
    }
    /// Sign-extends `i` to a [`u64`] before redirecting to [`Self::write_u64`].
    #[expect(
        clippy::as_conversions,
        clippy::cast_sign_loss,
        reason = "we simply need to convert into a u64 in a deterministic way"
    )]
    #[inline]
    fn write_i32(&mut self, i: i32) {
        self.write_u64(i as u64);
    }
    /// Redirects to [`Self::write_u64`].
    #[expect(
        clippy::as_conversions,
        clippy::cast_sign_loss,
        reason = "we simply need to convert into a u64 in a deterministic way"
    )]
    #[inline]
    fn write_i64(&mut self, i: i64) {
        self.write_u64(i as u64);
    }
    /// Truncates `i` to a [`u64`] before redirecting to [`Self::write_u64`].
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "we simply need to convert into a u64 in a deterministic way"
    )]
    #[inline]
    fn write_i128(&mut self, i: i128) {
        self.write_u64(i as u64);
    }
    /// Redirects to [`Self::write_u64`] on 64-bit platforms.
    /// Sign-extends `i` to a [`u64`] before redirecting to [`Self::write_u64`] on platforms of less than 64 bits.
    /// Truncates `i` to a [`u64`] before redirecting to [`Self::write_u64`] on platforms of more than 64 bits.
    #[expect(
        clippy::as_conversions,
        clippy::cast_sign_loss,
        reason = "we simply need to convert into a u64 in a deterministic way"
    )]
    #[inline]
    fn write_isize(&mut self, i: isize) {
        self.write_u64(i as u64);
    }
    /// Zero-extends `i` to a [`u64`] before redirecting to [`Self::write_u64`].
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.write_u64(u64::from(i));
    }
    /// Zero-extends `i` to a [`u64`] before redirecting to [`Self::write_u64`].
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.write_u64(u64::from(i));
    }
    /// Zero-extends `i` to a [`u64`] before redirecting to [`Self::write_u64`].
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.write_u64(u64::from(i));
    }
    /// Truncates `i` to a [`u64`] before redirecting to [`Self::write_u64`].
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "we simply need to convert into a u64 in a deterministic way"
    )]
    #[inline]
    fn write_u128(&mut self, i: u128) {
        self.write_u64(i as u64);
    }
    /// Redirects to [`Self::write_u64`] on 64-bit platforms.
    /// Zero-extends `i` to a [`u64`] before redirecting to [`Self::write_u64`] on platforms of less than 64 bits.
    /// Truncates `i` to a [`u64`] before redirecting to [`Self::write_u64`] on platforms of more than 64 bits.
    #[expect(
        clippy::as_conversions,
        reason = "we simply need to convert into a u64 in a deterministic way"
    )]
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }
    /// This does nothing iff `bytes.len() < 8`; otherwise the first 8 bytes are converted
    /// to a [`u64`] that is written via [`Self::write_u64`];
    #[expect(clippy::host_endian_bytes, reason = "endianness does not matter")]
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if let Some(data) = bytes.get(..8) {
            let mut val = [0; 8];
            val.copy_from_slice(data);
            self.write_u64(u64::from_ne_bytes(val));
        }
    }
}
/// [`BuildHasher`] of an [`IdentityHasher`].
///
/// This MUST only be used with hash maps with keys that are randomly generated on the server based on at least 64
/// bits of entropy.
#[derive(Clone, Copy, Debug, Default)]
pub struct BuildIdentityHasher;
impl BuildHasher for BuildIdentityHasher {
    type Hasher = IdentityHasher;
    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        IdentityHasher(0)
    }
}
