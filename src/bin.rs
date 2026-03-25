extern crate alloc;
use alloc::borrow::Cow;
use core::str;
/// Unit error returned from [`Encode::encode_into_buffer`] and
/// [`Decode::decode_from_buffer`] to simply signal an error occurred.
pub(super) struct EncDecErr;
/// Encodes data as a binary format into a passed `Vec` buffer with the possibility
/// of erring.
pub(super) trait EncodeBufferFallible {
    /// Error when [`Self::encode_into_buffer`] fails.
    type Err;
    /// Writes `self` into `buffer`.
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err>;
}
/// Encodes data as a binary format into a passed `Vec` buffer.
pub(super) trait EncodeBuffer {
    /// Writes `self` into `buffer`.
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>);
}
impl EncodeBuffer for u8 {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.push(*self);
    }
}
impl EncodeBuffer for u16 {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.to_le_bytes().as_slice());
    }
}
impl EncodeBuffer for u32 {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.to_le_bytes().as_slice());
    }
}
impl EncodeBuffer for u64 {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.to_le_bytes().as_slice());
    }
}
impl EncodeBuffer for u128 {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.to_le_bytes().as_slice());
    }
}
// `false as u8` is defined as 0.
/// `false` tag.
#[expect(clippy::as_conversions, reason = "this is safe, and we want a const")]
const FALSE: u8 = false as u8;
// `true as u8` is defined as 1.
/// `true` tag.
#[expect(clippy::as_conversions, reason = "this is safe, and we want a const")]
const TRUE: u8 = true as u8;
impl EncodeBuffer for bool {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.push(if *self { TRUE } else { FALSE });
    }
}
// We don't implement `EncodeBuffer` for `[T]` since we only ever need `[u8]`; and one can specialize
// the implementation such that it's _a lot_ faster than a generic `T`.
impl EncodeBufferFallible for [u8] {
    type Err = EncDecErr;
    /// # Errors
    ///
    /// Errors iff `self.len() > usize::from(u16::MAX)`.
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        u16::try_from(self.len())
            .map_err(|_e| EncDecErr)
            .map(|len| {
                len.encode_into_buffer(buffer);
                buffer.extend_from_slice(self);
            })
    }
}
// We don't implement `EncodeBuffer` for `Box<T>` since we only ever need `Box<[u8]>`; and one can specialize
// the implementation such that it's _a lot_ faster than a generic `T`.
impl EncodeBufferFallible for Box<[u8]> {
    type Err = EncDecErr;
    /// # Errors
    ///
    /// See [`[u8]::encode_into_buffer`].
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        (&self).encode_into_buffer(buffer)
    }
}
// We don't implement `EncodeBuffer` for `Vec<T>` since we only ever need `Vec<u8>`; and one can specialize
// the implementation such that it's _a lot_ faster than a generic `T`.
impl EncodeBufferFallible for Vec<u8> {
    type Err = EncDecErr;
    /// # Errors
    ///
    /// See [`[u8]::encode_into_buffer`].
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        self.as_slice().encode_into_buffer(buffer)
    }
}
// We don't implement `EncodeBuffer` for `[T; LEN]` since we only ever need `[u8; LEN]`; and one can specialize
// the implementation such that it's _a lot_ faster than a generic `T`.
impl<const LEN: usize> EncodeBuffer for [u8; LEN]
where
    [u8; LEN]: Default,
{
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        buffer.extend_from_slice(self.as_slice());
    }
}
/// [`Option::None`] tag.
const NONE: u8 = 0;
/// [`Option::Some`] tag.
const SOME: u8 = 1;
impl<T: EncodeBuffer> EncodeBuffer for Option<T> {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        match *self {
            None => {
                buffer.push(NONE);
            }
            Some(ref val) => {
                buffer.push(SOME);
                val.encode_into_buffer(buffer);
            }
        }
    }
}
impl<T: EncodeBuffer, T2: EncodeBuffer> EncodeBuffer for (T, T2) {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        self.0.encode_into_buffer(buffer);
        self.1.encode_into_buffer(buffer);
    }
}
impl EncodeBufferFallible for str {
    type Err = EncDecErr;
    /// # Errors
    ///
    /// See [`[u8]::encode_into_buffer`].
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        self.as_bytes().encode_into_buffer(buffer)
    }
}
impl EncodeBufferFallible for String {
    type Err = EncDecErr;
    /// # Errors
    ///
    /// See [`[u8]::encode_into_buffer`].
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        self.as_str().encode_into_buffer(buffer)
    }
}
impl EncodeBufferFallible for Cow<'_, str> {
    type Err = EncDecErr;
    /// # Errors
    ///
    /// See [`[u8]::encode_into_buffer`].
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        self.as_ref().encode_into_buffer(buffer)
    }
}
impl<T: EncodeBuffer + ?Sized> EncodeBuffer for &T {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        (**self).encode_into_buffer(buffer);
    }
}
impl<T: EncodeBuffer + ?Sized> EncodeBuffer for &mut T {
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) {
        (**self).encode_into_buffer(buffer);
    }
}
impl<T: EncodeBufferFallible + ?Sized> EncodeBufferFallible for &T {
    type Err = T::Err;
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        (**self).encode_into_buffer(buffer)
    }
}
impl<T: EncodeBufferFallible + ?Sized> EncodeBufferFallible for &mut T {
    type Err = T::Err;
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        (**self).encode_into_buffer(buffer)
    }
}
impl<T: EncodeBufferFallible> EncodeBufferFallible for Option<T> {
    type Err = T::Err;
    fn encode_into_buffer(&self, buffer: &mut Vec<u8>) -> Result<(), Self::Err> {
        match *self {
            None => {
                buffer.push(NONE);
                Ok(())
            }
            Some(ref val) => {
                buffer.push(SOME);
                val.encode_into_buffer(buffer)
            }
        }
    }
}
/// Decodes binary data generated by [`EncodeBuffer::encode_into_buffer`].
pub(super) trait DecodeBuffer<'a>: Sized {
    /// Error returned from [`Self::decode_from_buffer`].
    type Err;
    /// Transforms a sub-`slice` of `data` into `Self`; and upon success,
    /// mutates `data` to be the remaining portion.
    ///
    /// # Errors
    ///
    /// Errors iff `data` cannot be decoded into `Self`.
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err>;
}
impl<'a> DecodeBuffer<'a> for u8 {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        data.split_first().ok_or(EncDecErr).map(|(&val, rem)| {
            *data = rem;
            val
        })
    }
}
impl<'a> DecodeBuffer<'a> for u16 {
    type Err = EncDecErr;
    #[expect(
        clippy::little_endian_bytes,
        reason = "we must standardize the endianness to remove ambiguity"
    )]
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        /// Number of bytes `u16` is made of.
        const SIZE: usize = 2;
        data.split_at_checked(SIZE)
            .ok_or(EncDecErr)
            .map(|(le_bytes, rem)| {
                *data = rem;
                let mut val = [0; SIZE];
                val.copy_from_slice(le_bytes);
                Self::from_le_bytes(val)
            })
    }
}
impl<'a> DecodeBuffer<'a> for u32 {
    type Err = EncDecErr;
    #[expect(
        clippy::little_endian_bytes,
        reason = "we must standardize the endianness to remove ambiguity"
    )]
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        /// Number of bytes `u32` is made of.
        const SIZE: usize = 4;
        data.split_at_checked(SIZE)
            .ok_or(EncDecErr)
            .map(|(le_bytes, rem)| {
                *data = rem;
                let mut val = [0; SIZE];
                val.copy_from_slice(le_bytes);
                Self::from_le_bytes(val)
            })
    }
}
impl<'a> DecodeBuffer<'a> for u64 {
    type Err = EncDecErr;
    #[expect(
        clippy::little_endian_bytes,
        reason = "we must standardize the endianness to remove ambiguity"
    )]
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        /// Number of bytes `u64` is made of.
        const SIZE: usize = 8;
        data.split_at_checked(SIZE)
            .ok_or(EncDecErr)
            .map(|(le_bytes, rem)| {
                *data = rem;
                let mut val = [0; SIZE];
                val.copy_from_slice(le_bytes);
                Self::from_le_bytes(val)
            })
    }
}
impl<'a> DecodeBuffer<'a> for u128 {
    type Err = EncDecErr;
    #[expect(
        clippy::little_endian_bytes,
        reason = "we must standardize the endianness to remove ambiguity"
    )]
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        /// Number of bytes `u128` is made of.
        const SIZE: usize = 16;
        data.split_at_checked(SIZE)
            .ok_or(EncDecErr)
            .map(|(le_bytes, rem)| {
                *data = rem;
                let mut val = [0; SIZE];
                val.copy_from_slice(le_bytes);
                Self::from_le_bytes(val)
            })
    }
}
impl<'a> DecodeBuffer<'a> for bool {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|val| match val {
            FALSE => Ok(false),
            TRUE => Ok(true),
            _ => Err(EncDecErr),
        })
    }
}
// We don't implement `DecodeBuffer` for `&'a [T]` since we only ever need `&[u8]`; and one can specialize
// the implementation such that it's _a lot_ faster than a generic `T`.
impl<'a> DecodeBuffer<'a> for &'a [u8] {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u16::decode_from_buffer(data).and_then(|len| {
            data.split_at_checked(usize::from(len))
                .ok_or(EncDecErr)
                .map(|(val, rem)| {
                    *data = rem;
                    val
                })
        })
    }
}
// We don't implement `DecodeBuffer` for `Box<T>` since we only ever need `Box<[u8]>`; and one can specialize
// the implementation such that it's _a lot_ faster than a generic `T`.
impl<'a> DecodeBuffer<'a> for Box<[u8]> {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        <&[u8]>::decode_from_buffer(data).map(Self::from)
    }
}
// We don't implement `DecodeBuffer` for `Vec<T>` since we only ever need `Vec<u8>`; and one can specialize
// the implementation such that it's _a lot_ faster than a generic `T`.
impl<'a> DecodeBuffer<'a> for Vec<u8> {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        <&[u8]>::decode_from_buffer(data).map(ToOwned::to_owned)
    }
}
// We don't implement `DecodeBuffer` for `[T; LEN]` since we only ever need `[u8; LEN]`; and one can specialize
// the implementation such that it's _a lot_ faster than a generic `T`.
impl<'a, const LEN: usize> DecodeBuffer<'a> for [u8; LEN]
where
    [u8; LEN]: Default,
{
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        data.split_at_checked(LEN)
            .ok_or(EncDecErr)
            .map(|(val_slice, rem)| {
                *data = rem;
                let mut val = Self::default();
                val.copy_from_slice(val_slice);
                val
            })
    }
}
impl<'a, T> DecodeBuffer<'a> for Option<T>
where
    T: DecodeBuffer<'a, Err = EncDecErr>,
{
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        u8::decode_from_buffer(data).and_then(|tag| match tag {
            NONE => Ok(None),
            SOME => T::decode_from_buffer(data).map(Some),
            _ => Err(EncDecErr),
        })
    }
}
impl<'a, T, T2> DecodeBuffer<'a> for (T, T2)
where
    T: DecodeBuffer<'a, Err = EncDecErr>,
    T2: DecodeBuffer<'a, Err = EncDecErr>,
{
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        T::decode_from_buffer(data)
            .and_then(|val| T2::decode_from_buffer(data).map(|val2| (val, val2)))
    }
}
impl<'a> DecodeBuffer<'a> for &'a str {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        <&[u8]>::decode_from_buffer(data)
            .and_then(|utf8| str::from_utf8(utf8).map_err(|_e| EncDecErr))
    }
}
impl<'a> DecodeBuffer<'a> for String {
    type Err = EncDecErr;
    fn decode_from_buffer(data: &mut &'a [u8]) -> Result<Self, Self::Err> {
        <&str>::decode_from_buffer(data).map(ToOwned::to_owned)
    }
}
/// Encodes `self` into a "primitive"-like type that can be saved to persistent storage
/// and later decoded via [`Decode::decode`].
///
/// The purpose of this trait is to transform `Self` into something "easily" consumable by persistent
/// storage which already has some form of inherent metadata (e.g., a column in a relational database (RDB)).
pub trait Encode {
    /// "Primitive"-like type that `self` will be converted into. This should be one of the following:
    /// * [`u8`]
    /// * [`i8`]
    /// * [`u16`]
    /// * [`i16`]
    /// * [`u32`]
    /// * [`i32`]
    /// * [`u64`]
    /// * [`i64`]
    /// * [`u128`]
    /// * [`i128`]
    /// * [`f32`]
    /// * [`f64`]
    /// * [`bool`]
    /// * `&[u8]`
    /// * [`&str`](prim@str)
    /// * `[u8; N]`
    /// * `Vec<u8>`
    /// * [`String`]
    type Output<'a>
    where
        Self: 'a;
    /// Error returned when encoding fails.
    type Err;
    /// Transforms `self` into a "primitive"-like type.
    ///
    /// # Errors
    ///
    /// Errors iff `self` cannot be encoded into [`Self::Output`].
    fn encode(&self) -> Result<Self::Output<'_>, Self::Err>;
}
/// Decodes a "primitive"-like instance that was created via [`Encode::encode`]
/// into `Self`.
pub trait Decode: Sized {
    /// "Primitive"-like input to be decoded.
    ///
    /// This should be the same as or the "owned" version of the corresponding [`Encode::Output`]. For example if
    /// `Encode::Output` is `&[u8]`, then this should be `&[u8]` or `Vec<u8>`.
    type Input<'a>;
    /// Error returned when decoding fails.
    type Err;
    /// Decodes `input` into `Self`. Note `input` must not have any trailing data.
    ///
    /// # Errors
    ///
    /// Errors iff `input` cannot be decoded into `Self`.
    fn decode(input: Self::Input<'_>) -> Result<Self, Self::Err>;
}
