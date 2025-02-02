/*
 * Copyright (c) 2024, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Utilities for serialization and deserialization.

use std::{
    collections::TryReserveError,
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unalign};

/// A `Vec` wrapper that is compatible with tipc serialization.
///
/// Automatic tipc serde is implemented for `T` that can be freely converted
/// to and from bytes.
///
/// # The `len` field
///
/// The current design of [`Serialize::serialize`] means that it needs to
/// output a `&[u8]` that is directly tied to the lifetime of a `&Self`.
/// `Vec::len` returns a `usize` instead of `&u32`, so `as_bytes` borrows
/// a temporary. `Vec` does not expose a method to borrow its length field.
/// There's no way to do this stably even with `unsafe`.
///
/// So, a secondary field is used and its value kept in-sync with the inner `Vec`.
/// Any used `&mut Vec` methods should be mirrored.
///
/// # The `MAX_LEN` parameter
///
/// This is used to calculate the correct `Deserialize::MAX_SERIALIZED_SIZE`.
/// Constructing a `SerdeVec` with a length larger than `MAX_LEN` is allowed,
/// but may not be deserializable on the receiving end - use `is_over_max_len`
/// to check.
#[derive(Debug, Default)]
pub struct SerdeVec<T, const MAX_LEN: u32> {
    len: u32,
    values: Vec<T>,
}

impl<T, const MAX_LEN: u32> Deref for SerdeVec<T, MAX_LEN> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        &self.values
    }
}

impl<T, const MAX_LEN: u32> DerefMut for SerdeVec<T, MAX_LEN> {
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}

impl<T, const MAX_LEN: u32> SerdeVec<T, MAX_LEN> {
    /// Returns whether `self.len() > MAX_LEN`.
    pub fn is_over_max_len(&self) -> bool {
        assert_eq!(self.len, self.values.len().try_into().unwrap(), "length invariant invalidated");
        self.len > MAX_LEN
    }

    fn sync_len(&mut self) {
        self.len = self.values.len().try_into().expect("len shouldn't be able to exceed u32::MAX");
    }

    /// See [`Vec::push`]
    pub fn push(&mut self, val: T) {
        // TODO: kupiakos - ensure that the length can't exceed `u32::MAX`
        self.values.push(val);
        self.sync_len();
    }
}

impl<'s, T: Immutable + IntoBytes + 's, const MAX_LEN: u32> Serialize<'s> for SerdeVec<T, MAX_LEN> {
    fn serialize<'a: 's, S: Serializer<'s>>(
        &'a self,
        serializer: &mut S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.len.as_bytes())?;
        serializer.serialize_bytes(self[..].as_bytes())
    }
}

impl<T: Immutable + KnownLayout + IntoBytes + FromBytes + 'static, const MAX_LEN: u32>
    DeserializePrefix for SerdeVec<T, MAX_LEN>
{
    const MAX_SERIALIZED_SIZE: usize = size_of::<u32>() + size_of::<T>() * MAX_LEN as usize;

    fn deserialize_prefix(bytes: &mut &[u8]) -> Result<Self, DeserializeError> {
        let Ok((len, tail)) = u32::read_from_prefix(bytes) else {
            return Err(DeserializeError::NotEnoughBuffer);
        };
        let len_usize = u32_to_usize(len);
        let Ok((contents, rest)) = <[Unalign<T>]>::ref_from_prefix_with_elems(tail, len_usize)
        else {
            return Err(DeserializeError::NotEnoughBuffer);
        };
        let mut values = T::new_vec_zeroed(len_usize)?;
        values.as_mut_bytes().copy_from_slice(contents.as_bytes());
        *bytes = rest;
        Ok(Self { len, values })
    }
}

/// An `Option` alternative that is compatible with tipc serialization.
#[repr(u8)]
pub enum SerdeOption<T> {
    /// Equivalent to [`Option::None`].
    None = 0,

    /// Equivalent to [`Option::Some`].
    Some(T) = 1,
}

impl<T> From<SerdeOption<T>> for Option<T> {
    fn from(value: SerdeOption<T>) -> Self {
        match value {
            SerdeOption::None => None,
            SerdeOption::Some(x) => Some(x),
        }
    }
}

impl<T> From<Option<T>> for SerdeOption<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            None => SerdeOption::None,
            Some(x) => SerdeOption::Some(x),
        }
    }
}

impl<'s, T: Serialize<'s>> Serialize<'s> for SerdeOption<T> {
    fn serialize<'a: 's, S: Serializer<'s>>(
        &'a self,
        serializer: &mut S,
    ) -> Result<S::Ok, S::Error> {
        // TODO: b/372549215 - replace with zerocopy extracting the discriminant ref directly.
        let discriminant = match self {
            SerdeOption::Some(_) => &1u8,
            _ => &0u8,
        };
        let ok = serializer.serialize_bytes(discriminant.as_bytes())?;
        match self {
            SerdeOption::Some(val) => val.serialize(serializer),
            _ => Ok(ok),
        }
    }
}

impl<T: DeserializePrefix> DeserializePrefix for SerdeOption<T> {
    const MAX_SERIALIZED_SIZE: usize = size_of::<u8>() + T::MAX_SERIALIZED_SIZE;

    fn deserialize_prefix(bytes: &mut &[u8]) -> Result<Self, DeserializeError> {
        let &[has_value, ref rest @ ..] = *bytes else {
            return Err(DeserializeError::NotEnoughBuffer);
        };
        *bytes = rest;
        let has_value = has_value != 0;
        Ok(if has_value {
            SerdeOption::Some(T::deserialize_prefix(bytes)?)
        } else {
            SerdeOption::None
        })
    }
}

/// An error that occurred while deserializing.
#[derive(Debug)]
pub enum DeserializeError {
    /// The input buffer to deserialize was too small.
    NotEnoughBuffer,

    /// There were unacceptable bits in the input buffer.
    InvalidValue,

    /// Dynamic allocation failed.
    Alloc,
}

impl From<zerocopy::error::AllocError> for DeserializeError {
    fn from(_: zerocopy::error::AllocError) -> Self {
        DeserializeError::Alloc
    }
}

impl From<TryReserveError> for DeserializeError {
    fn from(_: TryReserveError) -> Self {
        DeserializeError::Alloc
    }
}

/// A copy of `tipc::Serializer` that can be used outside of Trusty.
pub trait Serializer<'s> {
    /// The value that is outputted upon success.
    type Ok;

    /// The value that is outputted upon error.
    type Error: Debug;

    /// Serialize a sequence of bytes.
    fn serialize_bytes(&mut self, bytes: &'s [u8]) -> Result<Self::Ok, Self::Error>;
}

// A newtype is not necessary here because it implements a local trait for foreign types.
#[cfg(target_os = "trusty")]
impl<'s, S: tipc::Serializer<'s>> Serializer<'s> for S {
    type Ok = <S as tipc::Serializer<'s>>::Ok;
    type Error = <S as tipc::Serializer<'s>>::Error;

    fn serialize_bytes(&mut self, bytes: &'s [u8]) -> Result<Self::Ok, Self::Error> {
        <S as tipc::Serializer<'s>>::serialize_bytes(self, bytes)
    }
}

/// A copy of `tipc::Serialize` that can be used outside of Trusty.
pub trait Serialize<'s> {
    /// Serialize this data as a byte slice that lives for at least as long as `&self`.
    fn serialize<'a: 's, S: Serializer<'s>>(
        &'a self,
        serializer: &mut S,
    ) -> Result<S::Ok, S::Error>;
}

#[cfg(target_os = "trusty")]
/// Newtype which forwards a local `Serialize` impl to the `tipc` version.
pub struct ForwardTipcSerialize<'a, T>(pub &'a T);

#[cfg(target_os = "trusty")]
impl<'b, 's, T: Serialize<'s>> tipc::Serialize<'s> for ForwardTipcSerialize<'b, T>
where
    's: 'b,
{
    fn serialize<'a: 's, S: tipc::Serializer<'s>>(
        &'a self,
        serializer: &mut S,
    ) -> Result<S::Ok, S::Error> {
        <T as Serialize<'s>>::serialize(self.0, serializer)
    }
}

/// A composable version of `tipc::Deserialize` that parses the start of the input.
pub trait DeserializePrefix: Sized {
    /// The maximum number of bytes that can be deserialized into this type.
    ///
    /// Used to reserve sufficient space.
    const MAX_SERIALIZED_SIZE: usize;

    /// Deserializes `Self` from the prefix of `bytes`,
    /// mutating the input slice to remove the prefix that was deserialized.
    ///
    /// On an `Err` return, the slice left in `bytes` is unspecified.
    fn deserialize_prefix(bytes: &mut &[u8]) -> Result<Self, DeserializeError>;
}

#[cfg(target_os = "trusty")]
/// Newtype to forward a [`DeserializePrefix`] impl as `tipc::Deserialize`,
/// rejecting the input buffer if larger than what `DeserializePrefix` parsed.
///
/// Ignores the `handles` parameter.
pub struct DeserializeExact<T>(pub T);

#[cfg(target_os = "trusty")]
impl<T: DeserializePrefix> tipc::Deserialize for DeserializeExact<T> {
    type Error = tipc::TipcError;
    const MAX_SERIALIZED_SIZE: usize = T::MAX_SERIALIZED_SIZE;

    fn deserialize(mut bytes: &[u8], _: &mut [Option<tipc::Handle>]) -> Result<Self, Self::Error> {
        let out = T::deserialize_prefix(&mut bytes).map_err(|e| match e {
            DeserializeError::InvalidValue => tipc::TipcError::InvalidData,
            DeserializeError::NotEnoughBuffer => tipc::TipcError::NotEnoughBuffer,
            DeserializeError::Alloc => tipc::TipcError::AllocError,
        })?;
        if bytes.is_empty() {
            Ok(DeserializeExact(out))
        } else {
            // TODO: kupiakos - log that the message is too long
            Err(tipc::TipcError::InvalidData)
        }
    }
}

pub(crate) const fn field_max_serialized_size<T, U: DeserializePrefix>(
    _accessor: &impl FnOnce(&T) -> &U,
) -> usize {
    U::MAX_SERIALIZED_SIZE
}

pub(crate) const fn sum_usize(elems: &[usize]) -> usize {
    let mut sum = 0;
    let mut i = 0;
    while i < elems.len() {
        sum += elems[i];
        i += 1;
    }
    sum
}

/// Returns `0` if `elems` is empty.
pub(crate) const fn max_usize(elems: &[usize]) -> usize {
    let mut max = None;
    let mut i = 0;
    while i < elems.len() {
        let elem = elems[i];
        match max {
            Some(current) if current > elem => {}
            _ => max = Some(elem),
        }
        i += 1;
    }
    match max {
        Some(x) => x,
        None => 0,
    }
}

/// Infallibly convert a `u32` to `usize`. Fails to compile if `usize` is 16-bit.
const fn u32_to_usize(x: u32) -> usize {
    const _: () = assert!(size_of::<u32>() <= size_of::<usize>(), "16-bit usize is unsupported");
    x as usize
}

/// Defines a new enum with fields that may be serialized/deserialized automatically.
///
/// Supports enums whose variants have either no data or a single field of one token.
/// Note: if an enum has no data to carry, serialize the bytes directly with zerocopy.
macro_rules! serde_enums {
    (@match_variant_pat $data:ident, $name:ident :: $variant:ident,) => {
        $name::$variant
    };
    (@match_variant_pat $data:ident, $name:ident :: $variant:ident, $inner:tt) => {
        $name::$variant($data)
    };
    (@serialize_variant_arm $data:ident, $discriminant:expr, $serializer:ident, ) => {{
        let discriminant: &'static u8 = &$discriminant;
        $crate::util::Serialize::serialize(discriminant, $serializer)
    }};
    (@serialize_variant_arm $data:ident, $discriminant:expr, $serializer:ident, $inner:tt) => {{
        // TODO: b/372549215 - replace with zerocopy extracting the discriminant ref directly.
        // The discriminant expression must not produce a temporary so it can `&'static`.
        let discriminant: &'static u8 = &$discriminant;
        $crate::util::Serialize::serialize(discriminant, $serializer)?;
        $crate::util::Serialize::serialize($data, $serializer)
    }};
    (@deserialize_variant_arm $bytes:ident, $name:ident :: $variant:ident,) => {
        $name::$variant
    };
    (@deserialize_variant_arm $bytes:ident, $name:ident :: $variant:ident, $inner:tt) => {
        $name::$variant($crate::util::DeserializePrefix::deserialize_prefix($bytes)?)
    };
    (@variant_max_serialized_size) => {0};
    (@variant_max_serialized_size $inner:tt) => {
        <$inner as $crate::util::DeserializePrefix>::MAX_SERIALIZED_SIZE
    };
    ($(
        $(#[$attr:meta])*
        pub enum $name:ident {
        $(
            $(#[$variant_attr:meta])*
            $variant:ident $(($data:tt))? = $discriminant:expr
        ),* $(,)?
        }
    )*) => {$(
        $(#[$attr])*
        #[repr(u8)]
        pub enum $name {$(
            $(#[$variant_attr])*
            $variant $(($data))? = $discriminant,
        )*}
        impl<'s> $crate::util::Serialize<'s> for $name {
            fn serialize<'a: 's, S: $crate::util::Serializer<'s>>(
                &'a self,
                serializer: &mut S,
            ) -> Result<S::Ok, S::Error> {
                match self {$(
                    $crate::util::serde_enums!(
                        @match_variant_pat
                        data, $name :: $variant,
                        $($data)?
                    ) => $crate::util::serde_enums!(
                        @serialize_variant_arm
                        data, $discriminant, serializer,
                        $($data)?
                    ),
                )*}
            }
        }

        impl $crate::util::DeserializePrefix for $name {
            const MAX_SERIALIZED_SIZE: usize = size_of::<u8>() +
                $crate::util::max_usize(&[$(
                    $crate::util::serde_enums!(
                        @variant_max_serialized_size
                        $($data)?
                    ),
                )*]);

            fn deserialize_prefix(bytes: &mut &[u8]) -> Result<Self, $crate::util::DeserializeError> {
                let &[discriminant, ref variant_data @ ..] = *bytes else {
                    return Err($crate::util::DeserializeError::NotEnoughBuffer);
                };
                *bytes = variant_data;
                Ok(match discriminant {
                    $(
                        $discriminant => $crate::util::serde_enums!(
                            @deserialize_variant_arm
                            bytes, $name :: $variant,
                            $($data)?
                        ),
                    )*
                    // TODO: kupiakos@ - log this error
                    _ => return Err($crate::util::DeserializeError::InvalidValue),
                })
            }
        }
    )*};
}

/// Implements `Serialize`/`DeserializePrefix` for all of the fields in the given wire order.
macro_rules! serde_fields {
    ($($name:ident {$($field:ident),* $(,)?}),* $(,)?) => {$(
        impl $crate::util::DeserializePrefix for $name {
            const MAX_SERIALIZED_SIZE: usize = $crate::util::sum_usize(&[$(
                $crate::util::field_max_serialized_size(&|x: &Self| &x.$field),
            )*]);
            fn deserialize_prefix(bytes: &mut &[u8]) -> Result<Self, $crate::util::DeserializeError> {
                $(
                    let $field = $crate::util::DeserializePrefix::deserialize_prefix(bytes)?;
                )*
                Ok(Self {
                    $($field),*
                })
            }
        }

        impl<'s> $crate::util::Serialize<'s> for $name {
            fn serialize<'a: 's, S: $crate::util::Serializer<'s>>(
                &'a self,
                serializer: &mut S,
            ) -> Result<S::Ok, S::Error> {
                // Check there are no missing fields.
                let $name { $($field),* } = self;
                $(
                    let _ok = $crate::util::Serialize::serialize($field, serializer)?;
                )*
                Ok(_ok)
            }
        }
    )*};
}

/// Uses `zerocopy` to serialize/deserialize all fields at once in order.
///
/// Note that this is sensitive to changes in field layout.
macro_rules! serde_zerocopy {
    ($($t:ty),* $(,)?) => {
        $(
            impl $crate::util::DeserializePrefix for $t {
                const MAX_SERIALIZED_SIZE: usize = size_of::<Self>();
                fn deserialize_prefix(
                    bytes: &mut &[u8]
                ) -> Result<Self, $crate::util::DeserializeError> {
                    let Ok((head, tail)) = <$t as zerocopy::FromBytes>::read_from_prefix(*bytes)
                    else {
                        return Err($crate::util::DeserializeError::NotEnoughBuffer);
                    };
                    *bytes = tail;
                    Ok(head)
                }
            }

            impl<'s> $crate::util::Serialize<'s> for $t {
                fn serialize<'a: 's, S: $crate::util::Serializer<'s>>(
                    &'a self,
                    serializer: &mut S,
                ) -> Result<S::Ok, S::Error> {
                    serializer.serialize_bytes(self.as_bytes())
                }
            }
        )*
    };
}

serde_zerocopy!(u8, i8, u16, i16, u32, i32, u64, i64);

pub(crate) use {serde_enums, serde_fields, serde_zerocopy};
