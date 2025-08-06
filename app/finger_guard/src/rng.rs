/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Trusty implementation of `kmr_common::crypto::Rng`.

use kmr_common::crypto::Rng;

/// [`kmr_common::crypto::Rng`] implementation for Trusty.
pub struct TrustyRng;

impl Rng for TrustyRng {
    // Safety: No op as intended, BoringSSL's RAND_bytes() doesn't utilize this function.
    fn add_entropy(&mut self, _data: &[u8]) {}

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // safe: BoringSSL's RAND_bytes() never fails
        openssl::rand::rand_bytes(dest).unwrap();
    }
}

/// Generate a buffer of size N filled with random bytes.
pub fn generate_random_buffer<const N: usize>() -> [u8; N] {
    let mut rng = TrustyRng;
    let mut bytes = [0; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a byte vector of size N filled with random bytes.
pub fn generate_random_vec<const N: usize>() -> Vec<u8> {
    let mut rng = TrustyRng;
    let mut bytes = vec![0u8; N];
    rng.fill_bytes(bytes.as_mut_slice());
    bytes
}

/// Generate a random integer of the given type.
///
/// This is implemented as a macro because there's no generic way to turn a blob of random bytes
/// into a specific type. In fact, even generating a random integer of a specific size is difficult
/// because size_of can't be used on generic types in current Rust.
#[macro_export]
macro_rules! _generate_random_int {
    ($int_type:ty) => {{
        const INT_SIZE: usize = std::mem::size_of::<$int_type>();
        let bytes = $crate::rng::generate_random_buffer::<INT_SIZE>();
        let var = <$int_type>::from_ne_bytes(bytes);
        var
    }};
}
pub use _generate_random_int as generate_random_int;

#[cfg(test)]
mod test {
    use super::{generate_random_buffer, generate_random_int, generate_random_vec};
    use std::array;

    // These tests all generate random buffers and then compare them, with the expectation that
    // said buffers should never be equal. This is technically not guaranteed to be true: you could
    // get two random buffers that just happen to be precisely the same value.
    //
    // If that happens to you, then congratulations: you are the unluckiest person in the universe.
    // But if this is actually failing, the much much more likely outcome is that the rng is
    // actually broken in some way.

    #[test]
    fn test_random_buffers() {
        let buf1 = generate_random_buffer::<512>();
        let buf2 = generate_random_buffer::<512>();
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_random_vectors() {
        let vec1 = generate_random_vec::<512>();
        let vec2 = generate_random_vec::<512>();
        assert_ne!(vec1, vec2);
    }

    #[test]
    fn test_random_u8() {
        let array1: [u8; 512] = array::from_fn(|_| generate_random_int!(u8));
        let array2: [u8; 512] = array::from_fn(|_| generate_random_int!(u8));
        assert_ne!(array1, array2);
    }

    #[test]
    fn test_random_u16() {
        let array1: [u16; 256] = array::from_fn(|_| generate_random_int!(u16));
        let array2: [u16; 256] = array::from_fn(|_| generate_random_int!(u16));
        assert_ne!(array1, array2);
    }

    #[test]
    fn test_random_u32() {
        let array1: [u32; 128] = array::from_fn(|_| generate_random_int!(u32));
        let array2: [u32; 128] = array::from_fn(|_| generate_random_int!(u32));
        assert_ne!(array1, array2);
    }

    #[test]
    fn test_random_u64() {
        let array1: [u64; 64] = array::from_fn(|_| generate_random_int!(u64));
        let array2: [u64; 64] = array::from_fn(|_| generate_random_int!(u64));
        assert_ne!(array1, array2);
    }

    #[test]
    fn test_random_u128() {
        let array1: [u128; 32] = array::from_fn(|_| generate_random_int!(u128));
        let array2: [u128; 32] = array::from_fn(|_| generate_random_int!(u128));
        assert_ne!(array1, array2);
    }
}
