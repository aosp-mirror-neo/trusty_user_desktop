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

/// [`crypto::Rng`] implementation for Trusty.
#[derive(Default)]
pub struct TrustyRng;

impl Rng for TrustyRng {
    fn add_entropy(&mut self, _data: &[u8]) {} // Safety: No op as intended, BoringSSL's RAND_bytes() doesn't utilize this function.
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        openssl::rand::rand_bytes(dest).unwrap(); // safe: BoringSSL's RAND_bytes() never fails
    }
}

// Generate a buffer of size N filled with random bytes.
pub fn generate_random_buffer<const N: usize>() -> [u8; N] {
    let mut rng = TrustyRng::default();
    let mut bytes = [0; N];
    rng.fill_bytes(&mut bytes);
    bytes
}

// Generate a byte vector of size N filled with random bytes.
pub fn generate_random_vec<const N: usize>() -> Vec<u8> {
    let mut rng = TrustyRng::default();
    let mut bytes = vec![0u8; N];
    rng.fill_bytes(&mut bytes.as_mut_slice());
    bytes
}

// Generate a random integer of the given type.
//
// This is implemented as a macro because there's no generic way to turn a blob of random bytes
// into a specific type. In fact, even generating a random integer of a specific size is difficult
// because size_of can't be used on generic types in current Rust.
macro_rules! generate_random_int {
    ($int_type:ty) => {{
        const INT_SIZE: usize = std::mem::size_of::<$int_type>();
        let bytes = $crate::rng::generate_random_buffer::<INT_SIZE>();
        let var = <$int_type>::from_ne_bytes(bytes);
        var
    }};
}
pub(crate) use generate_random_int;
