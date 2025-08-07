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

//! Data structures representing time-related abstractions for finger_guard.

use crate::aidl::ExportToAidl;
use crate::hat::SignedHat;
use std::ops::Add;
use std::time::Duration;

/// For the time elaspsed in nanoseconds.
#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Instant {
    nanos: i64,
}

impl Instant {
    /// Given an exapsed time in nanoseconds, construct an instant.
    pub fn from_nanos(nanos: i64) -> Self {
        Self { nanos }
    }
}

impl ExportToAidl<SignedHat> for Instant {
    fn export(&self, out: &mut SignedHat) {
        // The exported timestamp is in milliseconds.
        out.timestamp = self.nanos / 1000 / 1000;
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    /// # Panics
    ///
    /// This function may panic if the result exceeds i64::MAX or the duration's
    /// nanos representation is greater than i64::MAX. In practice, it should
    /// never happen as either the duration is greater than ~292 years or the
    /// result instant is ~292 years since boot.
    /// For the actual usage of fingerprint auth rate limiting and timeout, the
    /// duration is at most several hours, so panic shall never be a problem.
    fn add(self, other: Duration) -> Instant {
        let other_nanos =
            i64::try_from(other.as_nanos()).expect("overflow with duration conversion");
        Self {
            nanos: self
                .nanos
                .checked_add(other_nanos)
                .expect("overflow when adding duration to instant"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Instant;
    use std::time::Duration;

    #[test]
    fn test_instant_default() {
        let def = Instant::default();
        let zero = Instant::from_nanos(0);
        let one = Instant::from_nanos(1);
        assert_eq!(def, zero);
        assert_ne!(def, one);
    }

    #[test]
    fn test_instant_plus_zero() {
        let time = Instant::from_nanos(1234567890);
        let plus_zero = time + Duration::ZERO;
        assert_eq!(time, plus_zero);
    }

    #[test]
    fn test_instant_plus_one_ns() {
        let time = Instant::default();
        let one_ns = Instant::from_nanos(1);
        let time_plus = time + Duration::from_nanos(1);
        assert_eq!(time_plus, one_ns);
    }

    #[test]
    fn test_instant_plus_one_s() {
        let time = Instant::default();
        let one_s = Instant::from_nanos(1000000000);
        let time_plus = time + Duration::from_secs(1);
        assert_eq!(time_plus, one_s);
    }
}
