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
use std::ops::{Add, Sub};
use std::time::Duration;

/// For the time elaspsed in nanoseconds.
#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Instant {
    nanos: i64,
}

impl Instant {
    /// MAX represents the largest possible instant.
    pub const MAX: Instant = Instant { nanos: i64::MAX };
    /// MIN represents the smallest possible instant.
    pub const MIN: Instant = Instant { nanos: 0 };

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

    /// This function doesn't panic when the result or the Duration exceeds i64::MAX.
    /// Instead, the result is saturated to i64::MAX.
    /// When the duration's nanos representation is greater than i64::MAX, the
    /// converted is saturated at i64::MAX. In practice, it should never happen as the
    /// duration has to be greater than ~292 years.
    /// For the actual usage of fingerprint auth rate limiting and timeout, the
    /// duration is at most several days, so we don't worry about saturation.
    fn add(self, other: Duration) -> Self {
        let other_nanos = i64::try_from(other.as_nanos()).unwrap_or(i64::MAX);
        Self { nanos: self.nanos.saturating_add(other_nanos) }
    }
}

impl Sub for Instant {
    type Output = Duration;

    /// Saturating subtraction between Instants always produces a valid Duration.
    /// If `self` is in the past of `rhs`, it should return Duration::ZERO.
    fn sub(self, rhs: Self) -> Duration {
        Duration::from_nanos((self.nanos as u64).saturating_sub(rhs.nanos as u64))
    }
}

/// A trait that provides a way to get the current time.
pub trait Clock {
    /// returns the current time.
    fn now(&self) -> Instant;
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

    #[test]
    fn test_instant_saturating_plus_one_s() {
        let time = Instant::from_nanos(i64::MAX);
        let time_plus = time + Duration::from_secs(1);
        assert_eq!(time_plus, time);
    }

    #[test]
    fn test_instant_sub_another() {
        let ten_s = Instant::from_nanos(10000000000);
        let one_s = Instant::from_nanos(1000000000);
        let duration = ten_s - one_s;
        assert_eq!(duration, Duration::from_secs(9));
    }

    #[test]
    fn test_instant_saturating_sub() {
        let two_s = Instant::from_nanos(2000000000);
        let one_s = Instant::from_nanos(1000000000);
        let duration = one_s - two_s;
        assert_eq!(duration, Duration::ZERO);
    }
}
