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

//! Trusty system clock util functions.

use crate::aidl::ExportToAidl;
use crate::hat::SignedHat;
use finger_guard::error::{ServiceError, ServiceResult};
use std::ops::Add;
use std::time::Duration;

/// For the time elaspsed in nanoseconds.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    nanos: i64,
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

/// Returns nanoseconds since boot, including time spent in sleep.
pub fn now() -> ServiceResult<Instant> {
    let mut time_ns = 0;
    //Safety: trivial, external syscall gets valid raw pointer to a `i64`.
    let rc = unsafe { trusty_sys::gettime(0, 0, &mut time_ns) };
    if rc < 0 {
        Err(ServiceError::TrustySysRcError("gettime", rc))
    } else {
        Ok(Instant { nanos: time_ns })
    }
}
