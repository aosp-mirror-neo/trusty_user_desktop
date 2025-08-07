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

//! Trusty system clock functions.

use finger_guard::error::{ServiceError, ServiceResult};
use finger_guard::time;

/// Returns nanoseconds since boot, including time spent in sleep.
pub fn now() -> ServiceResult<time::Instant> {
    let mut time_ns = 0;
    //Safety: trivial, external syscall gets valid raw pointer to a `i64`.
    let rc = unsafe { trusty_sys::gettime(0, 0, &mut time_ns) };
    if rc < 0 {
        Err(ServiceError::TrustySysRcError("gettime", rc))
    } else {
        Ok(time::Instant::from_nanos(time_ns))
    }
}
