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

//! Fake implementations of some traits for use in testing.
use crate::error::ServiceResult;
use crate::time::{Clock, Instant};
use std::sync::Mutex;
use std::time::Duration;

/// A simulated clock implementation for testing. It provides additional functions to allow the
/// test code to control the current time that it will report.
pub struct SimulatedClock {
    /// The current time is protected by a mutex both because clocks need to be threadsafe but also
    /// because we require interior mutability to allow the test to manipulate the time while the
    /// code under test is holding a reference.
    current_time: Mutex<Instant>,
}

impl SimulatedClock {
    /// Creates a new simulated clock.
    ///
    /// Note that this will allocate a new clock globally which cannot be deallocated, so individual
    /// tests should not create more than one instance of this. Since the clock is conceptually
    /// intended to be a singleton this should not be a serious limitation in practice.
    pub fn new() -> &'static Self {
        Box::leak(Box::new(Self { current_time: Mutex::new(Instant::MIN) }))
    }

    /// Advances the clock by a specified duration.
    pub fn advance_time(&self, duration: Duration) {
        let mut now = self.current_time.lock().unwrap();
        *now = *now + duration;
    }
}

impl Clock for SimulatedClock {
    fn now(&self) -> ServiceResult<Instant> {
        Ok(*self.current_time.lock().unwrap())
    }
}
