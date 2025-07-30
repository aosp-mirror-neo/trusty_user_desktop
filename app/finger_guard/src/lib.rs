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

//! Implements the core capabilities of the finger_guard service.
//!
//! This crate only contains the aspects of the service that do not depend directly on other
//! trusty specific libraries and interfaces. This allows it to be built for non-trusty
//! environments which is useful for testing and debugging. However, it is not intended to provide
//! generically reusable features outside of implementing finger_guard.

pub mod error;
pub mod rng;
