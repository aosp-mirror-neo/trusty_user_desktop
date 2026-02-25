/*
 * Copyright (C) 2026 The Android Open Source Project
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
//! Unit tests.

use super::*;
use test::expect;
use tipc::Handle;
use trusty_std::ffi::{CString, FallibleCString};

test::init!();

#[test]
fn secretkeeper_ag_secure_connection_fails_test() {
    let ag_port = CString::try_new(AG_PORT_NAME).unwrap();
    let ag_result = Handle::connect(ag_port.as_c_str());
    expect!(
        ag_result.is_err(),
        "unexpected success connecting to nonsecure Authgraph port {AG_PORT_NAME}: {ag_result:?}"
    );
}

#[test]
fn secretkeeper_sk_secure_connection_fails_test() {
    let sk_port = CString::try_new(SK_PORT_NAME).unwrap();
    let sk_result = Handle::connect(sk_port.as_c_str());
    expect!(sk_result.is_err(), "unexpected success connecting to nonsecure Secretkeeper port {SK_PORT_NAME}: {sk_result:?}");
}
