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
//! Unit tests.

use gsc_svc_client::GscServiceClient;
use log::info;
use tpm_commands::pinweaver::Pinweaver;

test::init!();

#[test]
fn pinweaver_test() {
    let gsc = GscServiceClient::default();

    // TODO(TBD) Replace with:
    //   assert_matches!(gsc.sys_info(), Ok()))
    // when assert_matches stablizes.
    let result = gsc.sys_info();
    info!("pinweaver current time: {:?}", result);
    assert!(matches!(result, Ok(_)));
}
