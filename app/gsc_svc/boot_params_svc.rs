/*
* Copyright (C) 2024 The Android Open Source Project
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

use alloc::vec::Vec;
use android_desktop_security_boot_params::aidl::android::desktop::security::boot_params::IBootParams::IBootParams;
use android_desktop_security_boot_params::aidl::android::desktop::security::boot_params::IBootParams::BnBootParams;
use binder::{BinderFeatures, Interface, Result as BinderResult, Strong};
use boot_params::BootParams;
use tipc::TipcError;

pub struct Server {
    params: BootParams,
}

impl Interface for Server {}

impl IBootParams for Server {
    fn getEarlyEntropy(&self) -> BinderResult<Vec<u8>> {
        Ok(self.params.gsc_boot_params.early_entropy.to_vec())
    }
}

impl Server {
    fn new() -> Self {
        Self { params: BootParams::new() }
    }
}

pub fn create_boot_params_service() -> Result<Strong<dyn IBootParams>, TipcError> {
    let srv = Server::new();

    let service = BnBootParams::new_binder(srv, BinderFeatures::default());

    Ok(service)
}
