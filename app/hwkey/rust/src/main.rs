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

use android_desktop_security_boot_params::aidl::android::desktop::security::boot_params::IBootParams::IBootParams;
use service_manager::wait_for_interface;
use vmm_obj::get_vmm_obj;

const BP_SERVICE_PORT: &str = "com.android.trusty.rust.BootParamsService.V1";

// TODO(b/418065023) Support versioned keys.
// Until version keys are implemented, reserve a special case for use CDI_SEAL.
const VERSION_CDI_SEAL: i32 = 0;
// Until version keys are implement, reserve a special case for use when we bave the base framwork
// but cannot generate older versions.
const _VERSION_UNVERSIONED: i32 = 1;

extern "C" {
    // Implementations of run_hwkey should not retain any referencs but may clear the contents of
    // encrypt and sign.
    fn run_hwkey(
        encrypt: *mut u8,
        encrypt_size: usize,
        sign: *mut u8,
        sign_size: usize,
        auth_token_key_seed: *mut u8,
        auth_token_key_seed_size: usize,
        rollback_version: i32,
        running_version: i32,
    ) -> i32;
}

fn main() {
    trusty_log::init();
    log::info!("HwKey starting.");
    let bp: binder::Strong<dyn IBootParams> =
        wait_for_interface(BP_SERVICE_PORT).expect("Could not connect");

    let mut seal = get_vmm_obj(c"google,versioned-seed").expect("Could not get versioned seed");
    let mut sign = bp.getCdiAttest().expect("Could not get sign");
    let mut auth_token_key_seed =
        bp.getAuthTokenKeySeed().expect("Could not get auth token key seed");

    log::info!("Launching hwkey service.");
    // SAFETY: run_hwbcc copies the data from code and auth and does not retain references to them.
    unsafe {
        run_hwkey(
            seal.as_mut_ptr(),
            seal.len(),
            sign.as_mut_ptr(),
            sign.len(),
            auth_token_key_seed.as_mut_ptr(),
            auth_token_key_seed.len(),
            VERSION_CDI_SEAL,
            VERSION_CDI_SEAL,
        );
    }
}
