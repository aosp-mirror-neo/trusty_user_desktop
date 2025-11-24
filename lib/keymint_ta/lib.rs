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

use kmr_common::{crypto, Error};
use android_desktop_security_boot_params::aidl::android::desktop::security::boot_params::IBootParams::IBootParams;
use kmr_ta::device::DeviceHmac;
use kmr_ta::{HardwareInfo, KeyMintTa, RpcInfo};
use kmr_wire::keymint::Digest;
use service_manager::wait_for_interface;

const BP_SERVICE_PORT: &str = "com.android.trusty.rust.BootParamsService.V1";

/// Device HMAC implementation that holds the HMAC key in memory.
struct GscDeviceHmac {
    key: crypto::hmac::Key,
}

impl DeviceHmac for GscDeviceHmac {
    fn hmac(&self, imp: &dyn crypto::Hmac, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut hmac_op = imp.begin(self.key.clone().into(), Digest::Sha256)?;
        hmac_op.update(data)?;
        hmac_op.finish()
    }

    fn get_hmac_key(&self) -> Option<crypto::hmac::Key> {
        Some(self.key.clone())
    }
}

pub fn keymint_ta(
    hw_info: HardwareInfo,
    rpc_info: RpcInfo,
    imp: crypto::Implementation,
    dev: kmr_ta::device::Implementation,
) -> KeyMintTa {
    let bp: binder::Strong<dyn IBootParams> =
        wait_for_interface(BP_SERVICE_PORT).expect("Could not connect");
    // TODO(b/460252123): Do KDF(seed) instead.
    let auth_token_key_seed = bp.getAuthTokenKeySeed().expect("Could not get auth token key seed");

    let mut ta = KeyMintTa::new_allowing_versions(
        hw_info,
        rpc_info,
        imp,
        dev,
        vec![kmr_ta::KeyMintHalVersion::V4, kmr_ta::KeyMintHalVersion::V5],
    );
    let hm = GscDeviceHmac { key: kmr_common::crypto::hmac::Key(auth_token_key_seed.to_vec()) };
    ta.set_device_hmac(alloc::boxed::Box::new(hm));
    ta
}
