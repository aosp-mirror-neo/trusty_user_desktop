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
use android_desktop_security_boot_params::aidl::android::desktop::security::boot_params::IBootParams::{ERROR_INVALID_ARGUMENT, ERROR_OPENSSL, IBootParams};
use android_desktop_security_boot_params::aidl::android::desktop::security::boot_params::IBootParams::BnBootParams;
use binder::{BinderFeatures, Interface, Result as BinderResult, Status, Strong};
use boot_params::BootParams;
#[cfg(not(feature = "builtin-bcc"))]
use vmm_obj::get_vmm_obj;

pub struct Server {
    params: BootParams,
}

impl Interface for Server {}

impl IBootParams for Server {
    fn getEarlyEntropy(&self) -> BinderResult<Vec<u8>> {
        Ok(self.params.gsc_boot_params.early_entropy.to_vec())
    }
    fn getCdiSeal(&self) -> BinderResult<Vec<u8>> {
        Ok(self.params.dice.cdi_seal.to_vec())
    }
    fn getCdiAttest(&self) -> BinderResult<Vec<u8>> {
        Ok(self.params.dice.cdi_attest.to_vec())
    }
    fn getAuthTokenKeySeed(&self) -> BinderResult<Vec<u8>> {
        Ok(self.params.gsc_boot_params.auth_token_key_seed.to_vec())
    }
    fn deriveSessionKey(&self, salt: &[u8]) -> BinderResult<Vec<u8>> {
        if salt.is_empty() {
            return Err(Status::new_service_specific_error(
                ERROR_INVALID_ARGUMENT,
                Some(c"Salt must not be empty"),
            ));
        }

        let md = openssl::md::Md::sha256();
        let mut out = [0; 32];
        openssl::hkdf::hkdf_extract(
            &mut out,
            md,
            &self.params.gsc_boot_params.session_key_seed,
            salt,
        )
        .map_err(|_| {
            Status::new_service_specific_error(ERROR_OPENSSL, Some(c"HDF extraction failed"))
        })?;
        Ok(out.to_vec())
    }
}

#[cfg(feature = "builtin-bcc")]
impl Default for Server {
    /// Create a boot params struct from constant data.
    fn default() -> Self {
        Self { params: BootParams::default() }
    }
}

impl Server {
    #[cfg(not(feature = "builtin-bcc"))]
    fn new(entropy: [u8; 64], session: [u8; 32], auth: [u8; 32], dice: &[u8]) -> Self {
        Self {
            params: BootParams::new_from_dt(entropy, session, auth, dice)
                .expect("Unable to start server"),
        }
    }
}

#[cfg(feature = "builtin-bcc")]
pub(crate) fn create_boot_params_service() -> Strong<dyn IBootParams> {
    BnBootParams::new_binder(Server::default(), BinderFeatures::default())
}

#[cfg(not(feature = "builtin-bcc"))]
pub(crate) fn create_boot_params_service() -> Strong<dyn IBootParams> {
    let entropy = get_vmm_obj(c"google,early-entropy").expect("Could not get entropy");
    let session = get_vmm_obj(c"google,session-key-seed").expect("Could not get session key seed");
    let auth =
        get_vmm_obj(c"google,auth-token-key-seed").expect("Could not get auth token key seed");
    let dice = get_vmm_obj(c"google,open-dice").expect("Could not get DICE chain");

    let srv = Server::new(
        entropy.try_into().unwrap(),
        session.try_into().unwrap(),
        auth.try_into().unwrap(),
        &dice,
    );
    BnBootParams::new_binder(srv, BinderFeatures::default())
}
