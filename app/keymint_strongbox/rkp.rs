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

use android_system_desktop_security_gsc::aidl::android::system::desktop::security::gsc::IGsc::IGsc;
use binder::Strong;
use kmr_common::{km_err, Error};
use tpm_commands::strongbox::generate_ecdsa_p256_keypair;
use tpm_commands::{TpmRequestMessage, TpmResponseHeader, TpmResponseMessage};
use zerocopy::{FromBytes, IntoBytes};

pub fn generate_ecdsa_p256_keypair(client: &Strong<dyn IGsc>) -> Result<Vec<u8>, Error> {
    let cmd = TpmRequestMessage::new(generate_ecdsa_p256_keypair::Request {});
    let rsp =
        client.transmit(cmd.as_bytes()).map_err(|_| km_err!(SecureHwCommunicationFailed, ""))?;
    let rsp = TpmResponseMessage::<generate_ecdsa_p256_keypair::Response>::ref_from_bytes(&rsp)
        .map_err(|_| km_err!(SecureHwCommunicationFailed, ""))?;
    if rsp.header.error_code == 0 {
        let len = rsp.header.length.get() as usize - core::mem::size_of::<TpmResponseHeader>();
        Ok(rsp.response.data[..len].to_vec())
    } else {
        log::error!("Resp: {:X}", rsp.header.error_code);
        Err(km_err!(SecureHwCommunicationFailed, "0x{:X}", rsp.header.error_code))
    }
}
