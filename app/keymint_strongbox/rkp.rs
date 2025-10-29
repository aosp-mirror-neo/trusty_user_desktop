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
use kmr_wire::rpc::{EekCurve, HardwareInfo, MINIMUM_SUPPORTED_KEYS_IN_CSR};
use tpm_commands::strongbox::*;
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
        Err(km_err!(SecureHwCommunicationFailed, "0x{:X}", rsp.header.error_code))
    }
}

pub fn get_hardware_info(client: &Strong<dyn IGsc>) -> Result<HardwareInfo, Error> {
    let cmd = TpmRequestMessage::new(get_hardware_info::Request {});
    let rsp =
        client.transmit(cmd.as_bytes()).map_err(|_| km_err!(SecureHwCommunicationFailed, ""))?;
    let rsp = TpmResponseMessage::<get_hardware_info::Response>::ref_from_bytes(&rsp)
        .map_err(|_| km_err!(SecureHwCommunicationFailed, ""))?;
    if rsp.header.error_code == 0 {
        let author_len =
            (rsp.response.keymint_author_len.get() as usize).min(rsp.response.keymint_author.len());
        let keymint_name_len =
            (rsp.response.keymint_name_len.get() as usize).min(rsp.response.keymint_name.len());
        Ok(HardwareInfo {
            version_number: rsp.response.version.get(),
            rpc_author_name: String::from_utf8(rsp.response.keymint_author[..author_len].to_vec())
                .map_err(|_| km_err!(EncodingError, ""))?,

            supported_eek_curve: EekCurve::P256,
            unique_id: Some(
                String::from_utf8(rsp.response.keymint_name[..keymint_name_len].to_vec())
                    .map_err(|_| km_err!(EncodingError, ""))?,
            ),
            supported_num_keys_in_csr: MINIMUM_SUPPORTED_KEYS_IN_CSR,
        })
    } else {
        Err(km_err!(SecureHwCommunicationFailed, "0x{:X}", rsp.header.error_code))
    }
}
