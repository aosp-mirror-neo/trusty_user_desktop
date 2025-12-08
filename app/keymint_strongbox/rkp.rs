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
use kmr_wire::{
    GenerateCertificateRequestV2Request, GenerateCertificateRequestV2Response,
    GenerateEcdsaP256KeyPairRequest, GenerateEcdsaP256KeyPairResponse,
};
use tpm_commands::strongbox::*;
use tpm_commands::{TpmRequestMessage, TpmResponseHeader, TpmResponseMessage};
use zerocopy::{FromBytes, IntoBytes};

use crate::do_rpc;

pub fn generate_certificate_request_v2(
    request: GenerateCertificateRequestV2Request,
    device_info: Vec<u8>,
    client: &Strong<dyn IGsc>,
) -> Result<GenerateCertificateRequestV2Response, Error> {
    do_rpc::<
        generate_certificate_request_v2::Request,
        generate_certificate_request_v2::Response,
        generate_certificate_request_v2::RequestBuildParams,
        GenerateCertificateRequestV2Response,
    >(generate_certificate_request_v2::RequestBuildParams { request, device_info }, client)
}

pub fn generate_ecdsa_p256_keypair(
    request: GenerateEcdsaP256KeyPairRequest,
    client: &Strong<dyn IGsc>,
) -> Result<GenerateEcdsaP256KeyPairResponse, Error> {
    do_rpc::<
        generate_ecdsa_p256_keypair::Request,
        generate_ecdsa_p256_keypair::Response,
        GenerateEcdsaP256KeyPairRequest,
        GenerateEcdsaP256KeyPairResponse,
    >(request, client)
}

pub fn _get_dice_chain(client: &Strong<dyn IGsc>) -> Result<Vec<u8>, Error> {
    let cmd = TpmRequestMessage::new(get_dice_chain::Request {});
    let rsp =
        client.transmit(cmd.as_bytes()).map_err(|_| km_err!(SecureHwCommunicationFailed, ""))?;
    let rsp = TpmResponseMessage::<get_dice_chain::Response>::ref_from_bytes(&rsp)
        .map_err(|_| km_err!(SecureHwCommunicationFailed, ""))?;
    if rsp.header.error_code == 0 {
        let len = rsp.header.length.get() as usize - core::mem::size_of::<TpmResponseHeader>();
        Ok(rsp.response.data[..len].to_vec())
    } else {
        Err(km_err!(SecureHwCommunicationFailed, "0x{:X}", rsp.header.error_code))
    }
}
