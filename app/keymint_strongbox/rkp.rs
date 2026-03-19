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

use ciborium::Value;
use kmr_ta::rkp::serialize_cbor;
use kmr_wire::read_to_value;
use kmr_wire::rpc::AUTH_REQ_SCHEMA_V1;

use crate::do_rpc;

pub fn generate_certificate_request_v2(
    request: GenerateCertificateRequestV2Request,
    device_info: Vec<u8>,
    client: &Strong<dyn IGsc>,
) -> Result<GenerateCertificateRequestV2Response, Error> {
    let res = do_rpc::<
        generate_certificate_request_v2::Request,
        generate_certificate_request_v2::Response,
        generate_certificate_request_v2::RequestBuildParams,
        GenerateCertificateRequestV2Response,
    >(
        generate_certificate_request_v2::RequestBuildParams { request, device_info },
        client,
    )?;

    log::warn!("signed_data_cbor: len {}", res.ret.len());
    for chunk in res.ret.chunks(100) {
        log::warn!("  {:02x?}", chunk);
    }

    let signed_data_cbor: Value = ciborium::from_reader(res.ret.as_slice()).unwrap();
    assert!(signed_data_cbor.is_array());
    log::warn!("signed_data_cbor is an array");

    let dice_cert_chain = read_to_value(&get_dice_chain(client)?)?;

    // Construct `UdsCerts` as an empty CBOR map if not exist
    let uds_certs = match crate::fake_sb::secure_storage_manager::read_uds_cert() {
        Ok(uds_certs) => {
            let encoded_certs = uds_certs
                .into_iter()
                .map(|cert| Value::Bytes(cert.encoded_certificate))
                .collect::<Vec<_>>();
            serialize_cbor(&Value::Map(vec![(
                Value::Text(desktop_keymint::uds_signer_name().to_string()),
                Value::Array(encoded_certs),
            )]))
        }
        Err(err) => {
            log::warn!("Failed to read UDS certificates: {err:?}");
            serialize_cbor(&Value::Map(Vec::new()))
        }
    }?;
    let uds_certs = read_to_value(&uds_certs)?;

    // Construct `AuthenticatedRequest<CsrPayload>`
    let authn_req = Value::Array(vec![
        Value::Integer(AUTH_REQ_SCHEMA_V1.into()),
        uds_certs,
        dice_cert_chain,
        signed_data_cbor,
    ]);
    let authn_req = serialize_cbor(&authn_req)?;

    Ok(GenerateCertificateRequestV2Response { ret: authn_req })
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

pub fn get_dice_chain(client: &Strong<dyn IGsc>) -> Result<Vec<u8>, Error> {
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
