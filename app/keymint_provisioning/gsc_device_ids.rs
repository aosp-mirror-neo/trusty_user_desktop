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

//! Logic to provision device ids from the GSC directly

use gsc_svc_client::tpm_commands::get_device_ids::Subcommand;
use gsc_svc_client::GscServiceClient;
use keymint_legacy_client::KeyMintSecureLegacyClient;
use kmr_wire::legacy::SetAttestationIdsRequest;
use log::error;
use tipc::TipcError;

/// Set device ids in keymint by reading them from the gsc using a tpmv command
pub fn provision_device_ids_from_gsc() -> Result<(), TipcError> {
    log::info!("provision_device_ids_from_gsc: called");

    let client = GscServiceClient::new().map_err(|e| {
        error!("failed to connect to gsc_svc: {e:?}");
        TipcError::UnknownError
    })?;

    // Since this runs early in the boot process, we need to wait for the gsc_svc
    // to be ready.
    client.wait_for_gsc_svc(std::time::Duration::from_secs(1), 10).map_err(|e| {
        error!("failed to wait for gsc_svc: {e:?}");
        TipcError::UnknownError
    })?;

    let device_ids = client.get_device_ids(Subcommand::Info).map_err(|e| {
        error!("failed to get device ids from gsc: {e:?}");
        TipcError::UnknownError
    })?;

    // TODO: Support printing long strings in Trusty log messages, for now just
    // print small lines.
    log::info!(
        "provision_device_ids_from_gsc: brand: {}, device: {}, product: {}",
        device_ids.brand,
        device_ids.device,
        device_ids.product
    );
    log::info!(
        "provision_device_ids_from_gsc: serial: {}, manufacturer: {}, model: {}",
        device_ids.serial,
        device_ids.manufacturer,
        device_ids.model
    );

    let mut ids: SetAttestationIdsRequest = device_ids.into();
    // TODO(b/466129461): Choose a dedicated value for AL devices without cellular
    ids.imei = b"867400022047199".to_vec();

    // Device id workarounds for mis-provisioned GSCs to fix attestation. We can't fix this on the
    // GSC side since they're programmed into a write once info page. So, we use this as a very
    // temporary solution for test devices.
    #[allow(clippy::single_match)]
    match (ids.device.as_slice(), ids.manufacturer.as_slice(), ids.model.as_slice()) {
        // lapis EVT devices
        (b"lapis", b"Asus", b"CX9406CAA") => {
            ids.manufacturer = b"ASUS".to_vec();
            ids.model = b"CX9406CAA_CB9406CAA".to_vec();
        }
        _ => {}
    }

    let mut km = KeyMintSecureLegacyClient::new().map_err(|e| {
        error!("failed to create KeyMint legacy client: {e}");
        TipcError::UnknownError
    })?;

    km.set_attestation_ids(ids).map_err(|e| {
        error!("Failed to set attestation IDs: {e}");
        TipcError::UnknownError
    })?;

    log::info!("provision_device_ids_from_gsc: success");

    Ok(())
}
