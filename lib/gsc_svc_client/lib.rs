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
use rpcbinder::RpcSession;
use std::ffi::CStr;
use tpm_commands::TpmvRequest;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub use tpm_commands::trusty_storage_superblock_mac::{
    TrustyStorageMac, TrustyStorageMacFileIndex,
};

const GSC_SERVICE_PORT: &CStr = c"com.android.trusty.rust.GscAppService.V1";

/// Possible client errors.
#[derive(Debug, Eq, PartialEq)]
pub enum GscServiceClientError {
    /// Error connecting to the GSC service.
    ConnectError,
    /// Error when transacting with the GSC service.
    TransmitError,
    /// Message processing error.
    Deserialization,
}

fn get_service(port: &CStr) -> Result<Strong<dyn IGsc>, GscServiceClientError> {
    RpcSession::new().setup_trusty_client(port).map_err(|_| GscServiceClientError::ConnectError)
}

/// Client connected to the GSC service.
pub struct GscServiceClient(pub Strong<dyn IGsc>);

impl Default for GscServiceClient {
    fn default() -> Self {
        Self(get_service(GSC_SERVICE_PORT).unwrap())
    }
}

impl GscServiceClient {
    /// Create a new GSC service client. This method will attempt to connect to
    /// the service.
    pub fn new() -> Result<Self, GscServiceClientError> {
        Ok(Self(get_service(GSC_SERVICE_PORT)?))
    }

    /// Get the superblock `mac` value stored on the GSC for a given `index`.
    pub fn read_trusty_storage_superblock_mac(
        &self,
        index: TrustyStorageMacFileIndex,
    ) -> Result<TrustyStorageMac, GscServiceClientError> {
        use tpm_commands::trusty_storage_superblock_mac::{Request, Response};
        let response: Response = self.transmit(Request::new_read(index))?;

        Ok(response.mac)
    }

    /// Set the superblock `mac` value stored on the GSC for a given `index`.
    pub fn write_trusty_storage_superblock_mac(
        &self,
        index: TrustyStorageMacFileIndex,
        mac: TrustyStorageMac,
    ) -> Result<(), GscServiceClientError> {
        use tpm_commands::trusty_storage_superblock_mac::{Request, Response};
        let _: Response = self.transmit(Request::new_write(index, mac))?;

        Ok(())
    }

    /// Helper function to transmit a tpmv request and return a deserialized
    /// response type.
    fn transmit<Req: TpmvRequest, Rsp: FromBytes + KnownLayout + Immutable>(
        &self,
        request: Req,
    ) -> Result<Rsp, GscServiceClientError> {
        use tpm_commands::{TpmRequestMessage, TpmResponseMessage};
        let request = TpmRequestMessage::<Req>::new(request);
        let bytes = self
            .0
            .transmit(request.as_bytes())
            .map_err(|_| GscServiceClientError::TransmitError)?;
        let response = TpmResponseMessage::<Rsp>::read_from_bytes(&bytes)
            .map_err(|_| GscServiceClientError::Deserialization)?;

        Ok(response.response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    test::init!();

    #[test]
    fn read_trusty_storage_superblock_mac() {
        let client = GscServiceClient::new().unwrap();
        let index = TrustyStorageMacFileIndex::TamperDetectPersist;
        client.read_trusty_storage_superblock_mac(index).unwrap();
    }

    // This test is destructive so it is disabled by default.
    // #[test]
    #[allow(dead_code)]
    fn write_trusty_storage_superblock_mac() {
        let client = GscServiceClient::new().unwrap();
        let index = TrustyStorageMacFileIndex::TamperDetectPersist;
        let mac = TrustyStorageMac([0u8; 16]);

        let res = client.read_trusty_storage_superblock_mac(index);
        assert_eq!(Ok(mac), res);

        let mac = TrustyStorageMac([2u8; 16]);
        let res = client.write_trusty_storage_superblock_mac(index, mac);
        assert_eq!(Ok(()), res);

        let res = client.read_trusty_storage_superblock_mac(index);
        assert_eq!(Ok(mac), res);
    }
}
