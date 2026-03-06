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
use tpm_commands::{
    get_device_ids, TpmInterface, TpmRequestMessage, TpmResponseHeader, TpmResponseMessage,
    TpmvRequest, TpmvRequestBuild,
};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub use tpm_commands::{
    self,
    trusty_storage_superblock_mac::{
        TrustyStorageFlags, TrustyStorageMac, TrustyStorageMacData, TrustyStorageMacFileIndex,
    },
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
    /// Tpm error.
    Tpm(u32),
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

    // TOOO: This is a temporary fix for a gsc_svc design problem. The gsc_svc
    // should be ready to accept commands when it is starts accepting connections.
    //
    /// Wait until `gsc_svc` is fully connected to the tpm by retrying a command
    /// and waiting.
    pub fn wait_for_gsc_svc(
        &self,
        delay: std::time::Duration,
        max_attempts: usize,
    ) -> Result<(), GscServiceClientError> {
        let mut attempt = 0;
        loop {
            if self
                .read_trusty_storage_superblock_mac(TrustyStorageMacFileIndex::TamperDetectPersist)
                .is_ok()
            {
                log::debug!("wait_for_gsc_svc: attempt {attempt} of {max_attempts} succeeded, delay {delay:?}");
                break Ok(());
            }

            attempt += 1;
            if attempt >= max_attempts {
                return Err(GscServiceClientError::ConnectError);
            }

            // SAFETY: `clock_id` and `flags` are both zero, as required by the `trusty_nanosleep`
            // docs.
            //
            // Ignore errors if sleeping fails, we'll bail out of this loop after `max_attempts` in
            // that case.
            unsafe {
                trusty_sys::nanosleep(0, 0, delay.as_nanos() as u64);
            }
        }
    }

    /// Get the superblock `mac` value stored on the GSC for a given `index`.
    pub fn read_trusty_storage_superblock_mac(
        &self,
        index: TrustyStorageMacFileIndex,
    ) -> Result<TrustyStorageMacData, GscServiceClientError> {
        use tpm_commands::trusty_storage_superblock_mac::{Request, Response};
        let response: Response = self.transmit(Request::new_read(index))?;

        Ok(response.data)
    }

    /// Set the superblock mac `data` value stored on the GSC for a given
    /// `index`.
    pub fn write_trusty_storage_superblock_mac(
        &self,
        index: TrustyStorageMacFileIndex,
        data: TrustyStorageMacData,
    ) -> Result<(), GscServiceClientError> {
        use tpm_commands::trusty_storage_superblock_mac::{Request, Response};
        let _: Response = self.transmit(Request::new_write(index, data))?;

        Ok(())
    }

    /// Uninitialize the superblock mac `data` value stored on the GSC for a
    /// given `index`. The seven lower `flags` bits will be preserved.
    pub fn delete_trusty_storage_superblock_mac(
        &self,
        index: TrustyStorageMacFileIndex,
    ) -> Result<(), GscServiceClientError> {
        use tpm_commands::trusty_storage_superblock_mac::{Request, Response};
        let _: Response = self.transmit(Request::new_delete(index))?;

        Ok(())
    }

    /// Get device IDs stored on the GSC
    pub fn get_device_ids(
        &self,
        subcommand: get_device_ids::Subcommand,
    ) -> Result<get_device_ids::Response, GscServiceClientError> {
        use get_device_ids::{Request, Response};
        let response: Response = self.transmit(Request { subcommand })?;

        Ok(response)
    }
}

impl TpmInterface for GscServiceClient {
    type Error = GscServiceClientError;

    /// Helper function to transmit a tpmv request and return a deserialized
    /// response type.
    fn transmit<Req: TpmvRequest, Rsp: FromBytes + KnownLayout + Immutable>(
        &self,
        request: Req,
    ) -> Result<Rsp, GscServiceClientError> {
        let request = TpmRequestMessage::<Req>::new(request);
        let bytes = self
            .0
            .transmit(request.as_bytes())
            .map_err(|_| GscServiceClientError::TransmitError)?;

        // Check for TPM errors
        let (header, _) = TpmResponseHeader::ref_from_prefix(&bytes).map_err(|err| {
            log::error!("transmit: ref_from_prefix failed: {err}");
            GscServiceClientError::Deserialization
        })?;
        if header.error_code != 0 {
            return Err(GscServiceClientError::Tpm(header.error_code.into()));
        }

        let response = TpmResponseMessage::<Rsp>::read_from_bytes(&bytes).map_err(|err| {
            log::error!("transmit: read_from_bytes failed: {err}");
            GscServiceClientError::Deserialization
        })?;

        Ok(response.response)
    }

    fn transmit_into<
        'a,
        Req: TpmvRequestBuild + ?Sized,
        Rsp: FromBytes + IntoBytes + KnownLayout + Immutable + Unaligned + ?Sized,
    >(
        &self,
        request: &tpm_commands::TpmRequestMessage<Req>,
        buffer: &'a mut Vec<u8>,
    ) -> Result<&'a mut Rsp, Self::Error> {
        let mut bytes = self
            .0
            .transmit(request.as_bytes())
            .map_err(|_| GscServiceClientError::TransmitError)?;

        // Check for TPM errors
        let (header, _) = TpmResponseHeader::ref_from_prefix(&bytes).map_err(|err| {
            log::error!("transmit_into: ref_from_prefix failed: {err}");
            GscServiceClientError::Deserialization
        })?;
        if header.error_code != 0 {
            return Err(GscServiceClientError::Tpm(header.error_code.into()));
        }
        std::mem::swap(&mut bytes, buffer);
        drop(bytes);

        let response = TpmResponseMessage::<Rsp>::mut_from_bytes(buffer).map_err(|err| {
            log::error!("transmit_into: read_from_bytes failed: {err}");
            GscServiceClientError::Deserialization
        })?;
        Ok(&mut response.response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    test::init!();

    #[test]
    fn send_bad_tpmv_request() {
        use zerocopy::*;
        #[derive(Default, IntoBytes, Immutable, Unaligned)]
        #[repr(C)]
        pub struct Request;

        #[derive(Debug, Eq, FromBytes, Immutable, KnownLayout, PartialEq, Unaligned)]
        #[repr(C)]
        pub struct Response;

        impl TpmvRequest for Request {
            const TAG: U16<BE> = U16::new(0x8001);
            const COMMAND_CODE: U16<BE> = U16::new(0x0004);
            const ORDINAL: U32<BE> = U32::new(0x20000000);
            type TpmvResponse = Response;
        }

        let client = GscServiceClient::new().unwrap();
        let res: Result<Response, GscServiceClientError> = client.transmit(Request);
        assert!(res.is_err());

        // TODO(mvertescher): Resolve differences between Ti50/Cr50
        // assert_eq!(Err(GscServiceClientError::Tpm(0x508)), res);
    }

    #[test]
    fn read_trusty_storage_superblock_mac() {
        let client = GscServiceClient::new().unwrap();
        let tdp = TrustyStorageMacFileIndex::TamperDetectPersist;
        let td = TrustyStorageMacFileIndex::TamperDetectPersist;

        let rsp = client.read_trusty_storage_superblock_mac(tdp).unwrap();
        log::info!("TamperDetectPersist: {:x?}", rsp);
        let rsp = client.read_trusty_storage_superblock_mac(td).unwrap();
        log::info!("TamperDetect: {:x?}", rsp);
    }

    // This test is destructive so it is disabled by default.
    // #[test]
    #[allow(dead_code)]
    fn write_trusty_storage_superblock_mac() {
        let client = GscServiceClient::new().unwrap();
        let index = TrustyStorageMacFileIndex::TamperDetectPersist;

        // Reset mac storage
        let empty_data = TrustyStorageMacData::default();
        let res = client.write_trusty_storage_superblock_mac(index, empty_data);
        assert_eq!(Ok(()), res);
        let res = client.delete_trusty_storage_superblock_mac(index);
        assert_eq!(Ok(()), res);
        let res = client.read_trusty_storage_superblock_mac(index);
        assert_eq!(Ok(empty_data), res);

        // Verify that 0x80 bit is set on write
        let data = TrustyStorageMacData {
            mac: TrustyStorageMac([0xabu8; 16]),
            flags: TrustyStorageFlags(0x43),
        };
        let res = client.write_trusty_storage_superblock_mac(index, data);
        assert_eq!(Ok(()), res);
        let expected =
            TrustyStorageMacData { mac: data.mac, flags: TrustyStorageFlags(0x80 | data.flags.0) };
        let res = client.read_trusty_storage_superblock_mac(index);
        assert_eq!(Ok(expected), res);

        // Verify that flags 0x7f are preserved when delete is called
        let res = client.delete_trusty_storage_superblock_mac(index);
        assert_eq!(Ok(()), res);
        let expected = TrustyStorageMacData { mac: TrustyStorageMac::default(), flags: data.flags };
        let res = client.read_trusty_storage_superblock_mac(index);
        assert_eq!(Ok(expected), res);
    }

    // This test is destructive so it is disabled by default.
    // #[test]
    #[allow(dead_code)]
    fn delete_trusty_storage_superblock_macs() {
        let client = GscServiceClient::new().unwrap();
        let tdp = TrustyStorageMacFileIndex::TamperDetectPersist;
        let td = TrustyStorageMacFileIndex::TamperDetectPersist;

        client.delete_trusty_storage_superblock_mac(td).unwrap();
        client.delete_trusty_storage_superblock_mac(tdp).unwrap();

        let rsp = client.read_trusty_storage_superblock_mac(tdp).unwrap();
        log::info!("TamperDetectPersist: {:x?}", rsp);
        let rsp = client.read_trusty_storage_superblock_mac(td).unwrap();
        log::info!("TamperDetect: {:x?}", rsp);
    }
}
