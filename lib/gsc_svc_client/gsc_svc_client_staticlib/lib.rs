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

//! GSC service client C interface implementation
//!
//! To generate a new header file from this interface:
//!
//! ```shell
//! $ cbindgen lib.rs --output include/lib/gsc_svc/gsc_svc.h
//! ```

use libc::c_int;

use gsc_svc_client::{
    GscServiceClient, TrustyStorageFlags, TrustyStorageMac, TrustyStorageMacData,
    TrustyStorageMacFileIndex,
};
use static_assertions::const_assert_eq;
use zerocopy::TryFromBytes;

/// Tamper detect persist file index
pub const GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP: u8 = 1;

/// Tamper detect file index
pub const GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD: u8 = 2;

// Supported superblock MAC file constants should match
// `TrustyStorageMacFileIndex` values. We don't directly reference the enum so
// cbindgen can cleanly generate C defines without knowing about Rust
// dependencies.
const_assert_eq!(
    TrustyStorageMacFileIndex::TamperDetectPersist as u8,
    GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP
);
const_assert_eq!(
    TrustyStorageMacFileIndex::TamperDetect as u8,
    GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD
);

/// Reads the super block mac `data` from the GSC for a specific `index`.
///
/// Returns `0` on success and `-1` on failure.
#[no_mangle]
pub extern "C" fn gsc_svc_client_super_block_mac_read(
    index: u8,
    flags: &mut u8,
    mac: &mut [u8; 16],
) -> c_int {
    let Ok(index) = TrustyStorageMacFileIndex::try_read_from_bytes(&[index]) else {
        return -1;
    };

    let Ok(client) = GscServiceClient::new() else {
        return -1;
    };

    let Ok(data) = client.read_trusty_storage_superblock_mac(index) else {
        return -1;
    };
    *mac = data.mac.0;
    *flags = data.flags.0;

    0
}

/// Writes the super block mac `data` to the GSC for a specific `index`.
///
/// Returns `0` on success and `-1` on failure.
#[no_mangle]
pub extern "C" fn gsc_svc_client_super_block_mac_write(
    index: u8,
    flags: u8,
    mac: &[u8; 16],
) -> c_int {
    let mac = TrustyStorageMac(*mac);
    let Ok(index) = TrustyStorageMacFileIndex::try_read_from_bytes(&[index]) else {
        return -1;
    };

    let Ok(client) = GscServiceClient::new() else {
        return -1;
    };

    let data = TrustyStorageMacData { mac, flags: TrustyStorageFlags(flags) };
    let Ok(_) = client.write_trusty_storage_superblock_mac(index, data) else {
        return -1;
    };

    0
}

/// Delete a super block `mac` from the GSC for a specific `index`.
///
/// The seven least significant flags bits will be preserved through a delete
/// call.
///
/// Returns `0` on success and `-1` on failure.
#[no_mangle]
pub extern "C" fn gsc_svc_client_super_block_mac_delete(index: u8) -> c_int {
    let Ok(index) = TrustyStorageMacFileIndex::try_read_from_bytes(&[index]) else {
        return -1;
    };

    let Ok(client) = GscServiceClient::new() else {
        return -1;
    };

    let Ok(_) = client.delete_trusty_storage_superblock_mac(index) else {
        return -1;
    };

    0
}
