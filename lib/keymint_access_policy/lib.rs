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
//! The library implementing the generic access policy for Keymint Rust.
//! This originates from a replication of `trusty/user/app/keymint/generic_access_policy`.
//! It contains desktop specific modifications.

use tipc::Uuid;

pub const KEYMINT_ACCESSIBLE_UUIDS: [Uuid; 11] = [
    /* gatekeeper uuid */
    Uuid::new(0x38ba0cdc, 0xdf0e, 0x11e4, [0x98, 0x69, 0x23, 0x3f, 0xb6, 0xae, 0x47, 0x95]),
    /* confirmation UI uuid */
    Uuid::new(0x7dee2364, 0xc036, 0x425b, [0xb0, 0x86, 0xdf, 0x0f, 0x6c, 0x23, 0x3c, 0x1b]),
    /* keymaster unit test uuid */
    Uuid::new(0xf3ba7629, 0xe8cc, 0x44a0, [0x88, 0x4d, 0xf9, 0x16, 0xf7, 0x03, 0xa2, 0x00]),
    /* keymint unit test uuid */
    Uuid::new(0xd322eec9, 0x6d03, 0x49fa, [0x82, 0x1c, 0x1c, 0xcd, 0x27, 0x05, 0x71, 0x9c]),
    /* finger_guard trusty app uuid */
    Uuid::new(0x0c997054, 0xf477, 0x4cab, [0x96, 0x46, 0x46, 0x29, 0xe3, 0x4c, 0xb2, 0xf9]),
    /* finger_guard unit test uuid */
    Uuid::new(0x868899c6, 0xe820, 0x4cc0, [0xa8, 0x19, 0x11, 0x56, 0x5f, 0xfa, 0x8a, 0x45]),
    /* gsc_svc trusty app uuid */
    Uuid::new(0x77026d06, 0xbe0f, 0x4604, [0xa6, 0xd5, 0xf7, 0x29, 0x38, 0x8a, 0x44, 0x5b]),
    /* gsc_svc unit test uuid */
    Uuid::new(0x01b7938e, 0xabdd, 0x4e35, [0x93, 0x95, 0xc6, 0xb9, 0xb4, 0xdd, 0x82, 0x81]),
    /* keymint_legacy_client uuid */
    Uuid::new(0xf23a14c3, 0x9f99, 0x4481, [0xae, 0x41, 0x54, 0xe9, 0x62, 0x7d, 0xef, 0xbe]),
    /* keymint_provisioning trusty app uuid */
    Uuid::new(0x17ef817e, 0x35d9, 0x4e0a, [0xab, 0x2a, 0x78, 0xf8, 0xcc, 0x44, 0xec, 0xce]),
    /* vm_rkp trusty app uuid */
    Uuid::new(0x598c7f41, 0x167b, 0x4df6, [0x9c, 0xc3, 0x44, 0x91, 0xb1, 0x19, 0xd3, 0x35]),
];

pub fn keymint_check_secure_target_access_policy_provisioning(uuid: &Uuid) -> bool {
    const GSC_SVC_UUID: &Uuid = &KEYMINT_ACCESSIBLE_UUIDS[6];
    const GSC_SVC_UT_UUID: &Uuid = &KEYMINT_ACCESSIBLE_UUIDS[7];
    const KM_CLIENT_UUID: &Uuid = &KEYMINT_ACCESSIBLE_UUIDS[8];
    const KM_PROVISIONING_UUID: &Uuid = &KEYMINT_ACCESSIBLE_UUIDS[9];
    const RKP_TA_UUID: &Uuid = &KEYMINT_ACCESSIBLE_UUIDS[10];

    if uuid == GSC_SVC_UUID
        || uuid == GSC_SVC_UT_UUID
        || uuid == KM_CLIENT_UUID
        || uuid == KM_PROVISIONING_UUID
        || uuid == RKP_TA_UUID
    {
        return true;
    }
    /* Not Supported */
    return false;
}
