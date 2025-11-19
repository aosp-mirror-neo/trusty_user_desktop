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

//! Transliate Keymint operation related AIDLs to GSC strongbox RPCs.

use android_system_desktop_security_gsc::aidl::android::system::desktop::security::gsc::IGsc::IGsc;
use binder::Strong;
use kmr_common::Error;
use kmr_wire::{
    BeginRequest, BeginResponse, FinishRequest, FinishResponse, GetHardwareInfoRequest,
    GetHardwareInfoResponse, UpdateRequest, UpdateResponse,
};
use tpm_commands::strongbox::*;

use crate::do_rpc;

pub fn device_begin(
    request: BeginRequest,
    client: &Strong<dyn IGsc>,
) -> Result<BeginResponse, Error> {
    do_rpc::<begin::Request, begin::Response, BeginRequest, BeginResponse>(request, client)
}

pub fn device_get_hardware_info(
    request: GetHardwareInfoRequest,
    client: &Strong<dyn IGsc>,
) -> Result<GetHardwareInfoResponse, Error> {
    do_rpc::<
        get_hardware_info::Request,
        get_hardware_info::Response,
        GetHardwareInfoRequest,
        GetHardwareInfoResponse,
    >(request, client)
}

pub fn operation_update(
    request: UpdateRequest,
    client: &Strong<dyn IGsc>,
) -> Result<UpdateResponse, Error> {
    do_rpc::<update::Request, update::Response, UpdateRequest, UpdateResponse>(request, client)
}

pub fn operation_finish(
    request: FinishRequest,
    client: &Strong<dyn IGsc>,
) -> Result<FinishResponse, Error> {
    do_rpc::<finish::Request, finish::Response, FinishRequest, FinishResponse>(request, client)
}
