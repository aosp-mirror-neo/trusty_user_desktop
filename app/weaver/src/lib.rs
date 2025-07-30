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

use crate::errors::WeaverTAError;
use log::error;
use log::info;
use service::start_tipc_service;

mod errors;
mod message;
mod service;

pub fn init_and_start_loop() -> Result<(), WeaverTAError> {
    trusty_log::init();

    info!("Started Weaver");

    start_tipc_service().map_err(|e| {
        error!("Error when starting Weaver TA: {:?}", e);
        e
    })?;

    Ok(())
}
