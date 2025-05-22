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

mod crypto;
mod error;
mod keymint;
mod rng;
mod service;
mod storage;

use crate::service::FingerGuardService;
use binder::BinderFeatures;
use fingerguard_api::aidl::IFingerGuard::BnFingerGuard;
use rpcbinder::RpcServer;
use std::rc::Rc;
use tipc::{Manager, PortCfg};

// The port on FingerGuard TA which the Fingerprint sensor HAL connects to.
const APP_SERVICE_PORT: &str = "com.android.trusty.rust.FingerGuard.V1";

const PORT_COUNT: usize = 1;
const CONNECTION_COUNT: usize = 1;

tipc::service_dispatcher! {
    enum FingerGuardDispatcher {
        RpcServer
    }
}
pub fn init_and_start_loop() -> tipc::Result<()> {
    trusty_log::init();

    let mut dispatcher =
        FingerGuardDispatcher::<PORT_COUNT>::new().expect("Could not create dispatcher");
    let service = FingerGuardService::new();
    let binder_service = BnFingerGuard::new_binder(service, BinderFeatures::default());
    let rpc_service = RpcServer::new_per_session(move |_uuid| Some(binder_service.as_binder()));

    // Allow secure (within trusty) and non-secure (outside trusty) connections.
    // Originally only intended for non-secure connections, now allowed secure connection as well
    // to facilitate the unit tests within the trusty environment.
    let app_cfg = PortCfg::new(APP_SERVICE_PORT)
        .expect("Could not create port config")
        .allow_ta_connect()
        .allow_ns_connect();
    dispatcher
        .add_service(Rc::new(rpc_service), app_cfg)
        .expect("Could not add FingerGuardService to dispatcher");

    // <_, _, 1, 1> means we define a Manager with a single port, and max one connection.
    Manager::<_, _, PORT_COUNT, CONNECTION_COUNT>::new_with_dispatcher(dispatcher, [])
        .expect("Could not create service manager")
        .run_event_loop()
        .expect("FingerGuard event loop failed");

    Ok(())
}
