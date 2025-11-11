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

mod keymint_provisioning_service;
mod proto;

use rpcbinder::RpcServer;
use std::rc::Rc;
use tipc::{service_dispatcher, wrap_service, Manager, PortCfg, TipcError};

const KM_PROVISIONING_SERVICE_PORT: &str = "com.android.trusty.rust.KeyMintProvisioningService.V1";

wrap_service!(KeyMintProvisioningService(RpcServer: UnbufferedService));

service_dispatcher! {
    enum KeyMintProvisioningServiceDispatcher {
        KeyMintProvisioningService,
    }
}

const PORT_COUNT: usize = 1;
const MAX_CONNECTION_COUNT: usize = 1;

pub fn init_and_start_loop() -> Result<(), TipcError> {
    trusty_log::init();

    let mut dispatcher = KeyMintProvisioningServiceDispatcher::<PORT_COUNT>::new()
        .expect("Could not create dispatcher");
    let km_provisioning_cfg = PortCfg::new(KM_PROVISIONING_SERVICE_PORT)
        .expect("Could not create port config")
        .allow_ns_connect();
    let km_provisioning = keymint_provisioning_service::create_service();
    let km_provisioning_rpc_server =
        RpcServer::new_per_session(move |_uuid| Some(km_provisioning.as_binder()));
    dispatcher
        .add_service(
            Rc::new(KeyMintProvisioningService(km_provisioning_rpc_server)),
            km_provisioning_cfg,
        )
        .expect("Could not add keymint provisioning service to dispatcher");

    Manager::<_, _, PORT_COUNT, MAX_CONNECTION_COUNT>::new_with_dispatcher(dispatcher, [])
        .expect("Could not create service manager")
        .run_event_loop()
        .expect("Keymint Provisioning app event loop failed");

    Ok(())
}
