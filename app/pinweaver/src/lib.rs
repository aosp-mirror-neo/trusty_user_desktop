/*
* Copyright (C) 2024 The Android Open Source Project
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

use crate::dispatcher::PinWeaverDispatcher;
use crate::service::PinWeaverService;
use crate::storage::{StorageClient, StorageClientService};
use binder::BinderFeatures;
use gsc_svc_client::GscServiceClient;
use pinweaver_api::aidl::IPinWeaver::BnPinWeaver;
use rpcbinder::RpcServer;
use std::rc::Rc;
use std::sync::Arc;
use tipc::{Manager, PortCfg};

mod dispatcher;
mod service;
mod storage;
#[cfg(test)]
mod tests;

const PORT_COUNT: usize = 2;
const CONNECTION_COUNT: usize = 4;

struct ProdDeps;
impl service::PinWeaverServiceDeps for ProdDeps {
    type Storage = StorageClient;
    type Gsc = GscServiceClient;
}

pub fn init_and_start_loop() -> tipc::Result<()> {
    trusty_log::init();
    let storage = Arc::new(StorageClient::default());
    let storage_service = StorageClientService::new(storage.clone());
    let gsc = Arc::new(GscServiceClient::default());

    let service = BnPinWeaver::new_binder(
        PinWeaverService::<ProdDeps>::new(storage, gsc),
        BinderFeatures::default(),
    );
    let rpc_server = RpcServer::new_per_session(move |_uuid| Some(service.as_binder()));

    let mut dispatcher =
        PinWeaverDispatcher::<PORT_COUNT>::new().expect("Dispatcher should be created");

    let service_cfg = PortCfg::new(pinweaver_api::PORT)
        .expect("Service port shouldn't contain nul")
        .allow_ta_connect();
    dispatcher
        .add_service(Rc::new(rpc_server), service_cfg)
        .expect("RPC service should add to dispatcher");

    let storage_cfg = PortCfg::new(pinweaver_storage_api::PORT)
        .expect("Storage port shouldn't contain nul")
        .allow_ns_connect();
    dispatcher
        .add_service(Rc::new(storage_service), storage_cfg)
        .expect("Storage service should add to dispatcher");

    Manager::<_, _, PORT_COUNT, CONNECTION_COUNT>::new_with_dispatcher(dispatcher, [])
        .expect("Service manager should be created")
        .run_event_loop()
}
