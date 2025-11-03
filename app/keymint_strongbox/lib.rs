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

//! This library implements the functionality used by the KeyMint Strongbox
//! Trusty application.

use alloc::{rc::Rc, vec::Vec};
use core::{cell::RefCell, fmt};
use kmr_common::{km_err, Error, ErrorKind, ErrorLocation};
use kmr_ta::{HardwareInfo, RpcInfo, RpcInfoV3};
use log::{error, trace};
use tipc::{
    service_dispatcher, ConnectResult, Deserialize, Handle, Manager, MessageResult, PortCfg,
    Serialize, Serializer, Service, TipcError, Uuid,
};
use trusty_std::alloc::TryAllocFrom;

#[cfg(fake_strongbox)]
mod fake_sb;

mod rkp;
mod strongbox;
use strongbox::StrongBox;

/// Port that handles new style keymint messages from non-secure world
const KM_NS_TIPC_SRV_PORT: &str = "com.android.trusty.keymint.strongbox";

/// Port count for this TA (as above).
const PORT_COUNT: usize = 1;

/// Only one connection: non-secure world hal.
const MAX_CONNECTION_COUNT: usize = 1;

fn log_error(msg: fmt::Arguments, location: Option<ErrorLocation>) {
    match location {
        Some(l) => error!("Error: {msg} ({}:{})", l.file, l.line),
        None => error!("Error: {msg}"),
    };
}

fn log_formatter(record: &log::Record) -> String {
    // line number should be present, so keeping it simple by just returning a 0.
    let line = record.line().unwrap_or(0);
    let file = record.file().unwrap_or("unknown file");
    format!("{}: {}:{} {}\n", record.level(), file, line, record.args())
}

pub fn start() {
    #[cfg(fake_strongbox)]
    fake_sb::start();

    #[cfg(not(fake_strongbox))]
    start_impl();
}

#[allow(dead_code)]
fn start_impl() {
    let config = trusty_log::TrustyLoggerConfig::default()
        .with_min_level(log::Level::Trace)
        .format(log_formatter);
    trusty_log::init_with_config(config);

    log::warn!("Hello from KeyMint StrongBox TA!");

    // TODO(b/449803592): Fill in the correct info
    let hw_info = HardwareInfo {
        version_number: 3,
        security_level: kmr_common::wire::keymint::SecurityLevel::Strongbox,
        impl_name: "TEE KeyMint strongbox",
        author_name: "Google",
        unique_id: "TEE KeyMint strongbox",
    };

    // TODO(b/449803592): Fill in the correct info
    let rpc_info_v3 = RpcInfoV3 {
        author_name: "Google",
        unique_id: "TEE KeyMint strongbox TA",
        fused: false,
        supported_num_of_keys_in_csr: kmr_wire::rpc::MINIMUM_SUPPORTED_KEYS_IN_CSR,
    };

    handle_port_connections(hw_info, RpcInfo::V3(rpc_info_v3))
        .expect("handle_port_connections returned an error");
}

const KEYMINT_MAX_BUFFER_LENGTH: usize = 4096;
const KEYMINT_MAX_MESSAGE_CONTENT_SIZE: usize = 4000;

service_dispatcher! {
    enum KMServiceDispatcher {
        KMService,
    }
}

/// Main loop handler for the KeyMint TA.
pub fn handle_port_connections(_hw_info: HardwareInfo, _rpc_info: RpcInfo) -> Result<(), Error> {
    let sb_ta = Rc::new(RefCell::new(StrongBox::default()));
    let ns_service = KMService::new(sb_ta);

    let mut dispatcher = KMServiceDispatcher::<3>::new()
        .map_err(|e| km_err!(UnknownError, "could not create multi-service dispatcher: {:?}", e))?;
    let cfg = PortCfg::new(KM_NS_TIPC_SRV_PORT)
        .map_err(|e| {
            km_err!(
                UnknownError,
                "could not create port config for {}: {:?}",
                KM_NS_TIPC_SRV_PORT,
                e
            )
        })?
        .allow_ns_connect();
    dispatcher.add_service(Rc::new(ns_service), cfg).map_err(|e| {
        km_err!(UnknownError, "could not add non-secure service to dispatcher: {:?}", e)
    })?;

    let buffer = [0u8; 4096];
    let manager =
        Manager::<_, _, PORT_COUNT, MAX_CONNECTION_COUNT>::new_with_dispatcher(dispatcher, buffer)
            .map_err(|e| km_err!(UnknownError, "could not create service manager: {:?}", e))?;
    manager
        .run_event_loop()
        .map_err(|e| km_err!(UnknownError, "service manager received error: {:?}", e))?;
    Err(km_err!(SecureHwCommunicationFailed, "KeyMint TA handler terminated unexpectedly."))
}

/// TIPC service implementation for communication with the HAL service in Android.
struct KMService {
    sb_ta: Rc<RefCell<StrongBox>>,
}

impl KMService {
    /// Create a service implementation.
    fn new(sb_ta: Rc<RefCell<StrongBox>>) -> Self {
        KMService { sb_ta }
    }

    /// Process an incoming request message, returning the response as a collection of fragments
    /// that are each small enough to send over the channel.
    fn handle_message(&self, req_data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let resp = self.sb_ta.borrow_mut().process(req_data);
        kmr_ta::split_rsp(resp.as_slice(), KEYMINT_MAX_MESSAGE_CONTENT_SIZE)
    }
}

impl Service for KMService {
    type Connection = Context;
    type Message = KMMessage;

    fn on_connect(
        &self,
        _port: &PortCfg,
        _handle: &Handle,
        peer: &Uuid,
    ) -> tipc::Result<ConnectResult<Self::Connection>> {
        trace!("KeyMint Strongbox TA: Accepted connection from uuid {peer:?}.");
        Ok(ConnectResult::Accept(Context { uuid: *peer }))
    }

    fn on_message(
        &self,
        connection: &Self::Connection,
        handle: &Handle,
        msg: Self::Message,
    ) -> tipc::Result<MessageResult> {
        trace!("KeyMint Strongbox TA: received a message from {:?}.", connection.uuid);
        let resp_vec = self.handle_message(&msg.0).map_err(|e| match e.kind() {
            ErrorKind::Hal(_, msg) => {
                log_error(format_args!("{msg} in handling the message"), e.location());
                TipcError::InvalidData
            }
            ErrorKind::Alloc(msg) => {
                log_error(format_args!("{msg} in handling the message"), e.location());
                TipcError::AllocError
            }
            _ => TipcError::UnknownError,
        })?;
        for resp in resp_vec {
            handle.send(&KMMessage(resp))?;
        }
        Ok(MessageResult::MaintainConnection)
    }
}

/// TIPC connection context information.
#[derive(Debug)]
struct Context {
    uuid: Uuid,
}

/// Newtype wrapper for opaque messages.
struct KMMessage(Vec<u8>);

impl Deserialize for KMMessage {
    type Error = TipcError;
    const MAX_SERIALIZED_SIZE: usize = KEYMINT_MAX_BUFFER_LENGTH;

    fn deserialize(bytes: &[u8], _handles: &mut [Option<Handle>]) -> tipc::Result<Self> {
        Ok(KMMessage(Vec::try_alloc_from(bytes)?))
    }
}

impl<'s> Serialize<'s> for KMMessage {
    fn serialize<'a: 's, S: Serializer<'s>>(
        &'a self,
        serializer: &mut S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gsc_svc_client::GscServiceClient;
    test::init!();

    #[test]
    fn get_hardware_info() {
        let tpm = GscServiceClient::default().0;
        rkp::get_hardware_info(&tpm).unwrap();
    }

    #[test]
    fn generate_key() {
        let tpm = GscServiceClient::default().0;
        rkp::generate_ecdsa_p256_keypair(&tpm).unwrap();
    }

    #[test]
    fn get_dice_chain() {
        let tpm = GscServiceClient::default().0;
        rkp::_get_dice_chain(&tpm).unwrap();
    }
}
