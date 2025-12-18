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

#![allow(dead_code)]

use alloc::{rc::Rc, vec::Vec};
use core::{cell::RefCell, fmt};
use keymint::{CertSignInfo, TrustyKeys, TrustyMonotonicClock, TrustyRng, TrustyRpc};
use kmr_common::{crypto, km_err, Error, ErrorKind, ErrorLocation};
use kmr_ta::{HardwareInfo, KeyMintTa, RpcInfo, RpcInfoV3};
use kmr_wire::legacy::{
    self, AppendUdsCertificateResponse, ClearUdsCertificateResponse, TrustyMessageId,
    TrustyPerformOpReq, TrustyPerformOpRsp,
};
use log::{debug, error, trace};
use tipc::{
    service_dispatcher, ConnectResult, Deserialize, Handle, Manager, MessageResult, PortCfg,
    Serialize, Serializer, Service, TipcError, Uuid,
};
use trusty_std::alloc::TryAllocFrom;

#[allow(warnings)]
mod keymaster_attributes;
pub mod secure_storage_manager;

/// Port that handles new style keymint messages from non-secure world
const KM_NS_TIPC_SRV_PORT: &str = "com.android.trusty.keymint.strongbox";

/// Port that handles legacy style keymint/keymaster messages
const KM_NS_LEGACY_TIPC_SRV_PORT: &str = "com.android.trusty.keymaster.strongbox";

/// Port count for this TA (as above).
const PORT_COUNT: usize = 2;

/// Maximum connection count for this TA:
/// - udsattestation
/// - non-secure world hal
const MAX_CONNECTION_COUNT: usize = 2;

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
    format!("fake strongbox: {}: {}:{} {}\n", record.level(), file, line, record.args())
}

pub fn start() {
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

    let rng = TrustyRng;
    let clock = TrustyMonotonicClock;
    let imp = kmr_crypto_boring::implementation(Box::new(rng), Box::new(clock));

    let dev = kmr_ta::device::Implementation {
        keys: Box::new(TrustyKeys),
        sign_info: Some(Box::new(CertSignInfo)),
        attest_ids: None,
        sdd_mgr: None,
        bootloader: Box::new(kmr_ta::device::BootloaderDone),
        sk_wrapper: None,
        tup: Box::new(kmr_ta::device::TrustedPresenceUnsupported),
        legacy_key: None,
        rpc: Box::new(TrustyRpc::new(&mut TrustyRng)),
    };

    handle_port_connections(hw_info, RpcInfo::V3(rpc_info_v3), imp, dev)
        .expect("handle_port_connections returned an error");
}

const KEYMINT_MAX_BUFFER_LENGTH: usize = 4096;
const KEYMINT_MAX_MESSAGE_CONTENT_SIZE: usize = 4000;

service_dispatcher! {
    enum KMServiceDispatcher {
        KMService,
        KMLegacyService,
    }
}

/// Main loop handler for the KeyMint TA.
pub fn handle_port_connections(
    hw_info: HardwareInfo,
    rpc_info: RpcInfo,
    imp: crypto::Implementation,
    dev: kmr_ta::device::Implementation,
) -> Result<(), Error> {
    let km_ta = Rc::new(RefCell::new(KeyMintTa::new(hw_info, rpc_info, imp, dev)));
    let ns_service = KMService::new(Rc::clone(&km_ta));
    let legacy_service = KMLegacyService::new();

    let mut dispatcher = KMServiceDispatcher::<2>::new()
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

    let cfg = PortCfg::new(KM_NS_LEGACY_TIPC_SRV_PORT)
        .map_err(|e| {
            km_err!(
                UnknownError,
                "could not create port config for {}: {:?}",
                KM_NS_LEGACY_TIPC_SRV_PORT,
                e
            )
        })?
        .allow_ta_connect()
        .allow_ns_connect();
    dispatcher.add_service(Rc::new(legacy_service), cfg).map_err(|e| {
        km_err!(UnknownError, "could not add secure service to dispatcher: {:?}", e)
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
    km_ta: Rc<RefCell<KeyMintTa>>,
}

impl KMService {
    /// Create a service implementation.
    fn new(km_ta: Rc<RefCell<KeyMintTa>>) -> Self {
        KMService { km_ta }
    }

    /// Process an incoming request message, returning the response as a collection of fragments
    /// that are each small enough to send over the channel.
    fn handle_message(&self, req_data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let resp = self.km_ta.borrow_mut().process(req_data);
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

/// TIPC service implementation for communication with components outside Trusty (notably the
/// bootloader and provisioning tools), using legacy (C++) message formats.
struct KMLegacyService;

impl KMLegacyService {
    /// Create a service implementation.
    fn new() -> Self {
        KMLegacyService
    }

    /// Process an incoming request message, returning the corresponding response.
    fn handle_message(&self, req_msg: TrustyPerformOpReq) -> Result<TrustyPerformOpRsp, Error> {
        let _cmd_code = req_msg.code();

        // Handling received message
        match req_msg {
            TrustyPerformOpReq::AppendUdsCertificate(req) => {
                secure_storage_manager::append_uds_cert_chain(&req.cert_data)?;
                Ok(TrustyPerformOpRsp::AppendUdsCertificate(AppendUdsCertificateResponse {}))
            }
            TrustyPerformOpReq::ClearUdsCertificate(..) => {
                secure_storage_manager::maybe_delete_uds_cert_chain()?;
                Ok(TrustyPerformOpRsp::ClearUdsCertificate(ClearUdsCertificateResponse {}))
            }
            _ => {
                error!("KeyMint Strongbox TA: failed to process unimplemented legacy command!");
                Err(km_err!(InvalidArgument, "unimplemented legacy command"))
            }
        }
    }
}

impl Service for KMLegacyService {
    type Connection = Context;
    type Message = KMMessage;

    fn on_connect(
        &self,
        _port: &PortCfg,
        _handle: &Handle,
        peer: &Uuid,
    ) -> tipc::Result<ConnectResult<Self::Connection>> {
        debug!("Accepted connection from uuid {peer:?}.");
        Ok(ConnectResult::Accept(Context { uuid: *peer }))
    }

    fn on_message(
        &self,
        _connection: &Self::Connection,
        handle: &Handle,
        msg: Self::Message,
    ) -> tipc::Result<MessageResult> {
        debug!("Received legacy message.");
        let req_msg = legacy::deserialize_trusty_req(&msg.0).map_err(|e| {
            error!("Received error when parsing legacy message: {e:?}");
            TipcError::InvalidData
        })?;
        let op = req_msg.code();

        let resp = match self.handle_message(req_msg) {
            Ok(resp_msg) => legacy::serialize_trusty_rsp(resp_msg).map_err(|e| {
                error!("failed to serialize legacy response message: {e:?}");
                TipcError::InvalidData
            })?,
            Err(e) => match e.kind() {
                ErrorKind::Hal(rc, msg) => {
                    log_error(format_args!("operation {op:?} failed {rc:?} {msg}"), e.location());
                    legacy::serialize_trusty_error_rsp(op, *rc).map_err(|e| {
                        error!("failed to serialize legacy error {rc:?} response message: {e:?}");
                        TipcError::InvalidData
                    })?
                }
                _ => {
                    error!("error handling legacy message: {e:?}");
                    return Err(TipcError::UnknownError);
                }
            },
        };
        handle.send(&KMMessage(resp))?;
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
