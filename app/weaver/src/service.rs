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

use crate::message::{
    BinaryMessageParser, ResponseStatus, WeaverHalRequest, WeaverHalResponse, WeaverMessageParser,
};
use crate::weaver::{connect_to_pinweaver, PinWeaverImpl, Weaver};
use crate::WeaverTAError;
use alloc::rc::Rc;
use log::error;
use log::info;
use log::trace;
use std::default::Default;
use tipc::{
    service_dispatcher, ConnectResult, Deserialize, Handle, Manager, MessageResult, PortCfg,
    Serialize, Serializer, Service, TipcError, Uuid,
};
use trusty_std::alloc::TryAllocFrom;

// Port name for clients to connect to
const WEAVER_TIPC_PORT: &str = "com.android.trusty.weaver.desktop";
// Max Size of serialized message
// This may be able to be reduced since the longest message that we can get is a write which has...
// operation, slot id, key length, value length, key, value
// 1 + 4 + 4 + 4 + 16 + 16 = 45
const WEAVER_MAX_BUFFER_LENGTH: usize = 4096;
const CONNECTION_COUNT: usize = 1;

// Will use BinaryMessageParser (M) for message parsing and pinweaver for weaver implementation (W)
struct WeaverHalTA<M: WeaverMessageParser, W: Weaver> {
    message_parser: M,
    weaver_impl: W,
}

/// Raw tipc message to satisfy deserialize/Serialize requirement
struct TipcMessage(Vec<u8>);
impl Deserialize for TipcMessage {
    type Error = TipcError;
    const MAX_SERIALIZED_SIZE: usize = WEAVER_MAX_BUFFER_LENGTH;
    fn deserialize(bytes: &[u8], _handles: &mut [Option<Handle>]) -> tipc::Result<Self> {
        Ok(TipcMessage(Vec::try_alloc_from(bytes)?))
    }
}
impl<'s> Serialize<'s> for TipcMessage {
    fn serialize<'a: 's, S: Serializer<'s>>(
        &'a self,
        serializer: &mut S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_slice())
    }
}

/// TIPC connection context information.
struct Context {
    _uuid: Uuid,
}

impl<M: WeaverMessageParser, W: Weaver> WeaverHalTA<M, W> {
    fn new(message_parser: M, weaver_impl: W) -> Self {
        WeaverHalTA { message_parser, weaver_impl }
    }
}

impl<M: WeaverMessageParser, W: Weaver> Service for WeaverHalTA<M, W> {
    type Message = TipcMessage;
    type Connection = Context;
    fn on_connect(
        &self,
        _port: &PortCfg,
        _handle: &Handle,
        peer: &Uuid,
    ) -> tipc::Result<ConnectResult<Self::Connection>> {
        info!("Accepted weaver hal connection from uuid {:?}.", peer);
        Ok(ConnectResult::Accept(Context { _uuid: peer.clone() }))
    }

    fn on_message(
        &self,
        _connection: &Self::Connection,
        handle: &Handle,
        msg: Self::Message,
    ) -> tipc::Result<MessageResult> {
        trace!("Received a message.");

        // Parse Message
        let request = self.message_parser.deserialize(&msg.0).map_err(|e| match e {
            WeaverTAError::BadMessage(_) => {
                error!("Could not parse message: {:?}", e);
                TipcError::InvalidData
            }
            _ => {
                error!("Unexpected error while parsing message: {:?}", e);
                TipcError::UnknownError
            }
        })?;

        // Handle Message
        let response = match request {
            WeaverHalRequest::ReadRequest { slot_id, key } => {
                trace!("Received a read message.");
                self.weaver_impl.read(slot_id, &key).unwrap_or_else(|e| {
                    error!("Unexpected error while performing weaver read: {:?}", e);
                    WeaverHalResponse::ReadResponse {
                        status: ResponseStatus::Failed,
                        timeout: 0,
                        value: Vec::new(),
                    }
                })
            }
            WeaverHalRequest::WriteRequest { slot_id, key, value } => {
                trace!("Received a write message.");
                self.weaver_impl.write(slot_id, &key, &value).unwrap_or_else(|e| {
                    error!("Unexpected error while performing weaver write: {:?}", e);
                    WeaverHalResponse::WriteResponse { status: ResponseStatus::Failed }
                })
            }
        };

        // Serialize message to send
        let response = self.message_parser.serialize(response).map_err(|e| {
            error!("Unexpected error while serializing message: {:?}", e);
            TipcError::UnknownError
        })?;

        // Send message response
        handle.send(&TipcMessage(response))?;

        Ok(MessageResult::MaintainConnection)
    }
}

// Create a dispatcher for weaver service
type WeaverTA = WeaverHalTA<BinaryMessageParser, PinWeaverImpl>;
service_dispatcher! {
    enum WeaverDispatcher{
        // Handles calls to the android weaver hal
        WeaverTA,
    }
}

pub(crate) fn start_tipc_service() -> Result<(), WeaverTAError> {
    let pinweaver = connect_to_pinweaver()?;
    let weaver_ta = WeaverHalTA::new(BinaryMessageParser::default(), pinweaver);

    trace!("Weaver ta created.");

    // Configure a new tipc port
    let port_config = PortCfg::new(WEAVER_TIPC_PORT)
        .map_err(|e| {
            WeaverTAError::TipcError(
                format!("Could not create configuration for '{}'", WEAVER_TIPC_PORT),
                e,
            )
        })?
        .allow_ta_connect()
        .allow_ns_connect();

    let mut dispatcher = WeaverDispatcher::<1>::new()
        .map_err(|e| WeaverTAError::TipcError("Could not create dispatcher".to_string(), e))?;
    dispatcher.add_service(Rc::new(weaver_ta), port_config).map_err(|e| {
        WeaverTAError::TipcError(
            format!("Could not add serice to dispatcher for port '{}'", WEAVER_TIPC_PORT),
            e,
        )
    })?;

    trace!("Weaver service added to dispatcher.");

    Manager::<_, _, 1, CONNECTION_COUNT>::new_with_dispatcher(
        dispatcher,
        [0u8; WEAVER_MAX_BUFFER_LENGTH],
    )
    .map_err(|e| {
        WeaverTAError::TipcError("Manager for Weaver TA could not be created".to_string(), e)
    })?
    .run_event_loop()
    .map_err(|e| {
        WeaverTAError::TipcError(format!("Could not start event '{}'", WEAVER_TIPC_PORT), e)
    })
}
