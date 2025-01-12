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

use alloc::vec::Vec;
use log::{debug, info};
use tipc::{
    ConnectResult, Deserialize, Handle, Manager, MessageResult, PortCfg, Serialize, Serializer,
    TipcError, Uuid,
};
use trusty_std::alloc::TryAllocFrom;

// The port on FingerGuard TA which the Fingerprint sensor HAL connects to.
const APP_SERVICE_PORT: &str = "com.android.trusty.rust.FingerGuard.V1";

// Maximum message size.
const MAX_MSG_SIZE: usize = 4000;

const PORT_COUNT: usize = 1;
const CONNECTION_COUNT: usize = 1;

/// Newtype wrapper for opaque messages.
// TODO(b/388311168): replace with a AIDL interface.
struct FpMessage(Vec<u8>);

impl Deserialize for FpMessage {
    type Error = TipcError;
    const MAX_SERIALIZED_SIZE: usize = MAX_MSG_SIZE;

    fn deserialize(bytes: &[u8], _handles: &mut [Option<Handle>]) -> tipc::Result<Self> {
        Ok(FpMessage(Vec::try_alloc_from(bytes)?))
    }
}

impl<'s> Serialize<'s> for FpMessage {
    fn serialize<'a: 's, S: Serializer<'s>>(
        &'a self,
        serializer: &mut S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0.as_slice())
    }
}

/// Struct implementing a TIPC service for FingerGuard TA.
// TODO(b/388311168): implement a binder service.
struct FingerGuardService;

impl tipc::Service for FingerGuardService {
    // Associates the Connection with a specific struct
    type Connection = ();
    // Associates the Message with a specific struct
    type Message = FpMessage;

    // This method is called whenever a client connects.
    // It should return Ok(Some(Connection)) if the connection is to be accepted.
    fn on_connect(
        &self,
        _port: &PortCfg,
        _handle: &Handle,
        peer: &Uuid,
    ) -> tipc::Result<ConnectResult<Self::Connection>> {
        info!("Accepted connection from uuid {:?}.", peer);
        Ok(ConnectResult::Accept(()))
    }
    // This method is called when the service receives a message.
    // The manager handles the deserialization into msg, which is passed to this callback.
    fn on_message(
        &self,
        _connection: &Self::Connection,
        handle: &Handle,
        _msg: Self::Message,
    ) -> tipc::Result<MessageResult> {
        debug!("Received a message");

        // TODO(b/388311168): implement me.

        handle.send(&FpMessage(Vec::new()))?;

        Ok(MessageResult::MaintainConnection)
    }
}

pub fn init_and_start_loop() -> Result<(), TipcError> {
    trusty_log::init();

    let app_cfg =
        PortCfg::new(APP_SERVICE_PORT).expect("Could not create port config").allow_ns_connect();
    let service = FingerGuardService {};

    // The manager handles the IPC event loop. Given our port configuration, buffer, and
    // service, it forwards incoming connections & messages to the service.
    //
    // <_, _, 1, 1> means we define a Manager with a single port, and max one connection.
    let buffer = [0u8; MAX_MSG_SIZE];
    Manager::<_, _, PORT_COUNT, CONNECTION_COUNT>::new(service, app_cfg, buffer)
        .expect("Could not create service manager")
        .run_event_loop()
        .expect("FingerGuard event loop failed");

    Ok(())
}

#[cfg(test)]
mod tests {
    test::init!();

    #[test]
    fn always_pass() {}
}
