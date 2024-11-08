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

use alloc::vec::Vec;
use binder::{BinderFeatures, ExceptionCode, Interface, Result as BinderResult, Status};
use rpcbinder::RpcServer;
use std::borrow::Cow;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;
use tipc::TipcError;
use tipc::{
    service_dispatcher, ConnectResult, Deserialize, Handle, Manager, MessageResult, PortCfg,
    Serialize, Serializer, UnbufferedService, Uuid,
};
use trusty_sys::Error;
use vendor_google_gsc::aidl::vendor::google::gsc::IGsc::BnGsc;
use vendor_google_gsc::aidl::vendor::google::gsc::IGsc::IGsc;

const APP_SERVICE_PORT: &str = "com.android.trusty.rust.GscAppService.V1";
const TUNNEL_SERVICE_PORT: &str = "com.android.trusty.rust.GscTunnelService.V1";

/// A GscProxy implements the IGsc binder interface and forwards requests from trusty apps to the
/// GSC over a GscTunnel.
pub struct GscProxy {
    tunnel: Arc<GscTunnelInner>,
}

impl Interface for GscProxy {}

impl IGsc for GscProxy {
    fn transmit(&self, data: &[u8]) -> BinderResult<Vec<u8>> {
        self.tunnel
            .transmit(data)
            .map_err(|_| Status::new_exception(ExceptionCode::ILLEGAL_STATE, None))
    }
}

impl GscProxy {
    fn new(tunnel: Arc<GscTunnelInner>) -> Self {
        Self { tunnel: tunnel }
    }
}

/// GscTunnelInner satisfies GscProxy's requirement to be Sync + Send due to being a binder
/// interface.
pub struct GscTunnelInner {
    handle: Mutex<Option<Handle>>,
}

/// GscTunnel implements the tipc::UnbufferedService trait for an untrusted service (gscd) to
/// connect to and receive commands from.
pub struct GscTunnel {
    inner: Arc<GscTunnelInner>,
}

/// The content of a message is a TPM command and opaque to this service.
pub struct Message<'a>(Cow<'a, [u8]>);

impl Deserialize for Message<'_> {
    type Error = TipcError;
    const MAX_SERIALIZED_SIZE: usize = 4096;

    fn deserialize(bytes: &[u8], _handles: &mut [Option<Handle>]) -> tipc::Result<Self> {
        Ok(Message(Cow::from(bytes.to_vec())))
    }
}

impl<'s> Serialize<'s> for Message<'_> {
    fn serialize<'a: 's, S: Serializer<'s>>(
        &'a self,
        serializer: &mut S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_ref())
    }
}

impl UnbufferedService for GscTunnel {
    type Connection = ();

    /// on_connect stores the connection handle for later use.
    fn on_connect(
        &self,
        _port: &PortCfg,
        handle: &Handle,
        _peer: &Uuid,
    ) -> tipc::Result<ConnectResult<Self::Connection>> {
        *self.inner.handle.lock().map_err(|_| TipcError::SystemError(Error::BadState))? =
            Some(handle.try_clone()?);
        Ok(ConnectResult::Accept(()))
    }

    // on_message is never expected to be called since GscTunnel handles commands synchronously
    fn on_message(
        &self,
        _connection: &Self::Connection,
        _handle: &Handle,
        _buffer: &mut [u8],
    ) -> tipc::Result<MessageResult> {
        Ok(MessageResult::MaintainConnection)
    }
}

impl GscTunnelInner {
    fn new() -> Self {
        Self { handle: Mutex::new(None) }
    }

    /// tipc does not design for trusty applications connection to untrusted apps. As a result,
    /// it's possible the othe trusty apps will start sending messages before the connection from
    /// gscd is made.
    fn transmit(&self, data: &[u8]) -> tipc::Result<Vec<u8>> {
        if let Some(&ref handle) =
            self.handle.lock().or(Err(TipcError::SystemError(Error::BadState)))?.as_ref()
        {
            handle.send(&Message(Cow::from(data)))?;
            let mut buf = vec![0; Message::MAX_SERIALIZED_SIZE];
            let msg: Message = handle.recv(buf.as_mut_slice())?;
            Ok(msg.0.to_vec())
        } else {
            Err(TipcError::SystemError(Error::NotReady))
        }
    }
}

impl GscTunnel {
    fn new(inner: Arc<GscTunnelInner>) -> Self {
        Self { inner }
    }
}

service_dispatcher! {
    enum GscDispatcher {
        RpcServer,
        GscTunnel,
    }
}

const PORT_COUNT: usize = 2;
const CONNECTION_COUNT: usize = 4;

pub fn init_and_start_loop() -> Result<(), TipcError> {
    trusty_log::init();
    let inner_tunnel = Arc::new(GscTunnelInner::new());
    let tunnel = GscTunnel::new(inner_tunnel.clone());
    let proxy = GscProxy::new(inner_tunnel);

    let mut dispatcher =
        GscDispatcher::<PORT_COUNT>::new().expect("Could not create test dispatcher");
    let service = BnGsc::new_binder(proxy, BinderFeatures::default());
    let rpc_server = RpcServer::new_per_session(move |_uuid| Some(service.as_binder()));

    let app_cfg =
        PortCfg::new(APP_SERVICE_PORT).expect("Could not create port config").allow_ta_connect();
    dispatcher
        .add_service(Rc::new(rpc_server), app_cfg)
        .expect("Could not add service to dispatcher");

    let tunnel_cfg =
        PortCfg::new(TUNNEL_SERVICE_PORT).expect("Could not create port config").allow_ns_connect();
    dispatcher
        .add_service(Rc::new(tunnel), tunnel_cfg)
        .expect("Could not add service to dispatcher");

    Manager::<_, _, PORT_COUNT, CONNECTION_COUNT>::new_with_dispatcher(dispatcher, [])
        .expect("Could not create service manager")
        .run_event_loop()
        .expect("GSC tunnel event loop failed");

    Ok(())
}

#[cfg(test)]
mod tests {
    test::init!();
}
