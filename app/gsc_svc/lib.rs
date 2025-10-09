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

mod boot_params_svc;
mod keymint_provisioning;

use alloc::vec::Vec;
use android_system_desktop_security_gsc::aidl::android::system::desktop::security::gsc::IGsc::BnGsc;
use android_system_desktop_security_gsc::aidl::android::system::desktop::security::gsc::IGsc::IGsc;
use binder::{BinderFeatures, ExceptionCode, Interface, Result as BinderResult, Status};
use log::{error, info};
use rpcbinder::RpcServer;
use std::borrow::Cow;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;
use tipc::{
    service_dispatcher, ConnectResult, Deserialize, Handle, Manager, MessageResult, PortCfg,
    Serialize, Serializer, UnbufferedService, Uuid,
};
use tipc::{wrap_service, TipcError};
use trusty_sys::Error;

const GSC_SERVICE_PORT: &str = "com.android.trusty.rust.GscAppService.V1";
const TUNNEL_SERVICE_PORT: &str = "com.android.trusty.rust.GscTunnelService.V1";
const BP_SERVICE_PORT: &str = "com.android.trusty.rust.BootParamsService.V1.bnd";
const KM_PROVISIONING_SERVICE_PORT: &str = "com.android.trusty.rust.KeyMintProvisioningService.V1";

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
        Self { tunnel }
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
        info!("gscd connected to the Trusty gsc_svc");
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

    fn on_disconnect(&self, _connection: &Self::Connection) {
        error!("gscd disconnected!");
        *self.inner.handle.lock().unwrap_or_else(|e| e.into_inner()) = None;
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
        if let Some(handle) =
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

wrap_service!(GscService(RpcServer: UnbufferedService));
wrap_service!(BpService(RpcServer: UnbufferedService));
wrap_service!(KeyMintProvisioningService(RpcServer: UnbufferedService));

service_dispatcher! {
    enum GscDispatcher {
        GscService,
        GscTunnel,
        BpService,
        KeyMintProvisioningService,
    }
}

const PORT_COUNT: usize = 4;
const CONNECTION_COUNT: usize = 9;

pub fn init_and_start_loop() -> Result<(), TipcError> {
    trusty_log::init();
    let inner_tunnel = Arc::new(GscTunnelInner::new());
    let tunnel = GscTunnel::new(inner_tunnel.clone());
    let proxy = GscProxy::new(inner_tunnel);

    let mut dispatcher =
        GscDispatcher::<PORT_COUNT>::new().expect("Could not create test dispatcher");
    let gsc_service = BnGsc::new_binder(proxy, BinderFeatures::default());
    let gsc_rpc_server = RpcServer::new_per_session(move |_uuid| Some(gsc_service.as_binder()));

    let app_cfg =
        PortCfg::new(GSC_SERVICE_PORT).expect("Could not create port config").allow_ta_connect();
    dispatcher
        .add_service(Rc::new(GscService(gsc_rpc_server)), app_cfg)
        .expect("Could not add GSC service to dispatcher");

    let tunnel_cfg =
        PortCfg::new(TUNNEL_SERVICE_PORT).expect("Could not create port config").allow_ns_connect();
    dispatcher
        .add_service(Rc::new(tunnel), tunnel_cfg)
        .expect("Could not add tunnel service to dispatcher");

    let bp_cfg =
        PortCfg::new(BP_SERVICE_PORT).expect("Could not create port config").allow_ta_connect();
    let bp = boot_params_svc::create_boot_params_service();
    let bp_rpc_server = RpcServer::new_per_session(move |_uuid| Some(bp.as_binder()));
    dispatcher
        .add_service(Rc::new(BpService(bp_rpc_server)), bp_cfg)
        .expect("Could not add bp service to dispatcher");

    let km_provisioning_cfg = PortCfg::new(KM_PROVISIONING_SERVICE_PORT)
        .expect("Could not create port config")
        .allow_ta_connect()
        .allow_ns_connect();
    let km_provisioning = keymint_provisioning::create_service();
    let km_provisioning_rpc_server =
        RpcServer::new_per_session(move |_uuid| Some(km_provisioning.as_binder()));
    dispatcher
        .add_service(
            Rc::new(KeyMintProvisioningService(km_provisioning_rpc_server)),
            km_provisioning_cfg,
        )
        .expect("Could not add keymint provisioning service to dispatcher");

    Manager::<_, _, PORT_COUNT, CONNECTION_COUNT>::new_with_dispatcher(dispatcher, [])
        .expect("Could not create service manager")
        .run_event_loop()
        .expect("GSC tunnel event loop failed");

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;
    use binder::Strong;
    use rpcbinder::RpcSession;
    use std::ffi::CStr;

    test::init!();

    const GSC_SERVICE_PORT: &CStr = c"com.android.trusty.rust.GscAppService.V1";
    fn get_service(port: &CStr) -> Strong<dyn IGsc> {
        let session = RpcSession::new();
        log::error!("created session");
        let ret = session.setup_trusty_client(port).expect("Failed to create GSC session");
        log::error!("trusty setup");
        ret
    }

    #[test]
    fn get_random() {
        log::error!("get port");
        let service = get_service(GSC_SERVICE_PORT);
        log::error!("got port");
        let get_random =
            vec![0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b, 0x00, 0x10];
        let out = service.transmit(&get_random).unwrap();
        assert_eq!(out[..2], [0x80, 0x01], "Bad tag");
        assert_eq!(out[2..6], 0x1Cu32.to_be_bytes(), "Bad message size");
        assert_eq!(out[6..10], 0u32.to_be_bytes(), "Bad status");
        assert_eq!(out[10..12], 0x10u16.to_be_bytes(), "Bad TPM2B size");
        assert_eq!(out[12..].len(), 0x10, "Bad vec length");
        assert!(out[12..].iter().any(|&x| x != 0), "All zeroes for random bytes");
    }
}
