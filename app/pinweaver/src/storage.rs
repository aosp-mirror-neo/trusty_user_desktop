use pinweaver_storage_api::{
    util::{DeserializeExact, ForwardTipcSerialize},
    StorageInterface, StorageRequest, StorageResponse,
};
use std::sync::{Arc, Mutex, MutexGuard};
use tipc::{Handle, TipcError, UnbufferedService, MAX_MSG_HANDLES};
use trusty_std::alloc::FallibleVec;
use trusty_sys::Error;

type Response = DeserializeExact<StorageResponse>;
const MAX_MESSAGE_SIZE: usize = <Response as tipc::Deserialize>::MAX_SERIALIZED_SIZE;

/// The service that initializes the given `StorageClient` upon connection.
///
/// This is a tipc server: the storage daemon running in Android connects to
/// this service, acting as a tipc client. The connection remains open while
/// the main service sends commands to the storage daemon through the
/// `StorageClient`.
pub(crate) struct StorageClientService {
    client: Arc<StorageClient>,
}

impl StorageClientService {
    pub fn new(client: Arc<StorageClient>) -> Self {
        Self { client }
    }
}

impl UnbufferedService for StorageClientService {
    type Connection = ();

    /// Stores the connection handle for later use.
    fn on_connect(
        &self,
        _port: &tipc::PortCfg,
        handle: &tipc::Handle,
        _peer: &tipc::Uuid,
    ) -> tipc::Result<tipc::ConnectResult<Self::Connection>> {
        self.client.set_server_handle(handle)?;
        Ok(tipc::ConnectResult::Accept(()))
    }

    /// Not used, as the storage daemon acts as a server.
    fn on_message(
        &self,
        _connection: &Self::Connection,
        _handle: &tipc::Handle,
        _buffer: &mut [u8],
    ) -> tipc::Result<tipc::MessageResult> {
        Ok(tipc::MessageResult::MaintainConnection)
    }

    fn on_disconnect(&self, _connection: &Self::Connection) {
        log::error!("Storage client disconnected");
        self.client.clear_server_handle();
    }
}

#[derive(Default)]
pub(crate) struct StorageClient {
    /// Initialized by the [`StorageClientService`].
    server_handle: Mutex<Option<Handle>>,
}

impl StorageClient {
    /// Locks the mutex or returns an error.
    fn lock(&self) -> tipc::Result<MutexGuard<'_, Option<Handle>>> {
        self.server_handle.lock().map_err(|_| TipcError::SystemError(Error::BadState))
    }

    /// Sets the server handle for this storage client.
    ///
    /// Clones the handle to send messages, if a storage daemon hasn't already connected.
    pub fn set_server_handle(&self, handle: &Handle) -> tipc::Result<()> {
        match &mut *self.lock()? {
            Some(_) => Err(TipcError::SystemError(Error::AlreadyExists)),
            server_handle @ None => {
                *server_handle = Some(handle.try_clone()?);
                Ok(())
            }
        }
    }

    /// Clears the current server handle for this storage client.
    ///
    /// Ignores whether there is currently a handle set.
    pub fn clear_server_handle(&self) {
        if let Ok(mut handle) = self.lock() {
            *handle = None;
        }
    }
}

impl StorageInterface for StorageClient {
    type Error = tipc::TipcError;

    fn request(&self, request: &StorageRequest) -> tipc::Result<StorageResponse> {
        let guard = self.lock()?;
        let handle = guard.as_ref().ok_or(TipcError::SystemError(Error::NotReady))?;
        handle.send(&ForwardTipcSerialize(request))?;
        let mut buf: Vec<u8> = FallibleVec::try_with_capacity(MAX_MESSAGE_SIZE)?;
        buf.resize(MAX_MESSAGE_SIZE, 0);
        let response: Response = handle.recv(&mut buf)?;
        Ok(response.0)
    }

    fn request_raw(&self, request: &[u8]) -> tipc::Result<Vec<u8>> {
        let guard = self.lock()?;
        let handle = guard.as_ref().ok_or(TipcError::SystemError(Error::NotReady))?;
        handle.send_vectored(&[request], &[])?;
        let mut buf: Vec<u8> = FallibleVec::try_with_capacity(MAX_MESSAGE_SIZE)?;
        buf.resize(MAX_MESSAGE_SIZE, 0);
        let mut handles: [Option<Handle>; MAX_MSG_HANDLES] = Default::default();
        let (byte_count, handle_count) =
            handle.recv_vectored(&mut [buf.as_mut_slice()], &mut handles)?;
        if handle_count > 0 {
            return Err(tipc::TipcError::InvalidHandle);
        }
        buf.resize(byte_count, 0);
        Ok(buf)
    }
}
