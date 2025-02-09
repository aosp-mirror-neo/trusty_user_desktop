use crate::rng;
use binder::Interface;
use fingerguard_api::aidl::IFingerGuard::IFingerGuard;
use kmr_common::crypto::Rng;
use log::error;
use storage::{OpenMode, Port, Session};
use tipc::TipcError;
use trusty_sys::Error;

#[derive(Hash, Eq, PartialEq, Debug)]
struct SensorStateIndex {
    sensor_id: i32,
    user_id: i32,
}

impl SensorStateIndex {
    fn authenticator_id_file_name(&self) -> String {
        format!("s{}.u{}.authenticator_id", self.sensor_id, self.user_id)
    }
}

fn deserialize_authenticator_id(buffer: &[u8]) -> Result<i64, TipcError> {
    if let Ok(buffer) = buffer.try_into() {
        return Ok(i64::from_ne_bytes(buffer));
    }
    error!("failed to deserialize the auth id from buffer: expected size 8, got {}", buffer.len());
    Err(TipcError::SystemError(Error::BadState))
}

/// Implements the `IFingerGuard` AIDL interface for other Trusty apps to call.
pub struct FingerGuardService {}

impl FingerGuardService {
    pub fn new() -> Self {
        Self {}
    }

    fn read_authenticator_id(&self, sensor_id: i32, user_id: i32) -> Result<i64, TipcError> {
        let index = SensorStateIndex { sensor_id, user_id };
        let file_name = index.authenticator_id_file_name();
        let mut session = Session::new(Port::TamperDetect, false).map_err(|e| {
            error!("failed to create storage session: {:?}", e);
            TipcError::SystemError(Error::BadState)
        })?;
        let secure_file = session.open_file(&file_name, OpenMode::Create).map_err(|e| {
            error!("failed to open file {}: {:?}", file_name, e);
            TipcError::SystemError(Error::BadState)
        })?;
        let file_size = session.get_size(&secure_file).map_err(|e| {
            error!("failed to get file size for {}: {:?}", file_name, e);
            TipcError::SystemError(Error::BadState)
        })?;
        let mut buffer = vec![0; file_size];
        let content = session.read_all(&secure_file, buffer.as_mut_slice()).map_err(|e| {
            error!("failed to read file bytes for {}: {:?}", file_name, e);
            TipcError::SystemError(Error::BadState)
        })?;
        // By the HAL definition, When no authenticator id was ever generated, return 0.
        if content.len() == 0 {
            return Ok(0_i64);
        }
        deserialize_authenticator_id(&content)
    }

    fn generate_authenticator_id(&self, sensor_id: i32, user_id: i32) -> Result<i64, TipcError> {
        let mut rng = rng::TrustyRng::default();
        let mut buffer = [0u8; 8];
        rng.fill_bytes(&mut buffer[..]);
        let authenticator_id = deserialize_authenticator_id(&buffer)?;
        let index = SensorStateIndex { sensor_id, user_id };
        let file_name = index.authenticator_id_file_name();
        let mut session = Session::new(Port::TamperDetect, true).map_err(|e| {
            error!("failed to create storage session: {:?}", e);
            TipcError::SystemError(Error::BadState)
        })?;
        let mut secure_file = session.open_file(&file_name, OpenMode::Create).map_err(|e| {
            error!("failed to open file {}: {:?}", file_name, e);
            TipcError::SystemError(Error::BadState)
        })?;
        session.write_all(&mut secure_file, &buffer).map_err(|e| {
            error!("failed to write the serialized auth id to {}: {:?}", file_name, e);
            TipcError::SystemError(Error::BadState)
        })?;
        Ok(authenticator_id)
    }
}

impl Interface for FingerGuardService {}

impl IFingerGuard for FingerGuardService {
    fn getAuthenticatorId(&self, sensor_id: i32, user_id: i32) -> binder::Result<i64> {
        FingerGuardService::read_authenticator_id(&self, sensor_id, user_id)
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn newAuthenticatorId(&self, sensor_id: i32, user_id: i32) -> binder::Result<i64> {
        FingerGuardService::generate_authenticator_id(&self, sensor_id, user_id)
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
}
