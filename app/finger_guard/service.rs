use crate::rng;
use binder::Interface;
use fingerguard_api::aidl::{
    HandshakeResponse::HandshakeResponse, IFingerGuard::IFingerGuard,
    SessionResponse::SessionResponse,
};
use log::error;
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::hmac::HmacCtx;
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use std::sync::RwLock;
use storage::{OpenMode, Port, Session};
use tipc::TipcError;
use trusty_sys::Error;

const NIST_P256_CURVE_NAME: Nid = Nid::X9_62_PRIME256V1;

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

fn read_all_bytes(file_name: &str) -> Result<Vec<u8>, storage::Error> {
    let mut session = Session::new(Port::TamperDetect, true)?;
    let secure_file = session.open_file(&file_name, OpenMode::Open)?;
    let file_size = session.get_size(&secure_file)?;
    let mut buffer = vec![0u8; file_size];
    let content = session.read_all(&secure_file, buffer.as_mut_slice())?;
    Ok(content.to_vec())
}

fn ec_keygen() -> Result<EcKey<Private>, Box<dyn std::error::Error>> {
    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
    let server_private_key: EcKey<Private> = EcKey::generate(&group)?;
    Ok(server_private_key)
}

fn ec_public_key_serialization(
    private_key: &EcKey<Private>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
    let mut ctx = BigNumContext::new()?;
    let server_public_key_bytes =
        private_key.public_key().to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)?;
    Ok(server_public_key_bytes.to_vec())
}

fn perform_ecdh(
    server_private_key: &PKey<Private>,
    client_public_key_bytes: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME)?;
    let mut ctx = BigNumContext::new()?;
    let client_public_point = EcPoint::from_bytes(&group, &client_public_key_bytes, &mut ctx)?;
    let client_public_key: PKey<Public> =
        EcKey::from_public_key(&group, &client_public_point)?.try_into()?;
    let mut pk_deriver = Deriver::new(&server_private_key)?;
    pk_deriver.set_peer(&client_public_key)?;
    let pk = pk_deriver.derive_to_vec()?;
    Ok(pk)
}

fn compute_hmac_sha256(
    pk: &Vec<u8>,
    buffer: &Vec<u8>,
) -> Result<FixedSizeEntropy, Box<dyn std::error::Error>> {
    let mut hmac_ctx = HmacCtx::new(pk.as_slice(), Md::sha256())?;
    hmac_ctx.update(buffer.as_slice())?;
    let mut mac = [0u8; 32];
    let _ = hmac_ctx.finalize(mac.as_mut_slice())?;
    Ok(mac)
}

type FixedSizeEntropy = [u8; 32];

struct InitParams {
    pk: FixedSizeEntropy,
    tpm_seed: FixedSizeEntropy,
}

impl InitParams {
    const INIT_PARAMS_FILE_NAME: &str = "fingerguard_init_params";

    fn load() -> Option<Self> {
        let init_params_bytes = match read_all_bytes(Self::INIT_PARAMS_FILE_NAME) {
            Ok(content) => content,
            Err(e) => {
                error!("failed to read init_params: {:?}", e);
                return None;
            }
        };
        match init_params_bytes.len() {
            64 => Some(InitParams {
                pk: init_params_bytes[0..32].try_into().ok()?,
                tpm_seed: init_params_bytes[32..64].try_into().ok()?,
            }),
            _ => {
                error!("incorrect init_params size: {:?}", init_params_bytes.len());
                None
            }
        }
    }

    fn save(&self) -> Result<(), storage::Error> {
        let mut session = Session::new(Port::TamperDetect, true)?;
        let mut transaction = session.begin_transaction();
        let mut secure_file =
            transaction.open_file(Self::INIT_PARAMS_FILE_NAME, OpenMode::Create)?;
        transaction.write_at(&mut secure_file, 0, &self.pk.as_slice())?;
        transaction.write_at(&mut secure_file, self.pk.len(), &self.tpm_seed.as_slice())?;
        transaction.commit()?;
        Ok(())
    }
}

/// Implements the `IFingerGuard` AIDL interface for other Trusty apps to call.
pub struct FingerGuardService {
    init_params: RwLock<Option<InitParams>>,
}

impl FingerGuardService {
    pub fn new() -> Self {
        Self { init_params: RwLock::new(InitParams::load()) }
    }

    fn init_handshake(
        &self,
        client_public_key_bytes: &[u8],
    ) -> Result<HandshakeResponse, TipcError> {
        let mut init_params = self.init_params.write().map_err(|e| {
            error!("failed to acquire init_param write lock: {:?}", e);
            TipcError::SystemError(Error::BadState)
        })?;
        if let Some(_) = *init_params {
            return Err(TipcError::SystemError(Error::BadState));
        }
        let server_private_key = ec_keygen().map_err(|e| {
            error!("failed to ec keygen: {:?}", e);
            TipcError::SystemError(Error::BadState)
        })?;
        let server_public_key_bytes =
            ec_public_key_serialization(&server_private_key).map_err(|e| {
                error!("failed to serialize server public key: {:?}", e);
                TipcError::SystemError(Error::BadState)
            })?;
        let server_private_key: PKey<Private> = server_private_key.try_into().map_err(|e| {
            error!("failed to convert to PKey: {:?}", e);
            TipcError::SystemError(Error::BadState)
        })?;
        let pk = perform_ecdh(&server_private_key, client_public_key_bytes).map_err(|e| {
            error!("failed to derive pk: {:?}", e);
            TipcError::SystemError(Error::BadState)
        })?;
        // generate random 32-byte tpm_seed.
        let tpm_seed = rng::generate_random_buffer::<32>();
        let mac = compute_hmac_sha256(&pk, &b"tofu".to_vec()).map_err(|e| {
            error!("failed to compute pk hmac: {:?}", e);
            TipcError::SystemError(Error::BadState)
        })?;
        // save pk and tpm_seed to storage.
        let new_init_params = InitParams {
            pk: pk.try_into().map_err(|e| {
                error!("failed to convert to fixed size array: {:?}", e);
                TipcError::SystemError(Error::BadState)
            })?,
            tpm_seed: tpm_seed,
        };
        new_init_params.save().map_err(|e| {
            error!("failed to save init_params: {:?}", e);
            TipcError::SystemError(Error::BadState)
        })?;
        *init_params = Some(new_init_params);
        Ok(HandshakeResponse { server_public_key: server_public_key_bytes, pk_mac: mac.to_vec() })
    }

    fn read_authenticator_id(&self, sensor_id: i32, user_id: i32) -> Result<i64, TipcError> {
        let index = SensorStateIndex { sensor_id, user_id };
        let file_name = index.authenticator_id_file_name();
        let content = match read_all_bytes(&file_name) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("failed to read file bytes for {}: {:?}", file_name, e);
                // Treat read failure as there is no authenticator id. Return 0.
                return Ok(0_i64);
            }
        };
        // When no authenticator id was ever generated, return 0.
        if content.len() == 0 {
            return Ok(0_i64);
        }
        deserialize_authenticator_id(&content)
    }

    fn generate_authenticator_id(&self, sensor_id: i32, user_id: i32) -> Result<i64, TipcError> {
        let buffer = rng::generate_random_buffer::<8>();
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
    fn initHandshake(&self, client_public_key: &[u8]) -> binder::Result<HandshakeResponse> {
        FingerGuardService::init_handshake(&self, client_public_key)
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn newSession(&self, _client_nonce: &[u8]) -> binder::Result<SessionResponse> {
        // TODO(b/401303604): implement
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn getAuthenticatorId(&self, sensor_id: i32, user_id: i32) -> binder::Result<i64> {
        FingerGuardService::read_authenticator_id(&self, sensor_id, user_id)
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn newAuthenticatorId(&self, sensor_id: i32, user_id: i32) -> binder::Result<i64> {
        FingerGuardService::generate_authenticator_id(&self, sensor_id, user_id)
            .map_err(|_| binder::StatusCode::FAILED_TRANSACTION.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::service::NIST_P256_CURVE_NAME;
    use openssl::bn::BigNumContext;
    use openssl::derive::Deriver;
    use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
    use openssl::hmac::HmacCtx;
    use openssl::md::Md;
    use openssl::pkey::{PKey, Private, Public};
    test::init!();

    #[test]
    fn connect_server() {
        let _ = fingerguard_api::connect_finger_guard().unwrap();
    }

    #[test]
    fn init_service() {
        // Prepare the client key pair.
        let group = EcGroup::from_curve_name(NIST_P256_CURVE_NAME).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let client_private_key: EcKey<Private> = EcKey::generate(&group).unwrap();
        let client_public_key_bytes = client_private_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();

        // ECDH with the server.
        let service = fingerguard_api::connect_finger_guard().unwrap();
        let handshake_response = service.initHandshake(client_public_key_bytes.as_slice()).unwrap();
        let server_public_key_bytes = handshake_response.server_public_key;

        // Derive PK from the client side.
        let server_public_point =
            EcPoint::from_bytes(&group, &server_public_key_bytes, &mut ctx).unwrap();
        let server_public_key: PKey<Public> =
            EcKey::from_public_key(&group, &server_public_point).unwrap().try_into().unwrap();
        let client_private_key: PKey<Private> = client_private_key.try_into().unwrap();
        let mut pk_deriver = Deriver::new(&client_private_key).unwrap();
        pk_deriver.set_peer(&server_public_key).unwrap();
        let pk = pk_deriver.derive_to_vec().unwrap();
        assert_eq!(pk.len(), 32);

        // Check the computed MAC matches the one in the response.
        let mut hmac_ctx = HmacCtx::new(&pk.as_slice(), Md::sha256()).unwrap();
        hmac_ctx.update(b"tofu").unwrap();
        let mut mac = vec![0u8; 32];
        let _ = hmac_ctx.finalize(mac.as_mut_slice()).unwrap();
        assert_eq!(mac, handshake_response.pk_mac);
    }

    #[test]
    fn get_authenticator_id() {
        let service = fingerguard_api::connect_finger_guard().unwrap();
        assert_eq!(service.getAuthenticatorId(0, 0), Ok(0));
    }

    #[test]
    fn new_authenticator_id() {
        let service = fingerguard_api::connect_finger_guard().unwrap();
        let new_id = service.newAuthenticatorId(1, 1).unwrap();
        assert_ne!(new_id, 0_i64);
    }

    #[test]
    fn new_and_get_authenticator_id() {
        let service = fingerguard_api::connect_finger_guard().unwrap();
        let new_id = service.newAuthenticatorId(1, 1).unwrap();
        let got_id = service.getAuthenticatorId(1, 1).unwrap();
        assert_eq!(new_id, got_id);
    }
}
