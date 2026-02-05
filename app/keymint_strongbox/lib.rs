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
use android_system_desktop_security_gsc::aidl::android::system::desktop::security::gsc::IGsc::IGsc;
use binder::Strong;
use core::{cell::RefCell, fmt};
use kmr_common::{km_err, km_err_new, Error, ErrorKind, ErrorLocation};
use kmr_ta::{HardwareInfo, RpcInfo, RpcInfoV3};
use kmr_wire::keymint::ErrorCode;
use log::{debug, error, trace};
use tipc::{
    service_dispatcher, ConnectResult, Deserialize, Handle, Manager, MessageResult, PortCfg,
    Serialize, Serializer, Service, TipcError, Uuid,
};
use tpm_commands::{
    TpmRequestBuildError, TpmRequestMessage, TpmResponseMessage, TpmvRequest, TpmvRequestBuild,
};
use trusty_std::alloc::TryAllocFrom;
use zerocopy::{FromBytes, IntoBytes, KnownLayout, Unaligned};

use kmr_wire::legacy::{
    self, AppendUdsCertificateResponse, ClearUdsCertificateResponse, TrustyMessageId,
    TrustyPerformOpReq, TrustyPerformOpRsp,
};

macro_rules! km_from_tpm {
    { $ret:expr} => {{
        let ret = $ret;
        ret.map_err(|err| {
            match err {
                TpmRequestBuildError::Alloc => {
                    km_err!(MemoryAllocationFailed, "")
                },
                TpmRequestBuildError::Size => {
                    km_err!(EncodingError, "")
                },
                TpmRequestBuildError::Internal(err) => {
                    err
                },
            }
        })
    }}
}

// #[cfg(fake_strongbox)]
mod fake_sb;

mod device;
mod operation;
mod rkp;
mod strongbox;
use strongbox::StrongBox;

/// Port that handles new style keymint messages from non-secure world
const KM_NS_TIPC_SRV_PORT: &str = "com.android.trusty.keymint.strongbox";

/// Port that handles legacy style keymint/keymaster messages
const KM_NS_LEGACY_TIPC_SRV_PORT: &str = "com.android.trusty.keymaster.strongbox";

/// Port count for this TA (as above).
const PORT_COUNT: usize = 2;

/// Only one connection: non-secure world hal.
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
    format!("strongbox: {}: {}:{} {}\n", record.level(), file, line, record.args())
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

    let hw_info = HardwareInfo {
        version_number: 3,
        security_level: kmr_common::wire::keymint::SecurityLevel::Strongbox,
        impl_name: "CR50",
        author_name: "GOOGLE",
        unique_id: "CR50",
    };

    let rpc_info_v3 = RpcInfoV3 {
        author_name: "GOOGLE",
        unique_id: "Cr50",
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
        KMLegacyService,
    }
}

/// Main loop handler for the KeyMint TA.
pub fn handle_port_connections(hw_info: HardwareInfo, rpc_info: RpcInfo) -> Result<(), Error> {
    let sb_ta = Rc::new(RefCell::new(StrongBox::new(hw_info, rpc_info)?));

    let ns_service = KMService::new(sb_ta);
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
                fake_sb::secure_storage_manager::append_uds_cert_chain(&req.cert_data)?;
                Ok(TrustyPerformOpRsp::AppendUdsCertificate(AppendUdsCertificateResponse {}))
            }
            TrustyPerformOpReq::ClearUdsCertificate(..) => {
                fake_sb::secure_storage_manager::maybe_delete_uds_cert_chain()?;
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

const GSC_TAG_MASK: u32 = 0xff00;
const GSC_STRONGBOX_SUBSET_TAG: u32 = 0x500;
const GSC_KEY_MAX_OPS_EXCEEDED: u32 = GSC_STRONGBOX_SUBSET_TAG + 0x38;

fn error_from_tpm(error_code: u32) -> Error {
    if error_code == GSC_KEY_MAX_OPS_EXCEEDED {
        return km_err!(TooManyOperations, "too many operations");
    }

    // Check if it is a SBS error.
    if error_code & GSC_TAG_MASK == GSC_STRONGBOX_SUBSET_TAG {
        if let Ok(cast_code) =
            ErrorCode::try_from((GSC_STRONGBOX_SUBSET_TAG as i32) - (error_code as i32))
        {
            return km_err_new!(ErrorKind::Hal(
                cast_code,
                format!("converted from SBS 0x{:X}", error_code)
            ));
        }
    }

    km_err!(SecureHwCommunicationFailed, "0x{:X}", error_code)
}

fn do_rpc<
    GRQ: TpmvRequestBuild<BuildParams = ARQ, Err = Error> + TpmvRequest<TpmvResponse = GRSP> + ?Sized,
    GRSP: FromBytes + IntoBytes + KnownLayout + Unaligned + ?Sized,
    ARQ,
    ARSP: for<'a> TryFrom<&'a mut GRSP, Error = Error>,
>(
    request: ARQ,
    client: &Strong<dyn IGsc>,
) -> Result<ARSP, Error> {
    let mut req_buffer = Vec::<u8>::new();
    let req = km_from_tpm!(TpmRequestMessage::<GRQ>::new_in_vec(&mut req_buffer, request))?;

    let mut resp_buffer = client
        .transmit(req.as_bytes())
        .map_err(|_| km_err!(SecureHwCommunicationFailed, "transmit"))?;
    let rsp = TpmResponseMessage::<[u8]>::mut_from_bytes(&mut resp_buffer)
        .map_err(|_| km_err!(EncodingError, "parsing tpm response"))?;
    if rsp.header.error_code == 0 {
        let ret = GRSP::mut_from_bytes(&mut rsp.response)
            .map_err(|_| km_err!(EncodingError, "parsing keymint response"))?;
        ret.try_into()
    } else {
        Err(error_from_tpm(rsp.header.error_code.get()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gsc_svc_client::GscServiceClient;
    use kmr_wire::keymint::*;
    use kmr_wire::*;
    use std::fmt::Write;

    /// TODO drop this when it is stabilized in std.
    macro_rules! assert_matches {
        ($first:expr, $($second:pat_param)|+ $(if $third:expr)?) => {
            let a = $first;
            if !matches!(&a, $($second)|+ $(if $third)?) {
                panic!(
                    "'{}' does not match '{}'; Got '{:?}'",
                    stringify!($first),
                    stringify!($($second)|+ $(if $third)?),
                    a
                );
            }
        };
    }

    macro_rules! expect_eq {
        ($first:expr, $second:expr) => {{
            let a = $first;
            let b = $second;
            if a != b {
                log::error!(
                    "line {}: '{:?}' ('{}') does not equal '{:?}' ('{}')",
                    line!(),
                    a,
                    stringify!($first),
                    b,
                    stringify!($second),
                );
                false
            } else {
                true
            }
        }};
    }

    macro_rules! expect_ge {
        ($first:expr, $second:expr) => {{
            let a = $first;
            let b = $second;
            if a < b {
                log::error!(
                    "line {}: '{:?}' ('{}') not less than '{:?}' ('{}')",
                    line!(),
                    a,
                    stringify!($first),
                    b,
                    stringify!($second),
                );
                false
            } else {
                true
            }
        }};
    }

    macro_rules! expect_lt {
        ($first:expr, $second:expr) => {{
            let a = $first;
            let b = $second;
            if a >= b {
                log::error!(
                    "line {}: '{:?}' ('{}') not less than '{:?}' ('{}')",
                    line!(),
                    a,
                    stringify!($first),
                    b,
                    stringify!($second),
                );
                false
            } else {
                true
            }
        }};
    }

    fn validate_key_blob(key_blob: &[u8]) -> bool {
        let mut success = true;
        let mut buf = <[u32]>::ref_from_bytes(key_blob).expect("conversion failed");
        let blob_words = buf[0] as usize;
        buf = &buf[1..];

        //     /* Blobs have a fixed elements in structure.
        //     * see `process_gen_import_tags`
        //     */
        //     if (blob_words < KM_KEY_CHARACTERISTICS_WORDS + KM_AES_IV_WORDS +
        //                 SHA256_DIGEST_WORDS)
        //         return SBERR_InvalidKeyBlob;
        success &= expect_ge!(blob_words, 12 + 4 + 8);

        //     if (buf[0] != KM_SECURITY_STRONGBOX)
        //         return SBERR_InvalidKeyBlob;
        success &= expect_eq!(buf[0], 2);

        //     hw_tag_words = buf[1];
        let hw_tag_words = buf[1] as usize;
        //     /* Skip KM_SECURITY_STRONGBOX word + size word */
        //     tag_words = hw_tag_words + 2;
        let mut tag_words = hw_tag_words + 2;
        //     if (hw_tag_words >= blob_words)
        //         return SBERR_InvalidKeyBlob;
        success &= expect_lt!(hw_tag_words, blob_words);

        //     if (buf[tag_words] != KM_SECURITY_KEYSTORE)
        //         return SBERR_InvalidKeyBlob;
        success &= expect_eq!(buf[tag_words], 100);

        //     sw_tag_words = buf[tag_words + 1];
        let sw_tag_words = buf[tag_words + 1] as usize;
        //     if (sw_tag_words + tag_words >= blob_words)
        //         return SBERR_InvalidKeyBlob;
        success &= expect_lt!(tag_words + sw_tag_words, blob_words);

        //     /* Skip KM_SECURITY_KEYSTORE word + size word */
        //     tag_words += sw_tag_words + 2;
        tag_words += sw_tag_words + 2;

        //     /* Actual encrypted key blob size */
        //     key_blob_size = buf[tag_words];
        let key_blob_size = buf[tag_words] as usize;

        //     if (key_blob_size / sizeof(uint32_t) + tag_words + 1 != blob_words)
        //         return SBERR_InvalidKeyBlob;
        success &= expect_eq!(key_blob_size / 4 + tag_words + 1, blob_words);

        if !success {
            error!("Failed key:");
            log_bytes(&key_blob);
        }
        success
    }

    fn log_bytes(to_log: &[u8]) {
        error!("{} bytes", to_log.len());
        let mut buffer = String::with_capacity(32 + 3 - 2);
        for (i, v) in to_log.iter().copied().enumerate() {
            match i & 15 {
                15 => {
                    error!("{buffer:}{v:02x}");
                    buffer.clear();
                }
                4 | 8 | 12 => {
                    write!(&mut buffer, " {v:02x}").unwrap();
                }
                _ => {
                    write!(&mut buffer, "{v:02x}").unwrap();
                }
            }
        }
        if !buffer.is_empty() {
            error!("{buffer:}");
        }
    }

    test::init!();

    #[test]
    fn device_get_hardware_info() {
        let tpm = GscServiceClient::default().0;
        assert_matches!(device::get_hardware_info(GetHardwareInfoRequest {}, &tpm), Ok(_));
    }

    #[test]
    fn generate_key() {
        let key_params = vec![
            KeyParam::Algorithm(Algorithm::Ec),
            KeyParam::KeySize(KeySizeInBits(256)),
            KeyParam::Purpose(KeyPurpose::Sign),
            KeyParam::Digest(Digest::Sha256),
            KeyParam::AllowWhileOnBody,
            KeyParam::UserId(0xF00),
            KeyParam::ApplicationId(vec![0xAA, 0xBB, 0xCC, 0xDD]),
            KeyParam::ApplicationData(vec![0x11, 0x22, 0x33, 0x44]),
        ];
        let tpm = GscServiceClient::default().0;
        assert_matches!(
            device::generate_key(GenerateKeyRequest { key_params, attestation_key: None }, &tpm),
            Ok(_)
        );
    }

    #[test]
    fn generate_keypair() {
        let tpm = GscServiceClient::default().0;
        assert_matches!(
            rkp::generate_ecdsa_p256_keypair(
                GenerateEcdsaP256KeyPairRequest { test_mode: true },
                &tpm
            ),
            Ok(_)
        );
    }

    #[test]
    fn get_dice_chain() {
        let tpm = GscServiceClient::default().0;

        let ret = rkp::get_dice_chain(&tpm);
        assert_matches!(ret.as_ref(), Ok(_));

        log_bytes(&ret.unwrap());
    }

    #[test]
    fn generate_certificate_request_v2() {
        let tpm = GscServiceClient::default().0;

        let ret = rkp::generate_ecdsa_p256_keypair(
            GenerateEcdsaP256KeyPairRequest { test_mode: true },
            &tpm,
        );
        assert_matches!(ret.as_ref(), Ok(_));
        let GenerateEcdsaP256KeyPairResponse { maced_public_key, ret: _ } = ret.unwrap();

        let challenge = b"1234567890abcdefghijklmnopqrstuv".to_vec();
        let ret = rkp::generate_certificate_request_v2(
            GenerateCertificateRequestV2Request { keys_to_sign: vec![maced_public_key], challenge },
            vec![],
            &tpm,
        );
        assert_matches!(ret.as_ref(), Ok(_));
    }

    #[test]
    fn smoke_test() {
        let tpm = GscServiceClient::default().0;

        let ret = rkp::generate_ecdsa_p256_keypair(
            GenerateEcdsaP256KeyPairRequest { test_mode: true },
            &tpm,
        );
        assert_matches!(ret.as_ref(), Ok(_));
        let GenerateEcdsaP256KeyPairResponse { maced_public_key: _, ret: key_blob } = ret.unwrap();

        validate_key_blob(&key_blob);

        const APP_ID: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
        const APP_DATA: &[u8] = &[0x11, 0x22, 0x33, 0x44];

        let key_params = vec![
            KeyParam::Algorithm(Algorithm::Ec),
            KeyParam::KeySize(KeySizeInBits(256)),
            KeyParam::Purpose(KeyPurpose::Sign),
            KeyParam::Digest(Digest::Sha256),
            KeyParam::AllowWhileOnBody,
            KeyParam::UserId(0xF00),
            KeyParam::ApplicationId(APP_ID.to_vec()),
            KeyParam::ApplicationData(APP_DATA.to_vec()),
        ];
        let ret = device::generate_key(
            GenerateKeyRequest {
                key_params,
                attestation_key: Some(AttestationKey {
                    key_blob,
                    attest_key_params: Vec::new(),
                    issuer_subject_name: Vec::new(),
                }),
            },
            &tpm,
        );
        assert_matches!(ret.as_ref(), Ok(_));
        let GenerateKeyResponse {
            ret:
                KeyCreationResult {
                    key_blob: signing_key_blob,
                    key_characteristics: _,
                    certificate_chain: _,
                },
        } = ret.unwrap();

        validate_key_blob(&signing_key_blob);

        let ret = device::begin(
            BeginRequest {
                purpose: KeyPurpose::Sign,
                key_blob: signing_key_blob,
                params: vec![
                    KeyParam::ApplicationId(APP_ID.to_vec()),
                    KeyParam::ApplicationData(APP_DATA.to_vec()),
                ],
                auth_token: None,
            },
            &tpm,
        );
        assert_matches!(ret.as_ref(), Ok(_));
        let BeginResponse { ret: InternalBeginResult { challenge: _, params: _, op_handle } } =
            ret.unwrap();

        if let Err(err) = operation::update(
            UpdateRequest {
                op_handle,
                input: b"0123456789ABCDEF0123456789ABCDEF".to_vec(),
                auth_token: None,
                timestamp_token: None,
            },
            &tpm,
        ) {
            panic!("update failed: {:?}", err);
        }

        if let Err(err) = operation::finish(
            FinishRequest {
                op_handle,
                input: None,
                signature: None,
                auth_token: None,
                timestamp_token: None,
                confirmation_token: None,
            },
            &tpm,
        ) {
            panic!("finish failed: {:?}", err);
        }
    }
}
