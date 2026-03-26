/*
 * Copyright (C) 2026 The Android Open Source Project
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

use alloc::rc::Rc;
use android_desktop_security_boot_params::aidl::android::desktop::security::boot_params::IBootParams::IBootParams;
use authgraph_core::{
    key::{CertChain, EcSignKey, EcVerifyKey, Identity, PseudoRandKey, EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION, IDENTITY_VERSION},
    error::Error as AuthGraphError, traits::CryptoTraitImpl};
use core::cell::RefCell;
use coset::{iana, CoseKeyBuilder, ParseSec1OctetStringError};
use log::info;
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    error::ErrorStack,
    nid::Nid};
use secretkeeper_comm::data_types::error::Error as SkInternalError;
use secretkeeper_core::{store::KeyValueStore, ta::SecretkeeperTa};
use service_manager::wait_for_interface;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    AuthGraphFailure(AuthGraphError),
    BinderConnectionFailure(binder::StatusCode),
    BinderCallFailure(binder::Status),
    CosetFailure(ParseSec1OctetStringError),
    OpenSslFailure(ErrorStack),
    SecretKeeperFailure(SkInternalError),
    InternalFailure(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthGraphFailure(err) => write!(f, "Authgraph PRK generation failed: {:?}", err),
            Self::BinderConnectionFailure(code) => {
                write!(f, "Binder connection failed: {:?}", code)
            }
            Self::BinderCallFailure(status) => write!(f, "Binder call failed: {:?}", status),
            Self::CosetFailure(err) => write!(f, "Coset key builder failed: {:?}", err),
            Self::OpenSslFailure(err) => write!(f, "OpenSSL call failed: {:?}", err),
            Self::SecretKeeperFailure(err) => write!(f, "SecretKeeper internal error: {:?}", err),
            Self::InternalFailure(s) => write!(f, "Internal error: {:?}", s),
        }
    }
}

const BP_SERVICE_PORT: &str = "com.android.trusty.rust.BootParamsService.V1";

pub fn secretkeeper_ta(
    ag_impls: &mut CryptoTraitImpl,
    storage_impl: Box<dyn KeyValueStore>,
) -> Result<Rc<RefCell<SecretkeeperTa>>, Error> {
    info!("Retrieving derived session key from boot params");
    let bp: binder::Strong<dyn IBootParams> =
        wait_for_interface(BP_SERVICE_PORT).map_err(Error::BinderConnectionFailure)?;
    let salt = b"Secretkeeper";
    let prk_vec = bp.deriveSessionKey(salt).map_err(Error::BinderCallFailure)?;
    let prk_array = <[u8; 32]>::try_from(prk_vec).map_err(|v| {
        Error::InternalFailure(format!("PRK size mismatch: expected 32, got {}", v.len()))
    })?;

    let context = b"AuthGraph Identity Key Derivation";
    let derived_material = ag_impls
        .hkdf
        .expand(&PseudoRandKey(prk_array), context)
        .map_err(Error::AuthGraphFailure)?;

    info!("Deriving ECDSA P_256 key pair");
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(Error::OpenSslFailure)?;
    let mut ctx = BigNumContext::new().map_err(Error::OpenSslFailure)?;
    let priv_key_bn = BigNum::from_slice(&derived_material.0).map_err(Error::OpenSslFailure)?;
    let mut pub_key_point = EcPoint::new(&group).map_err(Error::OpenSslFailure)?;
    // Derive the public key point by multiplying the Generator point by the private key.
    pub_key_point.mul_generator(&group, &priv_key_bn, &ctx).map_err(Error::OpenSslFailure)?;
    let ec_key = EcKey::from_private_components(&group, &priv_key_bn, &pub_key_point)
        .map_err(Error::OpenSslFailure)?;
    // Secretkeeper expects the private key to be DER-encoded (ASN.1 structure).
    let priv_key = ec_key.private_key_to_der().map_err(Error::OpenSslFailure)?;
    let pub_bytes = ec_key
        .public_key()
        .to_bytes(&group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(Error::OpenSslFailure)?;
    let pub_key_builder =
        CoseKeyBuilder::new_ec2_pub_key_sec1_octet_string(iana::EllipticCurve::P_256, &pub_bytes)
            .map_err(Error::CosetFailure)?;
    let pub_key = pub_key_builder.algorithm(iana::Algorithm::ES256).build();

    let identity_sign_key = EcSignKey::P256(priv_key);
    let identity = Identity {
        version: IDENTITY_VERSION,
        cert_chain: CertChain {
            version: EXPLICIT_KEY_DICE_CERT_CHAIN_VERSION,
            root_key: EcVerifyKey::P256(pub_key),
            dice_cert_chain: None,
        },
        policy: None,
    };

    info!("Constructing and returning Secretkeeper TA");
    let ta =
        SecretkeeperTa::new_with_identity(ag_impls, storage_impl, identity_sign_key, identity, 4)
            .map_err(Error::SecretKeeperFailure)?;
    Ok(Rc::new(RefCell::new(ta)))
}
