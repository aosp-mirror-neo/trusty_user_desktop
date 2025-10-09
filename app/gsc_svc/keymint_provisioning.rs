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

use android_desktop_security_keymint_provisioning::aidl::android::desktop::security::keymint_provisioning::IKeyMintProvisioning::IKeyMintProvisioning;
use android_desktop_security_keymint_provisioning::aidl::android::desktop::security::keymint_provisioning::IKeyMintProvisioning::BnKeyMintProvisioning;
use binder::{Interface, Result as BinderResult, Strong, BinderFeatures};
use std::sync::{Arc, Mutex};
use keymint_legacy_client::KeyMintSecureLegacyClient;
use openssl::error::ErrorStack;
use openssl::stack::Stack;
use openssl::x509::{store::{X509StoreBuilder},  X509StoreContext, X509};

pub struct KeyMintProvisioningService {
    identity_certs: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Interface for KeyMintProvisioningService {}

impl Default for KeyMintProvisioningService {
    fn default() -> Self {
        Self { identity_certs: Arc::new(Mutex::new(Vec::new())) }
    }
}

pub(crate) fn create_service() -> Strong<dyn IKeyMintProvisioning> {
    BnKeyMintProvisioning::new_binder(
        KeyMintProvisioningService::default(),
        BinderFeatures::default(),
    )
}

const TRUSTED_ROOT_CA_DER: &[u8] = include_bytes!("privacy_root_ca.der");

fn parse_cert_bytes(cert_bytes: &[u8]) -> Result<X509, ErrorStack> {
    X509::from_der(cert_bytes).map_err(|e| {
        log::error!("failed to parse x509 certificate from DER bytes: {e}");
        e
    })
}

impl IKeyMintProvisioning for KeyMintProvisioningService {
    fn isUdsCertificateChainProvisioned(&self) -> BinderResult<bool> {
        log::info!("is_uds_certificate_chain_provisioned handler!");

        let Ok(mut km) = KeyMintSecureLegacyClient::new() else {
            log::error!("failed to create KeyMint legacy client");
            return Err(binder_error::illegal_state(c"create client"));
        };

        let Ok(certs) = km.get_uds_certs() else {
            log::error!("failed to get UDS certs");
            return Err(binder_error::illegal_state(c"get certs"));
        };

        log::info!("CERTS: {certs:?}");

        let Some(uds_cert_bytes) = certs.first() else {
            log::error!("UDS cert chain was empty");
            return Ok(false);
        };
        let uds_cert = parse_cert_bytes(uds_cert_bytes).map_err(|_| {
            binder_error::parse_certificate_failed(
                c"Failed to parse UDS certificate from DER bytes",
            )
        })?;

        let Some(intermediate_cert_bytes) = certs.get(1) else {
            log::error!("Intermediate cert was not present");
            return Ok(false);
        };
        let intermediate_cert = parse_cert_bytes(intermediate_cert_bytes).map_err(|_| {
            binder_error::parse_certificate_failed(
                c"Failed to parse intermediate certificate from DER bytes",
            )
        })?;

        let root_ca = parse_cert_bytes(TRUSTED_ROOT_CA_DER).map_err(|_| {
            binder_error::parse_certificate_failed(
                c"Failed to parse root privacy certificate from DER bytes",
            )
        })?;

        let mut intermediate_chain = Stack::new().map_err(|e| {
            log::error!("failed to create stack for intermediate certificate: {e}");
            binder_error::prepare_certificate_failed(c"create new certificate stack")
        })?;
        intermediate_chain.push(intermediate_cert).map_err(|e| {
            log::error!("failed to push intermediate cert onto certificate chain: {e}");
            binder_error::prepare_certificate_failed(c"push intermediate cert onto chain")
        })?;

        let mut builder = X509StoreBuilder::new().map_err(|e| {
            log::error!("failed to create new x509 store builder: {e}");
            binder_error::prepare_certificate_failed(c"create x509 store")
        })?;
        builder.add_cert(root_ca).map_err(|e| {
            log::error!("failed to add root certificate to x509 store: {e}");
            binder_error::prepare_certificate_failed(c"add root certificate to x509 store")
        })?;
        let store = builder.build();

        let mut context = X509StoreContext::new().map_err(|e| {
            log::error!("failed to create x509 store context: {e}");
            binder_error::prepare_certificate_failed(c"create x509 store context")
        })?;

        let verify_success = context
            .init(&store, &uds_cert, intermediate_chain.as_ref(), |ctx| ctx.verify_cert())
            .map_err(|e| {
                log::error!("certificate verification process failed: {e}");
                binder_error::verify_certificate_failed(c"certificate context init")
            })?;

        if !verify_success {
            let message = format!(
                "UDS Certificate chain validation failed. Reason: {:?}",
                context.error().error_string()
            );
            log::error!("{message}");
            return Err(binder_error::verify_certificate_unsuccessful());
        }

        log::info!("UDS Certificate Chain verification succeeded.");
        Ok(true)
    }

    fn appendProductIdentityCertificate(&self, data: &[u8]) -> BinderResult<()> {
        log::info!("append_product_identity_certificate handler!");

        self.identity_certs.lock().unwrap().push(data.to_vec());

        // TODO: If the certificate is a leaf, verify the certificate chain and provision the IDs.
        // TODO: Send a SetAttestationIds message to keymint.

        Ok(())
    }

    fn clearProductIdentityCertificateChain(&self) -> BinderResult<()> {
        log::info!("clear_product_identity_certificate_chain handler!");
        self.identity_certs.lock().unwrap().clear();
        Ok(())
    }
}

mod binder_error {
    use std::ffi::CStr;
    use binder::{ExceptionCode, Status};
    use android_desktop_security_keymint_provisioning::aidl::android::desktop::security::keymint_provisioning::IKeyMintProvisioning::{ERROR_PARSE_CERTIFICATE_FAILED, ERROR_CERTIFICATE_PREPARATION_FAILED, ERROR_CERTIFICATE_VERIFICATION_FAILED, ERROR_CERTIFICATE_VERIFICATION_UNSUCCESSFUL};

    pub fn illegal_state(msg: &CStr) -> Status {
        Status::new_exception(ExceptionCode::ILLEGAL_STATE, Some(msg))
    }

    pub fn parse_certificate_failed(msg: &CStr) -> Status {
        Status::new_service_specific_error(ERROR_PARSE_CERTIFICATE_FAILED, Some(msg))
    }

    pub fn prepare_certificate_failed(msg: &CStr) -> Status {
        Status::new_service_specific_error(ERROR_CERTIFICATE_PREPARATION_FAILED, Some(msg))
    }

    pub fn verify_certificate_failed(msg: &CStr) -> Status {
        Status::new_service_specific_error(ERROR_CERTIFICATE_VERIFICATION_FAILED, Some(msg))
    }

    pub fn verify_certificate_unsuccessful() -> Status {
        Status::new_service_specific_error(
            ERROR_CERTIFICATE_VERIFICATION_UNSUCCESSFUL,
            Some(c"certificates did not verify"),
        )
    }
}
