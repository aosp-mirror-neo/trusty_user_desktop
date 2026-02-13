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
use binder::{Interface, Result as BinderResult, Strong, BinderFeatures, Status as BinderStatus};
use std::sync::{Arc, Mutex};
use keymint_legacy_client::KeyMintSecureLegacyClient;
use openssl::{error::ErrorStack, stack::Stack, x509::{store::X509StoreBuilder, X509StoreContext, X509}};
use crate::proto::android_product_identity_certificate_extension;
use kmr_wire::legacy::SetAttestationIdsRequest;
use protobuf::Message;
use spki::{Error as SpkiError, ObjectIdentifier};
use x509_cert::{
    certificate::CertificateInner,
    der::{
        asn1::{OctetString, PrintableStringRef},
        Decode,
    },
    ext::{Extension, Extensions},
};

const TRUSTED_ROOT_CA_DER: &[u8] = include_bytes!("privacy_root_ca.der");
const CHROME_ANDROID_IDENTITY_DATA_OID: &str = "1.3.6.1.4.1.11129.2.1.54";
const ORGANIZATIONAL_UNIT_NAME_OID: &str = "2.5.4.11";

type Certificate = CertificateInner<CustomProfile>;

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

fn parse_cert_bytes(cert_bytes: &[u8]) -> Result<X509, ErrorStack> {
    X509::from_der(cert_bytes).map_err(|e| {
        log::error!("failed to parse x509 certificate from DER bytes: {e}");
        e
    })
}

fn get_android_identity_extension<'a>(
    cert: &'a Certificate,
) -> Result<Option<&'a Extension>, SpkiError> {
    let target_oid = CHROME_ANDROID_IDENTITY_DATA_OID.parse::<ObjectIdentifier>().unwrap();
    let extensions: &'a Extensions = match cert.tbs_certificate.extensions.as_ref() {
        Some(exts) => exts,
        None => return Ok(None),
    };

    let found_extension: Option<&'a Extension> =
        extensions.iter().find(|ext| ext.extn_id == target_oid);
    Ok(found_extension)
}

fn get_brand(cert: &Certificate) -> Option<&str> {
    let org_unit_name_oid = ORGANIZATIONAL_UNIT_NAME_OID.parse::<ObjectIdentifier>().unwrap();
    cert.tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .find(|attr| attr.oid == org_unit_name_oid)
        .and_then(|attr| PrintableStringRef::try_from(&attr.value).ok())
        .map(|printable_ref| printable_ref.as_str())
}

fn check_non_empty(data: Vec<u8>, field_name: &str) -> Result<Vec<u8>, BinderStatus> {
    if data.is_empty() {
        log::error!("Required field is empty: {field_name}");
        return Err(binder_error::identity_field_missing());
    }
    Ok(data)
}

impl IKeyMintProvisioning for KeyMintProvisioningService {
    fn isUdsCertificateChainProvisioned(&self) -> BinderResult<bool> {
        log::info!("isUdsCertificateChainProvisioned handler!");

        let Ok(mut km) = KeyMintSecureLegacyClient::new() else {
            log::error!("failed to create KeyMint legacy client");
            return Err(binder_error::illegal_state(c"create client"));
        };

        let Ok(certs) = km.get_uds_certs() else {
            log::error!("failed to get UDS certs");
            return Err(binder_error::illegal_state(c"get certs"));
        };

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
        log::info!("appendProductIdentityCertificate handler!");

        self.identity_certs.lock().unwrap().push(data.to_vec());

        // TODO: If the certificate is a leaf, verify the certificate chain
        let cert = Certificate::from_der(data).map_err(|e| {
            log::error!("Error decoding cert from DER bytes: {e}");
            binder_error::parse_certificate_failed(c"Failed to parse DER certificate from bytes")
        })?;

        let extension = get_android_identity_extension(&cert).map_err(|e| {
            log::error!("Error fetching certificate from X.509 certificate: {e}");
            binder_error::parse_certificate_failed(
                c"Failed to parse Android Identity extension from X509 cert",
            )
        })?;
        if extension.is_none() {
            return Err(binder_error::certificate_extension_missing());
        }

        let extn_bytes: &[u8] = extension.unwrap().extn_value.as_bytes();
        let octet_string = OctetString::from_der(extn_bytes).map_err(|e| {
            log::error!("Failed to decode extn_value bytes as DER octet string: {e}");
            binder_error::parse_certificate_failed(
                c"Failed to parse octet string from Android Identity extension",
            )
        })?;

        let proto_bytes: &[u8] = octet_string.as_bytes();
        let identity_data = android_product_identity_certificate_extension::AndroidProductIdentityCertificateExtension::parse_from_bytes(proto_bytes).map_err(|e| {
            log::error!("Failed to create AndroidProductIdentityCertificateExtension from bytes: {e}");
            binder_error::parse_certificate_failed(
                c"Failed to parse octet string into AndroidProductIdentityCertificateExtension proto"
            )
        })?;

        let product_data = identity_data.get_product_data_info().get_product_data();
        let serial_number_info = identity_data.get_serial_number_info();
        let device = check_non_empty(product_data.get_device().as_bytes().to_vec(), "device")?;
        let product = check_non_empty(product_data.get_product().as_bytes().to_vec(), "product")?;
        let serial =
            check_non_empty(serial_number_info.get_serial_number().as_bytes().to_vec(), "serial")?;
        let manufacturer =
            check_non_empty(product_data.get_manufacturer().as_bytes().to_vec(), "manufacturer")?;
        let model = check_non_empty(product_data.get_model().as_bytes().to_vec(), "model")?;

        let brand = get_brand(&cert);
        if brand.is_none() {
            log::error!("Failed to find brand in the certificate subject");
            return Err(binder_error::identity_field_missing());
        }
        let brand = brand.unwrap().as_bytes().to_vec();

        let Ok(mut km) = KeyMintSecureLegacyClient::new() else {
            log::error!("failed to create KeyMint legacy client");
            return Err(binder_error::illegal_state(c"create client"));
        };

        log::trace!(
            "appendProductIdentityCertificate: brand: {}, device: {}, product: {}",
            String::from_utf8_lossy(&brand).as_ref(),
            String::from_utf8_lossy(&device).as_ref(),
            String::from_utf8_lossy(&product).as_ref()
        );
        log::trace!(
            "appendProductIdentityCertificate: serial: {}, manufacturer: {}, model: {}",
            String::from_utf8_lossy(&serial).as_ref(),
            String::from_utf8_lossy(&manufacturer).as_ref(),
            String::from_utf8_lossy(&model).as_ref()
        );

        let mut ids = SetAttestationIdsRequest {
            brand,
            device,
            product,
            serial,
            manufacturer,
            model,
            // TODO(b/466129460): Choose a dedicated value for AL devices without cellular
            imei: b"867400022047199".to_vec(),
            meid: Vec::new(),
        };

        // TODO(b/460182466): For brya builds, we use "google" to match
        // `ro.product.brand`. Note that if a mismatch occurs, RKP/gECC/HPA will
        // fail.
        if product_data.get_device() == "brya" {
            ids.brand = "google".as_bytes().to_vec();
        }

        km.set_attestation_ids(ids).map_err(|e| {
            log::error!("Failed to set attestation IDs: {e}");
            binder_error::attestation_unsuccessful()
        })?;

        log::info!("Sending OK");
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
    use android_desktop_security_keymint_provisioning::aidl::android::desktop::security::keymint_provisioning::IKeyMintProvisioning::{ERROR_PARSE_CERTIFICATE_FAILED, ERROR_CERTIFICATE_PREPARATION_FAILED, ERROR_CERTIFICATE_VERIFICATION_FAILED, ERROR_CERTIFICATE_VERIFICATION_UNSUCCESSFUL, ERROR_CERTIFICATE_EXTENSION_MISSING, ERROR_IDENTITY_FIELD_MISSING, ERROR_SET_ATTESTATION_IDS_FAILED};

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

    pub fn certificate_extension_missing() -> Status {
        Status::new_service_specific_error(
            ERROR_CERTIFICATE_EXTENSION_MISSING,
            Some(c"certificate extension containing attestation details missing"),
        )
    }

    pub fn identity_field_missing() -> Status {
        Status::new_service_specific_error(
            ERROR_IDENTITY_FIELD_MISSING,
            Some(c"certificate did not contain required field"),
        )
    }

    pub fn attestation_unsuccessful() -> Status {
        Status::new_service_specific_error(
            ERROR_SET_ATTESTATION_IDS_FAILED,
            Some(c"SetAttestationIds call was unsuccessful"),
        )
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Default)]
struct CustomProfile;

impl x509_cert::certificate::Profile for CustomProfile {
    fn check_serial_number(
        _serial: &x509_cert::serial_number::SerialNumber<Self>,
    ) -> der::Result<()> {
        Ok(())
    }
}
