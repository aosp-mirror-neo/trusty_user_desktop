/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http, 0x//www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Hardcoded Root(s) of Trust for SDCP

use crate::crypto::{compute_sha256, P256Point, P256Sig, P256SigVerifier};
use crate::error::ServiceResult;
use crate::service::VerifiedBootState;
use once_cell::sync::OnceCell;
use openssl::ec::EcKey;
use openssl::pkey::Public;

/// Public keys of all SDCP trusted key signing keys.
pub static TRUSTED_ROOTS: OnceCell<Vec<EcKey<Public>>> = OnceCell::new();

type EcPointBytes = [u8; 65];

/// The production version of Google key signing keys.
//TODO(b/444233621): create a prod signing key.
const KSK_PUBLIC_KEYS: [&EcPointBytes; 0] = [];

/// The development version of key signing keys.
#[cfg(feature = "dev_sdcp_pki")]
const DEV_KSK_PUBLIC_KEYS: [&EcPointBytes; 1] =
    [include_bytes!("sdcp_pki_data/dev_ksk_public_key.bin")];

// Helper to convert p256 public key point raw bytes into EcKey<Public>.
fn parse_public_key_bytes(p256_point_bytes: &&EcPointBytes) -> EcKey<Public> {
    let p256_point = P256Point::from(*p256_point_bytes);
    EcKey::try_from(&p256_point).expect("static key should not fail.")
}

/// Verify the signature on the model key is issued from trusted key signing keys.
pub fn verify_public_key_signature(
    model_key: &P256Point,
    key_sig: &P256Sig,
    boot_state: &VerifiedBootState,
) -> ServiceResult<bool> {
    let trusted_roots = TRUSTED_ROOTS.get_or_init(|| {
        let mut trusted_roots = vec![];
        trusted_roots.extend(KSK_PUBLIC_KEYS.iter().map(parse_public_key_bytes));

        #[cfg(feature = "dev_sdcp_pki")]
        {
            trusted_roots.extend(DEV_KSK_PUBLIC_KEYS.iter().map(parse_public_key_bytes));
        }

        trusted_roots
    });
    let dgst = compute_sha256!(model_key);
    for root in trusted_roots {
        if root.verify(&dgst, key_sig)? {
            return Ok(true);
        }
    }
    // Allow the model key to be self signed when the device secure boot mode is off.
    if *boot_state == VerifiedBootState::Unverified && model_key.verify(&dgst, key_sig)? {
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod test {
    use super::{verify_public_key_signature, KSK_PUBLIC_KEYS};
    use crate::crypto::{self, compute_sha256};
    use crate::service::VerifiedBootState;
    use openssl::ec::EcKey;

    // A dev firmware model key.
    const DEV_MODEL_KEY_BYTES: &[u8; 65] = include_bytes!("test_data/dev_model_key.bin");
    // Signature produced by the dev key signing process.
    const DEV_SIG_BYTES: &[u8; 64] = include_bytes!("test_data/dev_model_key.sig.bin");

    #[test]
    fn verify_dev_signed_model_key() {
        let boot_state = VerifiedBootState::Verified;
        let model_key = crypto::P256Point::from(DEV_MODEL_KEY_BYTES);
        let sig = crypto::P256Sig::from(DEV_SIG_BYTES);
        let dev_key_works = verify_public_key_signature(&model_key, &sig, &boot_state).unwrap();
        let dev_key_should_work = cfg!(feature = "dev_sdcp_pki");
        assert_eq!(dev_key_works, dev_key_should_work);
    }

    #[test]
    fn load_prod_roots() {
        for public_key_bytes in KSK_PUBLIC_KEYS {
            let p256_point = crypto::P256Point::from(public_key_bytes);
            assert!(EcKey::try_from(&p256_point).is_ok());
        }
    }

    #[test]
    fn self_signed_model_key() {
        let boot_state = Default::default();
        let model_private_key = crypto::ec_keygen().unwrap();
        let model_public_key = crypto::ec_public_key_serialization(&model_private_key).unwrap();
        let dgst = compute_sha256!(&model_public_key);
        // By default the boot state is unverified and self signed key is allowed.
        let p256_sig = crypto::ecdsa_sign(&dgst, &model_private_key).unwrap();
        assert!(verify_public_key_signature(&model_public_key, &p256_sig, &boot_state).unwrap());
    }
}
