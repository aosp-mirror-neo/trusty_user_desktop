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
use once_cell::sync::OnceCell;
use openssl::ec::EcKey;
use openssl::pkey::Public;

/// Public keys of all SDCP trusted key signing keys.
pub static TRUSTED_ROOTS: OnceCell<Vec<EcKey<Public>>> = OnceCell::new();

/// The production version of Google key signing keys.
//TODO(b/444233621): create a prod signing key.
const KSK_PUBLIC_KEYS: [EcPointBytes; 0] = [];

/// The development version of key signing keys.
#[cfg(feature = "dev_sdcp_pki")]
const DEV_KSK_PUBLIC_KEYS: [EcPointBytes; 1] = [[
    0x04, 0xfd, 0xc8, 0xb2, 0xe0, 0xa2, 0x95, 0x12, 0x3f, 0x4a, 0x5b, 0x77, 0x13, 0xbc, 0xc5, 0x2f,
    0xf5, 0x50, 0x78, 0x19, 0x04, 0x4e, 0xa1, 0x48, 0x17, 0xb6, 0xa5, 0xb9, 0x94, 0xd7, 0xe7, 0x85,
    0xff, 0x8c, 0xdd, 0x49, 0x09, 0x91, 0xda, 0xf4, 0x81, 0x5a, 0xa1, 0x89, 0xfc, 0xa6, 0xee, 0x26,
    0x45, 0xdd, 0x6c, 0xf6, 0x6e, 0xb1, 0x61, 0x35, 0xdf, 0xa0, 0xec, 0xb5, 0x77, 0x44, 0xf7, 0xd2,
    0x95,
]];

type EcPointBytes = [u8; 65];

// Helper to convert p256 public key point raw bytes into EcKey<Public>.
fn parse_public_key_bytes(p256_point_bytes: &EcPointBytes) -> EcKey<Public> {
    let p256_point = P256Point::import(p256_point_bytes).expect("static key should not fail");
    EcKey::try_from(&p256_point).expect("static key should not fail.")
}

/// Verify the signature on the model key is issued from trusted key signing keys.
pub fn verify_public_key_signature(
    model_key: &P256Point,
    key_sig: &P256Sig,
) -> ServiceResult<bool> {
    let trusted_roots = TRUSTED_ROOTS.get_or_init(|| {
        let mut trusted_roots = vec![];
        trusted_roots.append(&mut KSK_PUBLIC_KEYS.iter().map(parse_public_key_bytes).collect());

        #[cfg(feature = "dev_sdcp_pki")]
        {
            trusted_roots
                .append(&mut DEV_KSK_PUBLIC_KEYS.iter().map(parse_public_key_bytes).collect());
        }

        trusted_roots
    });
    let dgst = compute_sha256!(model_key);
    for root in trusted_roots.iter() {
        if root.verify(&dgst, key_sig)? {
            return Ok(true);
        }
    }
    // Allow the model key to be self signed in the unit tests.
    #[cfg(test)]
    {
        if model_key.verify(&dgst, key_sig)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod test {
    use super::{verify_public_key_signature, KSK_PUBLIC_KEYS};
    use crate::crypto::{self, compute_sha256};
    use openssl::ec::EcKey;

    // A dev firmware model key.
    const DEV_MODEL_KEY_BYTES: [u8; 65] = [
        0x04, 0xdb, 0x68, 0x13, 0x51, 0xcf, 0xec, 0x9a, 0x92, 0xce, 0x00, 0xba, 0x17, 0xc6, 0xbe,
        0xd2, 0xd8, 0x5b, 0x1d, 0xb8, 0xd6, 0xbf, 0x07, 0x82, 0xad, 0xe7, 0xc6, 0xbe, 0x69, 0xe2,
        0x1d, 0x1a, 0x45, 0x7b, 0x40, 0x8c, 0xac, 0xc7, 0x4d, 0x89, 0x79, 0x98, 0x68, 0x74, 0x10,
        0xcd, 0x45, 0xe4, 0xfb, 0xff, 0x62, 0x73, 0x0e, 0xbc, 0xc8, 0x7d, 0xac, 0x81, 0xf6, 0xb2,
        0xba, 0x12, 0x6c, 0x1e, 0x8a,
    ];
    // Signature produced by the dev key signing process.
    const DEV_SIG_BYTES: [u8; 64] = [
        0x34, 0x51, 0x71, 0x9a, 0xab, 0x29, 0x1a, 0x3f, 0x37, 0x14, 0x03, 0xb2, 0xc3, 0x19, 0xcc,
        0x40, 0xba, 0x18, 0x4e, 0xee, 0xcf, 0x8d, 0xbc, 0x9d, 0x23, 0x40, 0x20, 0xbe, 0x15, 0x24,
        0xfd, 0xbd, 0xc1, 0xfb, 0xed, 0x69, 0x6d, 0xf5, 0xe9, 0xb5, 0xc6, 0x34, 0x6b, 0xa0, 0x27,
        0x3c, 0x75, 0x65, 0xd9, 0xe1, 0x3d, 0x8a, 0xa4, 0xf7, 0xa0, 0x45, 0x57, 0x76, 0x47, 0x10,
        0x67, 0xe0, 0xff, 0xa6,
    ];

    #[test]
    fn verify_dev_signed_model_key() {
        let model_key = crypto::P256Point::import(&DEV_MODEL_KEY_BYTES).unwrap();
        let sig = crypto::P256Sig::import(&DEV_SIG_BYTES).unwrap();
        let dev_key_works = verify_public_key_signature(&model_key, &sig).unwrap();
        let dev_key_should_work = cfg!(feature = "dev_sdcp_pki");
        assert_eq!(dev_key_works, dev_key_should_work);
    }

    #[test]
    fn load_prod_roots() {
        for public_key_bytes in KSK_PUBLIC_KEYS.iter() {
            let p256_point = crypto::P256Point::import(public_key_bytes).unwrap();
            assert!(EcKey::try_from(&p256_point).is_ok());
        }
    }

    #[test]
    fn self_signed_model_key() {
        let model_private_key = crypto::ec_keygen().unwrap();
        let model_public_key = crypto::ec_public_key_serialization(&model_private_key).unwrap();
        let dgst = compute_sha256!(&model_public_key);
        let p256_sig = crypto::ecdsa_sign(&dgst, &model_private_key).unwrap();
        assert!(verify_public_key_signature(&model_public_key, &p256_sig).unwrap());
    }
}
