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

//! Tests for the trusty FingerGuardService.
//!
//! These tests are integration tests, intended to be executed within the actual trusty VM using
//! the real services.

use crate::keymint;
use android_desktop_security_finger_guard::aidl::android::desktop::security::finger_guard::{
    AuthenticationResult::AuthenticationResult, EnrollmentResult::EnrollmentResult,
    SensorUserPair::SensorUserPair,
};
use finger_guard::crypto::{self, NIST_P256_CURVE_NAME};
use finger_guard::error::ServiceResult;
use finger_guard::hat::{AuthenticatorType, UnsignedHat};
use finger_guard::identifiers::{AuthenticatorId, SecureUserId};
use finger_guard::rng;
use finger_guard::time::Instant;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey, PointConversionForm};
use test::{assert, assert_eq, assert_ne, assert_ok, skip};
use zerocopy::FromBytes;

// Struct used in tests to allow arbitrary blobs to be supplied to the HMAC generator.
struct TestBlob<'a>(&'a [u8]);
impl<'a> crypto::HmacSignable for TestBlob<'a> {
    fn update(&self, mut add_bytes: impl FnMut(&[u8]) -> ServiceResult<()>) -> ServiceResult<()> {
        add_bytes(self.0)
    }
}

test::init!();

#[test]
fn connect_server() {
    let _ = assert_ok!(finger_guard_api::connect_finger_guard());
}

#[test]
fn everything_with_a_shared_session() {
    let auth_token_key = assert_ok!(keymint::get_auth_token_key());

    // Prepare the client key pair.
    let group = assert_ok!(EcGroup::from_curve_name(NIST_P256_CURVE_NAME));
    let mut ctx = assert_ok!(BigNumContext::new());
    let client_private_key = assert_ok!(EcKey::generate(&group));
    let client_public_key_bytes = assert_ok!(client_private_key.public_key().to_bytes(
        &group,
        PointConversionForm::UNCOMPRESSED,
        &mut ctx
    ));

    // ECDH with the server. If the service has already done a handshake then it's not
    // possible to run this test, skip it and move on.
    let service = assert_ok!(finger_guard_api::connect_finger_guard());
    let handshake = match service.init(client_public_key_bytes.as_slice()) {
        Err(status) if status.transaction_error() == binder::StatusCode::ALREADY_EXISTS => {
            skip!("service already bound to a controller")
        }
        result => assert_ok!(result),
    };
    let server_public_key_bytes = handshake.serverPublicKey;

    // Derive PK from the client side.
    let pk = assert_ok!(crypto::perform_ecdh(client_private_key, &server_public_key_bytes));

    // Check the computed MAC matches the one in the response.
    let hmac = assert_ok!(crypto::compute_hmac!(&pk, &TestBlob(b"tofu")));
    assert!(hmac == handshake.pkMac.as_slice());

    // Generate the client nonce.
    let client_nonce = rng::generate_random_vec::<32>();

    // Start a new session with the server.
    let session_response = assert_ok!(service.createClientSession(client_nonce.as_slice()));
    let session = session_response.clientSession.unwrap();
    let sk = assert_ok!(crypto::compute_hmac!(
        &pk,
        &TestBlob(&client_nonce),
        &TestBlob(&session_response.nonce)
    ));

    // Decrypt the wrapped tpm seed.
    let iv = assert_ok!(crypto::Iv::read_from_bytes(session_response.iv.as_slice()));
    let tag = assert_ok!(crypto::Aes256Tag::read_from_bytes(session_response.tag.as_slice()));
    let encrypted_tpm_seed = session_response.wrappedTpmSeed;
    let aad = b"tpm_seed";
    assert_ok!(crypto::decrypt_aes256_gcm(&sk, &iv, aad, encrypted_tpm_seed.as_slice(), &tag,));

    // Convert the HMAC into a key.
    let sk = crypto::Key::from(sk);

    let sensor_id = 1_i32;
    let user_id = 1_i32;
    let sup = SensorUserPair { sensorId: sensor_id, userId: user_id };
    let secure_user_id_int = 0x1337BEEF_i64;
    let secure_user_id = SecureUserId::from(secure_user_id_int);

    // ---- Start Enrollment Test ----
    let hat = UnsignedHat::new(
        assert_ok!(service.generateChallenge(&sup)),
        secure_user_id,
        AuthenticatorId::generate_random(),
        AuthenticatorType::FINGERPRINT,
        Instant::from_nanos(0),
    );
    let hat = assert_ok!(hat.sign(&auth_token_key));
    let nonce = rng::generate_random_vec::<32>();
    let prepare_resp = assert_ok!(session.prepareEnrollSession(&sup, &hat, &nonce));
    let hmac = assert_ok!(crypto::compute_hmac!(
        &sk,
        &TestBlob(&nonce),
        &TestBlob(&user_id.to_be_bytes()),
        &TestBlob(b"finger_guardenroll")
    ));
    assert!(hmac == prepare_resp.mac.as_slice());
    let old_auth_id = assert_ok!(service.getAuthenticatorId(&sup));
    let nonce = rng::generate_random_vec::<32>();
    let enrollment_result = EnrollmentResult { enrolled: true };
    let finish_resp = assert_ok!(session.finishEnrollSession(&sup, &enrollment_result, &nonce));
    // Ensure the authenticator id updates after enrollment.
    let new_auth_id = assert_ok!(service.getAuthenticatorId(&sup));
    assert_ne!(new_auth_id, old_auth_id);
    let hmac = assert_ok!(crypto::compute_hmac!(
        &sk,
        &TestBlob(&nonce),
        &TestBlob(&user_id.to_be_bytes()),
        &TestBlob(b"finger_guardenroll_finish")
    ));
    assert!(hmac == finish_resp.mac.as_slice());
    // Test enrollment session cancellation.
    let hat = UnsignedHat::new(
        assert_ok!(service.generateChallenge(&sup)),
        secure_user_id,
        AuthenticatorId::generate_random(),
        AuthenticatorType::FINGERPRINT,
        Instant::from_nanos(0),
    );
    let hat = assert_ok!(hat.sign(&auth_token_key));
    let nonce = rng::generate_random_vec::<32>();
    let _ = assert_ok!(session.prepareEnrollSession(&sup, &hat, &nonce));
    let cancel_result = EnrollmentResult { enrolled: false };
    let _ = assert_ok!(session.finishEnrollSession(&sup, &cancel_result, &nonce));
    // ---- End Enrollment Test ----

    // ---- Start Authentication Test ----
    let challenge = 0xc4a11e49e_i64;
    let nonce = rng::generate_random_vec::<32>();
    let prepare_resp = assert_ok!(session.prepareAuthSession(&sup, challenge, &nonce));
    let hmac = assert_ok!(crypto::compute_hmac!(
        &sk,
        &TestBlob(&nonce),
        &TestBlob(&user_id.to_be_bytes()),
        &TestBlob(b"finger_guardauth")
    ));
    assert!(hmac == prepare_resp.mac.as_slice());

    let hmac = assert_ok!(crypto::compute_hmac!(
        &sk,
        &TestBlob(&prepare_resp.nonce),
        &TestBlob(&user_id.to_be_bytes()),
        &TestBlob(b"fpmcuauth")
    ));
    let auth_result = AuthenticationResult::from(hmac);
    let valid_hat = assert_ok!(session.finishAuthSession(&sup, &auth_result));
    assert_eq!(valid_hat.challenge, challenge);
    assert_eq!(valid_hat.userId, secure_user_id_int);
    assert_eq!(valid_hat.authenticatorId, new_auth_id);
    assert_ne!(valid_hat.timestamp, 0);
    assert!(
        crypto::compute_hmac!(&auth_token_key, &valid_hat).unwrap() == valid_hat.mac.as_slice()
    );
    // ---- End Authentication Test ----
}

#[test]
fn get_authenticator_id() {
    let service = assert_ok!(finger_guard_api::connect_finger_guard());
    let sup = SensorUserPair { sensorId: 0, userId: 0 };
    assert_eq!(service.getAuthenticatorId(&sup), Ok(0));
}

#[test]
fn new_authenticator_id() {
    let service = assert_ok!(finger_guard_api::connect_finger_guard());
    let sup = SensorUserPair { sensorId: 1, userId: 1 };
    let new_id = assert_ok!(service.newAuthenticatorId(&sup));
    assert_ne!(new_id, 0_i64);
}

#[test]
fn new_and_get_authenticator_id() {
    let service = assert_ok!(finger_guard_api::connect_finger_guard());
    let sup = SensorUserPair { sensorId: 1, userId: 1 };
    let new_id = assert_ok!(service.newAuthenticatorId(&sup));
    let got_id = assert_ok!(service.getAuthenticatorId(&sup));
    assert_eq!(new_id, got_id);
}

#[test]
fn generate_and_revoke_challenge() {
    let service = assert_ok!(finger_guard_api::connect_finger_guard());
    let sup = SensorUserPair { sensorId: 1, userId: 1 };
    // Generate multiple challenges and revoke them individually.
    let c1 = assert_ok!(service.generateChallenge(&sup));
    assert_ne!(c1, 0_i64);
    let c2 = assert_ok!(service.generateChallenge(&sup));
    assert_ne!(c2, 0_i64);
    assert_ne!(c1, c2);
    // Revoke once, return the same challenge.
    let revoked_c1 = assert_ok!(service.revokeChallenge(&sup, c1));
    assert_eq!(c1, revoked_c1);
    let revoked_c2 = assert_ok!(service.revokeChallenge(&sup, c2));
    assert_eq!(c2, revoked_c2);
    // Revoke the 1st challenge twice, return zero.
    assert_eq!(service.revokeChallenge(&sup, c1), Ok(0));
}

#[test]
fn revoke_invalid_challenge() {
    let service = assert_ok!(finger_guard_api::connect_finger_guard());
    let sup = SensorUserPair { sensorId: 2, userId: 2 };
    let invalid_challenge = 1234_i64;
    assert_eq!(service.revokeChallenge(&sup, invalid_challenge), Ok(0));
}
