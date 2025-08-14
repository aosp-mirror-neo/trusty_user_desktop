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
//! Unit tests.

use crate::service::{api_to_storage, binder_error, gsc_to_storage};
use binder::Strong;
use gsc_svc_client::GscServiceClient;
use pinweaver_api::{
    connect_pinweaver, DelayScheduleEntry, IPinWeaver, InsertMode, LeafId, LeafSet, TryAuthResponse,
};
use pinweaver_storage_api::{
    request::{CommitOpRequest, StartOpRequest},
    response::{StartOpResponse, StartOpResponseData, StartTryAuthResponseData},
    util::{DeserializeExact, ForwardTipcSerialize, SerdeVec},
    StorageRequest, StorageResponse, EMPTY_TREE_HASH,
};
use std::convert::AsRef;
use tipc::{Deserialize, Handle, Serialize, Serializer};
use tpm_commands::pinweaver::{Pinweaver, UnimportedLeafData};
use zerocopy::FromBytes;

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

const DEFAULT_LEAF_ID: LeafId = LeafId { leafSet: LeafSet::WEAVER, id: 77i32 };
const DEFAULT_LOW_ENTROPY_SECRET: [u8; 32] = [5u8; 32];
const DEFAULT_HIGH_ENTROPY_SECRET: [u8; 32] = [6u8; 32];
const DEFAULT_LARGE_SECRET: [u8; 33] = [6u8; 33];
const DEFAULT_RESET_SECRET: [u8; 32] = [7u8; 32];
const DEFAULT_DELAY_SCHEDULE: [DelayScheduleEntry; 1] =
    [DelayScheduleEntry { attemptCount: 1, delaySecs: 999 }];
const OTHER_LEAF_ID: LeafId = LeafId { leafSet: LeafSet::WEAVER, id: 88i32 };
const OTHER_LOW_ENTROPY_SECRET: [u8; 32] = [8u8; 32];
const OTHER_HIGH_ENTROPY_SECRET: [u8; 32] = [9u8; 32];
const OTHER_DELAY_SCHEDULE: [DelayScheduleEntry; 1] =
    [DelayScheduleEntry { attemptCount: 10, delaySecs: 999 }];
const THIRD_LEAF_ID: LeafId = LeafId { leafSet: LeafSet::WEAVER, id: 99i32 };

test::init!();

/// A serializer that borrows its input bytes and does not allocate.
#[derive(Default)]
struct TestSerializer(Vec<u8>);

impl<'a> Serializer<'a> for TestSerializer {
    type Ok = ();
    type Error = ();

    fn serialize_bytes(&mut self, bytes: &'a [u8]) -> Result<Self::Ok, Self::Error> {
        self.0.extend(bytes);
        Ok(())
    }

    fn serialize_handle(&mut self, _handle: &'a Handle) -> Result<Self::Ok, Self::Error> {
        panic!("no handles should be used");
    }
}

/// A test-only helper to provide access to the storage daemon through IPinweaver.
fn storage_request(
    pinweaver: &dyn IPinWeaver,
    request: &StorageRequest,
) -> binder::Result<StorageResponse> {
    let mut serializer = TestSerializer::default();
    ForwardTipcSerialize(request).serialize(&mut serializer).expect("serialize failed");
    let buffer = pinweaver.testStorage(serializer.0.as_slice())?;
    let resp = DeserializeExact::<StorageResponse>::deserialize(buffer.as_slice(), &mut [])
        .expect("deserialize failed");
    Ok(resp.0)
}

#[test]
fn pinweaver_smoke_test() {
    // Start from a known state.
    let pinweaver: Strong<dyn IPinWeaver> =
        connect_pinweaver().expect("connect_pinweaver() failed");

    pinweaver.removeAll(LeafSet::ALL_LEAVES).expect("removeAll() failed");
    log::info!("After removeAll()");

    assert_eq!(pinweaver.removeAll(LeafSet::WEAVER), Err(binder_error::leaf_not_found()));

    // Insert a fresh leaf.
    pinweaver
        .insert(
            &DEFAULT_LEAF_ID,
            &DEFAULT_LOW_ENTROPY_SECRET,
            &DEFAULT_HIGH_ENTROPY_SECRET,
            &DEFAULT_RESET_SECRET,
            &DEFAULT_DELAY_SCHEDULE,
            InsertMode::NEW_ONLY,
        )
        .expect("insert() failed");
    log::info!("After first insert()");

    // Insert with replacement.
    pinweaver
        .insert(
            &DEFAULT_LEAF_ID,
            &DEFAULT_LOW_ENTROPY_SECRET,
            &DEFAULT_HIGH_ENTROPY_SECRET,
            &DEFAULT_RESET_SECRET,
            &DEFAULT_DELAY_SCHEDULE,
            InsertMode::REPLACE_EXISTING,
        )
        .expect("insert() failed");
    log::info!("After second insert()");

    // Insert that fails with WouldReplace.
    assert_eq!(
        pinweaver.insert(
            &DEFAULT_LEAF_ID,
            &DEFAULT_LOW_ENTROPY_SECRET,
            &DEFAULT_HIGH_ENTROPY_SECRET,
            &DEFAULT_RESET_SECRET,
            &DEFAULT_DELAY_SCHEDULE,
            InsertMode::NEW_ONLY,
        ),
        Err(binder_error::leaf_exists())
    );
    log::info!("After third insert()");

    // Try Auth that succeeds.
    assert_matches!(
        pinweaver.tryAuthenticate(&DEFAULT_LEAF_ID, &DEFAULT_LOW_ENTROPY_SECRET),
        Ok(TryAuthResponse::HighEntropySecret(s)) if s == &DEFAULT_HIGH_ENTROPY_SECRET
    );

    // Try Auth that fails.
    assert_matches!(
        pinweaver.tryAuthenticate(&DEFAULT_LEAF_ID, &[0u8; 32]),
        Err(s) if s == &binder_error::low_entropy_auth_failed()
    );

    // Try Auth during back-off.
    assert_matches!(
        pinweaver.tryAuthenticate(&DEFAULT_LEAF_ID, &DEFAULT_LOW_ENTROPY_SECRET),
        Ok(TryAuthResponse::SecondsToWait(s)) if *s > 0
    );

    // Reset Retries with wrong secret.
    assert_matches!(
        pinweaver.resetRetries(&DEFAULT_LEAF_ID, false, &DEFAULT_LOW_ENTROPY_SECRET),
        Err(s) if s == &binder_error::auth_failed()
    );

    // Reset Retries that succeeds.
    assert_matches!(pinweaver.resetRetries(&DEFAULT_LEAF_ID, false, &DEFAULT_RESET_SECRET), Ok(()));
    // Make sure the back-off is cleared.
    assert_matches!(
        pinweaver.tryAuthenticate(&DEFAULT_LEAF_ID, &DEFAULT_LOW_ENTROPY_SECRET),
        Ok(TryAuthResponse::HighEntropySecret(s)) if s == &DEFAULT_HIGH_ENTROPY_SECRET
    );

    // Remove that succeeds.
    pinweaver.remove(&DEFAULT_LEAF_ID).expect("remove() failed");

    // Remove that failes with DoesNotExist.
    assert_eq!(pinweaver.remove(&DEFAULT_LEAF_ID), Err(binder_error::leaf_not_found()));

    // Check that large secrets work.
    pinweaver
        .insert(
            &DEFAULT_LEAF_ID,
            &DEFAULT_LOW_ENTROPY_SECRET,
            &DEFAULT_LARGE_SECRET,
            &DEFAULT_RESET_SECRET,
            &DEFAULT_DELAY_SCHEDULE,
            InsertMode::NEW_ONLY,
        )
        .expect("insert() failed");
    assert_matches!(
        pinweaver.tryAuthenticate(&DEFAULT_LEAF_ID, &DEFAULT_LOW_ENTROPY_SECRET),
        Ok(TryAuthResponse::HighEntropySecret(s)) if s == &DEFAULT_LARGE_SECRET
    );

    let gsc = GscServiceClient::default();
    let mut buffer = Vec::new();
    let log_entries = gsc.get_log(None, &mut buffer).expect("get_log() failed");
    assert!(log_entries.len() > 0);

    let _ = storage_request(pinweaver.as_ref(), &StorageRequest::GetStatus);

    for id in 0i32..3 {
        pinweaver
            .insert(
                &LeafId { leafSet: LeafSet::WEAVER, id },
                &DEFAULT_LOW_ENTROPY_SECRET,
                &DEFAULT_HIGH_ENTROPY_SECRET,
                &DEFAULT_RESET_SECRET,
                &DEFAULT_DELAY_SCHEDULE,
                InsertMode::NEW_ONLY,
            )
            .expect("insert() failed");
    }
    pinweaver.removeAll(LeafSet::WEAVER).expect("removeAll() failed");
    assert_eq!(pinweaver.removeAll(LeafSet::WEAVER), Err(binder_error::leaf_not_found()));
}

#[test]
fn pinweaver_log_replay_test() {
    // Start from a known state.
    let pinweaver: Strong<dyn IPinWeaver> =
        connect_pinweaver().expect("connect_pinweaver() failed");

    pinweaver.removeAll(LeafSet::ALL_LEAVES).expect("removeAll() failed");
    log::info!("After removeAll()");

    pinweaver
        .insert(
            &DEFAULT_LEAF_ID,
            &DEFAULT_LOW_ENTROPY_SECRET,
            &DEFAULT_HIGH_ENTROPY_SECRET,
            &DEFAULT_RESET_SECRET,
            &OTHER_DELAY_SCHEDULE,
            InsertMode::NEW_ONLY,
        )
        .expect("insert() failed");

    pinweaver
        .insert(
            &OTHER_LEAF_ID,
            &OTHER_LOW_ENTROPY_SECRET,
            &OTHER_HIGH_ENTROPY_SECRET,
            &DEFAULT_RESET_SECRET,
            &OTHER_DELAY_SCHEDULE,
            InsertMode::NEW_ONLY,
        )
        .expect("insert() failed");

    // Try Auth that succeeds.
    assert_matches!(
        pinweaver.tryAuthenticate(&DEFAULT_LEAF_ID, &DEFAULT_LOW_ENTROPY_SECRET),
        Ok(TryAuthResponse::HighEntropySecret(s)) if s == &DEFAULT_HIGH_ENTROPY_SECRET
    );

    // Back up the leaf contents to force storage out of sync.
    let start_request = StartOpRequest::TryAuth(api_to_storage::leaf_id(&DEFAULT_LEAF_ID));
    let resp = storage_request(pinweaver.as_ref(), &StorageRequest::StartOp(start_request.clone()))
        .expect("storage request failed");
    let (new_leaf_hmac, new_leaf_contents) = if let StorageResponse::StartOp(StartOpResponse {
        op_data: StartOpResponseData::TryAuth(StartTryAuthResponseData { leaf_contents, .. }),
        ..
    }) = resp
    {
        let hmac = gsc_to_storage::hmac(
            &UnimportedLeafData::ref_from_bytes(leaf_contents.as_ref())
                .expect("parsing leaf data failed")
                .hmac,
        );
        (hmac, leaf_contents)
    } else {
        panic!("unexpected response: {:?}", resp);
    };
    // Try Auth that fails.
    assert_matches!(
        pinweaver.tryAuthenticate(&DEFAULT_LEAF_ID, &[0u8; 32]),
        Err(s) if s == &binder_error::low_entropy_auth_failed()
    );
    // Roll back the try-auth with a fake operation.
    let _ = storage_request(pinweaver.as_ref(), &StorageRequest::StartOp(start_request.clone()))
        .expect("storage request failed");
    let _ = storage_request(
        pinweaver.as_ref(),
        &StorageRequest::CommitOp(CommitOpRequest {
            start_request,
            new_leaf_hmac,
            new_leaf_contents,
        }),
    )
    .expect("storage request failed");

    // Test log-replay.
    pinweaver.reconcile().expect("reconcile failed");

    pinweaver
        .insert(
            &THIRD_LEAF_ID,
            &OTHER_LOW_ENTROPY_SECRET,
            &DEFAULT_HIGH_ENTROPY_SECRET,
            &DEFAULT_RESET_SECRET,
            &OTHER_DELAY_SCHEDULE,
            InsertMode::NEW_ONLY,
        )
        .expect("insert() failed");
    // Remove the THIRD_LEAF_ID to test replaying an insert.
    let start_request = StartOpRequest::Remove(api_to_storage::leaf_id(&THIRD_LEAF_ID));
    let _ = storage_request(pinweaver.as_ref(), &StorageRequest::StartOp(start_request.clone()))
        .expect("storage request failed");
    let _ = storage_request(
        pinweaver.as_ref(),
        &StorageRequest::CommitOp(CommitOpRequest {
            start_request,
            new_leaf_hmac: EMPTY_TREE_HASH,
            new_leaf_contents: SerdeVec::from_vec(Vec::new()),
        }),
    )
    .expect("storage request failed");

    // Test log-replay.
    pinweaver.reconcile().expect("reconcile failed");
    assert_matches!(
        pinweaver.tryAuthenticate(&THIRD_LEAF_ID, &OTHER_LOW_ENTROPY_SECRET),
        Err(err) if *err == binder_error::leaf_not_found()
    );

    // Back up the leaf contents to force storage out of sync.
    let resp = storage_request(
        pinweaver.as_ref(),
        &StorageRequest::StartOp(
            StartOpRequest::TryAuth(api_to_storage::leaf_id(&OTHER_LEAF_ID)).clone(),
        ),
    )
    .expect("storage request failed");
    let (path, new_leaf_hmac, new_leaf_contents) =
        if let StorageResponse::StartOp(StartOpResponse {
            path,
            op_data: StartOpResponseData::TryAuth(StartTryAuthResponseData { leaf_contents, .. }),
            ..
        }) = resp
        {
            let hmac = gsc_to_storage::hmac(
                &UnimportedLeafData::ref_from_bytes(leaf_contents.as_ref())
                    .expect("parsing leaf data failed")
                    .hmac,
            );
            (path, hmac, leaf_contents)
        } else {
            panic!("unexpected response: {:?}", resp);
        };

    pinweaver.remove(&OTHER_LEAF_ID).expect("remove failed");

    // Restore OTHER_LEAF_ID for the storage only.
    let start_request = StartOpRequest::LogReplay(path);
    let _ = storage_request(pinweaver.as_ref(), &StorageRequest::StartOp(start_request.clone()))
        .expect("storage request failed");
    let _ = storage_request(
        pinweaver.as_ref(),
        &StorageRequest::CommitOp(CommitOpRequest {
            start_request,
            new_leaf_hmac,
            new_leaf_contents,
        }),
    )
    .expect("storage request failed");

    // Test log-replay.
    pinweaver.reconcile().expect("reconcile failed");
    assert_matches!(
        pinweaver.tryAuthenticate(&OTHER_LEAF_ID, &OTHER_LOW_ENTROPY_SECRET),
        Err(err) if *err == binder_error::leaf_not_found()
    );

    // Make sure the existing leaf still works.
    assert_matches!(
        pinweaver.tryAuthenticate(&DEFAULT_LEAF_ID, &DEFAULT_LOW_ENTROPY_SECRET),
        Ok(TryAuthResponse::HighEntropySecret(s)) if s == &DEFAULT_HIGH_ENTROPY_SECRET
    );
}
