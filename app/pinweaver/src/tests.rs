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

use crate::service::binder_error;
use binder::Strong;
use gsc_svc_client::GscServiceClient;
use pinweaver_api::{
    connect_pinweaver, DelayScheduleEntry, IPinWeaver, InsertMode, LeafId, LeafSet, TryAuthResponse,
};
use tpm_commands::pinweaver::Pinweaver;

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

test::init!();

#[test]
fn pinweaver_smoke_test() {
    const DEFAULT_LEAF_ID: LeafId = LeafId { leafSet: LeafSet::WEAVER, id: 77i32 };
    const DEFAULT_LOW_ENTROPY_SECRET: [u8; 32] = [5u8; 32];
    const DEFAULT_HIGH_ENTROPY_SECRET: [u8; 32] = [6u8; 32];
    const DEFAULT_LARGE_SECRET: [u8; 33] = [6u8; 33];
    const DEFAULT_RESET_SECRET: [u8; 32] = [7u8; 32];
    const DEFAULT_DELAY_SCHEDULE: [DelayScheduleEntry; 1] =
        [DelayScheduleEntry { attemptCount: 1, delaySecs: 999 }];

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
