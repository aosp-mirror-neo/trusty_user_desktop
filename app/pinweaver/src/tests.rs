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
use pinweaver_api::{
    connect_pinweaver, DelayScheduleEntry, IPinWeaver, InsertMode, LeafId, LeafSet,
};

test::init!();

#[test]
fn pinweaver_smoke_test() {
    const DEFAULT_LEAF_ID: LeafId = LeafId { leafSet: LeafSet::WEAVER, id: 77i32 };
    const DEFAULT_LOW_ENTROPY_SECRET: [u8; 32] = [5u8; 32];
    const DEFAULT_HIGH_ENTROPY_SECRET: [u8; 32] = [6u8; 32];
    const DEFAULT_RESET_SECRET: [u8; 32] = [7u8; 32];
    const DEFAULT_DELAY_SCHEDULE: [DelayScheduleEntry; 1] =
        [DelayScheduleEntry { attemptCount: 15, delaySecs: 30 }];

    // Start from a known state.
    let pinweaver: Strong<dyn IPinWeaver> =
        connect_pinweaver().expect("connect_pinweaver() failed");

    pinweaver.removeAll(LeafSet::ALL_LEAVES).expect("removeAll() failed");
    log::info!("After removeAll()");

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

    // Remove that succeeds.
    pinweaver.remove(&DEFAULT_LEAF_ID).expect("remove() failed");

    // Remove that failes with DoesNotExist.
    assert_eq!(pinweaver.remove(&DEFAULT_LEAF_ID), Err(binder_error::leaf_not_found()));
}
