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

//! Implementation for the weaver hal

use crate::message::{ResponseStatus, WeaverHalResponse};
use crate::WeaverTAError;
use binder::Strong;
use pinweaver_api::aidl::IPinWeaver::ERROR_LEAF_NOT_FOUND;
use pinweaver_api::aidl::IPinWeaver::ERROR_LOWENT_AUTH_FAILED;
use pinweaver_api::aidl::IPinWeaver::ERROR_NOT_READY;
use pinweaver_api::connect_pinweaver;
use pinweaver_api::DelayScheduleEntry;
use pinweaver_api::IPinWeaver;
use pinweaver_api::InsertMode;
use pinweaver_api::LeafId;
use pinweaver_api::LeafSet;
use pinweaver_api::TryAuthResponse::HighEntropySecret;
use pinweaver_api::TryAuthResponse::SecondsToWait;
use std::thread;
use std::time;

pub(crate) struct PinWeaverImpl {
    pinweaver_connection: Strong<dyn IPinWeaver>,
}

pub(crate) trait Weaver {
    fn read(&self, slot_id: i32, key: &[u8]) -> Result<WeaverHalResponse, WeaverTAError>;
    fn write(
        &self,
        slot_id: i32,
        key: &[u8],
        value: &[u8],
    ) -> Result<WeaverHalResponse, WeaverTAError>;
}

pub(crate) fn connect_to_pinweaver() -> Result<PinWeaverImpl, WeaverTAError> {
    let pinweaver_connection = connect_pinweaver().map_err(|e| {
        WeaverTAError::PinweaverConnectionError("Could not connect to piweaver".to_string(), e)
    })?;
    Ok(PinWeaverImpl { pinweaver_connection })
}

macro_rules! retry_if_not_ready {
    ($expr:expr) => {
        loop {
            let pinweaver_response = $expr;
            if let Err(status) = &pinweaver_response {
                if status.service_specific_error() == ERROR_NOT_READY {
                    thread::sleep(time::Duration::from_millis(50));
                    continue;
                }
            }
            break pinweaver_response;
        }
    };
}

impl Weaver for PinWeaverImpl {
    fn read(&self, slot_id: i32, key: &[u8]) -> Result<WeaverHalResponse, WeaverTAError> {
        let mut key_resize = Vec::with_capacity(32);
        if key.len() < 32 {
            key_resize.extend_from_slice(key);
            key_resize.resize(32usize, 0u8);
        }
        let auth_response = retry_if_not_ready!(self.pinweaver_connection.tryAuthenticate(
            &LeafId { leafSet: LeafSet::WEAVER, id: slot_id },
            if key.len() >= 32 { &key[0..32] } else { key_resize.as_slice() },
        ));

        match auth_response {
            Ok(SecondsToWait(timeout)) => {
                // Convert timeout to uint
                let timeout = u64::try_from(timeout).map_err(|_| {
                    WeaverTAError::PinweaverUnexpectedResult(format!(
                        "Invalid timeout value {timeout} given"
                    ))
                })?;

                Ok(WeaverHalResponse::ReadResponse {
                    status: ResponseStatus::Throttle,
                    timeout,
                    value: Vec::new(),
                })
            }
            Ok(HighEntropySecret(value)) => Ok(WeaverHalResponse::ReadResponse {
                status: ResponseStatus::Ok,
                timeout: 0,
                value,
            }),
            Err(e) => {
                if e.service_specific_error() == ERROR_LOWENT_AUTH_FAILED {
                    Ok(WeaverHalResponse::ReadResponse {
                        status: ResponseStatus::IncorrectKey,
                        timeout: 0,
                        value: Vec::new(),
                    })
                } else if e.service_specific_error() == ERROR_LEAF_NOT_FOUND {
                    Ok(WeaverHalResponse::ReadResponse {
                        status: ResponseStatus::Failed,
                        timeout: 0,
                        value: Vec::new(),
                    })
                } else {
                    Err(WeaverTAError::PinweaverError(
                        "Could not perform 'tryAuthenticate'".to_string(),
                        e,
                    ))
                }
            }
        }
    }

    fn write(
        &self,
        slot_id: i32,
        key: &[u8],
        value: &[u8],
    ) -> Result<WeaverHalResponse, WeaverTAError> {
        let delay_schedule = vec![DelayScheduleEntry { attemptCount: 5, delaySecs: 60 }];

        let mut key_resize = Vec::with_capacity(32);
        if key.len() < 32 {
            key_resize.extend_from_slice(key);
            key_resize.resize(32usize, 0u8);
        }

        let mut reset_resize = Vec::with_capacity(32);
        if value.len() < 32 {
            reset_resize.extend_from_slice(value);
            reset_resize.resize(32usize, 0u8);
        }

        retry_if_not_ready!(self.pinweaver_connection.insert(
            &LeafId { leafSet: LeafSet::WEAVER, id: slot_id },
            if key.len() >= 32 { &key[0..32] } else { key_resize.as_slice() },
            value,
            if value.len() >= 32 { &value[0..32] } else { reset_resize.as_slice() },
            &delay_schedule,
            InsertMode::REPLACE_EXISTING,
        ))
        .map_err(|e| WeaverTAError::PinweaverError("Could not perform 'insert'".to_string(), e))?;

        Ok(WeaverHalResponse::WriteResponse { status: ResponseStatus::Ok })
    }
}
