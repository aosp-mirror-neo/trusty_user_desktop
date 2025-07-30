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

use crate::WeaverTAError;

const OP_TYPE_READ: u8 = 0x00;
const OP_TYPE_WRITE: u8 = 0x01;

const SIZE_OF_OP: usize = 1;
const SIZE_OF_SLOT_ID: usize = 4;
const SIZE_OF_SIZE: usize = 4;
const SIZE_OF_TIMEOUT: usize = 8;

pub enum ResponseStatus {
    Ok = 0,
    Failed = 1,
    _IncorrectKey = 2,
    _Throttle = 3,
}

pub enum WeaverHalRequest {
    ReadRequest { slot_id: i32, key: Vec<u8> },
    WriteRequest { slot_id: i32, key: Vec<u8>, value: Vec<u8> },
}

pub enum WeaverHalResponse {
    ReadResponse { status: ResponseStatus, timeout: u64, value: Vec<u8> },
    WriteResponse { status: ResponseStatus },
}

#[derive(Default)]
pub struct BinaryMessageParser {}

pub trait WeaverMessageParser {
    fn deserialize(&self, msg: &[u8]) -> Result<WeaverHalRequest, WeaverTAError>;
    fn serialize(&self, msg: WeaverHalResponse) -> Result<Vec<u8>, WeaverTAError>;
}

// implementation for serialization and deserialization of tipc message
impl WeaverMessageParser for BinaryMessageParser {
    // Deserialize the following message structure
    //   +-------------------+
    //   |                   |
    //   |      1 Byte       |
    //   |     0x0: Read     |
    //   |     0x1: Write    |
    //   |                   |
    //   +-------------------+
    //   |                   |
    //   |      4 Byte       |
    //   |      Slot Id      |
    //   |                   |
    //   +-------------------+
    //   |                   |
    //   |      4 Byte       |
    //   |    Size of key    |
    //   |                   |
    //   +-------------------+
    //   |                   |
    //   |      4 Byte       |
    //   |   Size of value   |
    //   |  (Only if write)  |
    //   |                   |
    //   +-------------------+
    //   |                   |
    //   |        Key        |
    //             .
    //             .
    //             .
    //   |                   |
    //   +-------------------+
    //   |                   |
    //   |       Value       |
    //   |  (Only if write)  |
    //             .
    //             .
    //             .
    //   |                   |
    //   +-------------------+
    fn deserialize(&self, msg: &[u8]) -> Result<WeaverHalRequest, WeaverTAError> {
        if msg.is_empty() {
            return Err(WeaverTAError::BadMessage("Message is empty".to_string()));
        }

        // Get request type
        let operation_type = msg[0];
        let mut current_offset = SIZE_OF_OP;

        // Validate minimum length for the specific operation type before trying to parse fields
        match operation_type {
            OP_TYPE_READ => {
                if msg.len() < SIZE_OF_OP + SIZE_OF_SLOT_ID + SIZE_OF_SIZE {
                    return Err(WeaverTAError::BadMessage("Read message is too short".to_string()));
                }
            }
            OP_TYPE_WRITE => {
                if msg.len() < SIZE_OF_OP + SIZE_OF_SLOT_ID + SIZE_OF_SIZE + SIZE_OF_SIZE {
                    return Err(WeaverTAError::BadMessage(
                        "Write message is too short".to_string(),
                    ));
                }
            }
            _ => {
                return Err(WeaverTAError::BadMessage(format!(
                    "Invalid operation type: {}",
                    operation_type
                )))
            }
        };

        // Get slot id
        let byte_slice_slot_id = &msg[current_offset..current_offset + SIZE_OF_SLOT_ID];
        let slot_id = i32::from_le_bytes(
            byte_slice_slot_id
                .try_into()
                .map_err(|_| WeaverTAError::BadMessage("Could not get slot id".to_string()))?,
        );
        current_offset += SIZE_OF_SLOT_ID;

        // Get key size
        let byte_slice_key_size = &msg[current_offset..current_offset + SIZE_OF_SIZE];
        let key_size = u32::from_le_bytes(
            byte_slice_key_size
                .try_into()
                .map_err(|_| WeaverTAError::BadMessage("Could not get key size".to_string()))?,
        ) as usize;
        current_offset += SIZE_OF_SIZE;

        // Get value size
        let mut value_size = 0;
        if operation_type == OP_TYPE_WRITE {
            let byte_slice_value_size = &msg[current_offset..current_offset + SIZE_OF_SIZE];
            value_size =
                u32::from_le_bytes(byte_slice_value_size.try_into().map_err(|_| {
                    WeaverTAError::BadMessage("Could not get value size".to_string())
                })?) as usize;
            current_offset += SIZE_OF_SIZE;
        }

        // Get key
        let byte_slice_key = &msg[current_offset..current_offset + key_size];
        let key = byte_slice_key.to_vec();
        current_offset += key_size;

        if operation_type == OP_TYPE_READ {
            return Ok(WeaverHalRequest::ReadRequest { slot_id, key });
        }

        // Get Value
        let byte_slice_value = &msg[current_offset..current_offset + value_size];
        let value = byte_slice_value.to_vec();

        Ok(WeaverHalRequest::WriteRequest { slot_id, key, value })
    }

    // serialize the following message structure for read response
    fn serialize(&self, msg: WeaverHalResponse) -> Result<Vec<u8>, WeaverTAError> {
        match msg {
            WeaverHalResponse::WriteResponse { status } => {
                let mut ret_msg = Vec::with_capacity(SIZE_OF_OP);

                ret_msg.push(status as u8);

                Ok(ret_msg)
            }
            WeaverHalResponse::ReadResponse { status, timeout, value } => {
                let mut ret_msg =
                    Vec::with_capacity(SIZE_OF_OP + SIZE_OF_TIMEOUT + SIZE_OF_SIZE + value.len());

                ret_msg.push(status as u8);
                ret_msg.extend_from_slice(&timeout.to_le_bytes());
                ret_msg.extend_from_slice(&(value.len() as u32).to_le_bytes());
                ret_msg.extend_from_slice(&value);

                Ok(ret_msg)
            }
        }
    }
}
