use ciborium::de::Error as CbError;
use coset::cbor;
use coset::CoseError;

use crate::get_cbor_bytes_from_map;

pub struct GscBootParams {
    pub early_entropy: [u8; 64],
    pub session_key_seed: [u8; 32],
    pub auth_token_key_seed: [u8; 32],
}
impl Default for GscBootParams {
    fn default() -> Self {
        Self {
            early_entropy: [0u8; 64],
            session_key_seed: [0u8; 32],
            auth_token_key_seed: [0u8; 32],
        }
    }
}

impl coset::AsCborValue for GscBootParams {
    fn from_cbor_value(value: cbor::value::Value) -> coset::Result<Self> {
        if let Some(vals) = value.as_map() {
            let params = GscBootParams {
                early_entropy: *get_cbor_bytes_from_map(vals, 1)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                session_key_seed: *get_cbor_bytes_from_map(vals, 2)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                auth_token_key_seed: *get_cbor_bytes_from_map(vals, 3)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
            };
            Ok(params)
        } else {
            Err(CoseError::DecodeFailed(CbError::Syntax(0)))
        }
    }
    fn to_cbor_value(self) -> coset::Result<cbor::value::Value> {
        Err(CoseError::EncodeFailed)
    }
}
