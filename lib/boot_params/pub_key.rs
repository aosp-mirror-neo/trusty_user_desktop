use ciborium::de::Error as CbError;
use coset::cbor;
use coset::CoseError;

use crate::get_cbor_array_from_map;
use crate::get_cbor_bytes_from_map;
use crate::get_cbor_int_from_map;

#[allow(dead_code)]
#[derive(Default, Clone)]
pub struct SubjectPublicKey {
    pub kty: u32,
    pub alg: i32,
    pub key_ops: [u8; 4],
    pub crv: u32,
    pub x: [u8; 32],
    pub y: [u8; 32],
}

const KEY_TYPE_LABEL: i32 = 1;
const ALG_TYPE_LABEL: i32 = 3;
const KEY_OPS_LABEL: i32 = 4;
const CURVE_LABEL: i32 = -1;
const X_LABEL: i32 = -2;
const Y_LABEL: i32 = -3;

impl coset::AsCborValue for SubjectPublicKey {
    fn from_cbor_value(value: cbor::value::Value) -> coset::Result<Self> {
        if let Some(vals) = value.as_map() {
            let key_ops = get_cbor_array_from_map(vals, KEY_OPS_LABEL)?;
            // This is just an int but encoded as an array, so ensure the size is 1.
            if key_ops.len() != 1 {
                return Err(CoseError::DecodeFailed(CbError::Syntax(0)));
            }
            let key_ops: u32 = key_ops[0]
                .as_integer()
                .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?
                .try_into()
                .map_err(|_| CoseError::DecodeFailed(CbError::Syntax(0)))?;

            let key = SubjectPublicKey {
                kty: get_cbor_int_from_map::<u32>(vals, KEY_TYPE_LABEL)?,
                alg: get_cbor_int_from_map::<i32>(vals, ALG_TYPE_LABEL)?,
                key_ops: key_ops.to_le_bytes(),
                crv: get_cbor_int_from_map::<u32>(vals, CURVE_LABEL)?,
                x: *get_cbor_bytes_from_map(vals, X_LABEL)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                y: *get_cbor_bytes_from_map(vals, Y_LABEL)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
            };
            Ok(key)
        } else {
            Err(CoseError::DecodeFailed(CbError::Syntax(0)))
        }
    }
    fn to_cbor_value(self) -> coset::Result<cbor::value::Value> {
        Err(CoseError::EncodeFailed)
    }
}
