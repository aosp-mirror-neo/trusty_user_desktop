use ciborium::de::Error as CbError;
use coset::cbor;
use coset::CoseError;
use coset::CoseKey;
use kmr_wire::read_to_value;

use crate::cdi::ConfigurationDescriptor;
use crate::get_cbor_bytes_from_map;
use crate::get_cbor_string_from_map;

#[allow(dead_code)]
#[derive(Default, Clone)]
pub struct CwtClaims {
    pub iss: String,
    pub sub: String,
    pub code_hash: [u8; 32],
    pub cfg_hash: [u8; 32],
    pub cfg_descr: ConfigurationDescriptor,
    pub auth_hash: [u8; 32],
    pub mode: [u8; 1],
    pub subject_pk: CoseKey,
    pub key_usage: [u8; 1],
    pub profile_name: String,
}

const ISS_LABEL: i32 = 1;
const SUB_LABEL: i32 = 2;
const CODE_HASH_LABEL: i32 = -4670545;
const CFG_HASH_LABEL: i32 = -4670547;
const CFG_DESCR_LABEL: i32 = -4670548;
const AUTH_HASH_LABEL: i32 = -4670549;
const MODE_LABEL: i32 = -4670551;
const SUBJECT_PK_LABEL: i32 = -4670552;
const KEY_USAGE_LABEL: i32 = -4670553;
const PROFILE_NAME_LABEL: i32 = -4670554;

impl coset::AsCborValue for CwtClaims {
    fn from_cbor_value(value: cbor::value::Value) -> coset::Result<Self> {
        if let Some(vals) = value.as_map() {
            let cdi = get_cbor_bytes_from_map(vals, CFG_DESCR_LABEL)?;
            let cdi =
                read_to_value(cdi).map_err(|_| CoseError::DecodeFailed(CbError::Syntax(0)))?;
            let cdi = ConfigurationDescriptor::from_cbor_value(cdi.clone())?;

            let subject_pk = get_cbor_bytes_from_map(vals, SUBJECT_PK_LABEL)?;
            let subject_pk = read_to_value(subject_pk)
                .map_err(|_| CoseError::DecodeFailed(CbError::Syntax(0)))?;
            let subject_pk = CoseKey::from_cbor_value(subject_pk.clone())?;

            let cwt = CwtClaims {
                iss: get_cbor_string_from_map(vals, ISS_LABEL)?.to_owned(),
                sub: get_cbor_string_from_map(vals, SUB_LABEL)?.to_owned(),
                cfg_hash: *get_cbor_bytes_from_map(vals, CFG_HASH_LABEL)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                code_hash: *get_cbor_bytes_from_map(vals, CODE_HASH_LABEL)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                cfg_descr: cdi,
                auth_hash: *get_cbor_bytes_from_map(vals, AUTH_HASH_LABEL)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                mode: *get_cbor_bytes_from_map(vals, MODE_LABEL)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                subject_pk,
                key_usage: *get_cbor_bytes_from_map(vals, KEY_USAGE_LABEL)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,

                profile_name: get_cbor_string_from_map(vals, PROFILE_NAME_LABEL)?.to_owned(),
            };

            Ok(cwt)
        } else {
            Err(CoseError::DecodeFailed(CbError::Syntax(0)))
        }
    }
    fn to_cbor_value(self) -> coset::Result<cbor::value::Value> {
        Err(CoseError::EncodeFailed)
    }
}
