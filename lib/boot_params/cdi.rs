use ciborium::de::Error as CbError;
use coset::cbor;
use coset::CoseError;

use crate::get_cbor_bytes_from_map;
use crate::get_cbor_int_from_map;
use crate::get_cbor_string_from_map;

#[allow(dead_code)]
#[derive(Default, Clone)]
pub struct ConfigurationDescriptor {
    pub comp_name: String,
    pub resettable: Option<u8>,
    pub sec_ver: u32,
    pub aprov_status: Option<[u8; 4]>,
    pub vboot_status: [u8; 32],
    pub ap_fw_ver: [u8; 32],
}

const COMP_NAME_LABEL: i32 = -70002;
const RESETTABLE_LABEL: i32 = -70004;
const SEC_VER_LABEL: i32 = -70005;
const APROV_STATUS_LABEL: i32 = -71000;
const VBOOT_STATUS_LABEL: i32 = -71001;
const AP_FW_VERSION_LABEL: i32 = -71002;

impl coset::AsCborValue for ConfigurationDescriptor {
    fn from_cbor_value(value: cbor::value::Value) -> coset::Result<Self> {
        if let Some(vals) = value.as_map() {
            let cdi = ConfigurationDescriptor {
                comp_name: get_cbor_string_from_map(vals, COMP_NAME_LABEL)?.to_owned(),
                resettable: get_cbor_int_from_map::<u8>(vals, RESETTABLE_LABEL).ok(),
                sec_ver: get_cbor_int_from_map::<u32>(vals, SEC_VER_LABEL)?,
                aprov_status: get_cbor_bytes_from_map(vals, APROV_STATUS_LABEL)
                    .and_then(|x| {
                        <[u8; 4]>::try_from(x.as_slice())
                            .map_err(|_| CoseError::DecodeFailed(CbError::Syntax(0)))
                    })
                    .ok(),
                vboot_status: *get_cbor_bytes_from_map(vals, VBOOT_STATUS_LABEL)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                ap_fw_ver: *get_cbor_bytes_from_map(vals, AP_FW_VERSION_LABEL)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
            };
            Ok(cdi)
        } else {
            Err(CoseError::DecodeFailed(CbError::Syntax(0)))
        }
    }
    fn to_cbor_value(self) -> coset::Result<cbor::value::Value> {
        Err(CoseError::EncodeFailed)
    }
}
