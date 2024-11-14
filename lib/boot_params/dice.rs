use ciborium::de::Error as CbError;
use coset::cbor;
use coset::CoseError;
use kmr_wire::read_to_value;

use crate::cwt::CwtClaims;
use crate::get_cbor_array_from_map;
use crate::get_cbor_bytes_from_map;
use crate::pub_key::SubjectPublicKey;

pub struct CdiCert {
    pub cwt: CwtClaims,
    pub signature: [u8; 64],
}

pub struct DiceHandover {
    pub cdi_attest: [u8; 32],
    pub cdi_seal: [u8; 32],
    pub uds_pubkey: SubjectPublicKey,
    pub cdi_cert: CdiCert,
}
impl coset::AsCborValue for DiceHandover {
    fn from_cbor_value(value: cbor::value::Value) -> coset::Result<Self> {
        if let Some(vals) = value.as_map() {
            let arr = get_cbor_array_from_map(vals, 3)?;

            let cwt_arr = arr[1].as_array().ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?;
            let cwt = read_to_value(
                cwt_arr[2].as_bytes().ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
            )
            .map_err(|_| CoseError::DecodeFailed(CbError::Syntax(0)))?;
            let cwt = CwtClaims::from_cbor_value(cwt.clone())?;

            let uds_pubkey = DiceHandover {
                cdi_attest: *get_cbor_bytes_from_map(vals, 1)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                cdi_seal: *get_cbor_bytes_from_map(vals, 2)?
                    .first_chunk()
                    .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                uds_pubkey: SubjectPublicKey::from_cbor_value(arr[0].clone())?,
                cdi_cert: CdiCert {
                    cwt,
                    signature: *cwt_arr[3]
                        .as_bytes()
                        .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?
                        .first_chunk()
                        .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?,
                },
            };
            Ok(uds_pubkey)
        } else {
            Err(CoseError::DecodeFailed(CbError::Syntax(0)))
        }
    }
    fn to_cbor_value(self) -> coset::Result<cbor::value::Value> {
        Err(CoseError::EncodeFailed)
    }
}
