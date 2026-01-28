use ciborium::de::Error as CbError;
use coset::cbor::value::Value;
use coset::AsCborValue;
use coset::CoseError;

pub mod cdi;
pub mod cwt;
pub mod dice;
pub mod gsc;
pub mod pub_key;

use crate::cdi::ConfigurationDescriptor;
use crate::dice::CdiCert;
use crate::dice::DiceHandover;
use crate::gsc::GscBootParams;
use crate::pub_key::SubjectPublicKey;

#[cfg(feature = "builtin-bcc")]
use kmr_wire::read_to_value;

#[derive(Debug)]
pub enum Error {
    NotAvailable,
    CborError,
}

#[allow(dead_code)]
pub struct BootParams {
    pub dice: DiceHandover,
    pub gsc_boot_params: GscBootParams,
}

#[cfg(feature = "builtin-bcc")]
impl Default for BootParams {
    /// Create a boot params struct from constant data.
    fn default() -> Self {
        let data = desktop_test_data::boot::BOOT_PARAM;
        let data = read_to_value(data).unwrap();
        let data = data.as_map().unwrap();

        let dice = find_in_cbor_map(data, Value::Integer(DICE_KEY.into())).unwrap();
        let dice = DiceHandover::from_cbor_value(dice.clone()).unwrap();

        let gsc_boot_params =
            find_in_cbor_map(data, Value::Integer(BOOT_PARAM_KEY.into())).unwrap();
        let gsc_boot_params = GscBootParams::from_cbor_value(gsc_boot_params.clone()).unwrap();

        Self { dice, gsc_boot_params }
    }
}

#[cfg(any(feature = "builtin-bcc", test))]
const BOOT_PARAM_KEY: i32 = 2;
#[cfg(any(feature = "builtin-bcc", test))]
const DICE_KEY: i32 = 3;

impl BootParams {
    pub fn new_from_dt(
        early_entropy: [u8; 64],
        session_key_seed: [u8; 32],
        auth_token_key_seed: [u8; 32],
        dice: &[u8],
    ) -> Result<Self, Error> {
        let dice = ciborium::de::from_reader_with_recursion_limit(dice, 16)
            .map_err(|_| Error::CborError)?;
        let dice = DiceHandover::from_cbor_value(dice).map_err(|_| Error::CborError)?;
        Ok(Self {
            dice,
            gsc_boot_params: GscBootParams::new(
                early_entropy,
                session_key_seed,
                auth_token_key_seed,
            ),
        })
    }

    /// Returns the UDS public key for the device.
    pub fn get_uds_public_key(&self) -> Result<&SubjectPublicKey, Error> {
        Ok(&self.dice.uds_pubkey)
    }

    /// Returns the AP firmware CDI.
    pub fn get_ap_fw_cdi(&self) -> Result<&ConfigurationDescriptor, Error> {
        Ok(&self.dice.cdi_cert.cwt.cfg_descr)
    }

    /// Returns the attestation CDI certificate.
    pub fn get_attestation_cdi_certificate(&self) -> Result<&CdiCert, Error> {
        Ok(&self.dice.cdi_cert)
    }

    /// Returns the CDI keypair as a tuple (attest, seal).
    pub fn get_cdi_keypair(&self) -> Result<(&[u8], &[u8]), Error> {
        Ok((&self.dice.cdi_attest, &self.dice.cdi_seal))
    }
}

/// Find a value in a CBOR map for the given key.
fn find_in_cbor_map(map: &[(Value, Value)], target: Value) -> coset::Result<&Value> {
    for (key, val) in map.iter() {
        if *key == target {
            return Ok(val);
        }
    }
    Err(CoseError::DecodeFailed(CbError::Syntax(0)))
}

/// Find a value in a CBOR map for the given key and attempt to parse it as an int.
fn get_cbor_int_from_map<T: std::convert::TryFrom<ciborium::value::Integer>>(
    map: &[(Value, Value)],
    key: i32,
) -> coset::Result<T> {
    find_in_cbor_map(map, Value::Integer(key.into()))?
        .as_integer()
        .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))?
        .try_into()
        .map_err(|_| CoseError::DecodeFailed(CbError::Syntax(0)))
}

/// Find a value in a CBOR map for the given key and attempt to parse it as a map.
fn get_cbor_array_from_map(map: &[(Value, Value)], key: i32) -> coset::Result<&Vec<Value>> {
    find_in_cbor_map(map, Value::Integer(key.into()))?
        .as_array()
        .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))
}

/// Find a value in a CBOR map for the given key and attempt to parse it as a Vec<u8>.
fn get_cbor_bytes_from_map(map: &[(Value, Value)], key: i32) -> coset::Result<&Vec<u8>> {
    find_in_cbor_map(map, Value::Integer(key.into()))?
        .as_bytes()
        .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))
}

/// Find a value in a CBOR map for the given key and attempt to parse it as a str.
fn get_cbor_string_from_map(map: &[(Value, Value)], key: i32) -> coset::Result<&str> {
    find_in_cbor_map(map, Value::Integer(key.into()))?
        .as_text()
        .ok_or(CoseError::DecodeFailed(CbError::Syntax(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::AsCborValue;
    use kmr_wire::read_to_value;

    test::init!();

    #[test]
    fn boot_params_test() {
        let data = desktop_test_data::boot::BOOT_PARAM;
        let data = read_to_value(data).unwrap();
        let data = data.as_map().unwrap();

        let dice = find_in_cbor_map(data, Value::Integer(DICE_KEY.into())).unwrap();
        let _ = DiceHandover::from_cbor_value(dice.clone()).unwrap();

        let gsc_boot_params =
            find_in_cbor_map(data, Value::Integer(BOOT_PARAM_KEY.into())).unwrap();
        let _ = GscBootParams::from_cbor_value(gsc_boot_params.clone()).unwrap();
    }
}
