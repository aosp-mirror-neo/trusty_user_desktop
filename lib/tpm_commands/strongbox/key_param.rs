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

//! Structs and items that define TPM communications with the GSC

use kmr_common::{km_err, Error};
use kmr_wire::keymint::*;
use kmr_wire::*;
use std::any::type_name;
use zerocopy::{FromBytes, IntoBytes};

use super::WORD_SIZE;

const TAG_LEN_BITS: usize = 12;
const TAG_LEN_SHIFT: i32 = 16;
const TAG_LEN_MASK_BITS: usize = (1 << TAG_LEN_BITS) - 1;
const TAG_LEN_MASK: u32 = (TAG_LEN_MASK_BITS << TAG_LEN_SHIFT) as u32;

const fn include_byte_len(tag: Tag, len: usize) -> i32 {
    if len > TAG_LEN_MASK_BITS {
        panic!("field is too large");
    }

    tag as i32 | ((len as i32) << TAG_LEN_SHIFT)
}

fn expected_size_one(param: &KeyParam) -> usize {
    let value = match tag_type(param.tag()) {
        TagType::Bool => 0usize,
        TagType::Enum => size_of::<i32>(),
        TagType::EnumRep => size_of::<i32>(),
        TagType::Uint => size_of::<u32>(),
        TagType::Date => size_of::<i64>(),
        TagType::Ulong => size_of::<u64>(),
        TagType::UlongRep => size_of::<u64>(),
        _ => match param {
            KeyParam::ApplicationData(value)
            | KeyParam::ApplicationId(value)
            | KeyParam::AttestationApplicationId(value)
            | KeyParam::AttestationChallenge(value)
            | KeyParam::AttestationIdBrand(value)
            | KeyParam::AttestationIdDevice(value)
            | KeyParam::AttestationIdProduct(value)
            | KeyParam::AttestationIdManufacturer(value)
            | KeyParam::AttestationIdModel(value)
            | KeyParam::AttestationIdSerial(value)
            | KeyParam::CertificateSerial(value)
            | KeyParam::CertificateSubject(value) => {
                return value
                    .len()
                    .next_multiple_of(WORD_SIZE)
                    .checked_add(size_of::<i32>())
                    .expect("overflow");
            }
            _ => {
                log::error!("Unexpected param: {:?}", param);
                return 0;
            }
        },
    };
    value + size_of::<i32>()
}

/// Provide the expected size of the parameters after serialization.
pub fn expected_size(params: &[KeyParam]) -> usize {
    let mut total = 0usize;
    for param in params.iter() {
        total = total.checked_add(expected_size_one(param)).expect("overflow");
    }
    total
}

fn serialize_bool(slice: &mut [u8], tag: Tag) -> &mut [u8] {
    let (out, suffix) = slice.split_at_mut(WORD_SIZE);
    out.copy_from_slice(&(tag as i32).to_le_bytes());
    suffix
}

fn serialize_i32(slice: &mut [u8], tag: Tag, val: i32) -> &mut [u8] {
    let (out, suffix) = slice.split_at_mut(size_of::<i32>());
    out.copy_from_slice(&(tag as i32).to_le_bytes());
    let (out, suffix) = suffix.split_at_mut(size_of::<i32>());
    out.copy_from_slice(&val.to_le_bytes());
    suffix
}

fn serialize_i64(slice: &mut [u8], tag: Tag, val: i64) -> &mut [u8] {
    let (out, suffix) = slice.split_at_mut(size_of::<i32>());
    out.copy_from_slice(&(tag as i32).to_le_bytes());
    let (out, suffix) = suffix.split_at_mut(size_of::<i64>());
    out.copy_from_slice(&val.to_le_bytes());
    suffix
}

fn serialize_u32(slice: &mut [u8], tag: Tag, val: u32) -> &mut [u8] {
    let (out, suffix) = slice.split_at_mut(size_of::<i32>());
    out.copy_from_slice(&(tag as i32).to_le_bytes());
    let (out, suffix) = suffix.split_at_mut(size_of::<u32>());
    out.copy_from_slice(&val.to_le_bytes());
    suffix
}

fn serialize_u64(slice: &mut [u8], tag: Tag, val: u64) -> &mut [u8] {
    let (out, suffix) = slice.split_at_mut(size_of::<i32>());
    out.copy_from_slice(&(tag as i32).to_le_bytes());
    let (out, suffix) = suffix.split_at_mut(size_of::<u64>());
    out.copy_from_slice(&val.to_le_bytes());
    suffix
}

fn serialize_u8_vec<'a>(slice: &'a mut [u8], tag: Tag, val: &[u8]) -> &'a mut [u8] {
    let (out, suffix) = slice.split_at_mut(WORD_SIZE);
    out.copy_from_slice(&include_byte_len(tag, val.len()).to_le_bytes());
    let (out, suffix) = suffix.split_at_mut(val.len().next_multiple_of(WORD_SIZE));
    out[0..val.len()].copy_from_slice(val);
    suffix
}

fn serialize<'a>(out: &'a mut [u8], param: &KeyParam) -> &'a mut [u8] {
    match param {
        // TagType::Bool
        KeyParam::AllowWhileOnBody
        | KeyParam::BootloaderOnly
        | KeyParam::CallerNonce
        | KeyParam::EarlyBootOnly
        | KeyParam::NoAuthRequired
        | KeyParam::RollbackResistance
        | KeyParam::TrustedUserPresenceRequired
        | KeyParam::TrustedConfirmationRequired
        | KeyParam::StorageKey => serialize_bool(out, param.tag()),

        // TagType::Enum
        KeyParam::Algorithm(a) => serialize_i32(out, param.tag(), *a as i32),
        KeyParam::EcCurve(c) => serialize_i32(out, param.tag(), *c as i32),
        KeyParam::Origin(o) => serialize_i32(out, param.tag(), *o as i32),
        KeyParam::UserAuthType(t) => serialize_i32(out, param.tag(), *t as i32),

        // TagType::EnumRep
        KeyParam::BlockMode(m) => serialize_i32(out, param.tag(), *m as i32),
        KeyParam::Digest(d) => serialize_i32(out, param.tag(), *d as i32),
        KeyParam::Padding(p) => serialize_i32(out, param.tag(), *p as i32),
        KeyParam::Purpose(p) => serialize_i32(out, param.tag(), *p as i32),
        KeyParam::RsaOaepMgfDigest(d) => serialize_i32(out, param.tag(), *d as i32),

        // TagType::Uint
        KeyParam::KeySize(s) => serialize_u32(out, param.tag(), s.0),
        KeyParam::AuthTimeout(value)
        | KeyParam::BootPatchlevel(value)
        | KeyParam::MaxUsesPerBoot(value)
        | KeyParam::MinMacLength(value)
        | KeyParam::OsPatchlevel(value)
        | KeyParam::OsVersion(value)
        | KeyParam::UserId(value)
        | KeyParam::VendorPatchlevel(value) => serialize_u32(out, param.tag(), *value),

        //TagType::Date
        KeyParam::CertificateNotAfter(date_time)
        | KeyParam::CertificateNotBefore(date_time)
        | KeyParam::CreationDatetime(date_time) => {
            serialize_i64(out, param.tag(), date_time.ms_since_epoch)
        }

        // TagType::Ulong
        KeyParam::RsaPublicExponent(e) => serialize_u64(out, param.tag(), e.0),

        // TagType::UlongRep
        KeyParam::UserSecureId(id) => serialize_u64(out, param.tag(), *id),

        // TAgType::BigNum
        KeyParam::CertificateSerial(value) => serialize_u8_vec(out, param.tag(), value),

        // TagType::Bytes
        KeyParam::ApplicationData(value)
        | KeyParam::ApplicationId(value)
        | KeyParam::AttestationApplicationId(value)
        | KeyParam::AttestationChallenge(value)
        | KeyParam::AttestationIdBrand(value)
        | KeyParam::AttestationIdDevice(value)
        | KeyParam::AttestationIdProduct(value)
        | KeyParam::AttestationIdManufacturer(value)
        | KeyParam::AttestationIdModel(value)
        | KeyParam::AttestationIdSerial(value)
        | KeyParam::CertificateSubject(value) => serialize_u8_vec(out, param.tag(), value),

        _ => {
            log::error!("Unexpected param: {:?}", param);
            let size = expected_size_one(param);
            if size == 0 {
                out
            } else {
                out[0..size].fill(0);
                &mut out[expected_size_one(param)..]
            }
        }
    }
}

/// Write key parameters to presized buffer.
pub fn serialize_key_params<'a>(mut out: &'a mut [u8], params: &[KeyParam]) -> &'a mut [u8] {
    for param in params.iter() {
        out = serialize(out, param);
    }
    out
}

/// Write key parameters to presized buffer and panic if the buffer is too small.
pub fn serialize_key_params_checked<'a>(
    out: &'a mut [u8],
    params: &[KeyParam],
) -> Option<&'a mut [u8]> {
    if out.len() < expected_size(params) {
        None
    } else {
        Some(serialize_key_params(out, params))
    }
}

fn parse_tag(tag_word: u32) -> Result<(Tag, TagType, usize), Error> {
    let tag = Tag::n(i32::from_ne_bytes((tag_word & !TAG_LEN_MASK).to_ne_bytes()))
        .ok_or_else(|| km_err!(EncodingError, "bad tag"))?;
    Ok((tag, tag_type(tag), (tag_word as usize >> TAG_LEN_SHIFT) & TAG_LEN_MASK_BITS))
}

fn tag_datetime_helper(buf: &[u32]) -> Result<DateTime, Error> {
    Ok(DateTime {
        ms_since_epoch: <i64>::from_ne_bytes(
            buf[0..2]
                .as_bytes()
                .try_into()
                .map_err(|_| km_err!(EncodingError, "datetime buffer size"))?,
        ),
    })
}

fn tag_int_helper<T: TryFrom<i32>>(v: u32) -> Result<T, Error> {
    T::try_from(i32::from_ne_bytes(v.to_ne_bytes()))
        .map_err(|_| km_err!(EncodingError, "{}", type_name::<T>()))
}

fn tag_vec_helper<F: FnOnce(Vec<u8>) -> KeyParam>(
    cast: F,
    buf: &[u32],
    len_bytes: usize,
) -> Result<(KeyParam, &[u32]), Error> {
    let (buf, next) = buf
        .split_at_checked(len_bytes.div_ceil(size_of::<u32>()) + 1)
        .ok_or_else(|| km_err!(EncodingError, "not enough buffer for tag"))?;
    Ok((cast(buf.as_bytes()[WORD_SIZE..WORD_SIZE + len_bytes].to_vec()), next))
}

fn parse_key_param(buf: &[u32]) -> Result<(KeyParam, &[u32]), Error> {
    let (tag, _tag_type, opt_len_bytes) = parse_tag(buf[0])?;
    let (param, skip) = match tag {
        // TagType::Bool
        Tag::AllowWhileOnBody => (KeyParam::AllowWhileOnBody, 1),
        Tag::BootloaderOnly => (KeyParam::BootloaderOnly, 1),
        Tag::CallerNonce => (KeyParam::CallerNonce, 1),
        Tag::EarlyBootOnly => (KeyParam::EarlyBootOnly, 1),
        Tag::NoAuthRequired => (KeyParam::NoAuthRequired, 1),
        Tag::RollbackResistance => (KeyParam::RollbackResistance, 1),
        Tag::TrustedUserPresenceRequired => (KeyParam::TrustedUserPresenceRequired, 1),
        Tag::TrustedConfirmationRequired => (KeyParam::TrustedConfirmationRequired, 1),
        Tag::StorageKey => (KeyParam::StorageKey, 1),

        // TagType::Enum
        Tag::Algorithm => (KeyParam::Algorithm(tag_int_helper(buf[1])?), 2),
        Tag::EcCurve => (KeyParam::EcCurve(tag_int_helper(buf[1])?), 2),
        Tag::Origin => (KeyParam::Origin(tag_int_helper(buf[1])?), 2),
        Tag::UserAuthType => (KeyParam::UserAuthType(tag_int_helper(buf[1])?), 2),

        // TagType::EnumRep
        Tag::BlockMode => (KeyParam::BlockMode(tag_int_helper(buf[1])?), 2),
        Tag::Digest => (KeyParam::Digest(tag_int_helper(buf[1])?), 2),
        Tag::Padding => (KeyParam::Padding(tag_int_helper(buf[1])?), 2),
        Tag::Purpose => (KeyParam::Purpose(tag_int_helper(buf[1])?), 2),
        Tag::RsaOaepMgfDigest => (KeyParam::RsaOaepMgfDigest(tag_int_helper(buf[1])?), 2),

        // TagType::Uint
        Tag::AuthTimeout => (KeyParam::AuthTimeout(buf[1]), 2),
        Tag::BootPatchlevel => (KeyParam::BootPatchlevel(buf[1]), 2),
        Tag::KeySize => (KeyParam::KeySize(KeySizeInBits(buf[1])), 2),
        Tag::MaxUsesPerBoot => (KeyParam::MaxUsesPerBoot(buf[1]), 2),
        Tag::MinMacLength => (KeyParam::MinMacLength(buf[1]), 2),
        Tag::OsPatchlevel => (KeyParam::OsPatchlevel(buf[1]), 2),
        Tag::OsVersion => (KeyParam::OsVersion(buf[1]), 2),
        Tag::UserId => (KeyParam::UserId(buf[1]), 2),
        Tag::VendorPatchlevel => (KeyParam::VendorPatchlevel(buf[1]), 2),

        // TagType::Date
        Tag::CertificateNotAfter => {
            (KeyParam::CertificateNotAfter(tag_datetime_helper(&buf[1..3])?), 3)
        }
        Tag::CertificateNotBefore => {
            (KeyParam::CertificateNotBefore(tag_datetime_helper(&buf[1..3])?), 3)
        }
        Tag::CreationDatetime => (KeyParam::CreationDatetime(tag_datetime_helper(&buf[1..3])?), 3),

        // TagType::Ulong
        Tag::RsaPublicExponent => (
            KeyParam::RsaPublicExponent(RsaExponent(<u64>::from_ne_bytes(
                // unwrap is ok here because size_of::<u64>() == size_of::<[u32; 2]>()
                buf[1..3].as_bytes().try_into().unwrap(),
            ))),
            3,
        ),

        // TagType::UlongRep
        Tag::UserSecureId => (
            KeyParam::UserSecureId(<u64>::from_ne_bytes(
                // unwrap is ok here because size_of::<u64>() == size_of::<[u32; 2]>()
                buf[1..3].as_bytes().try_into().unwrap(),
            )),
            3,
        ),

        // TagType::BigNum
        Tag::CertificateSerial => {
            return tag_vec_helper(KeyParam::CertificateSerial, buf, opt_len_bytes);
        }

        // TagType::Bytes
        Tag::ApplicationData => {
            return tag_vec_helper(KeyParam::ApplicationData, buf, opt_len_bytes);
        }
        Tag::ApplicationId => {
            return tag_vec_helper(KeyParam::ApplicationId, buf, opt_len_bytes);
        }
        Tag::AttestationApplicationId => {
            return tag_vec_helper(KeyParam::AttestationApplicationId, buf, opt_len_bytes);
        }
        Tag::AttestationChallenge => {
            return tag_vec_helper(KeyParam::AttestationChallenge, buf, opt_len_bytes);
        }
        Tag::AttestationIdBrand => {
            return tag_vec_helper(KeyParam::AttestationIdBrand, buf, opt_len_bytes);
        }
        Tag::AttestationIdDevice => {
            return tag_vec_helper(KeyParam::AttestationIdDevice, buf, opt_len_bytes);
        }
        Tag::AttestationIdProduct => {
            return tag_vec_helper(KeyParam::AttestationIdProduct, buf, opt_len_bytes);
        }
        Tag::AttestationIdManufacturer => {
            return tag_vec_helper(KeyParam::AttestationIdManufacturer, buf, opt_len_bytes);
        }
        Tag::AttestationIdModel => {
            return tag_vec_helper(KeyParam::AttestationIdModel, buf, opt_len_bytes);
        }
        Tag::AttestationIdSerial => {
            return tag_vec_helper(KeyParam::AttestationIdSerial, buf, opt_len_bytes);
        }
        Tag::CertificateSubject => {
            return tag_vec_helper(KeyParam::CertificateSubject, buf, opt_len_bytes);
        }

        _ => {
            return Err(km_err!(Unimplemented, "unexpected tag: {tag:?}"));
        }
    };
    Ok((
        param,
        buf.split_at_checked(skip)
            .ok_or_else(|| km_err!(EncodingError, "not enough buffer for tag"))?
            .1,
    ))
}

/// Parse key parameters returned by the GSC.
pub fn parse_key_params(mut buf: &[u32]) -> Result<Vec<KeyParam>, Error> {
    let mut params = Vec::<KeyParam>::new();
    loop {
        if buf.is_empty() {
            break;
        }
        let (param, new_buf) = parse_key_param(buf)?;
        params.push(param);
        buf = new_buf;
    }
    Ok(params)
}

fn parse_characteristics(buf: &[u32]) -> Result<(KeyCharacteristics, &[u32]), Error> {
    let security_level = SecurityLevel::n(i32::from_ne_bytes(buf[0].to_ne_bytes()))
        .ok_or_else(|| km_err!(EncodingError, "bad security level"))?;
    let tag_words = buf[1] as usize;
    let (mut buf, suffix) = buf
        .split_at_checked(tag_words + 2)
        .ok_or_else(|| km_err!(EncodingError, "not enough buffer for tags"))?;
    buf = &buf[2..];

    let authorizations = parse_key_params(buf)?;
    Ok((KeyCharacteristics { security_level, authorizations }, suffix))
}

/// Extract the key characteristics from a key blob so they can be returned in the
/// wire format.
pub fn characteristics_from_key_blob(key_blob: &[u8]) -> Result<Vec<KeyCharacteristics>, Error> {
    const KEY_CHARACTERISTICS_WORDS: usize = 12;
    // Skip the first word because it is the total length.
    let all_words = <[u32]>::ref_from_bytes(key_blob)
        .map_err(|_| km_err!(EncodingError, "key_blob padding"))?;
    let blob_words = all_words[0] as usize;
    let buf = &all_words[1..];
    if blob_words != buf.len() {
        return Err(km_err!(EncodingError, "bad key_blob"));
    }
    if buf.len() < KEY_CHARACTERISTICS_WORDS {
        return Err(km_err!(EncodingError, "key_blob too small"));
    }

    let mut ret = Vec::new();
    let (mut hw_tags, buf) = parse_characteristics(buf)?;
    let (sw_tags, _) = parse_characteristics(buf)?;

    if hw_tags.security_level == sw_tags.security_level {
        hw_tags.authorizations.extend(sw_tags.authorizations);
        ret.push(hw_tags);
    } else {
        ret.push(hw_tags);
        ret.push(sw_tags);
    }

    Ok(ret)
}

#[cfg(test)]
mod test {
    use kmr_wire::keymint::*;
    use kmr_wire::*;

    use super::*;
    fn tag_is_gen_disallowed(tag: Tag) -> bool {
        use Tag::*;
        matches!(
            tag,
            Invalid
                | MaxUsesPerBoot
                | MinSecondsBetweenOps
                | Origin
                | RootOfTrust
                | OsVersion
                | OsPatchlevel
                | BootPatchlevel
                | VendorPatchlevel
                | ResetSinceIdRotation
        )
    }

    fn tag_is_hw_enforced(tag: Tag) -> bool {
        use Tag::*;
        matches!(
            tag,
            UserSecureId
                | Algorithm
                | EcCurve
                | UserAuthType
                | Origin
                | Purpose
                | BlockMode
                | Digest
                | Padding
                | RsaOaepMgfDigest
                | KeySize
                | MinMacLength
                | MaxUsesPerBoot
                | AuthTimeout
                | OsVersion
                | OsPatchlevel
                | VendorPatchlevel
                | BootPatchlevel
                | RsaPublicExponent
                | CallerNonce
                | BootloaderOnly
                | RollbackResistance
                | EarlyBootOnly
                | NoAuthRequired
                | TrustedUserPresenceRequired
                | TrustedConfirmationRequired
                | StorageKey
        )
    }

    fn tag_is_sw_enforced(tag: Tag) -> bool {
        use Tag::*;
        matches!(
            tag,
            ActiveDatetime
                | OriginationExpireDatetime
                | UsageExpireDatetime
                | UserId
                | AllowWhileOnBody
                | CreationDatetime
                | MaxBootLevel
                | UnlockedDeviceRequired
        )
    }

    fn prefix_get_tag(tag_word: u32) -> Tag {
        Tag::try_from(i32::from_ne_bytes((tag_word & 0xf000ffffu32).to_ne_bytes())).unwrap()
    }

    fn prefix_get_word_len(tag: Tag, tag_word: u32) -> usize {
        use TagType::*;
        let data_len = match tag_type(tag) {
            Enum | EnumRep | Uint | UintRep => size_of::<u32>(),
            Date | Ulong | UlongRep => size_of::<u64>(),
            Bignum | Bytes => ((tag_word >> 16) & 0x0fffu32) as usize,
            _ => 0,
        };
        1 + data_len.div_ceil(WORD_SIZE)
    }

    fn process_tag(_tag: Tag, _buf: &[u32]) {}

    pub fn ported_gsc_buffer_validation(buf: &[u32]) {
        if buf.is_empty() {
            panic!("buffer is empty");
        }

        let tags_len_words = buf[0] as usize;
        if tags_len_words > buf.len().saturating_sub(1) {
            panic!("buffer length mismatch: {}, {}", tags_len_words, buf.len().saturating_sub(1));
        }

        //let mut hw_tag_start = KM_KEY_CHARACTERISTICS_WORDS;
        let mut sw_enforced_tag_size_words = 0;
        let mut tag_pos = 1; // start after length word

        // Pass 1: Parse tags, copy HW tags, count SW tags, extract attributes
        while tag_pos < tags_len_words + 1 {
            // Use slice indexing safely
            if tag_pos >= buf.len() {
                panic!("overflow");
            }

            let tag_word = buf[tag_pos];
            let tag = prefix_get_tag(tag_word);
            let word_len = prefix_get_word_len(tag, tag_word);

            if tag_is_gen_disallowed(tag) {
                panic!("tag disallowed");
            }

            // We pass the slice starting at tag_pos
            process_tag(tag, &buf[tag_pos..]);

            if tag_is_hw_enforced(tag) {
            } else if tag_is_sw_enforced(tag) {
                sw_enforced_tag_size_words += word_len;
            }
            tag_pos += word_len;
        }

        let _ = sw_enforced_tag_size_words;
    }

    #[test]
    fn smoke_test() {
        let key_params = vec![
            KeyParam::Algorithm(Algorithm::Ec),
            KeyParam::KeySize(KeySizeInBits(256)),
            KeyParam::Purpose(KeyPurpose::Sign),
            KeyParam::Digest(Digest::Sha256),
            KeyParam::AllowWhileOnBody,
            KeyParam::UserId(0xF00),
            KeyParam::ApplicationId(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]),
            KeyParam::ApplicationData(vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            KeyParam::CreationDatetime(DateTime { ms_since_epoch: 1765505306934 }),
            KeyParam::RsaPublicExponent(RsaExponent(13)),
        ];

        let params_len_bytes = expected_size(&key_params);
        let mut buf = vec![0; params_len_bytes + size_of::<u32>()];
        buf[0..WORD_SIZE].copy_from_slice(&((params_len_bytes / WORD_SIZE) as u32).to_le_bytes());
        assert_eq!(
            serialize_key_params_checked(&mut buf[WORD_SIZE..], &key_params)
                .expect("not enough buffer")
                .len(),
            0
        );
        let view: &[u32] = <[u32] as zerocopy::FromBytes>::ref_from_bytes(&buf)
            .expect("failed to convert buf type");
        ported_gsc_buffer_validation(view);
    }
}
