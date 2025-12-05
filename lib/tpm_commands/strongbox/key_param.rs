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

use kmr_common::Error;
use kmr_wire::keymint::*;
use kmr_wire::*;
use std::any::type_name;
use zerocopy::{FromBytes, IntoBytes};

use super::byte_len_with_word_padding;

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
    let value = match param {
        KeyParam::Algorithm(_) => size_of::<i32>(),
        KeyParam::AllowWhileOnBody => 0usize,
        KeyParam::ApplicationData(d) | KeyParam::ApplicationId(d) => {
            return byte_len_with_word_padding(d.len())
                .checked_add(size_of::<i32>())
                .expect("overflow");
        }
        KeyParam::Digest(_) => size_of::<i32>(),
        KeyParam::KeySize(_) => size_of::<u32>(),
        KeyParam::Purpose(_) => size_of::<i32>(),
        KeyParam::UserId(_) => size_of::<u32>(),
        _ => {
            log::error!("Unexpected param: {:?}", param);
            return 0;
        }
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
    let (out, suffix) = slice.split_at_mut(size_of::<i32>());
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

fn serialize_u32(slice: &mut [u8], tag: Tag, val: u32) -> &mut [u8] {
    let (out, suffix) = slice.split_at_mut(size_of::<i32>());
    out.copy_from_slice(&(tag as i32).to_le_bytes());
    let (out, suffix) = suffix.split_at_mut(size_of::<u32>());
    out.copy_from_slice(&val.to_le_bytes());
    suffix
}

fn serialize_u8_vec<'a>(slice: &'a mut [u8], tag: Tag, val: &[u8]) -> &'a mut [u8] {
    let (out, suffix) = slice.split_at_mut(size_of::<i32>());
    out.copy_from_slice(&include_byte_len(tag, val.len()).to_le_bytes());
    let (out, suffix) = suffix.split_at_mut(byte_len_with_word_padding(val.len()));
    out[0..val.len()].copy_from_slice(val);
    suffix
}

fn serialize<'a>(out: &'a mut [u8], param: &KeyParam) -> &'a mut [u8] {
    match param {
        KeyParam::Algorithm(a) => serialize_i32(out, param.tag(), *a as i32),
        KeyParam::AllowWhileOnBody => serialize_bool(out, param.tag()),
        KeyParam::ApplicationData(d) => serialize_u8_vec(out, param.tag(), d),
        KeyParam::ApplicationId(a) => serialize_u8_vec(out, param.tag(), a),
        KeyParam::Digest(d) => serialize_i32(out, param.tag(), *d as i32),
        KeyParam::KeySize(s) => serialize_u32(out, param.tag(), s.0),
        KeyParam::Purpose(p) => serialize_i32(out, param.tag(), *p as i32),
        KeyParam::UserId(u) => serialize_u32(out, param.tag(), *u),
        _ => {
            log::error!("Unexpected param: {:?}", param);
            out
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

fn tag_int_helper<T: TryFrom<i32>>(v: u32) -> Result<T, Error> {
    T::try_from(i32::from_ne_bytes(v.to_ne_bytes()))
        .map_err(|_| km_err!(EncodingError, type_name::<T>()))
}

fn tag_vec_helper<F: FnOnce(Vec<u8>) -> KeyParam>(
    cast: F,
    buf: &[u32],
    len_bytes: usize,
) -> Result<(KeyParam, &[u32]), Error> {
    let (buf, next) = buf
        .split_at_checked(len_bytes.div_ceil(size_of::<u32>()) + 1)
        .ok_or_else(|| km_err!(EncodingError, "not enough buffer for tag"))?;
    Ok((cast(buf.as_bytes()[4..4 + len_bytes].to_vec()), next))
}

fn parse_key_param(buf: &[u32]) -> Result<(KeyParam, &[u32]), Error> {
    let (tag, _tag_type, opt_len_bytes) = parse_tag(buf[0])?;
    let (param, skip) = match tag {
        Tag::Algorithm => (KeyParam::Algorithm(tag_int_helper(buf[1])?), 2),
        Tag::AllowWhileOnBody => (KeyParam::AllowWhileOnBody, 1),
        Tag::ApplicationData => {
            return tag_vec_helper(KeyParam::ApplicationData, buf, opt_len_bytes);
        }
        Tag::ApplicationId => {
            return tag_vec_helper(KeyParam::ApplicationId, buf, opt_len_bytes);
        }
        Tag::BootPatchlevel => (KeyParam::BootPatchlevel(buf[1]), 2),
        Tag::Digest => (KeyParam::Digest(tag_int_helper(buf[1])?), 2),
        Tag::KeySize => (KeyParam::KeySize(KeySizeInBits(buf[1])), 2),
        Tag::Origin => (
            KeyParam::Origin(match buf[1] {
                0 => KeyOrigin::Generated,
                1 => KeyOrigin::Imported,
                3 => KeyOrigin::SecurelyImported,
                _ => {
                    return Err(km_err!(EncodingError, "bad origin"));
                }
            }),
            2,
        ),
        Tag::OsPatchlevel => (KeyParam::OsPatchlevel(buf[1]), 2),
        Tag::OsVersion => (KeyParam::OsVersion(buf[1]), 2),
        Tag::Purpose => (KeyParam::Purpose(tag_int_helper(buf[1])?), 2),
        Tag::UserId => (KeyParam::UserId(buf[1]), 2),
        Tag::VendorPatchlevel => (KeyParam::VendorPatchlevel(buf[1]), 2),
        _ => {
            return Err(km_err!(Unimplemented, format!("unexpected tag: {tag:?}")));
        }
    };
    Ok((
        param,
        buf.split_at_checked(skip)
            .ok_or_else(|| km_err!(EncodingError, "not enough buffer for tag"))?
            .1,
    ))
}

fn parse_characteristics(buf: &[u32]) -> Result<(KeyCharacteristics, &[u32]), Error> {
    let security_level = SecurityLevel::n(i32::from_ne_bytes(buf[0].to_ne_bytes()))
        .ok_or_else(|| km_err!(EncodingError, "bad security level"))?;
    let tag_words = buf[1] as usize;
    let (mut buf, suffix) = buf
        .split_at_checked(tag_words + 2)
        .ok_or_else(|| km_err!(EncodingError, "not enough buffer for tags"))?;
    buf = &buf[2..];

    let mut authorizations = Vec::<KeyParam>::new();
    loop {
        if buf.is_empty() {
            break;
        }
        let (param, new_buf) = parse_key_param(buf)?;
        authorizations.push(param);
        buf = new_buf;
    }

    Ok((KeyCharacteristics { security_level, authorizations }, suffix))
}

/// Extract theKeyCaracteristics from a key blob so they can be returned in the
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
        1 + data_len.div_ceil(4)
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
        ];

        let params_len_bytes = expected_size(&key_params);
        let mut buf = vec![0; params_len_bytes + size_of::<u32>()];
        buf[0..4].copy_from_slice(&((params_len_bytes / 4) as u32).to_le_bytes());
        assert_eq!(
            serialize_key_params_checked(&mut buf[4..], &key_params)
                .expect("not enough buffer")
                .len(),
            0
        );
        let view: &[u32] = <[u32] as zerocopy::FromBytes>::ref_from_bytes(&buf)
            .expect("failed to convert buf type");
        ported_gsc_buffer_validation(view);
    }
}
