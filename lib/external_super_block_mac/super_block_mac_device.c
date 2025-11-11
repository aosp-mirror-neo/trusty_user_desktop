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

#include <stdint.h>

#include <lib/gsc_svc/gsc_svc.h>
#include <storage_internal/super_block_mac_device.h>
#include <trusty/time.h>

#define MS_TO_NS(ms) ((ms)*1000ULL * 1000ULL)

static int super_block_mac_get(const uint8_t index,
           uint8_t *flags,
           struct mac* mac) {
    int ret = gsc_svc_client_super_block_mac_read(index, flags, &mac->byte);
    for(int i = 0; i < 600; ++i) {
        if (!ret) {
            /*
            * Check the flags MSB to determine if the mac is initialized or not. If the
            * bit is not set, notify the storage application by returning a specific
            * error code.
            */
            if (!(*flags & 0x80)) {
                return SUPER_BLOCK_MAC_DEVICE_ERROR_NOT_INITIALIZED;
            } else {
                return ret;
            }
        }
        trusty_nanosleep(0, 0, MS_TO_NS(100));
        ret = gsc_svc_client_super_block_mac_read(index, flags, &mac->byte);
    }
    return ret;
}

static int super_block_mac_set(const uint8_t index,
           const uint8_t flags,
           const struct mac* mac) {
    int ret = gsc_svc_client_super_block_mac_write(index, flags, &mac->byte);
    if (ret) {
        return SUPER_BLOCK_MAC_DEVICE_ERROR_COMMUNICATION;
    }

    return ret;
}

static int super_block_mac_delete(const uint8_t index) {
    int ret = gsc_svc_client_super_block_mac_delete(index);
    if (ret) {
        return SUPER_BLOCK_MAC_DEVICE_ERROR_COMMUNICATION;
    }

    return ret;
}

int super_block_mac_get_td(struct super_block_mac_device* super_block_mac_dev,
           uint8_t* flags,
           struct mac* mac) {
    return super_block_mac_get(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD, flags, mac);
}

int super_block_mac_set_td(struct super_block_mac_device* super_block_mac_dev,
           const uint8_t flags,
           const struct mac* mac) {
    return super_block_mac_set(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD, flags, mac);
}

int super_block_mac_delete_td(struct super_block_mac_device* super_block_mac_dev) {
    return super_block_mac_delete(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TD);
}

struct super_block_mac_device super_block_mac_dev_td = {
    .get = super_block_mac_get_td,
    .set = super_block_mac_set_td,
    .delete_mac = super_block_mac_delete_td,
};

int super_block_mac_get_tdp(struct super_block_mac_device* super_block_mac_dev,
           uint8_t* flags,
           struct mac* mac) {
    return super_block_mac_get(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP, flags, mac);
}

int super_block_mac_set_tdp(struct super_block_mac_device* super_block_mac_dev,
           const uint8_t flags,
           const struct mac* mac) {
    return super_block_mac_set(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP, flags, mac);
}

int super_block_mac_delete_tdp(struct super_block_mac_device* super_block_mac_dev) {
    return super_block_mac_delete(GSC_SVC_CLIENT_SUPER_BLOCK_MAC_FILE_INDEX_TDP);
}

struct super_block_mac_device super_block_mac_dev_tdp = {
    .get = super_block_mac_get_tdp,
    .set = super_block_mac_set_tdp,
    .delete_mac = super_block_mac_delete_tdp,
};

