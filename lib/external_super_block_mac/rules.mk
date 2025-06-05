# Copyright (C) 2025 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SDK_LIB_NAME := desktop_external_super_block_mac

MODULE_SRCS := \
    $(LOCAL_DIR)/super_block_mac_device.c \

MODULE_LIBRARY_DEPS := \
    frameworks/native/libs/binder/trusty \
    frameworks/native/libs/binder/trusty/binder_rpc_unstable \
    trusty/user/base/lib/libc-trusty \
    trusty/user/app/storage/lib_internal \
    trusty/user/base/lib/tipc \
    trusty/user/desktop/lib/gsc_svc_client/gsc_svc_client_staticlib \

include make/library.mk
