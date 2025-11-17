# Copyright (C) 2025 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MANIFEST := $(LOCAL_DIR)/manifest.json

MODULE_SRCS += \
    $(LOCAL_DIR)/lib.rs \

MODULE_CRATE_NAME := keymint_provisioning

MODULE_LIBRARY_DEPS += \
    $(call FIND_CRATE,libc) \
    $(call FIND_CRATE,log) \
    $(call FIND_CRATE,protobuf) \
    $(call FIND_CRATE,x509-cert) \
    $(call FIND_CRATE,spki) \
    frameworks/native/libs/binder/trusty/rust \
    frameworks/native/libs/binder/trusty/rust/rpcbinder \
    trusty/user/base/lib/keymint-rust/common \
    trusty/user/base/lib/keymint-rust/wire \
    trusty/user/base/lib/tipc/rust \
    trusty/user/base/lib/trusty-log \
    trusty/user/base/lib/openssl-rust \
    trusty/user/desktop/interface/keymint_provisioning \
    trusty/user/desktop/lib/keymint_legacy_client \

MODULE_RUST_USE_CLIPPY := true
MODULE_RUST_TESTS := false

include make/library.mk
