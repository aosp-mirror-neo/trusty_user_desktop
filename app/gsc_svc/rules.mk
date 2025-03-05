# Copyright (C) 2024 The Android Open Source Project
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

MODULE_CRATE_NAME := gsc_svc

MODULE_LIBRARY_DEPS += \
	$(call FIND_CRATE,libc) \
	$(call FIND_CRATE,log) \
	trusty/user/base/lib/tipc/rust \
	trusty/user/base/lib/trusty-log \
	trusty/user/base/lib/vmm_obj/rust \
	trusty/user/desktop/interface/boot_params/aidl \
	trusty/user/desktop/interface/gscd \
	trusty/user/desktop/lib/boot_params \
	frameworks/native/libs/binder/trusty/rust \
	frameworks/native/libs/binder/trusty/rust/rpcbinder \
	trusty/user/base/lib/keymint-rust/wire \

MODULE_RUST_USE_CLIPPY := true

include make/library.mk
