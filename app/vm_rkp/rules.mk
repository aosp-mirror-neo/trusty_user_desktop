# Copyright (C) 2026 The Android Open Source Project
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

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MANIFEST := $(LOCAL_DIR)/manifest.json

MODULE_SRCS += \
	$(LOCAL_DIR)/lib.rs \

MODULE_CRATE_NAME := vm_rkp

MODULE_LIBRARY_DEPS += \
	$(call FIND_CRATE,ciborium) \
	$(call FIND_CRATE,coset) \
	$(call FIND_CRATE,log) \
	$(call FIND_CRATE,zeroize) \
	frameworks/native/libs/binder/trusty/rust \
	frameworks/native/libs/binder/trusty/rust/rpcbinder \
	packages/modules/Virtualization/libs/cborutil \
	packages/modules/Virtualization/libs/dice/open_dice \
	packages/modules/Virtualization/libs/libavf_attestation \
	trusty/user/app/keymint/see/keymint/libs/lib-rkp-ta \
	trusty/user/base/interface/vm_attestation/aidl \
	trusty/user/base/lib/hwbcc/rust \
	trusty/user/base/lib/hwkey/rust \
	trusty/user/base/lib/tipc/rust \
	trusty/user/base/lib/trusty-log \

MODULE_RUST_USE_CLIPPY := true

include make/library.mk
