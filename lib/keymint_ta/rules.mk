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

MODULE_SRCS += \
	$(LOCAL_DIR)/lib.rs \

MODULE_CRATE_NAME := desktop_keymint

MODULE_LIBRARY_DEPS += \
	$(DESKTOP_TRUSTY_BUILD_PARAMS_RS) \
	frameworks/native/libs/binder/trusty/rust \
	frameworks/native/libs/binder/trusty/rust/rpcbinder \
	trusty/user/base/lib/keymint-rust/common \
	trusty/user/base/lib/keymint-rust/ta \
	trusty/user/base/lib/keymint-rust/wire \
	trusty/user/base/lib/service_manager/client \
	trusty/user/base/lib/trusty-std \
	trusty/user/desktop/interface/boot_params/aidl \

MODULE_RUST_USE_CLIPPY := true

include make/library.mk
