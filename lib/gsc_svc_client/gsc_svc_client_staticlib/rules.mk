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

MODULE_CRATE_NAME := gsc_svc_client_staticlib

MODULE_RUST_CRATE_TYPES := staticlib

MODULE_EXPORT_INCLUDES += $(LOCAL_DIR)/include/

MODULE_LIBRARY_DEPS += \
	$(call FIND_CRATE,libc) \
	$(call FIND_CRATE,log) \
	$(call FIND_CRATE,static_assertions) \
	$(call FIND_CRATE,zerocopy) \
	trusty/user/base/lib/trusty-log \
	trusty/user/desktop/lib/gsc_svc_client \

MODULE_RUST_USE_CLIPPY := true

include make/library.mk
