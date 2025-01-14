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

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_AIDL_PACKAGE := android/desktop/security/fingerguard
MODULE_CRATE_NAME := android_desktop_security_fingerguard

MODULE_AIDLS := \
	$(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/IFingerGuard.aidl \

MODULE_AIDL_LANGUAGE := rust

MODULE_LIBRARY_DEPS += \
	$(call FIND_CRATE,static_assertions) \

include make/aidl.mk
