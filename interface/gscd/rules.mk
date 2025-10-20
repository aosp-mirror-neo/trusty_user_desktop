LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_AIDL_PACKAGE := android/system/desktop/security/gsc

MODULE_AIDL_LANGUAGE := rust

MODULE_CRATE_NAME := android_system_desktop_security_gsc

MODULE_AIDL_FLAGS := --stability=vintf

MODULE_AIDLS := \
	$(LOCAL_DIR)/android/system/desktop/security/gsc/IGsc.aidl \

include make/aidl.mk
