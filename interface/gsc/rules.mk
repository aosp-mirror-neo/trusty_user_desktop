LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_AIDL_PACKAGE := vendor/google/gsc

MODULE_AIDL_LANGUAGE := rust

MODULE_CRATE_NAME := vendor_google_gsc

MODULE_AIDLS := \
	$(LOCAL_DIR)/vendor/google/gsc/IGsc.aidl \

include make/aidl.mk
