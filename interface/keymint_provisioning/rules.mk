LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_AIDL_PACKAGE := android/desktop/security/keymint_provisioning

MODULE_AIDL_LANGUAGE := rust

MODULE_CRATE_NAME := android_desktop_security_keymint_provisioning

MODULE_AIDLS := \
	$(LOCAL_DIR)/android/desktop/security/keymint_provisioning/IKeyMintProvisioning.aidl \

include make/aidl.mk
