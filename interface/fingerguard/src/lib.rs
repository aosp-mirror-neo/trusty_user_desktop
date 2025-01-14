// ! Convenience client API for IFingerGuard

use binder::Strong;
use core::ffi::CStr;
use rpcbinder::RpcSession;

pub use android_desktop_security_fingerguard::aidl::android::desktop::security::fingerguard::{
    self as aidl, IFingerGuard::IFingerGuard,
};
pub const PORT_CSTR: &CStr = c"com.android.trusty.rust.FingerGuard.V1";

/// Creates a new FingerGuard client.
pub fn connect_finger_guard() -> Result<Strong<dyn IFingerGuard>, binder::StatusCode> {
    RpcSession::new().setup_trusty_client(PORT_CSTR)
}
