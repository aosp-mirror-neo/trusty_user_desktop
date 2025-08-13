//! Convenience API for Trusty apps to access PinWeaver.

use binder::Strong;
use rpcbinder::RpcSession;
use std::ffi::CStr;

pub use android_desktop_security_pinweaver::aidl::android::desktop::security::pinweaver::{
    self as aidl,
    DelayScheduleEntry::DelayScheduleEntry,
    IPinWeaver::{IPinWeaver, IPinWeaverAsync},
    InsertMode::InsertMode,
    LeafId::LeafId,
    LeafSet::LeafSet,
    TryAuthResponse::TryAuthResponse,
};

/// Convert LeafId into an i64 value that can be used with storage.
pub const fn leafid_value(mode: &LeafId) -> i64 {
    let upper: i64 = (mode.leafSet.get() as i64) << 32;
    upper | mode.id as i64
}

/// Constructs the appropriate delay schedule entry table to request no rate limiting.
///
/// An empty delay schedule table is rejected, so use this to opt-out of rate limiting.
pub fn ignore_rate_limiting_table() -> &'static [DelayScheduleEntry] {
    &[DelayScheduleEntry { attemptCount: i32::MAX, delaySecs: 0 }]
}

pub const PORT: &str = match PORT_CSTR.to_str() {
    Ok(x) => x,
    Err(_) => unreachable!(),
};
const PORT_CSTR: &CStr = c"com.android.desktop.security.PinWeaver.V1";

/// Creates a new PinWeaver client.
pub fn connect_pinweaver() -> Result<Strong<dyn IPinWeaver>, binder::StatusCode> {
    RpcSession::new().setup_trusty_client(PORT_CSTR)
}

/// Creates a new async PinWeaver client.
pub fn connect_pinweaver_async<P: binder::BinderAsyncPool + 'static>(
) -> Result<Strong<dyn IPinWeaverAsync<P>>, binder::StatusCode> {
    RpcSession::new().setup_trusty_client(PORT_CSTR)
}
