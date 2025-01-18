use binder::Interface;
use fingerguard_api::aidl::IFingerGuard::IFingerGuard;

/// Implements the `IFingerGuard` AIDL interface for other Trusty apps to call.
pub struct FingerGuardService {
    // TODO(b/385191164): add `gsc: Arc<dyn IGSc>`for seeding randomness.
    // TODO(b/385191164): add secure storage for persisting authenticator ids.
}

impl FingerGuardService {
    pub fn new() -> Self {
        Self {}
    }
}

impl Interface for FingerGuardService {}

impl IFingerGuard for FingerGuardService {
    fn getAuthenticatorId(&self, _sensor_id: i32, _user_id: i32) -> binder::Result<i64> {
        // TODO(b/385191164): implement.
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }
    fn newAuthenticatorId(&self, _sensor_id: i32, _user_id: i32) -> binder::Result<i64> {
        // TODO(b/385191164): implement.
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }
}
