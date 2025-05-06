use binder::Interface;
use pinweaver_api::{DelayScheduleEntry, IPinWeaver, InsertMode, LeafId, LeafSet, TryAuthResponse};
use pinweaver_storage_api::StorageInterface;
use std::sync::Arc;
use tipc::TipcError;

// The `'static` is necessary for implicit `PinWeaverService<Deps>: 'static`.
pub trait PinWeaverServiceDeps: 'static {
    type Storage: StorageInterface<Error = TipcError> + Send + Sync + ?Sized + 'static;
}

#[allow(dead_code)]
/// Implements the `IPinWeaver` AIDL interface for other Trusty apps to call.
pub struct PinWeaverService<Deps: PinWeaverServiceDeps> {
    storage: Arc<Deps::Storage>,
    // TODO: b/359374997 - add `gsc: Arc<Deps::Gsc>`
}

impl<Deps: PinWeaverServiceDeps> PinWeaverService<Deps> {
    pub fn new(storage: Arc<Deps::Storage>) -> Self {
        Self { storage }
    }
}

impl<Deps: PinWeaverServiceDeps> Interface for PinWeaverService<Deps> {}

impl<Deps: PinWeaverServiceDeps> IPinWeaver for PinWeaverService<Deps> {
    fn insert(
        &self,
        _id: &LeafId,
        _low_entropy_secret: &[u8],
        _high_entropy_secret: &[u8],
        _delay_schedule: &[DelayScheduleEntry],
        _allow_existing: InsertMode,
    ) -> binder::Result<()> {
        // TODO: b/359374997 - Implement.
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }

    fn tryAuthenticate(
        &self,
        _id: &LeafId,
        _low_entropy_secret: &[u8],
    ) -> binder::Result<TryAuthResponse> {
        // TODO: b/359374997 - Implement.
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }

    fn tryAuthenticateThenReplace(
        &self,
        _id: &LeafId,
        _current_low_entropy_secret: &[u8],
        _new_low_entropy_secret: &[u8],
        _new_high_entropy_secret: Option<&[u8]>,
        _new_delay_schedule: Option<&[Option<DelayScheduleEntry>]>,
    ) -> binder::Result<TryAuthResponse> {
        // TODO: b/359374997 - Implement.
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }

    fn remove(&self, _id: &LeafId) -> binder::Result<()> {
        // TODO: b/359374997 - Implement.
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }

    fn removeAll(&self, _leaf_set: LeafSet) -> binder::Result<()> {
        // TODO: b/359374997 - Implement.
        Err(binder::StatusCode::FAILED_TRANSACTION.into())
    }
}
