use binder::Interface;
use log::{error, info, warn};
use openssl::{
    rand::rand_bytes,
    symm::{decrypt_aead, encrypt_aead, Cipher},
};
use pinweaver_api::{
    leafid_value, DelayScheduleEntry, IPinWeaver, InsertMode, LeafId, LeafSet, TryAuthResponse,
};
use pinweaver_storage_api::{
    request::{
        CommitOpRequest, InsertMode as StorageInsertMode, InsertOpRequest, ResetTreeRequest,
        StartOpRequest, StorageRequest,
    },
    response::{
        CommitOpResponse, CommitOpResponseData, CommitRemoveBulkResponseData,
        ContinueRemoveBulkResponse, GetStatusResponse, ResponseError, StartInsertResponseData,
        StartOpResponse, StartOpResponseData, StartRemoveResponseData, StartTryAuthResponseData,
        StorageResponse,
    },
    util::{SerdeOption, SerdeVec},
    LargeSecretAuthTag, LargeSecretInfo, LargeSecretIv, LeafId as StorageLeafId,
    LeafSet as StorageLeafSet, Path, StorageInterface, TreeHash, TreeHashes, TreeParams,
    EMPTY_TREE_HASH, RESERVED_LEAF_ID, U32,
};
use std::{
    collections::BTreeMap as Map,
    ffi::CStr,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tipc::TipcError;
use tpm_commands::pinweaver::{
    request::{
        InsertLeafHeader, LogReplayHeader, RemoveLeafHeader, ResetAuthHeader, TryAuthHeader,
    },
    response::{Error as GscError, ResultCode},
    DelaySchedule, DelayScheduleEntry as GscDelayScheduleEntry, Error as TpmError, Hash, Label,
    LogEntryData, Pinweaver, Secret, TimeDiff, TreeParams as GscTreeParams, ValidPcrCriteria,
    DELAY_SCHEDULE_ENTRIES,
};
use zerocopy::{IntoBytes, LittleEndian, U64};

const DEFAULT_TREE_HEIGHT: u8 = 6u8;
const DEFAULT_TREE_BITS_PER_LEVEL: u8 = 2u8;

static RECONCILED: AtomicBool = AtomicBool::new(false);

pub(crate) mod api_to_gsc {
    use super::*;

    use tpm_commands::pinweaver::TimeDiff;

    pub fn delay_schedule_entry(
        entry: &DelayScheduleEntry,
    ) -> binder::Result<GscDelayScheduleEntry> {
        Ok(GscDelayScheduleEntry {
            attempt_count: u32::try_from(entry.attemptCount)
                .map_err(|_| binder_error::illegal_argument(c"delay schedule entry attemptCount"))?
                .into(),
            time_diff: TimeDiff::from_secs(
                u32::try_from(entry.delaySecs).map_err(|_| {
                    binder_error::illegal_argument(c"delay schedule entry delaySecs")
                })?,
            ),
        })
    }

    pub fn delay_schedule(
        api_delay_schedule: &[DelayScheduleEntry],
    ) -> binder::Result<DelaySchedule> {
        if api_delay_schedule.len() > DELAY_SCHEDULE_ENTRIES {
            return Err(binder_error::illegal_argument(c"delay_schedule too long"));
        }
        let mut delay_schedule = DelaySchedule::default();
        for (i, entry) in api_delay_schedule.iter().enumerate() {
            delay_schedule[i] = api_to_gsc::delay_schedule_entry(entry)?;
        }
        Ok(delay_schedule)
    }

    pub fn secret(api_secret: &[u8]) -> binder::Result<Secret> {
        Ok(Secret(
            api_secret
                .try_into()
                .map_err(|_| binder_error::illegal_argument(c"secret has wrong length"))?,
        ))
    }
}

pub(crate) mod api_to_storage {
    use super::*;

    pub fn leaf_id(leaf_id: &LeafId) -> StorageLeafId {
        StorageLeafId::from(leafid_value(leaf_id))
    }

    pub fn leaf_set(leaf_set: LeafSet) -> StorageLeafSet {
        StorageLeafSet(U32::new(leaf_set.get() as u32))
    }

    pub fn insertmode(mode: InsertMode) -> binder::Result<StorageInsertMode> {
        use StorageInsertMode::*;
        Ok(match mode {
            InsertMode::NEW_ONLY => NewOnly,
            InsertMode::REPLACE_EXISTING => ReplaceExisting,
            _ => return Err(binder::StatusCode::FAILED_TRANSACTION.into()),
        })
    }
}

pub(crate) mod gsc_to_storage {
    use super::*;

    use pinweaver_storage_api::TreeHash;

    pub fn hmac(hmac: &Hash) -> TreeHash {
        TreeHash(hmac.0)
    }
}

pub(crate) mod storage_to_gsc {
    use pinweaver_storage_api::TreeHashes;

    use super::*;

    pub fn hash(hash: TreeHash) -> Hash {
        Hash(hash.0)
    }

    pub fn path(path: Path) -> U64<LittleEndian> {
        u64::from(path).into()
    }

    pub fn path_hashes(path_hashes: TreeHashes) -> Vec<Hash> {
        path_hashes.iter().map(|tree_hash| Hash(tree_hash.0)).collect()
    }
}

pub(crate) mod binder_error {
    use super::*;

    use binder::{ExceptionCode, Status};
    use pinweaver_api::aidl::IPinWeaver::{
        ERROR_AUTH_FAILED, ERROR_GSC, ERROR_LEAF_EXISTS, ERROR_LEAF_NOT_FOUND,
        ERROR_LOWENT_AUTH_FAILED, ERROR_NOT_READY, ERROR_PINWEAVER,
    };

    pub fn gsc() -> Status {
        Status::new_service_specific_error(ERROR_GSC, None)
    }

    pub fn illegal_argument(msg: &CStr) -> Status {
        Status::new_exception(ExceptionCode::ILLEGAL_ARGUMENT, Some(msg))
    }

    pub fn pinweaver(msg: &CStr) -> Status {
        Status::new_service_specific_error(ERROR_PINWEAVER, Some(msg))
    }

    pub fn leaf_exists() -> Status {
        Status::new_service_specific_error(ERROR_LEAF_EXISTS, Some(c"leaf exists"))
    }

    pub fn leaf_not_found() -> Status {
        Status::new_service_specific_error(ERROR_LEAF_NOT_FOUND, Some(c"leaf not found"))
    }

    pub fn low_entropy_auth_failed() -> Status {
        Status::new_service_specific_error(
            ERROR_LOWENT_AUTH_FAILED,
            Some(c"low entropy auth failed"),
        )
    }

    pub fn auth_failed() -> Status {
        Status::new_service_specific_error(ERROR_AUTH_FAILED, Some(c"auth failed"))
    }

    pub fn not_ready() -> Status {
        Status::new_service_specific_error(ERROR_NOT_READY, Some(c"not ready"))
    }

    pub fn from_tipc(err: TipcError) -> Status {
        if matches!(err, TipcError::SystemError(trusty_sys::Error::NotReady)) {
            not_ready()
        } else {
            pinweaver(c"tipc error")
        }
    }

    pub fn unsupported_operation() -> Status {
        Status::new_exception(ExceptionCode::UNSUPPORTED_OPERATION, None)
    }
}

// The `'static` is necessary for implicit `PinWeaverService<Deps>: 'static`.
pub trait PinWeaverServiceDeps: 'static {
    type Storage: StorageInterface<Error = TipcError> + Send + Sync + ?Sized + 'static;
    type Gsc: Pinweaver + Send + Sync + 'static;
}

#[allow(dead_code)]
/// Implements the `IPinWeaver` AIDL interface for other Trusty apps to call.
pub struct PinWeaverService<Deps: PinWeaverServiceDeps> {
    storage: Arc<Deps::Storage>,
    gsc: Arc<Deps::Gsc>,
}

impl<Deps: PinWeaverServiceDeps> PinWeaverService<Deps> {
    pub fn new(storage: Arc<Deps::Storage>, gsc: Arc<Deps::Gsc>) -> Self {
        Self { storage, gsc }
    }

    pub fn reconcile_once(&self) -> binder::Result<()> {
        if !RECONCILED.load(Ordering::Acquire) {
            self.reconcile()?;
        }
        Ok(())
    }

    pub fn reconcile_storage_with_gsc(&self) -> binder::Result<bool> {
        // Get storage root
        let resp =
            self.storage.request(&StorageRequest::GetStatus).map_err(binder_error::from_tipc)?;
        let storage_root =
            if let StorageResponse::GetStatus(GetStatusResponse { root_hash, .. }) = resp {
                root_hash
            } else {
                // Don't bother to reconcile if the storage is inaccessible or uninitialized.
                return Ok(true);
            };

        // Get GSC root
        let (gsc_root, _) = self.gsc.sys_info().map_err(|err| {
            error!("gsc.sys_info() failed: {err:?}");
            binder_error::gsc()
        })?;
        if storage_root.0 == gsc_root.0 {
            return Ok(true);
        }
        warn!("GSC and storage out of sync; attempting log replay");

        // Get the GSC log.
        let mut buffer = Vec::new();
        let entries = self.gsc.get_log(Some(Hash(storage_root.0)), &mut buffer).map_err(|err| {
            error!("gsc.get_log() failed: {err:?}");
            binder_error::gsc()
        })?;

        // Replay the log
        let mut to_replay = entries.iter().rev().peekable();
        // We need to skip the first operation if we have already applied it to storage.
        if matches!(to_replay.peek(), Some(entry) if entry.root.0 == storage_root.0) {
            let _skip = to_replay.next();
        }
        let mut to_remove = Map::new();
        let mut new_root: TreeHash = storage_root;
        while let Some(entry) = to_replay.next() {
            match entry.data() {
                LogEntryData::ResetTree => {
                    return Ok(false);
                }
                LogEntryData::InsertLeaf(hmac) => {
                    // This is somewhat precarious because we don't have the data to recover this leaf.
                    // The best we can do is try to remove it.
                    if let Ok((root, leaf_id)) =
                        self.replay_without_gsc(entry.label, TreeHash(hmac.0))
                    {
                        new_root = root;
                        to_remove.insert(entry.label.get(), leaf_id);
                    } else {
                        return Ok(false);
                    }
                }
                LogEntryData::TryAuth00(_) | LogEntryData::TryAuth02(_) => {
                    // Skip try-auth for an inserted leaf since it will fail, and if it gets removed
                    // before it is needed, replay may still succeed.
                    if to_remove.contains_key(&entry.label.get()) {
                        continue;
                    }
                    // Skip non-remove operations on the same leaf.
                    if matches!(to_replay.peek(), Some(next_entry) if next_entry.label == entry.label)
                    {
                        continue;
                    }
                    if let Ok(root) = self.replay_try_auth(entry.root, entry.label) {
                        new_root = root;
                    } else {
                        return Ok(false);
                    }
                }
                LogEntryData::RemoveLeaf => {
                    if let Ok((root, _)) = self.replay_without_gsc(entry.label, EMPTY_TREE_HASH) {
                        new_root = root;
                    } else {
                        return Ok(false);
                    };
                    to_remove.remove(&entry.label.get());
                }
                LogEntryData::UnrecognizedOperation => {
                    error!("Got unrecognized option: {:02x}", entry.operation.0);
                    continue;
                }
            }
        }
        // If there are leaves to remove skip the root check since, self.remove_leaf(..) will only
        // succeed if the storage and gsc roots are in sync after the operation.
        if to_remove.is_empty() {
            if new_root.0 != gsc_root.0 {
                return Ok(false);
            }
        } else {
            // For now there should only be at most one leaf to remove.
            warn!("GSC and storage out of sync; removing {} leaf", to_remove.len());
            for leaf_id in to_remove.into_values() {
                self.remove_leaf(leaf_id)?;
            }
        }
        info!("log replay successful");
        Ok(true)
    }

    fn start_replay(&self, label: Label) -> binder::Result<StorageResponse> {
        self.storage
            .request(&StorageRequest::StartOp(StartOpRequest::LogReplay(Path::from(label.get()))))
            .map_err(binder_error::from_tipc)
    }

    fn replay_without_gsc(
        &self,
        label: Label,
        new_leaf_hmac: TreeHash,
    ) -> binder::Result<(TreeHash, StorageLeafId)> {
        let start_resp = self.start_replay(label)?;
        let leaf_id = if let StorageResponse::StartOp(StartOpResponse {
            op_data: StartOpResponseData::LogReplay(data),
            ..
        }) = start_resp
        {
            data.id
        } else {
            error!("start_replay: unexpected response: {:?}", &start_resp);
            return Err(binder_error::pinweaver(c"unexpected response"));
        };

        let resp = self
            .storage
            .request(&StorageRequest::CommitOp(CommitOpRequest {
                start_request: StartOpRequest::LogReplay(Path::from(label.get())),
                new_leaf_hmac,
                new_leaf_contents: SerdeVec::from_vec(Vec::new()),
            }))
            .map_err(binder_error::from_tipc)?;
        let root_hash = if let StorageResponse::CommitOp(CommitOpResponse { root_hash, .. }) = resp
        {
            root_hash
        } else {
            error!("commit_replay: unexpected response: {:?}", &resp);
            return Err(binder_error::pinweaver(c"unexpected response"));
        };
        Ok((root_hash, leaf_id))
    }

    fn replay_try_auth(&self, log_root: Hash, label: Label) -> binder::Result<TreeHash> {
        let start_resp = self.start_replay(label)?;
        let (contents, path_hashes) = if let StorageResponse::StartOp(StartOpResponse {
            op_data: StartOpResponseData::LogReplay(data),
            tree_hashes,
            ..
        }) = start_resp
        {
            (data.leaf_contents, storage_to_gsc::path_hashes(tree_hashes))
        } else {
            error!("start_replay: unexpected response: {:?}", &start_resp);
            return Err(binder_error::pinweaver(c"unexpected response"));
        };

        let mut buffer = Vec::new();
        let new_data = self
            .gsc
            .log_replay(
                GscTreeParams {
                    bits_per_level: DEFAULT_TREE_BITS_PER_LEVEL,
                    height: DEFAULT_TREE_HEIGHT,
                },
                LogReplayHeader { log_root },
                contents.as_ref(),
                path_hashes.as_slice(),
                &mut buffer,
            )
            .map_err(|err| {
                error!("gsc log replay failed: {err:?}");
                binder_error::gsc()
            })?;

        let new_leaf_hmac = TreeHash(new_data.hmac.0);
        let resp = self
            .storage
            .request(&StorageRequest::CommitOp(CommitOpRequest {
                start_request: StartOpRequest::LogReplay(Path::from(label.get())),
                new_leaf_hmac,
                new_leaf_contents: SerdeVec::from_vec(new_data.as_bytes().to_vec()),
            }))
            .map_err(binder_error::from_tipc)?;
        let root_hash = if let StorageResponse::CommitOp(CommitOpResponse { root_hash, .. }) = resp
        {
            root_hash
        } else {
            error!("commit_replay: unexpected response: {:?}", &resp);
            return Err(binder_error::pinweaver(c"unexpected response"));
        };
        Ok(root_hash)
    }

    fn handle_secret_size(
        &self,
        leaf_id: StorageLeafId,
        secret: &[u8],
    ) -> binder::Result<(Secret, SerdeOption<LargeSecretInfo>)> {
        if let Ok(ret) = secret.try_into().map(|s| (Secret(s), SerdeOption::None)) {
            return Ok(ret);
        }

        let mut key = Secret([0u8; 32]);
        rand_bytes(&mut key.0).map_err(|err| {
            error!("failed to generate key: {err:?}");
            binder_error::pinweaver(c"failed to generate key")
        })?;

        let mut iv = LargeSecretIv([0u8; 12]);
        rand_bytes(&mut iv.0).map_err(|err| {
            error!("failed to generate iv: {err:?}");
            binder_error::pinweaver(c"failed to generate iv")
        })?;

        // Use the leaf_id as additional auth data to prevent the secret
        // from being moved between leaf_id's
        let mut auth_tag = LargeSecretAuthTag(0.into());
        let secret_ciphertext = SerdeVec::from_vec(
            encrypt_aead(
                Cipher::aes_256_gcm(),
                &key.0,
                Some(&iv.0),
                leaf_id.as_bytes(),
                secret,
                auth_tag.0.deref_mut().as_mut(),
            )
            .map_err(|err| {
                error!("failed to encrypt large secret: {err:?}");
                binder_error::pinweaver(c"failed to generate key")
            })?,
        );
        Ok((key, SerdeOption::Some(LargeSecretInfo { iv, auth_tag, secret_ciphertext })))
    }

    fn decrypt_large_secret(
        &self,
        leaf_id: StorageLeafId,
        secret: &[u8],
        large_secret_info: &LargeSecretInfo,
    ) -> binder::Result<Vec<u8>> {
        decrypt_aead(
            Cipher::aes_256_gcm(),
            secret,
            Some(&large_secret_info.iv.0),
            leaf_id.as_bytes(),
            large_secret_info.secret_ciphertext.deref(),
            large_secret_info.auth_tag.0.as_bytes(),
        )
        .map_err(|err| {
            error!("failed to encrypt large secret: {err:?}");
            binder_error::pinweaver(c"failed to generate key")
        })
    }

    fn reset_tree(&self) -> binder::Result<()> {
        // Reset from the GSC first to make sure it succeeds before clearing the storage.
        let root_hash = self
            .gsc
            .reset_tree(GscTreeParams {
                bits_per_level: DEFAULT_TREE_BITS_PER_LEVEL,
                height: DEFAULT_TREE_HEIGHT,
            })
            .map_err(|err| {
                error!("gsc reset tree failed: {err:?}");
                binder_error::gsc()
            })?;

        // The tree is reset on the GSC, so continue with the leaf storage.
        let ret = self
            .storage
            .request(&StorageRequest::ResetTree(ResetTreeRequest {
                tree_params: TreeParams {
                    height: DEFAULT_TREE_HEIGHT,
                    bits_per_level: DEFAULT_TREE_BITS_PER_LEVEL,
                },
            }))
            .map_err(|err| {
                error!("storage reset tree failed: {err:?}");
                binder_error::from_tipc(err)
            })?;
        if let StorageResponse::ResetTree(resp) = ret {
            if *resp.root_hash == root_hash.0 {
                Ok(())
            } else {
                // This should never happen.
                error!("root_hash mismatch during reset; please file a bug");
                Err(binder_error::pinweaver(c"reset_tree: unexpected response"))
            }
        } else {
            error!("reset_tree: got unexpected response: {ret:?}");
            Err(binder_error::pinweaver(c"reset_tree: unexpected response"))
        }
    }

    fn commit_remove_leaf(
        &self,
        leaf_id: StorageLeafId,
        path: Path,
        leaf_hmac: TreeHash,
        path_hashes: TreeHashes,
    ) -> binder::Result<()> {
        // Convert parameters.
        let gsc_path = storage_to_gsc::path(path);
        let gsc_leaf_hmac = storage_to_gsc::hash(leaf_hmac);
        let gsc_path_hashes = storage_to_gsc::path_hashes(path_hashes);

        // Remove from the GSC first.
        let gsc_root = self
            .gsc
            .remove_leaf(
                GscTreeParams {
                    bits_per_level: DEFAULT_TREE_BITS_PER_LEVEL,
                    height: DEFAULT_TREE_HEIGHT,
                },
                RemoveLeafHeader { leaf_location: gsc_path, leaf_hmac: gsc_leaf_hmac },
                gsc_path_hashes.as_slice(),
            )
            .map_err(|err| {
                error!("gsc remove leaf failed: {err:?}");
                binder_error::gsc()
            })?;

        // Commit the remove operation.
        let resp = self
            .storage
            .request(&StorageRequest::CommitOp(CommitOpRequest {
                start_request: StartOpRequest::Remove(leaf_id),
                new_leaf_hmac: EMPTY_TREE_HASH,
                new_leaf_contents: SerdeVec::from_vec(Vec::new()),
            }))
            .map_err(binder_error::from_tipc)?;
        let root_hash = if let StorageResponse::CommitOp(CommitOpResponse { root_hash, .. }) = resp
        {
            root_hash
        } else {
            error!("commit_remove: unexpected response: {:?}", &resp);
            return Err(binder_error::pinweaver(c"unexpected response"));
        };
        if root_hash.0 != gsc_root.0 {
            error!("root and storage out of sync");
            return Err(binder_error::pinweaver(c"root and storage out of sync"));
        }
        Ok(())
    }

    fn commit_remove_bulk(
        &self,
        leaf_set: StorageLeafSet,
        path: Path,
        leaf_hmac: TreeHash,
        path_hashes: TreeHashes,
    ) -> binder::Result<CommitRemoveBulkResponseData> {
        // Convert parameters.
        let gsc_path = storage_to_gsc::path(path);
        let gsc_leaf_hmac = storage_to_gsc::hash(leaf_hmac);
        let gsc_path_hashes = storage_to_gsc::path_hashes(path_hashes);

        // Remove from the GSC first.
        let gsc_root = self
            .gsc
            .remove_leaf(
                GscTreeParams {
                    bits_per_level: DEFAULT_TREE_BITS_PER_LEVEL,
                    height: DEFAULT_TREE_HEIGHT,
                },
                RemoveLeafHeader { leaf_location: gsc_path, leaf_hmac: gsc_leaf_hmac },
                gsc_path_hashes.as_slice(),
            )
            .map_err(|err| {
                error!("gsc remove leaf failed: {err:?}");
                binder_error::gsc()
            })?;

        // Commit the remove operation.
        let resp = self
            .storage
            .request(&StorageRequest::CommitOp(CommitOpRequest {
                start_request: StartOpRequest::RemoveBulk(leaf_set),
                new_leaf_hmac: EMPTY_TREE_HASH,
                new_leaf_contents: SerdeVec::from_vec(Vec::new()),
            }))
            .map_err(binder_error::from_tipc)?;
        let (root_hash, continue_or_done) = if let StorageResponse::CommitOp(CommitOpResponse {
            root_hash,
            op_data: CommitOpResponseData::RemoveBulk(continue_or_done),
            ..
        }) = resp
        {
            (root_hash, continue_or_done)
        } else {
            error!("commit_remove: unexpected response: {:?}", &resp);
            return Err(binder_error::pinweaver(c"unexpected response"));
        };
        if root_hash.0 != gsc_root.0 {
            error!("root and storage out of sync");
            return Err(binder_error::pinweaver(c"root and storage out of sync"));
        }
        Ok(continue_or_done)
    }

    fn remove_leaf(&self, leaf_id: StorageLeafId) -> binder::Result<()> {
        let resp = self
            .storage
            .request(&StorageRequest::StartOp(StartOpRequest::Remove(leaf_id)))
            .map_err(binder_error::from_tipc)?;
        let (path, tree_hashes, leaf_hmac) = match resp {
            StorageResponse::StartOp(StartOpResponse {
                path,
                tree_hashes,
                op_data: StartOpResponseData::Remove(StartRemoveResponseData { leaf_hmac }),
            }) => (path, tree_hashes, leaf_hmac),
            StorageResponse::Error(ResponseError::DoesNotExist) => {
                return Err(binder_error::leaf_not_found());
            }
            _ => {
                error!("start_remove: unexpected response: {:?}", &resp);
                return Err(binder_error::pinweaver(c"unexpected response"));
            }
        };

        self.commit_remove_leaf(leaf_id, path, leaf_hmac, tree_hashes)
    }

    fn handle_pending_operation(&self) -> binder::Result<()> {
        let resp =
            self.storage.request(&StorageRequest::GetStatus).map_err(binder_error::from_tipc)?;
        if let StorageResponse::GetStatus(GetStatusResponse {
            pending_op: SerdeOption::Some(StartOpRequest::Remove(leaf_id)),
            ..
        }) = resp
        {
            self.remove_leaf(leaf_id)
        } else {
            // We should not get here.
            error!("handle_pending_operation: unexpected response: {:?}", &resp);
            Err(binder_error::unsupported_operation())
        }
    }

    // Handle errors expected during the first storage request such as ResponseError::NotInitialized
    //
    // This will retry the command as appropriate after initializing the tree.
    fn first_request_helper(&self, request: &StorageRequest) -> binder::Result<StorageResponse> {
        let mut ret = self.storage.request(request);
        if let Ok(StorageResponse::Error(err)) = &ret {
            match err {
                ResponseError::NotInitialized => {
                    self.reset_tree()?;
                    ret = self.storage.request(request);
                }
                ResponseError::OperationPending => {
                    self.handle_pending_operation()?;
                    ret = self.storage.request(request);
                }
                _ => {}
            }
        }
        ret.map_err(binder_error::from_tipc)
    }
}

impl<Deps: PinWeaverServiceDeps> Interface for PinWeaverService<Deps> {}

impl<Deps: PinWeaverServiceDeps> IPinWeaver for PinWeaverService<Deps> {
    fn insert(
        &self,
        api_leaf_id: &LeafId,
        api_low_entropy_secret: &[u8],
        api_high_entropy_secret: &[u8],
        api_reset_secret: &[u8],
        api_delay_schedule: &[DelayScheduleEntry],
        api_insert_mode: InsertMode,
    ) -> binder::Result<()> {
        self.reconcile_once()?;

        // Convert parameters from IPinweaver to storage and GSC types.
        let leaf_id = api_to_storage::leaf_id(api_leaf_id);
        let low_entropy_secret = api_to_gsc::secret(api_low_entropy_secret)?;
        let (high_entropy_secret, large_key_info) =
            self.handle_secret_size(leaf_id, api_high_entropy_secret)?;
        let reset_secret = api_to_gsc::secret(api_reset_secret)?;
        let delay_schedule = api_to_gsc::delay_schedule(api_delay_schedule)?;
        let insert_mode = api_to_storage::insertmode(api_insert_mode)?;

        // Start the operation with Storage to find an empty leaf and whether a replacement will occur.
        let start_request =
            StartOpRequest::Insert(InsertOpRequest { leaf_id, mode: insert_mode, large_key_info });
        let ret = self.first_request_helper(&StorageRequest::StartOp(start_request.clone()))?;
        // Extract returned values and convert from Storage to GSC.
        let (path, tree_hashes, replacing_path) = match ret {
            StorageResponse::StartOp(StartOpResponse {
                path,
                tree_hashes,
                op_data: StartOpResponseData::Insert(StartInsertResponseData { replacing_path }),
            }) => (path, tree_hashes, replacing_path),
            StorageResponse::Error(ResponseError::WouldReplace) => {
                return Err(binder_error::leaf_exists());
            }
            _ => {
                error!("start_insert: unexpected response: {ret:?}");
                return Err(binder_error::pinweaver(c"unexpected response"));
            }
        };
        if replacing_path.as_ref().is_some() && matches!(api_insert_mode, InsertMode::NEW_ONLY) {
            // This should never happen.
            error!("unexpected replacing_path; please file a bug");
            return Err(binder_error::pinweaver(c"unexpected replacing_path; please file a bug"));
        }
        let path_hashes: Vec<Hash> = storage_to_gsc::path_hashes(tree_hashes);

        // Insert the leaf through the GSC.
        let mut resp_buffer = Vec::<u8>::new();
        let (gsc_root, leaf_data) = self
            .gsc
            .insert_leaf(
                GscTreeParams {
                    bits_per_level: DEFAULT_TREE_BITS_PER_LEVEL,
                    height: DEFAULT_TREE_HEIGHT,
                },
                InsertLeafHeader {
                    label: storage_to_gsc::path(path),
                    low_entropy_secret,
                    high_entropy_secret,
                    reset_secret,
                    valid_pcr_criteria: ValidPcrCriteria::default(),
                    delay_schedule,
                    expiration_delay: TimeDiff::from_secs(0),
                    leaf_type: Default::default(),
                    auth_channel: Default::default(),
                },
                path_hashes.as_slice(),
                &mut resp_buffer,
            )
            .map_err(|err| {
                error!("gsc insert leaf failed: {err:?}");
                binder_error::gsc()
            })?;
        let new_leaf_hmac = gsc_to_storage::hmac(&leaf_data.hmac);

        // Commit the insert to storage.
        let resp = self
            .storage
            .request(&StorageRequest::CommitOp(CommitOpRequest {
                start_request,
                new_leaf_hmac,
                new_leaf_contents: SerdeVec::from_vec(leaf_data.as_bytes().to_vec()),
            }))
            .map_err(binder_error::from_tipc)?;
        let (_path, root_hash, op_data) = if let StorageResponse::CommitOp(CommitOpResponse {
            path,
            root_hash,
            op_data,
        }) = resp
        {
            (path, root_hash, op_data)
        } else {
            error!("commit_insert: unexpected response: {:?}", &resp);
            return Err(binder_error::pinweaver(c"unexpected response"));
        };
        if root_hash.0 != gsc_root.0 {
            error!("root and storage out of sync");
            return Err(binder_error::pinweaver(c"root and storage out of sync"));
        }

        let (remove_hashes, remove_path) = match (op_data, replacing_path) {
            (
                CommitOpResponseData::InsertReplace(remove_hashes),
                SerdeOption::Some(remove_path),
            ) => (remove_hashes, remove_path),
            (CommitOpResponseData::None, SerdeOption::None) => {
                return Ok(());
            }
            (op_data, replacing_path) => {
                error!("unexpected (op_data, replacing_path): ({op_data:?}, {replacing_path:?})");
                return Err(binder_error::pinweaver(c"unexpected op_data"));
            }
        };
        self.commit_remove_leaf(
            RESERVED_LEAF_ID,
            remove_path,
            remove_hashes.leaf_hmac,
            remove_hashes.tree_hashes,
        )
    }

    fn tryAuthenticate(
        &self,
        api_leaf_id: &LeafId,
        api_low_entropy_secret: &[u8],
    ) -> binder::Result<TryAuthResponse> {
        self.reconcile_once()?;

        // Convert parameters from IPinweaver to storage and GSC types.
        let leaf_id = api_to_storage::leaf_id(api_leaf_id);
        let low_entropy_secret = api_to_gsc::secret(api_low_entropy_secret)?;

        // Start try auth
        let start_request = StartOpRequest::TryAuth(leaf_id);
        let ret = self.first_request_helper(&StorageRequest::StartOp(start_request.clone()))?;
        // Extract returned values and convert from Storage to GSC.
        let (tree_hashes, leaf_contents, large_key_info) = match ret {
            StorageResponse::StartOp(StartOpResponse {
                tree_hashes,
                op_data:
                    StartOpResponseData::TryAuth(StartTryAuthResponseData {
                        leaf_contents,
                        large_key_info,
                    }),
                ..
            }) => (tree_hashes, leaf_contents, large_key_info),
            StorageResponse::Error(ResponseError::DoesNotExist) => {
                return Err(binder_error::leaf_not_found());
            }
            _ => {
                error!("start_try_auth: unexpected response: {ret:?}");
                return Err(binder_error::pinweaver(c"unexpected response"));
            }
        };
        let path_hashes: Vec<Hash> = storage_to_gsc::path_hashes(tree_hashes);

        // GSC try auth
        let mut resp_buffer = Vec::<u8>::new();
        let (gsc_root, result_code, try_auth) = self
            .gsc
            .try_auth(
                GscTreeParams {
                    bits_per_level: DEFAULT_TREE_BITS_PER_LEVEL,
                    height: DEFAULT_TREE_HEIGHT,
                },
                TryAuthHeader { low_entropy_secret },
                leaf_contents.deref(),
                path_hashes.as_slice(),
                &mut resp_buffer,
            )
            .map_err(|err| {
                error!("gsc try auth failed: {err:?}");
                binder_error::gsc()
            })?;
        if matches!(result_code, ResultCode::RateLimitReached) {
            return Ok(TryAuthResponse::SecondsToWait(
                try_auth.head.seconds_to_wait.to_secs().try_into().unwrap_or(i32::MAX),
            ));
        }
        let new_leaf_hmac = gsc_to_storage::hmac(&try_auth.unimported_leaf_data.hmac);

        // Commit try auth
        let resp = self
            .storage
            .request(&StorageRequest::CommitOp(CommitOpRequest {
                start_request,
                new_leaf_hmac,
                new_leaf_contents: SerdeVec::from_vec(
                    try_auth.unimported_leaf_data.as_bytes().to_vec(),
                ),
            }))
            .map_err(binder_error::from_tipc)?;
        let root_hash = if let StorageResponse::CommitOp(CommitOpResponse { root_hash, .. }) = resp
        {
            root_hash
        } else {
            error!("commit_insert: unexpected response: {:?}", &resp);
            return Err(binder_error::pinweaver(c"unexpected response"));
        };
        if root_hash.0 != gsc_root.0 {
            error!("root and storage out of sync");
            return Err(binder_error::pinweaver(c"root and storage out of sync"));
        }

        match result_code {
            ResultCode::Success => {}
            ResultCode::LowentAuthFailed => return Err(binder_error::low_entropy_auth_failed()),
            _ => {
                error!("unexpected result code: {result_code:?}");
                return Err(binder_error::pinweaver(c"unexpected result code"));
            }
        }

        let high_entropy_secret = if let SerdeOption::Some(large_secret_info) = large_key_info {
            self.decrypt_large_secret(
                leaf_id,
                &try_auth.head.high_entropy_secret.0,
                &large_secret_info,
            )?
        } else {
            try_auth.head.high_entropy_secret.0.to_vec()
        };
        Ok(TryAuthResponse::HighEntropySecret(high_entropy_secret))
    }

    fn resetRetries(
        &self,
        api_leaf_id: &LeafId,
        strong_reset: bool,
        api_reset_secret: &[u8],
    ) -> binder::Result<()> {
        self.reconcile_once()?;

        // Convert parameters from IPinweaver to storage and GSC types.
        let leaf_id = api_to_storage::leaf_id(api_leaf_id);
        let reset_secret = api_to_gsc::secret(api_reset_secret)?;

        // Start try auth
        let start_request = StartOpRequest::TryAuth(leaf_id);
        let ret = self.first_request_helper(&StorageRequest::StartOp(start_request.clone()))?;
        // Extract returned values and convert from Storage to GSC.
        let (tree_hashes, leaf_contents) = match ret {
            StorageResponse::StartOp(StartOpResponse {
                tree_hashes,
                op_data:
                    StartOpResponseData::TryAuth(StartTryAuthResponseData { leaf_contents, .. }),
                ..
            }) => (tree_hashes, leaf_contents),
            StorageResponse::Error(ResponseError::DoesNotExist) => {
                return Err(binder_error::leaf_not_found());
            }
            _ => {
                error!("start_try_auth: unexpected response: {ret:?}");
                return Err(binder_error::pinweaver(c"unexpected response"));
            }
        };
        let path_hashes: Vec<Hash> = storage_to_gsc::path_hashes(tree_hashes);

        // GSC reset auth
        let mut resp_buffer = Vec::<u8>::new();
        let (gsc_root, reset_auth) = self
            .gsc
            .reset_auth(
                GscTreeParams {
                    bits_per_level: DEFAULT_TREE_BITS_PER_LEVEL,
                    height: DEFAULT_TREE_HEIGHT,
                },
                ResetAuthHeader { reset_secret, strong_reset: strong_reset as u8 },
                leaf_contents.deref(),
                path_hashes.as_slice(),
                &mut resp_buffer,
            )
            .map_err(|err| {
                error!("gsc reset auth failed: {err:?}");
                if matches!(err, TpmError::Response(GscError::ResultCode(code)) if code == ResultCode::ResetAuthFailed)
                {
                    binder_error::auth_failed()
                } else {
                    binder_error::gsc()
                }
            })?;
        let new_leaf_hmac = gsc_to_storage::hmac(&reset_auth.unimported_leaf_data.hmac);

        // Commit try auth
        let resp = self
            .storage
            .request(&StorageRequest::CommitOp(CommitOpRequest {
                start_request,
                new_leaf_hmac,
                new_leaf_contents: SerdeVec::from_vec(
                    reset_auth.unimported_leaf_data.as_bytes().to_vec(),
                ),
            }))
            .map_err(binder_error::from_tipc)?;
        let root_hash = if let StorageResponse::CommitOp(CommitOpResponse { root_hash, .. }) = resp
        {
            root_hash
        } else {
            error!("commit_insert: unexpected response: {:?}", &resp);
            return Err(binder_error::pinweaver(c"unexpected response"));
        };
        if root_hash.0 != gsc_root.0 {
            error!("root and storage out of sync");
            return Err(binder_error::pinweaver(c"root and storage out of sync"));
        }
        Ok(())
    }

    fn tryAuthenticateThenReplace(
        &self,
        _id: &LeafId,
        _current_low_entropy_secret: &[u8],
        _new_low_entropy_secret: &[u8],
        _new_high_entropy_secret: Option<&[u8]>,
        _new_delay_schedule: Option<&[Option<DelayScheduleEntry>]>,
    ) -> binder::Result<TryAuthResponse> {
        self.reconcile_once()?;

        // TODO: b/359374997 - Implement.
        Err(binder_error::unsupported_operation())
    }

    fn remove(&self, id: &LeafId) -> binder::Result<()> {
        self.reconcile_once()?;

        self.remove_leaf(api_to_storage::leaf_id(id))
    }

    fn removeAll(&self, api_leaf_set: LeafSet) -> binder::Result<()> {
        if matches!(api_leaf_set, LeafSet::ALL_LEAVES) {
            self.reset_tree()?;
            RECONCILED.store(true, Ordering::Release);
            return Ok(());
        }
        self.reconcile_once()?;

        let leaf_set = api_to_storage::leaf_set(api_leaf_set);

        let resp = self
            .storage
            .request(&StorageRequest::StartOp(StartOpRequest::RemoveBulk(leaf_set)))
            .map_err(binder_error::from_tipc)?;
        let (mut path, mut tree_hashes, mut leaf_hmac) = match resp {
            StorageResponse::StartOp(StartOpResponse {
                path,
                tree_hashes,
                op_data: StartOpResponseData::Remove(StartRemoveResponseData { leaf_hmac }),
            }) => (path, tree_hashes, leaf_hmac),
            StorageResponse::Error(ResponseError::DoesNotExist) => {
                return Err(binder_error::leaf_not_found());
            }
            _ => {
                error!("start_remove: unexpected response: {:?}", &resp);
                return Err(binder_error::pinweaver(c"unexpected response"));
            }
        };

        loop {
            match self.commit_remove_bulk(leaf_set, path, leaf_hmac, tree_hashes)? {
                CommitRemoveBulkResponseData::Continue(ContinueRemoveBulkResponse {
                    header,
                    hashes,
                }) => {
                    path = header.path;
                    tree_hashes = hashes.tree_hashes;
                    leaf_hmac = hashes.leaf_hmac
                }
                CommitRemoveBulkResponseData::Finished => {
                    return Ok(());
                }
            }
        }
    }

    fn reconcile(&self) -> binder::Result<()> {
        if !self.reconcile_storage_with_gsc()? {
            error!("log replay failed; resetting pinweaver");
            self.reset_tree()?;
        }
        RECONCILED.store(true, Ordering::Release);
        Ok(())
    }

    fn testStorage(&self, request: &[u8]) -> binder::Result<Vec<u8>> {
        self.storage.request_raw(request).map_err(binder_error::from_tipc)
    }
}
