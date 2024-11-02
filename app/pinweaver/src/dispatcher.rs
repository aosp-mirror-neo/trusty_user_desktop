/// The RPC server that forwards to the `PinWeaverService` binder.
type PinWeaver = rpcbinder::RpcServer;

/// Forwards to the `StorageClientService`.
type Storage = crate::storage::StorageClientService;

// This macro requires that each variant name a type that implements
// `tipc::UnbufferedService`.
tipc::service_dispatcher! {
    pub(crate) enum PinWeaverDispatcher {
        PinWeaver,
        Storage,
    }
}
