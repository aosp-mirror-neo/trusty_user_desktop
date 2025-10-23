/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Secure storage interface for StrongBox KeyMint

use super::keymaster_attributes::{self, UdsCerts};
use kmr_common::{km_err, try_to_vec, vec_try, Error};
use log::info;
use protobuf::{self, Message};
use storage::{OpenMode, Port, SecureFile, Session};

const PORT: Port = Port::TamperDetectPersist;

/// Filename for holding UDS Certificate.
const KM_RKP_UDS_CERT_FILENAME: &str = "UdsCerts";

/// Maximum size of each attestation certificate
const MAX_CERT_SIZE: usize = 2048;

/// Maximum number of UDS certificates
const MAX_UDS_CERT_CHAIN_LEN: usize = 3;

/// Factory function to start a new storage session.
fn new_storage_session() -> Result<Box<dyn StorageSession>, Error> {
    Ok(Box::new(TrustyStorageSession))
}

/// Tries to read the file containing the UdsCerts and append a cert on it.
/// If the file doesn't exist it will create it and save the provided key.
pub fn append_uds_cert_chain(cert_data: &[u8]) -> Result<(), Error> {
    if cert_data.is_empty() || cert_data.len() > MAX_CERT_SIZE {
        return Err(km_err!(
            InvalidArgument,
            "Invalid certificate size: {}, max size {}",
            cert_data.len(),
            MAX_CERT_SIZE
        ));
    }
    let session = new_storage_session()?;
    session.update_protobuf_file(KM_RKP_UDS_CERT_FILENAME, |uds_cert_pb: &mut UdsCerts| {
        let cert_chain_len = uds_cert_pb.get_certs().len();
        if cert_chain_len >= MAX_UDS_CERT_CHAIN_LEN {
            return Err(km_err!(
                InvalidArgument,
                "cannot accept more certificates, {} already provisioned",
                cert_chain_len
            ));
        }
        let mut cert = keymaster_attributes::AttestationCert::new();
        cert.set_content(try_to_vec(cert_data)?);
        uds_cert_pb.mut_certs().push(cert);
        Ok(())
    })
}

/// Tries to read the file containing the UdsCert. It's fine if that file is clear, or will try to
/// delete it. After this call, all "read" operation will get a default <UdsCerts> object.
pub fn maybe_delete_uds_cert_chain() -> Result<(), Error> {
    let session = new_storage_session()?;
    let mut uds_cert_pb: UdsCerts = session.read_protobuf(KM_RKP_UDS_CERT_FILENAME)?;
    if uds_cert_pb.get_certs().is_empty() {
        // No certs found, nothing to delete.
        return Ok(());
    }
    session.delete_file(KM_RKP_UDS_CERT_FILENAME)?;
    session.commit()?;
    let session = new_storage_session()?;
    uds_cert_pb = session.read_protobuf(KM_RKP_UDS_CERT_FILENAME)?;
    let cert_chain_len = uds_cert_pb.get_certs().len();
    if cert_chain_len != 0 {
        return Err(km_err!(
            UnknownError,
            "couldn't delete all certificates, found {cert_chain_len}"
        ));
    }
    Ok(())
}

/// An abstract interface for a transactional secure storage session.
///
/// A session allows for multiple read/write/delete operations to be
/// chained.
trait StorageSession {
    /// Reads the entire contents of a file.
    ///
    /// Returns `Ok(None)` if the file does not exist.
    /// Returns `Err` for other I/O errors.
    fn read_all(&self, path: &str) -> Result<Option<Vec<u8>>, Error>;

    /// Writes data to a file, creating it if it doesn't exist and
    /// overwriting it if it does.
    fn write_all(&self, path: &str, data: &[u8]) -> Result<(), Error>;

    /// Deletes a file.
    fn delete_file(&self, path: &str) -> Result<(), Error>;

    /// This method consumes the session to prevent further operations.
    ///
    /// This default implementation is a no-op, suitable for non-transactional
    /// storage backends where write operations are performed immediately rather
    /// than buffered.
    fn commit(self: Box<Self>) -> Result<(), Error> {
        Ok(())
    }
}

/// An extension trait for `StorageSession` to add helper methods.
trait StorageSessionExt {
    /// Reads and parses a protobuf message from a file.
    fn read_protobuf<M>(&self, path: &str) -> Result<M, Error>
    where
        M: Message + Default;

    /// Serializes and writes a protobuf message to a file.
    fn write_protobuf<M: Message>(&self, path: &str, message: &M) -> Result<(), Error>;

    /// Performs a read-modify-write operation on a given protobuf file and commits the session.
    ///
    /// Since this method consumes the session, we must start a new one to read back the data
    /// for subsequent operations such as verification.
    fn update_protobuf_file<M, F>(self: Box<Self>, path: &str, update_fn: F) -> Result<(), Error>
    where
        M: Message + Default,
        F: FnOnce(&mut M) -> Result<(), Error>;
}

impl<T: ?Sized + StorageSession> StorageSessionExt for T {
    fn read_protobuf<M>(&self, path: &str) -> Result<M, Error>
    where
        M: Message + Default,
    {
        match self.read_all(path)? {
            Some(content) => M::parse_from_bytes(&content)
                .map_err(|e| km_err!(UnknownError, "failed to parse protobuf: {:?}", e)),
            None => Ok(M::default()),
        }
    }

    fn write_protobuf<M: Message>(&self, path: &str, message: &M) -> Result<(), Error> {
        let serialized_buffer = message
            .write_to_bytes()
            .map_err(|e| km_err!(UnknownError, "couldn't serialize protobuf: {:?}", e))?;
        self.write_all(path, &serialized_buffer)
    }

    fn update_protobuf_file<M, F>(self: Box<Self>, path: &str, update_fn: F) -> Result<(), Error>
    where
        M: Message + Default,
        F: FnOnce(&mut M) -> Result<(), Error>,
    {
        let mut message: M = self.read_protobuf(path)?;
        update_fn(&mut message)?;
        self.write_protobuf(path, &message)?;
        self.commit()
    }
}

/// A concrete implementation for secure storage on Trusty.
pub(super) struct TrustyStorageSession;

impl StorageSession for TrustyStorageSession {
    fn read_all(&self, path: &str) -> Result<Option<Vec<u8>>, Error> {
        let mut session = Session::new(PORT, true).map_err(|e| {
            km_err!(SecureHwCommunicationFailed, "failed to connect to storage port: {:?}", e)
        })?;

        // Distinguishing between file not found and other errors, so we can match c++ behavior
        // when retrieving attestation IDs on unprovisioned devices.
        let file = match session.open_file(path, OpenMode::Open) {
            Ok(file) => file,
            Err(storage::Error::Code(trusty_sys::Error::NotFound)) => {
                info!("{path:?} NotFound");
                return Ok(None);
            }
            Err(e) => {
                return Err(km_err!(
                    SecureHwCommunicationFailed,
                    "failed to open '{}': {:?}",
                    path,
                    e
                ));
            }
        };

        let size = session.get_size(&file).map_err(|e| {
            km_err!(SecureHwCommunicationFailed, "failed to get size for '{}': {:?}", path, e)
        })?;
        let mut buffer = vec_try![0; size]?;
        let content = session.read_all(&file, buffer.as_mut_slice()).map_err(|e| {
            km_err!(SecureHwCommunicationFailed, "failed to read '{}': {:?}", path, e)
        })?;
        let total_size = content.len();
        buffer.resize(total_size, 0);
        Ok(Some(buffer))
    }

    fn write_all(&self, path: &str, data: &[u8]) -> Result<(), Error> {
        let mut open_file = OpenSecureFile::new(path)?;
        open_file.write_all(data)
    }

    fn delete_file(&self, path: &str) -> Result<(), Error> {
        let mut session = Session::new(PORT, true).map_err(|e| {
            km_err!(SecureHwCommunicationFailed, "failed to connect to storage port: {:?}", e)
        })?;
        session.remove(path).map_err(|e| {
            km_err!(SecureHwCommunicationFailed, "failed to delete file '{path}': {:?}", e)
        })
    }
}

// `session` and `secure_file` are of type `Option` because close() takes self by value, so this was
// needed for the `Drop` implementation. The intent though is that they should always be populated
// on a OpenSecureFile object; which is `OpenSecureFile::new` behavior.
struct OpenSecureFile {
    session: Option<Session>,
    secure_file: Option<SecureFile>,
}

impl OpenSecureFile {
    /// Opens a secure storage session and creates the requested file
    fn new(file_name: &str) -> Result<Self, Error> {
        let mut session = Session::new(PORT, true).map_err(|e| {
            km_err!(SecureHwCommunicationFailed, "couldn't create storage session: {:?}", e)
        })?;
        let secure_file = session.open_file(file_name, OpenMode::Create).map_err(|e| {
            km_err!(SecureHwCommunicationFailed, "couldn't create file {}: {:?}", file_name, e)
        })?;
        Ok(OpenSecureFile { session: Some(session), secure_file: Some(secure_file) })
    }

    /// Writes provided data in the previously opened file
    fn write_all(&mut self, data: &[u8]) -> Result<(), Error> {
        // Even though we are handling the case when secure_file and session are None, this is not
        // expected; if an OpenSecureFile object exists its `secure_file` and `session` elements
        // shall be populated.
        let session =
            self.session.as_mut().ok_or(km_err!(UnknownError, "session shouldn't ever be None"))?;
        let file = self
            .secure_file
            .as_mut()
            .ok_or(km_err!(UnknownError, "secure_file shouldn't ever be None"))?;
        session.write_all(file, data).map_err(|e| {
            km_err!(SecureHwCommunicationFailed, "failed to write data; received error: {:?}", e)
        })
    }
}

impl Drop for OpenSecureFile {
    fn drop(&mut self) {
        // Even though we are handling the case when secure_file and session are None, this is not
        // expected; if an OpenSecureFile object exists its `secure_file` and `session` elements
        // shall be populated.
        if let Some(file) = self.secure_file.take() {
            file.close();
        }
        if let Some(session) = self.session.take() {
            session.close();
        }
    }
}
