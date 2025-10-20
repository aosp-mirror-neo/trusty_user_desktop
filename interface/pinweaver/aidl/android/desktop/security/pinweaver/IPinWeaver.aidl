/*
 * Copyright (c) 2024, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.desktop.security.pinweaver;

import android.desktop.security.pinweaver.DelayScheduleEntry;
import android.desktop.security.pinweaver.InsertMode;
import android.desktop.security.pinweaver.LeafId;
import android.desktop.security.pinweaver.LeafSet;
import android.desktop.security.pinweaver.TryAuthResponse;

/**
 * Adapts the ChromiumOS PinWeaver API for Android.
 *
 * PinWeaver is a hardware rate-limited secret storage system.
 * High entropy secrets are stored in leaves of a Merkle tree, encrypted with an on-chip secret.
 * Low entropy secrets are used to securely authorize access to these high entropy secrets,
 * with the backing hardware ensuring that the secret cannot discovered through brute force.
 *
 * See: https://chromium.googlesource.com/chromiumos/platform/pinweaver/
 */
@SensitiveData
interface IPinWeaver {
    /** Error communicating with the GSC */
    const int ERROR_GSC = 1;

    /** PinWeaver returned an internal error */
    const int ERROR_PINWEAVER = 2;

    /** The low-entropy secret was not correct for this leaf */
    const int ERROR_LOWENT_AUTH_FAILED = 3;

    /** The leaf with that ID already exists, and that's forbidden by the InsertMode */
    const int ERROR_LEAF_EXISTS = 4;

    /** The leaf doesn't exist */
    const int ERROR_LEAF_NOT_FOUND = 5;

    /** The secret was not correct for this leaf */
    const int ERROR_AUTH_FAILED = 6;

    /** The service is not ready yet either because of the GSC or pinweaver_storaged. */
    const int ERROR_NOT_READY = 7;

    /**
     * Inserts a leaf into PinWeaver.
     *
     * The new high entropy secret is encrypted and protected by the low entropy secret.
     * The delay schedule table cannot exceed 16 entries.
     *
     * @param id                 Chosen by the client to identify this leaf
     * @param lowEntropySecret   The new low entropy secret to protect this leaf
     * @param highEntropySecret  The new high entropy secret to protect
     * @param resetSecret        The secret used to reset attempt counters
     * @param delaySchedule      The rate limiting configuration for authentication
     * @param allowExisting      Whether to replace an existing leaf with the same id or fail
     *
     * @throws EX_ILLEGAL_ARGUMENT if either secret is empty or the delay schedule is invalid
     * @throws EX_SERVICE_SPECIFIC if there was an internal error:
     *   - ERROR_LEAF_EXISTS if a leaf with this ID already exists and is not replaced.
     */
    void insert(
        in LeafId id, in byte[] lowEntropySecret, in byte[] highEntropySecret,
        in byte[] resetSecret, in DelayScheduleEntry[] delaySchedule,
        in InsertMode allowExisting);

    /**
     * Authenticates the reset secret for this leaf and resets the retries.
     *
     * This authentication is not rate limited.
     *
     * @param id               The leaf to authenticate against
     * @param strongReset      The expiration should be reset too.
     * @param resetSecret      The current reset secret protecting this leaf
     *
     * @throws EX_ILLEGAL_ARGUMENT  if the low entropy secret is empty
     * @throws EX_SERVICE_SPECIFIC  if there was an internal error:
     *   - ERROR_LEAF_NOT_FOUND     if a leaf with this ID does not exist in PinWeaver
     *   - ERROR_AUTH_FAILED if the reset secret is incorrect
     */
    void resetRetries(in LeafId id, in boolean strongReset, in byte[] resetSecret);

    /**
     * Authenticates the low entropy secret for this leaf, returning the high entropy secret.
     *
     * This authentication is rate limited according to the configured delay table for the leaf.
     * If the authorization is rate limited:
     * - The high entropy secret is not released.
     * - An OK status is returned from this method with the amount of time to wait.
     * - The low entropy secret has not been attempted; try the same secret again after the delay.
     *
     * @param id               The leaf to authenticate against
     * @param lowEntropySecret The current low entropy secret protecting this leaf
     * @return                 The high entropy secret, or the time to wait if rate limited
     *
     * @throws EX_ILLEGAL_ARGUMENT  if the low entropy secret is empty
     * @throws EX_SERVICE_SPECIFIC  if there was an internal error:
     *   - ERROR_LEAF_NOT_FOUND     if a leaf with this ID does not exist in PinWeaver
     *   - ERROR_LOWENT_AUTH_FAILED if the lowEntropySecret is incorrect
     */
    TryAuthResponse tryAuthenticate(in LeafId id, in byte[] lowEntropySecret);

    /**
     * Authenticates the low entropy secret for this leaf and replaces it with a new leaf.
     *
     * The new leaf configuration is ignored if authentication fails or is rate limited.
     * Like tryAuthenticate, this return an OK status with the time to wait when rate
     * limiting occurs.
     *
     * @param id                      The leaf to authenticate and then replace
     * @param currentLowEntropySecret The current low entropy secret protecting this leaf
     * @param newLowEntropySecret     The new low entropy secret to protect this leaf
     * @param newHighEntropySecret    The new high entropy secret to protect, or null to
     *                                leave it unchanged
     * @param newDelaySchedule        The new delay schedule to configure, or null to leave
     *                                it unchanged. See `insert`
     * @return                        The previous high entropy secret, or the time to wait
     *                                if rate limited
     *
     * @throws EX_ILLEGAL_ARGUMENT  if any of the provided secrets are empty (and not null),
     *                              or if the new delay schedule is invalid
     * @throws EX_SERVICE_SPECIFIC  if there was an internal error:
     *   - ERROR_LEAF_NOT_FOUND     if a leaf with this ID does not exist in PinWeaver
     *   - ERROR_LOWENT_AUTH_FAILED if the lowEntropySecret is incorrect
     */
    TryAuthResponse tryAuthenticateThenReplace(
        in LeafId id, in byte[] currentLowEntropySecret,
        in byte[] newLowEntropySecret, in @nullable byte[] newHighEntropySecret,
        in @nullable DelayScheduleEntry[] newDelaySchedule);

    /**
     * Removes a specific leaf.
     *
     * @param id The leaf to remove
     *
     * @throws EX_SERVICE_SPECIFIC if there was an internal error:
     *   - ERROR_LEAF_NOT_FOUND    if a leaf with this ID does not exist in PinWeaver
     */
    void remove(in LeafId id);

    /**
     * Removes all leaves in the given leaf set.
     *
     * @param leafSet The set of leaves to remove. Resets the entire tree for ALL_LEAVES
     */
    void removeAll(in LeafSet leafSet);

    /**
     * Reconciles the on-disk Merkle tree with the GSC.
     *
     * This is normally done transparently once per boot on during first operation, but
     * this RPC makes it testable.
     *
     * @throws EX_SERVICE_SPECIFIC if there was an internal error:
     */
    void reconcile();

    /**
     * An interface that provides access to the storage daemon for tests.
     *
     * This isn't intended to be used in production because it can put the
     * GSC and storage out of sync potentially leading to a tree reset and
     * complete data loss.
     *
     * @param request The storage request.
     * return the storage response.
     */
    byte[] testStorage(in byte[] request);
}
