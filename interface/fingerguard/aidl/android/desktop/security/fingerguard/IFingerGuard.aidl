/*
 * Copyright (c) 2025, The Android Open Source Project
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

package android.desktop.security.fingerguard;

import android.desktop.security.fingerguard.EnrollmentResult;
import android.desktop.security.fingerguard.HandshakeResponse;
import android.desktop.security.fingerguard.PrepareEnrollSessionResponse;
import android.desktop.security.fingerguard.SessionResponse;
import android.desktop.security.fingerguard.HardwareAuthToken;

interface IFingerGuard {
    /** Return the HandshakeResponse.
     * The pairing key, PK, is derived from ECDH key agreement.
     * The client would use HandshakeResponse to derive
     * the same PK.
     * Once the PK is established, it will be persisted and
     * block further initHandshake calls until the device is
     * powerwashed.
     */
    HandshakeResponse initHandshake(in byte[] client_public_key);
    /** Return the nonce for a common shared session key and
     * the session key encrypted TPM seed.
     * The session key is derived from the pairing key, plus
     * the client nonce and the returned nonce.
     */
    SessionResponse newSession(in byte[] client_nonce);
    /** Create an enroll session for a given pair of (user, sensor).
     * A nonce and a session counter will be returned, along with the associated MAC.
     * The details of the MAC computation is up to the agreement between FingerGuard
     * and its client.
     */
    PrepareEnrollSessionResponse prepareEnrollSession(in int sensorId, in int userId, in HardwareAuthToken hat);
    /** Finish a created enroll session.
     * The associated AuthenticatorID will be updated with a successful enrollment.
     */
    void finishEnrollSession(in int sensorId, in int userId, in EnrollmentResult result);
    /** Return the AuthenticatorId associated with
     * the (user, sensor) pair.
     */
    long getAuthenticatorId(in int sensorId, in int userId);
     /** Return a newly generated AuthenticatorId associated with
     * the (user, sensor) pair.
     */
    long newAuthenticatorId(in int sensorId, in int userId);
}
