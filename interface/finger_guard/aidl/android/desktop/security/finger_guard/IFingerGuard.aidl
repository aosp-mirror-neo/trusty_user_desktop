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

package android.desktop.security.finger_guard;

import android.desktop.security.finger_guard.ClientSessionResponse;
import android.desktop.security.finger_guard.InitResponse;
import android.desktop.security.finger_guard.HardwareAuthToken;
import android.desktop.security.finger_guard.LockoutStatus;
import android.desktop.security.finger_guard.SensorUserPair;

@VintfStability
interface IFingerGuard {
    /**
     * Return the InitResponse, which will be used by the client to
     * derive the shared pairing key.
     *
     * The pairing key, PK, is derived from ECDH key agreement. The client
     * should derive the same PK as FingerGuard does.
     * Once the PK is established, it will be persisted and block further
     * init calls until the device is powerwashed.
     */
    InitResponse init(in byte[] clientPublicKey);
    /**
     * Return the nonce for a common shared session key, the session key
     * encrypted TPM seed, and an instance of the IClientSession.
     *
     * The session key is derived from the pairing key, plus the client nonce
     * and the returned nonce.
     *
     * IClientSession can be used to perform authenticated operations as
     * IClientSession#PrepareEnrollSession, IClientSession#FinishEnrollSession, etc.
     */
    ClientSessionResponse createClientSession(in byte[] clientNonce);
    /**
     * Return a newly generated challange associated with the
     * (sensor, user) pair.
     * The challange should be returned in the HAT when prepareEnrollSession
     * is invoked. The challenge will expire after a minute.
     * It allows multiple in-flight challenges. Invoking generateChallenge
     * twice does not invalidate the first challenge. The challenge is invalidated only when:
     *   1) It expires.
     *   2) revokeChallenge is invoked.
     */
    long generateChallenge(in SensorUserPair sensorUserPair);
    /**
     * Revoke and return the challenge associated with the (sensor, user) pair.
     * If there is no previously generated challange matched the requested one
     * or the challenge has expired, return 0.
     */
    long revokeChallenge(in SensorUserPair sensorUserPair, long challenge);
    /**
     * Return the AuthenticatorId associated with the (sensor, user) pair.
     */
    long getAuthenticatorId(in SensorUserPair sensorUserPair);
    /**
     * Return a newly generated AuthenticatorId associated with the
     * (sensor, user) pair.
     */
    long newAuthenticatorId(in SensorUserPair sensorUserPair);
    /**
     * Return the lockout info associated with the (sensor, user) pair.
     */
    LockoutStatus getLockoutStatus(in SensorUserPair sensorUserPair);
    /**
     * Reset the lockout state associated with the (sensor, user) pair.
     * The provided HAT must be minted within one minute.
     */
    void resetLockout(in SensorUserPair sensorUserPair, in HardwareAuthToken hat);
}
