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

import android.desktop.security.fingerguard.AuthenticationResult;
import android.desktop.security.fingerguard.EnrollmentResult;
import android.desktop.security.fingerguard.HandshakeResponse;
import android.desktop.security.fingerguard.LockoutStatus;
import android.desktop.security.fingerguard.PrepareAuthSessionResponse;
import android.desktop.security.fingerguard.PrepareEnrollSessionResponse;
import android.desktop.security.fingerguard.SensorUserPair;
import android.desktop.security.fingerguard.SessionResponse;
import android.desktop.security.fingerguard.HardwareAuthToken;

interface IFingerGuard {
    /**
     * Return the HandshakeResponse.
     * The pairing key, PK, is derived from ECDH key agreement. The client
     * would use HandshakeResponse to derive the same PK.
     * Once the PK is established, it will be persisted and block further
     * initHandshake calls until the device is powerwashed.
     */
    HandshakeResponse initHandshake(in byte[] clientPublicKey);
    /**
     * Return the nonce for a common shared session key and the session key
     * encrypted TPM seed.
     * The session key is derived from the pairing key, plus the client nonce
     * and the returned nonce.
     */
    SessionResponse newSession(in byte[] clientNonce);
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
     * Create an enroll session for a given pair of (sensor, user).
     * A nonce and a session counter will be returned, along with the
     * associated MAC. The details of the MAC computation is up to the
     * agreement between FingerGuard and its client.
     *
     * The challenge in the provided HAT must match the recorded challenge for
     * the same (senor, user) pair and must not exceeds the timeout.
     */
    PrepareEnrollSessionResponse prepareEnrollSession(in SensorUserPair sensorUserPair, in HardwareAuthToken hat);
    /**
     * Finish a created enroll session.
     * The associated AuthenticatorID will be updated with a successful
     * enrollment.
     */
    void finishEnrollSession(in SensorUserPair sensorUserPair, in EnrollmentResult result);
    /**
     * Create an auth session for a given pair of (sensor, user).
     * A nonce and a session counter will be returned, along with the
     * associated MAC. The details of the MAC computation is up to the
     * agreement between FingerGuard and its client.
     */
    PrepareAuthSessionResponse prepareAuthSession(in SensorUserPair sensorUserPair, in long challenge);
    /**
     * Finish a created auth session.
     * If the authentication succeeds, return a valid auth token contains
     * the challenge in prepareAuthSession. Otherwise, return an empty token.
     */
    HardwareAuthToken finishAuthSession(in SensorUserPair sensorUserPair, in AuthenticationResult result);
    /**
     * Return the AuthenticatorId associated with the (sensor, user) pair.
     */
    long getAuthenticatorId(in SensorUserPair sensorUserPair);
    /**
     * Return a newly generated AuthenticatorId associated with the
     * (sensor, user) pair.
     */
    long newAuthenticatorId(in SensorUserPair sensorUserPair);
    /*
     * Returns the lockout info associated with the (sensor, user) pair.
     */
    LockoutStatus getLockoutStatus(in SensorUserPair sensorUserPair);
    /*
     * Resets the lockout state associated with the (sensor, user) pair.
     */
    void resetLockout(in SensorUserPair sensorUserPair, in HardwareAuthToken hat);
}
