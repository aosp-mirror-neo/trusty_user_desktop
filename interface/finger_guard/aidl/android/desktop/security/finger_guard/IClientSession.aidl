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

import android.desktop.security.finger_guard.AuthenticationResult;
import android.desktop.security.finger_guard.EnrollmentResult;
import android.desktop.security.finger_guard.FinishEnrollSessionResponse;
import android.desktop.security.finger_guard.HardwareAuthToken;
import android.desktop.security.finger_guard.PrepareAuthSessionResponse;
import android.desktop.security.finger_guard.PrepareEnrollSessionResponse;
import android.desktop.security.finger_guard.SensorUserPair;

@VintfStability
interface IClientSession {
    /**
     * Create an enroll session for a given pair of (sensor, user).
     * A MAC over the user id and the nonce will be returned.
     *
     * The challenge in the provided HAT must match a previously generated
     * challenge for the same (senor, user) pair and must not exceeds the
     * timeout.
     */
    PrepareEnrollSessionResponse prepareEnrollSession(in SensorUserPair sensorUserPair, in HardwareAuthToken hat, in byte[32] nonce);
    /**
     * Finish a created enroll session.
     * A MAC over the user id and the nonce will be returned.
     * The associated AuthenticatorID will be updated with a successful
     * enrollment.
     */
    FinishEnrollSessionResponse finishEnrollSession(in SensorUserPair sensorUserPair, in EnrollmentResult result, in byte[32] nonce);
    /**
     * Create an auth session for a given pair of (sensor, user).
     * A MAC over the user id and the nonce will be returned.
     * |hatChallenge| should be returned in the HardwareAuthToken when the
     * authentication succeeds.
     */
    PrepareAuthSessionResponse prepareAuthSession(in SensorUserPair sensorUserPair, in long hatChallenge, in byte[32] nonce);
    /**
     * Finish a created auth session.
     * If the authentication succeeds, return a valid auth token contains
     * the challenge in prepareAuthSession. Otherwise, return an empty token.
     */
    HardwareAuthToken finishAuthSession(in SensorUserPair sensorUserPair, in AuthenticationResult result);
}
