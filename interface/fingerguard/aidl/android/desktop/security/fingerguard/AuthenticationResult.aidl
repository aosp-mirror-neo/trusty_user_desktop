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

/**
 * AuthenticationResult represents an attested authentication result.
 */
parcelable AuthenticationResult {
    boolean authenticated;
    /**
     * The MAC attests the authentication result.
     * If authenticated = true:
     * The MAC is a 32 bytes HMAC-SHA256, signed with the session key
     * over the following string:
     *         nonce || user_id || sensor_name || "auth" || session_counter
     * where ``||'' represents concatenation; nonce, user_id,
     * and session_counter are obtained from a previous prepareAuthSession
     * request and response; sensor_name is the name of the sensor stack,
     * e.g. "fpmcu".
     *
     * If authenticated = false: the MAC is empty.
     */
    byte[] mac;
}


