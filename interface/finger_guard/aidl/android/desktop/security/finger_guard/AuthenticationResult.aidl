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

/**
 * AuthenticationResult represents an attested authentication result.
 */
@VintfStability
parcelable AuthenticationResult {
    boolean authenticated;
    /**
     * The MAC attests the authentication result.
     * If authenticated = true:
     * The MAC is a 32 bytes HMAC-SHA256, signed with the session key
     * over the following string:
     *         challenge || user_id || fpmcu_name || "auth"
     * where ``||'' represents concatenation; challenge is from a previous
     * PrepareAuthSessionResponse; user_id is from the input of a previous
     * PrepareAuthSession call. fpmcu_name is the name of the sensor MCU,
     * e.g. "fpmcu".
     *
     * If authenticated = false: the MAC is empty.
     */
    byte[32] mac;
}
