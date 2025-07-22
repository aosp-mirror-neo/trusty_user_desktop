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

parcelable PrepareEnrollSessionResponse {
    /**
     * The MAC is a 32 bytes HMAC-SHA256 with the session key over the
     * following string:
     *         nonce || user_id || ta_name || "enroll"
     *
     * where ``||'' represents concatenation; nonce and user_id are
     * from the input of PrepareEnrollSession, ta_name is the public name
     * identifying the FingerGuard TA, i.e. "fingerguard".
     */
    byte[] mac;
}


