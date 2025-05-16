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
 * HardwareAuthToken mirrors the struct of hw_auth_token_t in hw_auth_token.h.
 */
parcelable HardwareAuthToken {
    // Current version is 0. No other values allowed.
    byte version = 0;

    long challenge;

    long userId;

    long authenticatorId;

    long authenticatorType = 0;

    long timestamp;

    /**
     * MACs are computed with a backward-compatible method, used by Keymaster 3.0, Gatekeeper 1.0
     * and Fingerprint 1.0, as well as pre-treble HALs.
     *
     * The MAC is a 32 bytes HMAC-SHA256 with the auth token signing key over the following string
     *         version || challenge || user_id || authenticator_id || authenticator_type || timestamp
     *
     * where ``||'' represents concatenation, the leading version is a single byte, and all integers
     * are represented as unsigned values, the full width of the type.  The challenge, userId and
     * authenticatorId values are in machine order, but authenticatorType and timestamp are in
     * network order (big-endian).  This odd construction is compatible with the hw_auth_token_t
     * structure,
     *
     * Note that mac can be empty indicates the auth token is not yet signed and not valid.
     */
    byte[] mac;
}
