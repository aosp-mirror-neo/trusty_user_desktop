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

@VintfStability
parcelable SdcpClaim {
    /**
     * Client side nonce for session key derivation.
     */
    byte[32] nonce;

    /**
     * Per-model public key pk_m: 65-byte uncompressed point representation.
     */
    byte[65] modelPublicKey;

    /**
     * 64-byte ECDSA signature produced by Google owned key signer on per-model
     * public key.
     *
     * modelKeySignature = Sign(sk_goog, SHA256(pk_m))
     * The signature are a pair of 32-byte integer.
     */
    byte[64] modelKeySignature;

    /**
     * Per-device public key pk_d : 65-byte uncompressed representation.
     */
    byte[65] devicePublicKey;

    /**
     * 64-byte ECDSA signature produced by per-model private key on per-device
     * public key.
     *
     * deviceKeySignature = Sign(sk_m, SHA256(pk_d))
     * The signature are a pair of 32-byte integer.
     */
    byte[64] deviceKeySignature;

    /**
     * Per-boot ephemeral public key pk_f : 65-byte uncompressed representation.
     */
    byte[65] ephemeralPublicKey;

    /**
     * SHA256 hash of RO firmware, h_f.
     */
    byte[32] firmwareHash;

    /**
     * 64-byte ECDSA signature produced by per-device private key on firmwareHash
     * and ephemeralPublicKey.
     *
     * firmwareSignature = Sign(sk_d, SHA256( 0xC001 || h_f || pk_f))
     * The signature are a pair of 32-byte integer.
     */
    byte[64] firmwareSignature;
}

