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

package vendor.google.pinweaver;

/**
 * Distinguishes IDs for different PinWeaver clients from each other, so they don't conflict.
 * Each `(set, id)` tuple identifies a unique leaf in PinWeaver.
 */
enum LeafSet {
    /**
     * Selects all leaves at once. Only valid to specify when no `id` is provided.
     *
     * If a LeafId is used with this set, it will be rejected with EX_ILLEGAL_ARGUMENT.
     */
    ALL_LEAVES = 0,

    /** Leaves for Gatekeeper. The `id` corresponds to a user ID. */
    GATEKEEPER = 1,

    /** Leaves for Weaver. The `id` is a Weaver slot number, starting from 0. */
    WEAVER = 2,

    /** Leaves for KeyMint. The `id` is an opaque identifier for various device secrets. */
    KEYMINT = 3,
}
