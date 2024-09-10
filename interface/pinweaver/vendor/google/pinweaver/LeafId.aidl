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

import vendor.google.pinweaver.LeafSet;

/**
 * Identifies a leaf entry in PinWeaver.
 */
@FixedSize
parcelable LeafId {
    /**
     * The set of IDs to consider.
     *
     * The default is not valid for a LeafId and must be changed before use.
     */
    LeafSet leafSet = LeafSet.ALL_LEAVES;

    /** Distinguishes leaves for this leaf set, selected by the client of this API. */
    int id;
}
