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
 * An entry in the delay schedule table, configuring rate limiting for a leaf.
 *
 * If attempt #N fails, the entry with the smallest attemptCount ≥ N indicates how long to wait
 * before another authentication attempt is allowed.
 *
 * If there are no entries, rate limiting is disabled for this leaf.
*/
@FixedSize
parcelable DelayScheduleEntry {
    /** The number of previous successive failed auth attempts before this entry is considered. */
    int attemptCount;

    /** The number of seconds to block authentication after this attempt count is reached. */
    int delaySecs;
}
