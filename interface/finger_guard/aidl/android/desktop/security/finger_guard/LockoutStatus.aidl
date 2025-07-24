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

// Represents the authenticator status for each (sensor, user) pair.
union LockoutStatus {
    // Indicates the sensor is not locked out.
    parcelable Available {}
    // Indicates the senor is permanently locked out and requires reset.
    parcelable PermanentLockout {}
    // Indicates the senor is temporarily locked out with a timer.
    parcelable TimedLockout {
        // The time to be elapsed before the sensor becomes available.
        long durationMillis;
    }
    Available available;
    PermanentLockout permanentLockout;
    TimedLockout timedLockout;
}
