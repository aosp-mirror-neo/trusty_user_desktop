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

package android.system.desktop.security.gsc;

@VintfStability
interface IGsc {
    /**
     * Transmits a GSC command. The data size must be less than or equal to 4KB,
     * which the GSC firmware's limits.
     *
     * @param A serialized TPM 2.0 command to be sent to GSC.
     * @return a serialized TPM 2.0 response to the command. In case of error
     *         in communicating with the GSC, an empty vector is returned.
     */
    byte[] transmit(in byte[] data);
}
