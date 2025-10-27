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

package android.desktop.security.keymint_provisioning;

interface IKeyMintProvisioning {

    /** Error parsing a certificate into DER format */
    const int ERROR_PARSE_CERTIFICATE_FAILED = 1;

    /** Error preparing certificate verification */
    const int ERROR_CERTIFICATE_PREPARATION_FAILED = 2;

    /** Error verifying certificate */
    const int ERROR_CERTIFICATE_VERIFICATION_FAILED = 3;

    /**
     * Certificate verification was successful, but the chain did not verify
     * in the order provided.
     */
    const int ERROR_CERTIFICATE_VERIFICATION_UNSUCCESSFUL = 4;

    /** Certificate extension encoding attestation IDs could not be found. */
    const int ERROR_CERTIFICATE_EXTENSION_MISSING = 5;

    /** One of the required attestation identity fields was not encoded in the extension. */
    const int ERROR_IDENTITY_FIELD_MISSING = 6;

    /** SetAttestationIds call through the KeyMintSecureLegacyClient failed. */
    const int ERROR_SET_ATTESTATION_IDS_FAILED = 7;

    /**
     * Requests the UDS certificates from the KeyMint secure legacy client, and
     * verifies the certificate chain was issued by the root CA.
     *
     * @return the status of the provisioned UDS certificate chain.
     */
    boolean isUdsCertificateChainProvisioned();

    /**
     * Appends a certificate to the product identity certificates stored in
     * KeyMint secure storage.
     */
    void appendProductIdentityCertificate(in byte[] data);

    /**
     * Clears the product identity certificates in the KeyMint secure storage.
     */
    void clearProductIdentityCertificateChain();
}
