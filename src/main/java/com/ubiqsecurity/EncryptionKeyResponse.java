/*
 * Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains the property
 * of Ubiq Security, Inc. The intellectual and technical concepts contained
 * herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
 * covered by U.S. and Foreign Patents, patents in process, and are
 * protected by trade secret or copyright law. Dissemination of this
 * information or reproduction of this material is strictly forbidden
 * unless prior written permission is obtained from Ubiq Security, Inc.
 *
 * Your use of the software is expressly conditioned upon the terms
 * and conditions available at:
 *
 *     https://ubiqsecurity.com/legal
 *
 */

package com.ubiqsecurity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

class EncryptionKeyResponse {
    @SerializedName("encrypted_private_key")
    String EncryptedPrivateKey;

    @SerializedName("encryption_session")
    String EncryptionSession;

    @SerializedName("key_fingerprint")
    String KeyFingerprint;

    @SerializedName("security_model")
    SecurityModel SecurityModel;

    @SerializedName("max_uses")
    int MaxUses;

    @SerializedName("wrapped_data_key")
    String WrappedDataKey;

    @SerializedName("encrypted_data_key")
    String EncryptedDataKey;

    // not serialized - used only at runtime
    @Expose(serialize = false, deserialize = false)
    int Uses;

    // not serialized - used only at runtime
    @Expose(serialize = false, deserialize = false)
    byte[] UnwrappedDataKey;

    // not serialized - used only at runtime
    @Expose(serialize = false, deserialize = false)
    byte[] EncryptedDataKeyBytes;
}
