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
