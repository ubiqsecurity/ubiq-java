package com.ubiqsecurity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

class DecryptionKeyResponse {
    @SerializedName("encrypted_private_key")
    String EncryptedPrivateKey;

    @SerializedName("encryption_session")
    String EncryptionSession;

    @SerializedName("key_fingerprint")
    String KeyFingerprint;

    @SerializedName("wrapped_data_key")
    String WrappedDataKey;

    // not serialized - used only at runtime
    @Expose(serialize = false, deserialize = false)
    byte[] UnwrappedDataKey;

    // not serialized - used only at runtime
    @Expose(serialize = false, deserialize = false)
    int KeyUseCount;

    // not serialized - used only at runtime
    @Expose(serialize = false, deserialize = false)
    byte[] LastCipherHeaderEncryptedDataKeyBytes;
}
