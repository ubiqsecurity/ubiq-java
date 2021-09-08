package com.ubiqsecurity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

class FPEKeyResponse {
    @SerializedName("encrypted_private_key")
    String EncryptedPrivateKey;

    @SerializedName("wrapped_data_key")
    String WrappedDataKey;

    @SerializedName("key_number")
    int KeyNumber;

}
