package com.ubiqsecurity;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

class DecryptionKeyResponse {
    @SerializedName("encrypted_private_key")
    String EncryptedPrivateKey;

    @SerializedName("wrapped_data_key")
    String WrappedDataKey;

    // not serialized - used only at runtime
    @Expose(serialize = false, deserialize = false)
    byte[] UnwrappedDataKey;

    @Override
    public int hashCode() {
      int result = 17;
      result = 31 * result + ((WrappedDataKey != null) ? WrappedDataKey.hashCode() : 0);
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (obj == null) return false;
      if (getClass() != obj.getClass()) return false;
      final DecryptionKeyResponse other = (DecryptionKeyResponse) obj;

      return (this.hashCode() == other.hashCode());
    }

}
