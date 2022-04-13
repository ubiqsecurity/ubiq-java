package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
import com.google.gson.annotations.SerializedName;



/**
 * Caches key information to minimize access to the server.
 */
class FFSKeyCache  {
    private boolean verbose= false;
    public LoadingCache<FFS_KeyId, FFS_KeyRecord> FFSKeyCache; // The KeyId is the FFS_NAME and optional KEY-number


    /**
     * FFSKeyCache constructor
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param ffs  The FFS record model
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     *
     */
    public FFSKeyCache(UbiqWebServices ubiqWebServices) {

        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFSKeyCache =
            CacheBuilder.newBuilder()
            .maximumSize(100)                               // maximum 100 records can be cached
            .expireAfterAccess(24 * 60 * 3, TimeUnit.MINUTES)        // cache will expire after 30 minutes of access
            .build(new CacheLoader<FFS_KeyId, FFS_KeyRecord>() {  // build the cacheloader
                @Override
                public FFS_KeyRecord load(FFS_KeyId keyId) throws Exception {
                   //make the expensive call
                   return getFFSKeyFromCloudAPI(ubiqWebServices, keyId);   // <AccessKeyId>-<FFS Name>
                }
         });
    }


    /**
    * Clears the encryption key cache
    *
    */
    public void invalidateAllCache() {
        FFSKeyCache.invalidateAll();
    }



    /**
     * Called when Key data is not in cache and need to make remote call to the server
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param cachingKey  Format <AccessKeyId>-<FFS Name> used as the record locator
     * @param ffs  The FFS record model
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     *
     */
    private  FFS_KeyRecord getFFSKeyFromCloudAPI(UbiqWebServices ubiqWebServices, FFS_KeyId keyId) {
        FPEKeyResponse ffsKeyRecordResponse;

        if (verbose) System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getFFSKeyFromCloudAPI for caching key: " + keyId.ffs_name + " " + keyId.key_number);

        if (keyId.key_number != null) {
            if (verbose) System.out.println("getFFSKeyFromCloudAPI DOING DECRYPT");
            if (verbose) System.out.println("     key_number: " + keyId.key_number);
            if (verbose) System.out.println("     ffs_name: " + keyId.ffs_name);
            ffsKeyRecordResponse= ubiqWebServices.getFPEDecryptionKey(keyId.ffs_name, keyId.key_number);
        } else {
            if (verbose) System.out.println("getFFSKeyFromCloudAPI DOING ENCRYPT");
            if (verbose) System.out.println("     ffs_name: " + keyId.ffs_name);
            ffsKeyRecordResponse= ubiqWebServices.getFPEEncryptionKey(keyId.ffs_name);
        }


        String jsonStr= "{}";
        Gson gson = new Gson();
        FFS_KeyRecord ffsKey = gson.fromJson(jsonStr, FFS_KeyRecord.class);

        if ((ffsKeyRecordResponse.EncryptedPrivateKey == null) || (ffsKeyRecordResponse.WrappedDataKey == null)) {
            if (verbose) System.out.println("Missing keys in FPEKey definition.");
        } else {
            ffsKey.setEncryptedPrivateKey(ffsKeyRecordResponse.EncryptedPrivateKey);
            ffsKey.setWrappedDataKey(ffsKeyRecordResponse.WrappedDataKey);
            ffsKey.setKeyNumber(ffsKeyRecordResponse.KeyNumber);
        }
        return ffsKey;
    }


}

/**
 * Representation of the JSON record for the key data
 */
class FFS_KeyRecord {

    String EncryptedPrivateKey;
    String WrappedDataKey;
    int KeyNumber;


	public String getEncryptedPrivateKey() {
		return EncryptedPrivateKey;
	}
	public void setEncryptedPrivateKey(String EncryptedPrivateKey) {
		this.EncryptedPrivateKey = EncryptedPrivateKey;
	}

	public String getWrappedDataKey() {
		return WrappedDataKey;
	}
	public void setWrappedDataKey(String WrappedDataKey) {
		this.WrappedDataKey = WrappedDataKey;
	}

	public int getKeyNumber() {
		return KeyNumber;
	}
	public void setKeyNumber(int KeyNumber) {
		this.KeyNumber = KeyNumber;
	}
}

class FFS_KeyId {
  Integer key_number;
  String ffs_name;

  FFS_KeyId(String name, Integer number) {
    ffs_name = name;
    key_number = number; // May be NULL - indicating an encrypt
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + ((ffs_name != null) ? ffs_name.hashCode() : 0);
    result = 31 * result + ((key_number != null) ? key_number.hashCode() : 0);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    final FFS_KeyId other = (FFS_KeyId) obj;
    if (this.ffs_name != other.ffs_name) {
        return false;
    } else return (this.key_number == other.key_number);
  }

}
