package com.ubiqsecurity;

import com.ubiqsecurity.structured.FF1;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
import com.google.gson.annotations.SerializedName;
import java.util.Base64;



/**
 * Caches structured key information to minimize access to the server.
 * This cache will typically only be used when the structured data encryption keys 
 * are being cached encrypted.  If they are being used decrypted, then the 
 * FFXCache will already have what is needed and this cache may not be needed
 */
class StructuredKeyCache  {
    private boolean verbose= false;
    public LoadingCache<FFS_KeyId, FPEKeyResponse> structuredKeyCache; // The KeyId is the FFS_NAME and optional KEY-number


    /**
     * StructuredKeyCache constructor
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param ffs  The FFS record model
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     *
     */
    public StructuredKeyCache(UbiqWebServices ubiqWebServices, UbiqConfiguration configuration) {

        // If we want to cache structured keys, then use the TTL.
        // Otherwise set ttl to 0 so it is retrieved once and then discarded.

        Integer ttl = configuration.getKeyCacheTtlSeconds();
        if (!configuration.getKeyCacheStructuredKeys()) {
          ttl = 0;
        }

        if (verbose) System.out.println(StructuredKeyCache.class.getName() + ": ttl - " + ttl);

        //create a cache for FFS based on the <encryption_algorithm>-<name>
        structuredKeyCache =
            CacheBuilder.newBuilder()
            .maximumSize(1000)                               // maximum 1000 records can be cached
            .expireAfterWrite(ttl, TimeUnit.SECONDS)        // cache will expire after 3 days
            .build(new CacheLoader<FFS_KeyId, FPEKeyResponse>() {  // build the cacheloader
                @Override
                public FPEKeyResponse load(FFS_KeyId keyId) throws Exception {
                   //make the expensive call
                   return getFFSKeyFromCloudAPI(ubiqWebServices, configuration, keyId);   // <AccessKeyId>-<FFS Name>
                }
         });
    }


    /**
    * Clears the encryption key cache
    *
    */
    public void invalidateAll() {
      structuredKeyCache.invalidateAll();
    }

    /**
     * Called when Key data is not in cache and need to make remote call to the server
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param configuration used to control caching behavior
     * @param keyId  The dataset key identifier for the desired key
     *
     */
    private  FPEKeyResponse getFFSKeyFromCloudAPI(UbiqWebServices ubiqWebServices, 
        UbiqConfiguration configuration,
        FFS_KeyId keyId) {

        FPEKeyResponse ffsKeyRecordResponse;

        if (verbose) System.out.println(StructuredKeyCache.class.getName() + "\n****** PERFORMING EXPENSIVE CALL ----- getFFSKeyFromCloudAPI for caching key: " + keyId.ffs.getName() + " " + keyId.key_number);

        if (keyId.key_number != null) {
            if (verbose) System.out.println("getFFSKeyFromCloudAPI DOING DECRYPT");
            if (verbose) System.out.println("     key_number: " + keyId.key_number);
            if (verbose) System.out.println("     ffs_name: " + keyId.ffs.getName());
            ffsKeyRecordResponse= ubiqWebServices.getFPEDecryptionKey(keyId.ffs.getName(), keyId.key_number);
        } else {
            if (verbose) System.out.println("getFFSKeyFromCloudAPI DOING ENCRYPT");
            if (verbose) System.out.println("     ffs_name: " + keyId.ffs.getName());
            ffsKeyRecordResponse= ubiqWebServices.getFPEEncryptionKey(keyId.ffs.getName());
        }


        if ((ffsKeyRecordResponse.EncryptedPrivateKey == null) || (ffsKeyRecordResponse.WrappedDataKey == null)) {
            if (verbose) System.out.println("Missing keys in FPEKey definition.");
        } else {
          if (!configuration.getKeyCacheEncryptKeys()) {
          // Decrypt if we aren't storing encrypted  keys
            ffsKeyRecordResponse.UnwrappedDataKey = ubiqWebServices.getUnwrappedKey(ffsKeyRecordResponse.EncryptedPrivateKey, ffsKeyRecordResponse.WrappedDataKey);
          } else {
            ffsKeyRecordResponse.UnwrappedDataKey = new byte[0];
          }
        }

        return ffsKeyRecordResponse;
    }
}
