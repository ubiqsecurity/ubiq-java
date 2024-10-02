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
 * Caches key information to minimize access to the server.
 */
class UnstructuredKeyCache  {
    private boolean verbose= false;
    public LoadingCache<String, DecryptionKeyResponse> unstructuredCache; // The KeyId is the FFS_NAME and optional KEY-number


    /**
     * UnstructuredKeyCache constructor
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param configuration used to control caching behavior
     *
     */
    public UnstructuredKeyCache(UbiqWebServices ubiqWebServices, UbiqConfiguration configuration) {

        // If we want to cache unstructured keys, then use the TTL.
        // If we don't want to cache unstructured keys, then set TTL to 0 second so it 
        // will be purged after it is used once

        Integer ttl = configuration.getKeyCacheTtlSeconds();
        if (!configuration.getKeyCacheUnstructuredKeys()) {
          ttl = 0;
        }

        if (verbose) System.out.println("ttl: " + ttl);

        //create a cache for unstructured data encryption keys.
        unstructuredCache =
            CacheBuilder.newBuilder()
            .maximumSize(1000)                               // maximum 1000 records can be cached
            .expireAfterWrite(ttl, TimeUnit.SECONDS)        // cache will expire after 3 days
            .build(new CacheLoader<String, DecryptionKeyResponse>() {  // build the cacheloader
                @Override
                public DecryptionKeyResponse load(String base64EncryptedDataKey) throws Exception {
                   //make the expensive call
                   return getUnstructuredKeyFromCloudAPI(ubiqWebServices, configuration, base64EncryptedDataKey);   // <AccessKeyId>-<FFS Name>
                }
         });
    }


    /**
    * Clears the encryption key cache
    *
    */
    public void invalidateAllCache() {
      unstructuredCache.invalidateAll();
    }

    /**
     * Called when Key data is not in cache and need to make remote call to the server
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param configuration  used to control caching behavior
     * @param encryptedDataKey  the encrypted data key to decrypt
     *
     */
    private  DecryptionKeyResponse getUnstructuredKeyFromCloudAPI(UbiqWebServices ubiqWebServices, UbiqConfiguration configuration, String base64EncryptedDataKey) {

        if (verbose) System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getDecryptionKey for caching key: " );

        byte[] encryptedDataKey = Base64.getDecoder().decode(base64EncryptedDataKey);
        DecryptionKeyResponse decryptionKeyResponse= ubiqWebServices.getDecryptionKey(encryptedDataKey);

        // Should the key be stored in the cache decrypted or not?
        if (!configuration.getKeyCacheEncryptKeys()) {
          decryptionKeyResponse.UnwrappedDataKey = ubiqWebServices.getUnwrappedKey(decryptionKeyResponse.EncryptedPrivateKey, decryptionKeyResponse.WrappedDataKey);
        }
        return decryptionKeyResponse;
    }


}


