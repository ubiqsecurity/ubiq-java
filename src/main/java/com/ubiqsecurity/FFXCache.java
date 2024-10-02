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
class FFXCache  {
    private boolean verbose= false;
    public LoadingCache<FFS_KeyId, FFX_Ctx> FFXCache; // The KeyId is the FFS_NAME and optional KEY-number
    private StructuredKeyCache keyCache;


    /**
     * FFXCache constructor
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param ffs  The FFS record model
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     *
     */
    public FFXCache(UbiqWebServices ubiqWebServices, UbiqConfiguration configuration) {


        keyCache = new StructuredKeyCache(ubiqWebServices, configuration);
        Integer ttl = configuration.getKeyCacheTtlSeconds();
        // If we aren't caching structured keys or if we are encrypting structured keys
        // set ttl to 0 to force recreating each time
        if (!configuration.getKeyCacheStructuredKeys() || configuration.getKeyCacheEncryptKeys()) {
          ttl = 0;
        }

        if (verbose) System.out.println(FFXCache.class.getName() + ": ttl - " + ttl);

        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFXCache =
            CacheBuilder.newBuilder()
            .maximumSize(1000)                               // maximum 1000 records can be cached
            .expireAfterWrite(ttl, TimeUnit.SECONDS)        // cache will expire after 3 days
            .build(new CacheLoader<FFS_KeyId, FFX_Ctx>() {  // build the cacheloader
                @Override
                public FFX_Ctx load(FFS_KeyId keyId) throws Exception {
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
      FFXCache.invalidateAll();
      keyCache.invalidateAll();
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
    private  FFX_Ctx getFFSKeyFromCloudAPI(UbiqWebServices ubiqWebServices, FFS_KeyId keyId) {
        FFX_Ctx ctx = new FFX_Ctx();

        if (verbose) System.out.println(FFXCache.class.getName() + " getFFSKeyFromCloudAPI");



        try {

          FPEKeyResponse ffsKeyRecordResponse = keyCache.structuredKeyCache.get(keyId);

          byte[] tweak = null;

          byte[] unwrappedDataKey = ffsKeyRecordResponse.UnwrappedDataKey;
          if (unwrappedDataKey.length == 0) {
            if (verbose) System.out.println(FFXCache.class.getName() + " unwrap");
            unwrappedDataKey = ubiqWebServices.getUnwrappedKey(ffsKeyRecordResponse.EncryptedPrivateKey, ffsKeyRecordResponse.WrappedDataKey);
          }

          if (keyId.ffs.getTweakSource().equals("constant")) {
            tweak= Base64.getDecoder().decode(keyId.ffs.getTweak());
          }

          switch(keyId.ffs.getEncryptionAlgorithm()) {
            case "FF1":
                if (verbose) System.out.println("    twkmin= " + keyId.ffs.getMinTweakLength() + "    twkmax= " + keyId.ffs.getMaxTweakLength() +   "    tweak.length= " + keyId.ffs.getTweak().length() +   "    unwrappedDataKey.length= " + unwrappedDataKey.length );
                ctx.setFF1(new FF1(unwrappedDataKey, tweak, 
                keyId.ffs.getMinTweakLength(), 
                keyId.ffs.getMaxTweakLength(), 
                keyId.ffs.getInputCharacterSet().length(), keyId.ffs.getInputCharacterSet()), 
                ffsKeyRecordResponse.KeyNumber);
            break;
            default:
                throw new RuntimeException("Unknown FPE Algorithm: " + keyId.ffs.getEncryptionAlgorithm());
          }
          return ctx;
        } catch (ExecutionException e) {
          e.printStackTrace();
          return null;
        }
    }


}

class FFX_Ctx {
  protected FF1 ctxFF1;
  protected Integer key_number;


  public FF1 getFF1() {
    return ctxFF1;
  }

  public void setFF1(FF1 ctxFF1, Integer key_number) {
    this.ctxFF1 = ctxFF1;
    this.key_number = key_number;
  }

  public int getKeyNumber() {
		return key_number;
	}

}