package com.ubiqsecurity;

import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;

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


    /**
     * FFXCache constructor
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param ffs  The FFS record model
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     *
     */
    public FFXCache(UbiqWebServices ubiqWebServices) {

        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFXCache =
            CacheBuilder.newBuilder()
            .maximumSize(1000)                               // maximum 1000 records can be cached
            .expireAfterAccess(24 * 60 * 3, TimeUnit.MINUTES)        // cache will expire after 3 days
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

        FPEKeyResponse ffsKeyRecordResponse;

        if (verbose) System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getFFSKeyFromCloudAPI for caching key: " + keyId.ffs.getName() + " " + keyId.key_number);

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


        String jsonStr= "{}";
        Gson gson = new Gson();
        byte[] tweak = null;

        FFS_KeyRecord ffsKey = gson.fromJson(jsonStr, FFS_KeyRecord.class);

        if ((ffsKeyRecordResponse.EncryptedPrivateKey == null) || (ffsKeyRecordResponse.WrappedDataKey == null)) {
            if (verbose) System.out.println("Missing keys in FPEKey definition.");
        } else {
            // ffsKeyRecordResponse.EncryptedPrivateKey;
            // ffsKeyRecordResponse.WrappedDataKey;
            //ffsKeyRecordResponse.KeyNumber;
            byte[] key = ubiqWebServices.getUnwrappedKey(ffsKeyRecordResponse.EncryptedPrivateKey, ffsKeyRecordResponse.WrappedDataKey);

            if (keyId.ffs.getTweak_source().equals("constant")) {
              tweak= Base64.getDecoder().decode(keyId.ffs.getTweak());
            }

            switch(keyId.ffs.getAlgorithm()) {
              case "FF1":
                  if (verbose) System.out.println("    twkmin= " + keyId.ffs.getMin_tweak_length() + "    twkmax= " + keyId.ffs.getMax_tweak_length() +   "    tweak.length= " + keyId.ffs.getTweak().length() +   "    key.length= " + key.length );
                  ctx.setFF1(new FF1(key, tweak, 
                  keyId.ffs.getMin_tweak_length(), 
                  keyId.ffs.getMax_tweak_length(), 
                  keyId.ffs.getInput_character_set().length(), keyId.ffs.getInput_character_set()), 
                  ffsKeyRecordResponse.KeyNumber);
              break;
              case "FF3_1":
                  ctx.setFF3_1(new FF3_1(key, 
                    tweak,
                    keyId.ffs.getInput_character_set().length(), keyId.ffs.getInput_character_set()),
                    ffsKeyRecordResponse.KeyNumber);
              break;
              default:
                  throw new RuntimeException("Unknown FPE Algorithm: " + keyId.ffs.getAlgorithm());
          }



        }
        return ctx;
    }


}

/**
 * Representation of the JSON record for the key data
 */
class FFS_KeyRecord2 {

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

class FFX_Ctx {
  protected FF1 ctxFF1;
  protected FF3_1 ctxFF3_1;
  protected Integer key_number;


  public FF1 getFF1() {
    return ctxFF1;
  }

  public void setFF1(FF1 ctxFF1, Integer key_number) {
    this.ctxFF1 = ctxFF1;
    this.key_number = key_number;
  }

  public FF3_1 getFF3_1() {
    return ctxFF3_1;
  }

  public void setFF3_1(FF3_1 ctxFF3_1, Integer key_number) {
    this.ctxFF3_1 = ctxFF3_1;
    this.key_number = key_number;
  }

  public int getKeyNumber() {
		return key_number;
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
  FFS_Record ffs;

  FFS_KeyId(FFS_Record ffs, Integer number) {
    this.ffs = ffs;
    this.key_number = number; // May be NULL - indicating an encrypt
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + ((ffs != null && ffs.getName() != null) ? ffs.getName().hashCode() : 0);
    result = 31 * result + ((key_number != null) ? key_number.hashCode() : 0);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    final FFS_KeyId other = (FFS_KeyId) obj;
    if (((this.ffs == null) == (other.ffs == null)) && (this.ffs == null)) return false;
    if (this.ffs.getName() != other.ffs.getName()) {
        return false;
    } else return (this.key_number == other.key_number);
  }

}
