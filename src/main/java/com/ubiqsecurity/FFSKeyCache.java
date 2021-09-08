package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
 
import com.google.gson.annotations.SerializedName;

public class FFSKeyCache  {
    private boolean verbose= true;
    public LoadingCache<String, FFS_KeyRecord> FFSKeyCache;
    




    public FFSKeyCache(UbiqWebServices ubiqWebServices, FFS_Record ffs, String ffs_name) {
        
        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFSKeyCache = 
            CacheBuilder.newBuilder()
            .maximumSize(100)                               // maximum 100 records can be cached
            .expireAfterAccess(30, TimeUnit.MINUTES)        // cache will expire after 30 minutes of access
            .build(new CacheLoader<String, FFS_KeyRecord>() {  // build the cacheloader
                @Override
                public FFS_KeyRecord load(String cachingKey) throws Exception {
                   //make the expensive call
                   return getFFSKeyFromCloudAPI(ubiqWebServices, cachingKey, ffs, ffs_name);   // <AccessKeyId>-<FFS Name> 
                } 
         });
    }


    // clear the cache entirely
    public void invalidateAllCache() {
        FFSKeyCache.invalidateAll(); 
    }

    
    
    // called when Key data is not in cache and need to make remote call
    private  FFS_KeyRecord getFFSKeyFromCloudAPI(UbiqWebServices ubiqWebServices, String cachingKey, FFS_Record ffs, String ffs_name) {
        FPEKeyResponse ffsKeyRecordResponse;
        
        if (verbose) System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getFFSKeyFromCloudAPI for caching key: " + cachingKey);
        
        
        int key_number_loc= cachingKey.lastIndexOf("-key_number=");
        if (key_number_loc > 0 ) {
            if (verbose) System.out.println("DOING DECRYPT");
            String key_number = cachingKey.substring(key_number_loc + "-key_number=".length());
            if (verbose) System.out.println("     key_number: " + key_number);
            ffsKeyRecordResponse= ubiqWebServices.getFPEDecryptionKey(ffs_name, Integer.parseInt(key_number)); 
        } else {
            if (verbose) System.out.println("DOING ENCRYPT");
            ffsKeyRecordResponse= ubiqWebServices.getFPEEncryptionKey(ffs, ffs_name); 
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






