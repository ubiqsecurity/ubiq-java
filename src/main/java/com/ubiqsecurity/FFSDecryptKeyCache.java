package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
 
import com.google.gson.annotations.SerializedName;

public class FFSDecryptKeyCache  {
    private boolean verbose= true;
    public LoadingCache<String, FFS_DecryptionKeyRecord> FFSDecryptionKeyCache;




    public FFSDecryptKeyCache(UbiqWebServices ubiqWebServices, String ffs_name, int key_number) {
        
        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFSDecryptionKeyCache = 
            CacheBuilder.newBuilder()
            .maximumSize(100)                               // maximum 100 records can be cached
            .expireAfterAccess(30, TimeUnit.MINUTES)        // cache will expire after 30 minutes of access
            .build(new CacheLoader<String, FFS_DecryptionKeyRecord>() {  // build the cacheloader
                @Override
                public FFS_DecryptionKeyRecord load(String cachingKey) throws Exception {
                   //make the expensive call
                   return getFFSDecryptionKeyFromCloudAPI(ubiqWebServices, cachingKey, ffs_name, key_number);   // <AccessKeyId>-<FFS Name> 
                } 
         });
    }


    // clear the cache entirely
    public void invalidateAllCache() {
        FFSDecryptionKeyCache.invalidateAll(); 
    }

 
    
    
    // called when FFS is not in cache and need to make remote call
    private  FFS_DecryptionKeyRecord getFFSDecryptionKeyFromCloudAPI(UbiqWebServices ubiqWebServices, String cachingKey, String ffs_name, int key_number) {

        if (verbose) System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getFFSDecryptionKeyFromCloudAPI for caching key: " + cachingKey);
        
        DecryptionKeyResponse ffsDecryptionKeyRecordResponse= ubiqWebServices.getFPEDecryptionKey(ffs_name, key_number); 
     
        String jsonStr= "{}";                
        Gson gson = new Gson();        
        FFS_DecryptionKeyRecord ffsDecrypt = gson.fromJson(jsonStr, FFS_DecryptionKeyRecord.class);        
        
        if ((ffsDecryptionKeyRecordResponse.EncryptedPrivateKey == null) || (ffsDecryptionKeyRecordResponse.WrappedDataKey == null)) { 
        //if (ffsDecryptionKeyRecordResponse.UnwrappedDataKey == null) {
            if (verbose) System.out.println("Missing keys in FPEDecryptionKey definition.");
            //ffsDecrypt.setAlgorithm("FF1");
        } else {
            ffsDecrypt.setEncryptedPrivateKey(ffsDecryptionKeyRecordResponse.EncryptedPrivateKey); 
            ffsDecrypt.setWrappedDataKey(ffsDecryptionKeyRecordResponse.WrappedDataKey); 
        }
        return ffsDecrypt;
    }
    
    
    
}    






class FFS_DecryptionKeyRecord {
    String EncryptedPrivateKey;
    String WrappedDataKey;
    
    
    
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
	
	
} 