package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
 
import com.google.gson.annotations.SerializedName;

public class FFSEncryptKeyCache  {
    private boolean verbose= true;
    public LoadingCache<String, FFS_EncryptionKeyRecord> FFSEncryptionKeyCache;
    




    public FFSEncryptKeyCache(UbiqWebServices ubiqWebServices, FFS_Record ffs, String ffs_name) {
        
        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFSEncryptionKeyCache = 
            CacheBuilder.newBuilder()
            .maximumSize(100)                               // maximum 100 records can be cached
            .expireAfterAccess(30, TimeUnit.MINUTES)        // cache will expire after 30 minutes of access
            .build(new CacheLoader<String, FFS_EncryptionKeyRecord>() {  // build the cacheloader
                @Override
                public FFS_EncryptionKeyRecord load(String cachingKey) throws Exception {
                   //make the expensive call
                   return getFFSEncryptionKeyFromCloudAPI(ubiqWebServices, cachingKey, ffs, ffs_name);   // <AccessKeyId>-<FFS Name> 
                } 
         });
    }


    // clear the cache entirely
    public void invalidateAllCache() {
        FFSEncryptionKeyCache.invalidateAll(); 
    }

    
    
    // called when FFS is not in cache and need to make remote call
    //private  FFS_Record getFFSFromCloudAPI(UbiqWebServices ubiqWebServices, String cachingKey, String ffs_name) {
    private  FFS_EncryptionKeyRecord getFFSEncryptionKeyFromCloudAPI(UbiqWebServices ubiqWebServices, String cachingKey, FFS_Record ffs, String ffs_name) {

        if (verbose) System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getFFSEncryptionKeyFromCloudAPI for caching key: " + cachingKey);
        
        EncryptionKeyResponse ffsEncryptionKeyRecordResponse= ubiqWebServices.getFPEEncryptionKey(ffs, ffs_name); 
         
        String jsonStr= "{}";                
        Gson gson = new Gson();        
        FFS_EncryptionKeyRecord ffsEncrypt = gson.fromJson(jsonStr, FFS_EncryptionKeyRecord.class);        
         
        if ((ffsEncryptionKeyRecordResponse.EncryptedPrivateKey == null) || (ffsEncryptionKeyRecordResponse.WrappedDataKey == null)) {
            if (verbose) System.out.println("Missing keys in FPEEncryptionKey definition.");
            //ffs.setAlgorithm("FF1");
        } else {
            ffsEncrypt.setEncryptedPrivateKey(ffsEncryptionKeyRecordResponse.EncryptedPrivateKey); 
            ffsEncrypt.setWrappedDataKey(ffsEncryptionKeyRecordResponse.WrappedDataKey); 
        }
        return ffsEncrypt;
    }
    
    
}    





class FFS_EncryptionKeyRecord {

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






