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
    private String encryption_algorithm;   //e.g. FF1 or FF3_1
    private String user;
    private String customer;
    private String name;   //e.g."SSN",
    private String regex;   //e.g. "(\d{3})-(\d{2})-(\d{4})",
    private String tweak_source;   //e.g. "generated",
    private long min_input_length;   //e.g. 9 
    private long max_input_length;   //e.g. 9
    private boolean fpe_definable;
    //public LoadingCache<String, FFS_Record> FFSCache;
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



    
    

    
    
    // called when FFS is not in cache and need to make remote call
    //private  FFS_Record getFFSFromCloudAPI(UbiqWebServices ubiqWebServices, String cachingKey, String ffs_name) {
    private  FFS_EncryptionKeyRecord getFFSEncryptionKeyFromCloudAPI(UbiqWebServices ubiqWebServices, String cachingKey, FFS_Record ffs, String ffs_name) {

        if (verbose) System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getFFSEncryptionKeyFromCloudAPI for caching key: " + cachingKey);
        
//         FFSEncryptionKeyRecordResponse ffsEncryptionKeyRecordResponse;
//         ffsEncryptionKeyRecordResponse= ubiqWebServices.getFFSDefinition(ffs_name);
        EncryptionKeyResponse ffsEncryptionKeyRecordResponse= ubiqWebServices.getFPEEncryptionKey(ffs, ffs_name); 
         
        
        // STUB - populate FFS_Record with default values if missing from backend FFS definition
        //    Some of these would be mandatory and should report an exception
        String jsonStr= "{}";                
        Gson gson = new Gson();        
        FFS_EncryptionKeyRecord ffsEncrypt = gson.fromJson(jsonStr, FFS_EncryptionKeyRecord.class);        
         

        if (ffsEncryptionKeyRecordResponse.UnwrappedDataKey == null) {
            if (verbose) System.out.println("Missing UnwrappedDataKey in FPEEncryptionKey definition.");
            //ffs.setAlgorithm("FF1");
        } else {
            ffsEncrypt.setUnwrappedDataKey(ffsEncryptionKeyRecordResponse.UnwrappedDataKey);
        }


          
        return ffsEncrypt;
    }
    
    
    
}    





class FFS_EncryptionKeyRecord {

    private byte[] UnwrappedDataKey;



	public byte[] getUnwrappedDataKey() {
		return UnwrappedDataKey;
	}
	public void setUnwrappedDataKey(byte[] UnwrappedDataKey) {
		this.UnwrappedDataKey = UnwrappedDataKey;
	}
	
} 






