package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;

import java.util.concurrent.ExecutionException;
 
 
 
 


public class FFS {
    private String encryption_algorithm;   //e.g. FF1 or FF3_1
    
    private String user;
    private String customer;
    private String name;   //e.g."SSN",
    private String regex;   //e.g. "(\d{3})-(\d{2})-(\d{4})",
    private String tweak_source;   //e.g. "generated",
    private int min_input_length;   //e.g. 9 
    private int max_input_length;   //e.g. 9
    private boolean fpe_definable;
    
    // cachingKey is in the format of <encryption_algorithm>-<name>
    //  and used to retrieve cached FFS record
    private String cachingKey;
    
    private Gson FFSdata;
    private LoadingCache<String, FFS> FFSCache;
    
    
    
    public FFS() {
        
        System.out.println("NEW OBJECT FFS");
        
        
        
        //create a cache for FFS based on the encryption_algorithm
        //LoadingCache<String, FFS> FFSCache =
        FFSCache = 
            CacheBuilder.newBuilder()
            .maximumSize(100)                             // maximum 100 records can be cached
            .expireAfterAccess(30, TimeUnit.MINUTES)      // cache will expire after 30 minutes of access
            .build(new CacheLoader<String, FFS>() {  // build the cacheloader

                @Override
                public FFS load(String cachingKey) throws Exception {
                   //make the expensive call
                   return getFFSFromCloudAPI(cachingKey);
                } 
         });
         
         
    }
    
    // called when FFS is not in cache and need to make remote call
    private  FFS getFFSFromCloudAPI(String encryption_algorithm) {
        
        FFS ffs = TEMP_getFFSdataFromCloud_1();
        
        System.out.println("----- getFFSFromCloudAPI");
        
        return ffs;
    }
    
    // STUB - Get fresh FFS data
    public FFS TEMP_getFFSdataFromCloud_1() {
        System.out.println("----- TEMP_getFFSdataFromCloud_1");
        
        
        // TODO - pull this data from an API call instead of hardcoding it here
        String jsonStr= "{'encryption_algorithm': 'FF1'}";
        Gson gson = FFSdata;        
        FFS ffs = gson.fromJson(jsonStr, FFS.class);
        
        ffs.setName("SSN");
        ffs.setRegex("(\\d{3})-(\\d{2})-(\\d{4})");
        ffs.setTweak_source("generated");
        ffs.setMin_input_length(9);
        ffs.setMax_input_length(9);
        ffs.setFpe_definable(true);
        
	    return ffs;
    }



    // STUB - Get fresh FFS data
    public FFS TEMP_getFFSdataFromCloud_2() {
        System.out.println("----- TEMP_getFFSdataFromCloud_2");
        
        
        // TODO - pull this data from an API call instead of hardcoding it here
        String jsonStr= "{'encryption_algorithm': 'FF3_1'}";
        Gson gson = FFSdata;        
        FFS ffs = gson.fromJson(jsonStr, FFS.class);
        
        ffs.setName("SSN");
        ffs.setRegex("(\\d{3})-(\\d{2})-(\\d{4})");
        ffs.setTweak_source("generated");
        ffs.setMin_input_length(9);
        ffs.setMax_input_length(9);
        ffs.setFpe_definable(true);
	    
	    return ffs;
    }
    




    
	
	public String getAlgorithm() {
		return encryption_algorithm;
	}
	public void setAlgorithm(String encryption_algorithm) {
		this.encryption_algorithm = encryption_algorithm;
		this.cachingKey = this.encryption_algorithm + "-" + this.name;
	}
	
	public String getUser() {
		return user;
	}
	public void setUser(String user) {
		this.user = user;
	}
	
	public String getCustomer() {
		return customer;
	}
	public void setCustomer(String customer) {
		this.customer = customer;
	}
	
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
		this.cachingKey = this.encryption_algorithm + "-" + this.name;
	}
	
	public String getRegex() {
		return regex;
	}
	public void setRegex(String regex) {
		this.regex = regex;
	}
	
	public String getTweak_source() {
		return tweak_source;
	}
	public void setTweak_source(String tweak_source) {
		this.tweak_source = tweak_source;
	}
	
	public int getMin_input_length() {
		return min_input_length;
	}
	public void setMin_input_length(int min_input_length) {
		this.min_input_length = min_input_length;
	}
	
	public int getMax_input_length() {
		return max_input_length;
	}
	public void setMax_input_length(int max_input_length) {
		this.max_input_length = max_input_length;
	}
	
	public boolean getFpe_definable() {
		return fpe_definable;
	}
	public void setFpe_definable(boolean fpe_definable) {
		this.fpe_definable = fpe_definable;
	}
	
	
} 