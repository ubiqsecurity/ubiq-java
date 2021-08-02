package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
 


public class FFS  {
    private String encryption_algorithm;   //e.g. FF1 or FF3_1
    private String user;
    private String customer;
    private String name;   //e.g."SSN",
    private String regex;   //e.g. "(\d{3})-(\d{2})-(\d{4})",
    private String tweak_source;   //e.g. "generated",
    private int min_input_length;   //e.g. 9 
    private int max_input_length;   //e.g. 9
    private boolean fpe_definable;
    public LoadingCache<String, FFS_Record> FFSCache;
    
    
    
    public FFS() {
        System.out.println("NEW OBJECT FFS");
        
        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFSCache = 
            CacheBuilder.newBuilder()
            .maximumSize(100)                               // maximum 100 records can be cached
            .expireAfterAccess(30, TimeUnit.MINUTES)        // cache will expire after 30 minutes of access
            .build(new CacheLoader<String, FFS_Record>() {  // build the cacheloader
                @Override
                public FFS_Record load(String cachingKey) throws Exception {
                   //make the expensive call
                   return getFFSFromCloudAPI(cachingKey);   // <AccessKeyId>-<FFS Name> 
                } 
         });
    }
    
    
    // called when FFS is not in cache and need to make remote call
    private  FFS_Record getFFSFromCloudAPI(String cachingKey) {
        FFS_Record ffs;

        System.out.println("\n****** START EXPENSIVE CALL ----- getFFSFromCloudAPI for caching key: " + cachingKey);
        
        // STUB - HARDCODE FOR NOW. NOTE HARDCODED ACCESS KEY!
        if (cachingKey.equals("0cxsgl9sL2QLGlBpm6D3s6KG-SSN"))    // <AccessKeyId>-<FFS Name> 
            ffs = TEMP_getFFSdataFromCloud_1();
        else if (cachingKey.equals("0cxsgl9sL2QLGlBpm6D3s6KG-PIN"))  
            ffs = TEMP_getFFSdataFromCloud_2();
        else 
            ffs = TEMP_getFFSdataFromCloud_2();

        System.out.println("****** END EXPENSIVE CALL ----- getFFSFromCloudAPI for caching key: " + cachingKey + "\n");

            
        return ffs;
    }
    
    
    // STUB - Get fresh FFS data
    public FFS_Record TEMP_getFFSdataFromCloud_1() {
        System.out.println("----- TEMP_getFFSdataFromCloud_1");
        
        
        
        // TODO - pull this data from an API call instead of hardcoding it here
        String jsonStr= "{   'encryption_algorithm': 'FF1', 'user': '0000', 'customer': '1111', 'name': 'SSN', 'regex': '(\\\\d{3})-(\\\\d{2})-(\\\\d{4})', 'tweak_source': 'generated', 'min_input_length': '9', 'max_input_length': '9', 'fpe_definable': 'true'}";    
        Gson gson = new Gson();        
        FFS_Record ffs = gson.fromJson(jsonStr, FFS_Record.class);
    
        System.out.println("----- ffs.getAlgorithm= " + ffs.getAlgorithm() );
        System.out.println("----- ffs.getName= " + ffs.getName() );
        System.out.println("----- ffs.getRegex= " + ffs.getRegex() );
        System.out.println("----- ffs.getTweak_source= " + ffs.getTweak_source() );
        System.out.println("----- ffs.getMin_input_length= " + ffs.getMin_input_length() );
        System.out.println("----- ffs.getMax_input_length= " + ffs.getMax_input_length() );
        System.out.println("----- ffs.getFpe_definable= " + ffs.getFpe_definable() );
        System.out.println("----- ffs.getUser= " + ffs.getUser() );
    
        
	    return ffs;
    }



    // STUB - Get fresh FFS data
    public FFS_Record TEMP_getFFSdataFromCloud_2() {
        System.out.println("----- TEMP_getFFSdataFromCloud_2");
        
        // TODO - pull this data from an API call instead of hardcoding it here
        String jsonStr= "{   'encryption_algorithm': 'FF3_1', 'user': '0000', 'customer': '1111', 'name': 'SSN', 'regex': '(\\\\d{3})-(\\\\d{2})-(\\\\d{4})', 'tweak_source': 'generated', 'min_input_length': '9', 'max_input_length': '9', 'fpe_definable': 'true'}";    
        Gson gson = new Gson();        
        FFS_Record ffs = gson.fromJson(jsonStr, FFS_Record.class);
    
        System.out.println("----- ffs.getAlgorithm= " + ffs.getAlgorithm() );
        System.out.println("----- ffs.getName= " + ffs.getName() );
        System.out.println("----- ffs.getRegex= " + ffs.getRegex() );
        System.out.println("----- ffs.getTweak_source= " + ffs.getTweak_source() );
        System.out.println("----- ffs.getMin_input_length= " + ffs.getMin_input_length() );
        System.out.println("----- ffs.getMax_input_length= " + ffs.getMax_input_length() );
        System.out.println("----- ffs.getFpe_definable= " + ffs.getFpe_definable() );
        System.out.println("----- ffs.getUser= " + ffs.getUser() );
        
        	    
	    return ffs;
    }
    
}    



class FFS_Record {
    private String encryption_algorithm;   //e.g. FF1 or FF3_1
    private String user;
    private String customer;
    private String name;   //e.g."SSN",
    private String regex;   //e.g. "(\d{3})-(\d{2})-(\d{4})",   // "(\d{3})-(\d{2})-\d{4}",  last 4 in the clear
    private String tweak_source;   //e.g. "generated",
    private int min_input_length;   //e.g. 9 
    private int max_input_length;   //e.g. 9
    private boolean fpe_definable;
    private String input_character_set;   //  "alphabet (inut/output radix)
    private String output_character_set;  // not for fpe (most likely)
    


	
	public String getAlgorithm() {
		return encryption_algorithm;
	}
	public void setAlgorithm(String encryption_algorithm) {
		this.encryption_algorithm = encryption_algorithm;
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