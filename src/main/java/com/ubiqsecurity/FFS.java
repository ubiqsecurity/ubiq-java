package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
 
import com.google.gson.annotations.SerializedName;

public class FFS  {
    private String encryption_algorithm;   //e.g. FF1 or FF3_1
    private String user;
    private String customer;
    private String name;   //e.g."SSN",
    private String regex;   //e.g. "(\d{3})-(\d{2})-(\d{4})",
    private String tweak_source;   //e.g. "generated",
    private long min_input_length;   //e.g. 9 
    private long max_input_length;   //e.g. 9
    private boolean fpe_definable;
    public LoadingCache<String, FFS_Record> FFSCache;
    
    
    
    public FFS(UbiqWebServices ubiqWebServices, String ffs_name) {
        
        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFSCache = 
            CacheBuilder.newBuilder()
            .maximumSize(100)                               // maximum 100 records can be cached
            .expireAfterAccess(30, TimeUnit.MINUTES)        // cache will expire after 30 minutes of access
            .build(new CacheLoader<String, FFS_Record>() {  // build the cacheloader
                @Override
                public FFS_Record load(String cachingKey) throws Exception {
                   //make the expensive call
                   return getFFSFromCloudAPI(ubiqWebServices, cachingKey, ffs_name);   // <AccessKeyId>-<FFS Name> 
                } 
         });
    }
    
    
    // called when FFS is not in cache and need to make remote call
    private  FFS_Record getFFSFromCloudAPI(UbiqWebServices ubiqWebServices, String cachingKey, String ffs_name) {

        System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getFFSFromCloudAPI for caching key: " + cachingKey);
        
        FFSRecordResponse ffsRecordResponse;
        ffsRecordResponse= ubiqWebServices.getFFSDefinition(ffs_name);
        
        
        System.out.println("   FfsName= " + ffsRecordResponse.FfsName);
        System.out.println("   TweakSource= " + ffsRecordResponse.TweakSource);
        System.out.println("   MinInputLength= " + ffsRecordResponse.MinInputLength);
        System.out.println("   MaxInputLength= " + ffsRecordResponse.MaxInputLength);
        System.out.println("   Regex= " + ffsRecordResponse.Regex);
        
        System.out.println("   InputCharacterSet= " + ffsRecordResponse.InputCharacterSet);
        System.out.println("   OutputCharacterSet= " + ffsRecordResponse.OutputCharacterSet);
        System.out.println("   CurrentKey= " + ffsRecordResponse.CurrentKey);
        System.out.println("   PassthroughCharacterSet= " + ffsRecordResponse.PassthroughCharacterSet);
        System.out.println("   MaxKeyRotations= " + ffsRecordResponse.MaxKeyRotations);
        
        
        
        // STUB - populate FFS_Record with default values if missing from backend FFS definition
        //    Some of these would be mandatory and should report an exception
        String jsonStr= "{}";                
        Gson gson = new Gson();        
        FFS_Record ffs = gson.fromJson(jsonStr, FFS_Record.class);        
         

        if (ffsRecordResponse.EncryptionAlgorithm == null) {
            System.out.println("Missing encryption_algorithm in FFS definition. Setting to: " + "FF1");
            ffs.setAlgorithm("FF1");
        } else {
            ffs.setAlgorithm(ffsRecordResponse.EncryptionAlgorithm);
        }
        
        if (ffsRecordResponse.User == null) {
            System.out.println("Missing User in FFS definition. Setting to: " + "0000");
            ffs.setUser("0000");
        } else {
            ffs.setUser(ffsRecordResponse.User);
        }

        if (ffsRecordResponse.Customer == null) {
            System.out.println("Missing Customer in FFS definition. Setting to: " + "1111");
            ffs.setCustomer("1111");
        } else {
            ffs.setCustomer(ffsRecordResponse.Customer);
        }
 
        if (ffsRecordResponse.FfsName == null) {
            System.out.println("Missing FfsName in FFS definition. Setting to: " + "SSN");
            ffs.setName("SSN");
        } else {
            ffs.setName(ffsRecordResponse.FfsName);
        }

        if (ffsRecordResponse.Regex == null) {
            System.out.println("Missing Regex in FFS definition. Setting to: " + "(\\\\d{3})-(\\\\d{2})-(\\\\d{4})");
            ffs.setRegex("(\\\\d{3})-(\\\\d{2})-(\\\\d{4})");
        } else {
            ffs.setRegex(ffsRecordResponse.Regex);
        }

        if (ffsRecordResponse.TweakSource == null) {
            System.out.println("Missing TweakSource in FFS definition. Setting to: " + "generated");
            ffs.setTweak_source("generated");
        } else {
            ffs.setTweak_source(ffsRecordResponse.TweakSource);
        }

        if (ffsRecordResponse.MinInputLength == -1) {
            System.out.println("Missing MinInputLength in FFS definition. Setting to: " + "9");
            ffs.setMin_input_length(9);
        } else {
            ffs.setMin_input_length(ffsRecordResponse.MinInputLength);
        }

        if (ffsRecordResponse.MaxInputLength == -1) {
            System.out.println("Missing MaxInputLength in FFS definition. Setting to: " + "9");
            ffs.setMax_input_length(9);
        } else {
            ffs.setMax_input_length(ffsRecordResponse.MaxInputLength);
        }

        if (ffsRecordResponse.InputCharacterSet == null) {
            System.out.println("Missing InputCharacterSet in FFS definition. Setting to: " + "0123456789");
            ffs.setInput_character_set("0123456789");
        } else {
            ffs.setInput_character_set(ffsRecordResponse.InputCharacterSet);
        }

        if (ffsRecordResponse.OutputCharacterSet == null) {
            System.out.println("Missing OutputCharacterSet in FFS definition. Setting to: " + "9876543210");
            ffs.setOutput_character_set("9876543210");
        } else {
            ffs.setOutput_character_set(ffsRecordResponse.OutputCharacterSet);
        }




        if (ffsRecordResponse.CurrentKey == -1) {
            System.out.println("Missing CurrentKey in FFS definition. Setting to: " + "0");
            ffs.setCurrent_key(0);
        } else {
            ffs.setCurrent_key(ffsRecordResponse.CurrentKey);
        }

        if (ffsRecordResponse.PassthroughCharacterSet == null) {
            System.out.println("Missing PassthroughCharacterSet in FFS definition. Setting to: " + "!@#{$%^-_:;");
            ffs.setPassthrough_character_set("!@#{$%^-_:;");
        } else {
            ffs.setPassthrough_character_set(ffsRecordResponse.PassthroughCharacterSet);
        }

        if (ffsRecordResponse.MaxKeyRotations == -1) {
            System.out.println("Missing MaxKeyRotations in FFS definition. Setting to: " + "1");
            ffs.setMax_key_rotations(1);
        } else {
            ffs.setMax_key_rotations(ffsRecordResponse.MaxKeyRotations);
        }



        // STUB - switch to a different cipher
        if (cachingKey.equals("aox5ZRptLg8B758xllfEFsNG-SSN"))    // <AccessKeyId>-<FFS Name> 
            ffs.setAlgorithm("FF1");
        else if (cachingKey.equals("aox5ZRptLg8B758xllfEFsNG-PIN"))  
            ffs.setAlgorithm("FF3_1");
        else 
            ffs.setAlgorithm("FF1");
       
// TDOD - TESTING ONLY        
// ffs.setRegex("(\\d{3})-(\\d{2})-\\d{4}");
// ffs.setMin_input_length(2);  
// System.out.println("ffsRecordResponse.MinInputLength: " + ffsRecordResponse.MinInputLength);
// System.out.println("ffs.getMin_input_length: " + ffs.getMin_input_length());
          
        return ffs;
    }
    
    
    
}    




class FFSRecordResponse {
    @SerializedName("encryption_algorithm")
    String EncryptionAlgorithm;

    @SerializedName("user")
    String User;

    @SerializedName("customer")
    String Customer;

    @SerializedName("ffs_name")
    String FfsName;

    @SerializedName("regex")
    String Regex;
    
    @SerializedName("current_key")
    long CurrentKey = -1;

    @SerializedName("tweak_source")
    String TweakSource;

    @SerializedName("min_input_length")
    long MinInputLength = -1;

    @SerializedName("max_input_length")
    long MaxInputLength = -1;

    @SerializedName("fpe_definable")
    boolean FpeDefinable;

    @SerializedName("input_character_set")
    String InputCharacterSet;

    @SerializedName("output_character_set")
    String OutputCharacterSet;
    
    @SerializedName("encryption_session")
    String EncryptionSession;

    @SerializedName("key_fingerprint")
    String KeyFingerprint;

    @SerializedName("passthrough_character_set")
    String PassthroughCharacterSet;

    @SerializedName("max_key_rotations")
    long MaxKeyRotations = -1;

}



class FFS_Record {
    private String encryption_algorithm;   //e.g. FF1 or FF3_1
    private String user;
    private String customer;
    private String name;   //e.g."SSN",
    private String regex;   //e.g. "(\d{3})-(\d{2})-(\d{4})",   // "(\d{3})-(\d{2})-\d{4}",  last 4 in the clear
    private long current_key;
    private String tweak_source;   //e.g. "generated",
    private long min_input_length;   //e.g. 9 
    private long max_input_length;   //e.g. 9
    private boolean fpe_definable;
    private String input_character_set;   //  "alphabet (inut/output radix)
    private String output_character_set;  // not for fpe (most likely)
    private String passthrough_character_set;  
    private long max_key_rotations;


    
	
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
	
	public long getCurrent_key() {
		return current_key;
	}
	public void setCurrent_key(long current_key) {
		this.current_key = current_key;
	}

	public String getTweak_source() {
		return tweak_source;
	}
	public void setTweak_source(String tweak_source) {
		this.tweak_source = tweak_source;
	}
	
	public long getMin_input_length() {
		return min_input_length;
	}
	public void setMin_input_length(long min_input_length) {
		this.min_input_length = min_input_length;
	}
	
	public long getMax_input_length() {
		return max_input_length;
	}
	public void setMax_input_length(long max_input_length) {
		this.max_input_length = max_input_length;
	}
	
	public boolean getFpe_definable() {
		return fpe_definable;
	}
	public void setFpe_definable(boolean fpe_definable) {
		this.fpe_definable = fpe_definable;
	}

	public String getInput_character_set() {
		return input_character_set;
	}
	public void setInput_character_set(String input_character_set) {
		this.input_character_set = input_character_set;
	}

	public String getOutput_character_set() {
		return output_character_set;
	}
	public void setOutput_character_set(String output_character_set) {
		this.output_character_set = output_character_set;
	}

	public String getPassthrough_character_set() {
		return passthrough_character_set;
	}
	public void setPassthrough_character_set(String passthrough_character_set) {
		this.passthrough_character_set = passthrough_character_set;
	}

	public long getMax_key_rotations() {
		return max_key_rotations;
	}
	public void setMax_key_rotations(long max_key_rotations) {
		this.max_key_rotations = max_key_rotations;
	}

	
	
} 