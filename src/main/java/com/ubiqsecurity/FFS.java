package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
import com.google.gson.annotations.SerializedName;

class FFS  {
    private boolean verbose= false;
    public LoadingCache<String, FFS_Record> FFSCache; // FFS Name / Contents of the FFS from the server


    /**
     * FFS constructor
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     *
     */
    public FFS(UbiqWebServices ubiqWebServices) {

        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFSCache =
            CacheBuilder.newBuilder()
            .maximumSize(100)                               // maximum 100 records can be cached
            .expireAfterAccess(24 * 60 * 3, TimeUnit.MINUTES)        // cache will expire after 30 minutes of access
            .build(new CacheLoader<String, FFS_Record>() {  // build the cacheloader
                @Override
                public FFS_Record load(String ffs_name) throws Exception {
                   //make the expensive call
                   return getFFSFromCloudAPI(ubiqWebServices, ffs_name);   // FFS_Name - returns the contents of the FFS
                }
         });
    }


    /**
    * Clears the FFS cache
    *
    */
    public void invalidateAllCache() {
        FFSCache.invalidateAll();
    }


    /**
     * Called when FFS data is not in cache and need to make remote call to the server
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param cachingKey  Format <AccessKeyId>-<FFS Name> used as the record locator
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     *
     */
    private  FFS_Record getFFSFromCloudAPI(UbiqWebServices ubiqWebServices, String ffs_name) {

        if (verbose) System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getFFSFromCloudAPI for ffs_name: " + ffs_name);

        FFSRecordResponse ffsRecordResponse;
        ffsRecordResponse= ubiqWebServices.getFFSDefinition(ffs_name);

        String jsonStr= "{}";
        Gson gson = new Gson();
        FFS_Record ffs = gson.fromJson(jsonStr, FFS_Record.class);

        // If the server fails, we would have already sent a getFFSDefinition exception
        if (ffsRecordResponse!= null) {
            if (ffsRecordResponse.EncryptionAlgorithm == null) {
                if (verbose) System.out.println("Missing encryption_algorithm in FFS definition.");
            } else {
                ffs.setAlgorithm(ffsRecordResponse.EncryptionAlgorithm);
            }

            if (ffsRecordResponse.FfsName == null) {
                if (verbose) System.out.println("Missing name in FFS definition.");
            } else {
                ffs.setName(ffsRecordResponse.FfsName);
            }

            if (ffsRecordResponse.Regex == null) {
                if (verbose) System.out.println("Missing Regex in FFS definition.");
            } else {
                ffs.setRegex(ffsRecordResponse.Regex);
            }

            if (ffsRecordResponse.TweakSource == null) {
                if (verbose) System.out.println("Missing tweak_source in FFS definition.");
            } else {
                ffs.setTweak_source(ffsRecordResponse.TweakSource);
            }

            if (ffsRecordResponse.MinInputLength == -1) {
                if (verbose) System.out.println("Missing min_input_length in FFS definition.");
            } else {
                ffs.setMin_input_length(ffsRecordResponse.MinInputLength);
            }

            if (ffsRecordResponse.MaxInputLength == -1) {
                if (verbose) System.out.println("Missing max_input_length in FFS definition.");
            } else {
                ffs.setMax_input_length(ffsRecordResponse.MaxInputLength);
            }

            if (ffsRecordResponse.InputCharacterSet == null) {
                if (verbose) System.out.println("Missing input_character_set in FFS definition.");
            } else {
                ffs.setInput_character_set(ffsRecordResponse.InputCharacterSet);
            }

            if (ffsRecordResponse.OutputCharacterSet == null) {
                if (verbose) System.out.println("Missing output_character_set in FFS definition.");
            } else {
                ffs.setOutput_character_set(ffsRecordResponse.OutputCharacterSet);
            }

            if (ffsRecordResponse.PassthroughCharacterSet == null) {
                if (verbose) System.out.println("Missing passthrough in FFS definition.");
            } else {
                ffs.setPassthrough_character_set(ffsRecordResponse.PassthroughCharacterSet);
            }

            if (ffsRecordResponse.MsbEncodingBits == -1) {
                if (verbose) System.out.println("Missing msb_encoding_bits in FFS definition.");
            } else {
                ffs.setMsb_encoding_bits(ffsRecordResponse.MsbEncodingBits);
            }

            if (ffsRecordResponse.MinTweakLength == -1) {
                if (verbose) System.out.println("Missing tweak_min_len in FFS definition.");
            } else {
                ffs.setMin_tweak_length(ffsRecordResponse.MinTweakLength);
            }

            if (ffsRecordResponse.MaxTweakLength == -1) {
                if (verbose) System.out.println("Missing tweak_max_len in FFS definition.");
            } else {
                ffs.setMax_tweak_length(ffsRecordResponse.MaxTweakLength);
            }

            if (ffsRecordResponse.Tweak == null) {
                if (verbose) System.out.println("Missing Tweak in FFS definition.");
            } else {
                ffs.setTweak(ffsRecordResponse.Tweak);
            }
        }

        return ffs;
    }



}



/**
 * Server response elements of the JSON record for the FFS data
 */
class FFSRecordResponse {
    @SerializedName("encryption_algorithm")
    String EncryptionAlgorithm;

    @SerializedName("name")
    String FfsName;

    @SerializedName("regex")
    String Regex;

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

    @SerializedName("passthrough")
    String PassthroughCharacterSet;

    @SerializedName("msb_encoding_bits")
    long MsbEncodingBits = -1;

    @SerializedName("tweak_min_len")
    long MinTweakLength = -1;

    @SerializedName("tweak_max_len")
    long MaxTweakLength = -1;

    @SerializedName("tweak")
    String Tweak;


}


/**
 * Representation of the JSON record for the FFS data
 */
class FFS_Record {
    private String encryption_algorithm;   //e.g. FF1 or FF3_1
    private String name;   //e.g."SSN",
    private String regex;   //e.g. "(\d{3})-(\d{2})-(\d{4})",   // "(\d{3})-(\d{2})-\d{4}",  last 4 in the clear
    private String tweak_source;   //e.g. "generated",
    private long min_input_length;   //e.g. 9
    private long max_input_length;   //e.g. 9
    private boolean fpe_definable;
    private String input_character_set;   //  "alphabet (inut/output radix)
    private String output_character_set;  // not for fpe (most likely)
    private String passthrough_character_set;
    private long max_key_rotations;
    private long msb_encoding_bits;
    private long  tweak_min_len;
    private long  tweak_max_len;
    private String Tweak;


	public String getAlgorithm() {
		return encryption_algorithm;
	}
	public void setAlgorithm(String encryption_algorithm) {
		this.encryption_algorithm = encryption_algorithm;
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

	public long getMsb_encoding_bits() {
		return msb_encoding_bits;
	}
	public void setMsb_encoding_bits(long msb_encoding_bits) {
		this.msb_encoding_bits = msb_encoding_bits;
	}

	public long getMin_tweak_length() {
		return tweak_min_len;
	}
	public void setMin_tweak_length(long tweak_min_len) {
		this.tweak_min_len = tweak_min_len;
	}

	public long getMax_tweak_length() {
		return tweak_max_len;
	}
	public void setMax_tweak_length(long tweak_max_len) {
		this.tweak_max_len = tweak_max_len;
	}

	public String getTweak() {
		return Tweak;
	}
	public void setTweak(String Tweak) {
		this.Tweak = Tweak;
	}




}
