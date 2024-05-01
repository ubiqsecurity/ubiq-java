package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
import com.google.gson.annotations.SerializedName;
import com.google.gson.*;
import java.util.ArrayList;
import java.util.List;

class FFS  {
    private boolean verbose= false;
    public LoadingCache<String, FFS_Record> FFSCache; // FFS Name / Contents of the FFS from the server

    protected enum PASSTHROUGH_RULES_TYPE {
      NONE,
      PASSTHROUGH,
      PREFIX,
      SUFFIX
    }

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
    private  FFS_Record getFFSFromCloudAPI(UbiqWebServices ubiqWebServices, String ffs_name) throws Exception{

        if (verbose) System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getFFSFromCloudAPI for ffs_name: " + ffs_name);

        FFS_Record ffsRecord;
        ffsRecord= ubiqWebServices.getFFSDefinition(ffs_name);

        Gson gson = new Gson();

        if (verbose) System.out.println(gson.toJson(ffsRecord));

        return ffsRecord;
    }
}



/**
 * Server response elements of the JSON record for the FFS data
 */
class FFS_Record {

  // Some values need to be post-processed to make this object
  // usable
  public void completeDeserialization() throws Exception  {

    // Make sure the passthrough rules is not null
    if (this.Passthrough_Rules == null) {
      setPassthrough_Rules(new ArrayList<PassthroughRules>());
    }
    passthrough_rules_priority = new ArrayList<FFS.PASSTHROUGH_RULES_TYPE>(3);
    passthrough_rules_priority.add(FFS.PASSTHROUGH_RULES_TYPE.NONE);
    passthrough_rules_priority.add(FFS.PASSTHROUGH_RULES_TYPE.NONE);
    passthrough_rules_priority.add(FFS.PASSTHROUGH_RULES_TYPE.NONE);
    setPrefixPassthroughLength(0);
    setSuffixPassthroughLength(0);
    for (PassthroughRules rule : getPassthrough_Rules()) {
      System.out.println("Type: " + rule.Type + "     priority: " + rule.Priority);
      if (rule.Type.equals("passthrough")) {
        passthrough_rules_priority.set(rule.Priority - 1, FFS.PASSTHROUGH_RULES_TYPE.PASSTHROUGH);
        setPassthroughCharacterSet(rule.Value.toString());
      } else if (rule.Type.equals("suffix")) {
        passthrough_rules_priority.set(rule.Priority - 1, FFS.PASSTHROUGH_RULES_TYPE.SUFFIX);
        setSuffixPassthroughLength((new Double(rule.Value.toString())).intValue());
      } else if (rule.Type.equals("prefix")) {
        passthrough_rules_priority.set(rule.Priority - 1, FFS.PASSTHROUGH_RULES_TYPE.PREFIX);
        setPrefixPassthroughLength((new Double(rule.Value.toString())).intValue());
      } else {
        new RuntimeException("Invalid passthrough rule type '" + rule.Type + "'");
      }
    }
    // Just make sure it isn't NULL to avoid NULL checks and object exceptions
    if (getPassthroughCharacterSet() == null) {
      setPassthroughCharacterSet("");
    }
  }


  @SerializedName("encryption_algorithm")
  String EncryptionAlgorithm;

  public String getEncryptionAlgorithm() {
    return this.EncryptionAlgorithm;
  }

  public void setEncryptionAlgorithm(String EncryptionAlgorithm) {
    this.EncryptionAlgorithm = EncryptionAlgorithm;
  }

  public String getName() {
    return this.Name;
  }

  public void setName(String Name) {
    this.Name = Name;
  }

  public String getRegex() {
    return this.Regex;
  }

  public void setRegex(String Regex) {
    this.Regex = Regex;
  }

  public String getTweakSource() {
    return this.TweakSource;
  }

  public void setTweakSource(String TweakSource) {
    this.TweakSource = TweakSource;
  }

  public long getMinInputLength() {
    return this.MinInputLength;
  }

  public void setMinInputLength(long MinInputLength) {
    this.MinInputLength = MinInputLength;
  }

  public long getMaxInputLength() {
    return this.MaxInputLength;
  }

  public void setMaxInputLength(long MaxInputLength) {
    this.MaxInputLength = MaxInputLength;
  }

  public boolean isFpeDefinable() {
    return this.FpeDefinable;
  }

  public boolean getFpeDefinable() {
    return this.FpeDefinable;
  }

  public void setFpeDefinable(boolean FpeDefinable) {
    this.FpeDefinable = FpeDefinable;
  }

  public String getInputCharacterSet() {
    return this.InputCharacterSet;
  }

  public void setInputCharacterSet(String InputCharacterSet) {
    this.InputCharacterSet = InputCharacterSet;
  }

  public String getOutputCharacterSet() {
    return this.OutputCharacterSet;
  }

  public void setOutputCharacterSet(String OutputCharacterSet) {
    this.OutputCharacterSet = OutputCharacterSet;
  }

  public String getPassthroughCharacterSet() {
    return this.PassthroughCharacterSet;
  }

  public void setPassthroughCharacterSet(String PassthroughCharacterSet) {
    this.PassthroughCharacterSet = PassthroughCharacterSet;
  }

  public long getMsbEncodingBits() {
    return this.MsbEncodingBits;
  }

  public void setMsbEncodingBits(long MsbEncodingBits) {
    this.MsbEncodingBits = MsbEncodingBits;
  }

  public long getMinTweakLength() {
    return this.MinTweakLength;
  }

  public void setMinTweakLength(long MinTweakLength) {
    this.MinTweakLength = MinTweakLength;
  }

  public long getMaxTweakLength() {
    return this.MaxTweakLength;
  }

  public void setMaxTweakLength(long MaxTweakLength) {
    this.MaxTweakLength = MaxTweakLength;
  }

  public String getTweak() {
    return this.Tweak;
  }

  public void setTweak(String Tweak) {
    this.Tweak = Tweak;
  }

  public List<PassthroughRules> getPassthrough_Rules() {
    return this.Passthrough_Rules;
  }

  public void setPassthrough_Rules(List<PassthroughRules> Passthrough_Rules) {
    this.Passthrough_Rules = Passthrough_Rules;
  }

  public Integer getPrefixPassthroughLength() {
    return this.PrefixPassthroughLength;
  }

  public void setPrefixPassthroughLength(Integer PrefixPassthroughLength) {
    this.PrefixPassthroughLength = PrefixPassthroughLength;
  }

  public Integer getSuffixPassthroughLength() {
    return this.SuffixPassthroughLength;
  }

  public void setSuffixPassthroughLength(Integer SuffixPassthroughLength) {
    this.SuffixPassthroughLength = SuffixPassthroughLength;
  }

  public List<FFS.PASSTHROUGH_RULES_TYPE> getPassthrough_rules_priority() {
    return this.passthrough_rules_priority;
  }

  public void setPassthrough_rules_priority(List<FFS.PASSTHROUGH_RULES_TYPE> passthrough_rules_priority) {
    this.passthrough_rules_priority = passthrough_rules_priority;
  }

    @SerializedName("name")
    String Name;

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

    @SerializedName("passthrough_rules")
    List<PassthroughRules> Passthrough_Rules;

    transient Integer PrefixPassthroughLength;
    transient Integer SuffixPassthroughLength;
    transient List<FFS.PASSTHROUGH_RULES_TYPE> passthrough_rules_priority;
}

class PassthroughRules {
  @SerializedName("type")
  String Type;
  @SerializedName("priority")
  Integer Priority;
  @SerializedName("value")
  Object Value;
}
