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
import java.util.Collections;
import java.util.Comparator;


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
    public FFS(UbiqWebServices ubiqWebServices, UbiqConfiguration configuration) {

        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFSCache =
            CacheBuilder.newBuilder()
            .maximumSize(100)                               // maximum 100 records can be cached
            .expireAfterWrite(configuration.getKeyCacheTtlSeconds(), TimeUnit.SECONDS) 
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
    final boolean verbose = false;
    // Make sure the passthrough rules is not null
    if (this.Passthrough_Rules == null) {
      setPassthrough_Rules(new ArrayList<PassthroughRules>());
    }
    passthrough_rules_priority = new ArrayList<FFS.PASSTHROUGH_RULES_TYPE>();
    setPrefixPassthroughLength(0);
    setSuffixPassthroughLength(0);
    // Rules are returned sorted by priority
    for (PassthroughRules rule : getPassthrough_Rules()) {
      if (verbose) System.out.println("Type: " + rule.Type + "     priority: " + rule.Priority);
      if (rule.Type.equals("passthrough")) {
        passthrough_rules_priority.add(FFS.PASSTHROUGH_RULES_TYPE.PASSTHROUGH);
        setPassthroughCharacterSet(rule.Value.toString());
      } else if (rule.Type.equals("suffix")) {
        passthrough_rules_priority.add(FFS.PASSTHROUGH_RULES_TYPE.SUFFIX);
        setSuffixPassthroughLength((new Double(rule.Value.toString())).intValue());
      } else if (rule.Type.equals("prefix")) {
        passthrough_rules_priority.add(FFS.PASSTHROUGH_RULES_TYPE.PREFIX);
        setPrefixPassthroughLength((new Double(rule.Value.toString())).intValue());
      } else {
        // Ignore other rule types
       // new RuntimeException("Invalid passthrough rule type '" + rule.Type + "'");
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
    Collections.sort(this.Passthrough_Rules, Comparator.comparingInt(PassthroughRules::getPriority));
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

  public boolean canEncrypt() {
    return this.CanEncrypt;
  }

  public boolean canDecrypt() {
    return this.CanDecrypt;
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

    transient Boolean CanEncrypt = false;
    transient Boolean CanDecrypt = false;

    transient Integer PrefixPassthroughLength;
    transient Integer SuffixPassthroughLength;
    transient List<FFS.PASSTHROUGH_RULES_TYPE> passthrough_rules_priority;

    private static String getString(JsonObject data, String key) {
      String ret = null;
      JsonElement value = data.get(key);
      if (value != null && value.isJsonPrimitive() && value.getAsString() != null) {
        ret = value.getAsString();
      }
      return ret;
    }

    private static Long getNumber(JsonObject data, String key) {
      Long ret = null;
      JsonElement value = data.get(key);
      if (value != null && value.isJsonPrimitive() && value.getAsNumber() != null) {
        ret = value.getAsNumber().longValue();
      }
      return ret;
    }

    public static FFS_Record parse(String data) throws Exception{
      return FFS_Record.parse((JsonParser.parseString(data).getAsJsonObject()));
    }

    /*
    *   CAUTION: MUST USE Parse function below -
    *   APIGEE does not allow gson.fromJson(<data>,FFS_Record.class)
    *   due to reflection - Will throw
    *     Exception: access denied ("java.lang.RuntimePermission" "accessDeclaredMembers")java.security.AccessControlException: access denied ("java.lang.RuntimePermission" "accessDeclaredMembers")
    */

    public static FFS_Record parse(JsonObject data) throws Exception{
      FFS_Record rec = new FFS_Record();
      rec.setEncryptionAlgorithm(getString(data,"encryption_algorithm"));
      rec.setName(getString(data,"name"));

      rec.setRegex(getString(data,"regex"));
      rec.setTweakSource(getString(data,"tweak_source"));
      rec.setInputCharacterSet(getString(data,"input_character_set"));
      rec.setOutputCharacterSet(getString(data,"output_character_set"));
      rec.setPassthroughCharacterSet(getString(data,"passthrough"));
      rec.setTweak(getString(data,"tweak"));

      rec.setMinInputLength(getNumber(data,"min_input_length"));
      rec.setMaxInputLength(getNumber(data,"max_input_length"));
      rec.setMsbEncodingBits(getNumber(data,"msb_encoding_bits"));
      rec.setMinTweakLength(getNumber(data,"tweak_min_len"));
      rec.setMaxTweakLength(getNumber(data,"tweak_max_len"));

      JsonElement permissions = data.get("permissions");
      if (permissions != null && permissions.isJsonObject()) {
        JsonObject p = permissions.getAsJsonObject();
        JsonElement tmp = p.get("encrypt");
        if (tmp != null && tmp.isJsonPrimitive() && tmp.getAsJsonPrimitive().isBoolean()){
            rec.CanEncrypt = tmp.getAsBoolean();
        }
        tmp = p.get("decrypt");
        if (tmp != null && tmp.isJsonPrimitive() && tmp.getAsJsonPrimitive().isBoolean()){
            rec.CanDecrypt = tmp.getAsBoolean();
        }

      }


      JsonElement passthrough_rules = data.get("passthrough_rules");
      ArrayList<PassthroughRules> rules = new  ArrayList<PassthroughRules>();

      if (passthrough_rules != null && !passthrough_rules.isJsonNull() && passthrough_rules.isJsonArray()) {
        JsonArray arr = passthrough_rules.getAsJsonArray();
        for (JsonElement rule : arr) {
          PassthroughRules element = new PassthroughRules();
          JsonObject obj = rule.getAsJsonObject();
          element.Type = getString(obj,"type");
          element.Priority = getNumber(obj,"priority").intValue();
          JsonElement value = obj.get("value");
          if (value.getAsJsonPrimitive().isString()) {
            element.Value = getString(obj,"value");
          } else {
            element.Value = getNumber(obj,"value").intValue();
          }
          rules.add(element);
        }
      }
      rec.setPassthrough_Rules(rules);
      rec.completeDeserialization();
      return rec;
    }
}

class PassthroughRules {
  @SerializedName("type")
  String Type;
  @SerializedName("priority")
  Integer Priority;
  @SerializedName("value")
  Object Value;

  public Integer getPriority() {
    return Priority;
  }
}
