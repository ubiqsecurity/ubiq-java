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

import com.ubiqsecurity.JsonUtils;
/**
 * Server response elements of the JSON record for the FFS data
 */
public class FFS_Record {

  // Some values need to be post-processed to make this object
  // usable
  public void completeDeserialization() /*throws Exception*/  {
    final boolean verbose = false;
    // Make sure the passthrough rules is not null
    if (this.Passthrough_Rules == null) {
      setPassthrough_Rules(new ArrayList<DatasetPassthroughRule>());
    }
    passthrough_rules_priority = new ArrayList<FFS.PASSTHROUGH_RULES_TYPE>();
    setPassthroughPrefixLength(0);
    setPassthroughSuffixLength(0);

    // Sort the passthrough rules - It is a shared object so should be
    // done after load.
    Collections.sort(this.Passthrough_Rules, Comparator.comparingInt(DatasetPassthroughRule::getPriority));

    for (DatasetPassthroughRule rule : getPassthrough_Rules()) {
      if (verbose) System.out.println("Type: " + rule.Type + "     priority: " + rule.Priority);
      if (rule.Type.equals("passthrough")) {
        passthrough_rules_priority.add(FFS.PASSTHROUGH_RULES_TYPE.PASSTHROUGH);
        setPassthroughCharacterSet(rule.Value.toString());
      } else if (rule.Type.equals("suffix")) {
        passthrough_rules_priority.add(FFS.PASSTHROUGH_RULES_TYPE.SUFFIX);
        setPassthroughSuffixLength((new Double(rule.Value.toString())).intValue());
      } else if (rule.Type.equals("prefix")) {
        passthrough_rules_priority.add(FFS.PASSTHROUGH_RULES_TYPE.PREFIX);
        setPassthroughPrefixLength((new Double(rule.Value.toString())).intValue());
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

  public List<DatasetPassthroughRule> getPassthrough_Rules() {
    return this.Passthrough_Rules;
  }

  public void setPassthrough_Rules(List<DatasetPassthroughRule> Passthrough_Rules) {
    this.Passthrough_Rules = Passthrough_Rules;
  }

  public Integer getPassthroughPrefixLength() {
    return this.PassthroughPrefixLength;
  }

  public void setPassthroughPrefixLength(Integer PassthroughPrefixLength) {
    this.PassthroughPrefixLength = PassthroughPrefixLength;
  }

  public Integer getPassthroughSuffixLength() {
    return this.PassthroughSuffixLength;
  }

  public void setPassthroughSuffixLength(Integer PassthroughSuffixLength) {
    this.PassthroughSuffixLength = PassthroughSuffixLength;
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

  public String getInputEncoding() {
    return this.InputEncoding;
  }

  public void setInputEncoding(String InputEncoding) {
    this.InputEncoding = InputEncoding;
  }

  public Character getInputPadCharacter() {
    return this.InputPadCharacter;
  }

  public void setInputPadCharacter(Character InputPadCharacter) {
    this.InputPadCharacter = InputPadCharacter;
  }

  public String getDataType() {
    return this.DataType;
  }

  public void setDataType(String dataType) {
    this.DataType = dataType;
  }

  public DataTypeConfig getDataTypeConfig() {
    return this.DataTypeConfig;
  }
  public void setDataTypeConfig(DataTypeConfig cfg) {
    this.DataTypeConfig = cfg;
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

    @SerializedName("input_encoding")
    String InputEncoding;

    @SerializedName("input_pad_character")
    Character InputPadCharacter;

    @SerializedName("passthrough_rules")
    List<DatasetPassthroughRule> Passthrough_Rules;

    @SerializedName("data_type")
    String DataType;

    @SerializedName("data_type_config")
    DataTypeConfig DataTypeConfig;

    transient Boolean CanEncrypt = false;
    transient Boolean CanDecrypt = false;

    transient Integer PassthroughPrefixLength;
    transient Integer PassthroughSuffixLength;
    transient List<FFS.PASSTHROUGH_RULES_TYPE> passthrough_rules_priority;

    public static FFS_Record parse(String data) /*throws Exception*/{
      return FFS_Record.parse((JsonParser.parseString(data).getAsJsonObject()));
    }

    /*
    *   CAUTION: MUST USE Parse function below -
    *   APIGEE does not allow gson.fromJson(<data>,FFS_Record.class)
    *   due to reflection - Will throw
    *     Exception: access denied ("java.lang.RuntimePermission" "accessDeclaredMembers")java.security.AccessControlException: access denied ("java.lang.RuntimePermission" "accessDeclaredMembers")
    */

    public static FFS_Record parse(JsonObject data) /*throws Exception */{
      FFS_Record rec = new FFS_Record();
      rec.setEncryptionAlgorithm(JsonUtils.getString(data,"encryption_algorithm"));
      rec.setName(JsonUtils.getString(data,"name"));

      rec.setRegex(JsonUtils.getString(data,"regex"));
      rec.setTweakSource(JsonUtils.getString(data,"tweak_source"));
      rec.setInputCharacterSet(JsonUtils.getString(data,"input_character_set"));
      rec.setOutputCharacterSet(JsonUtils.getString(data,"output_character_set"));
      rec.setPassthroughCharacterSet(JsonUtils.getString(data,"passthrough"));
      rec.setTweak(JsonUtils.getString(data,"tweak"));

      rec.setMinInputLength(JsonUtils.getNumber(data,"min_input_length"));
      rec.setMaxInputLength(JsonUtils.getNumber(data,"max_input_length"));
      rec.setMsbEncodingBits(JsonUtils.getNumber(data,"msb_encoding_bits"));
      rec.setMinTweakLength(JsonUtils.getNumber(data,"tweak_min_len"));
      rec.setMaxTweakLength(JsonUtils.getNumber(data,"tweak_max_len"));

      rec.setDataType(JsonUtils.getString(data, "data_type"));
      rec.setInputEncoding(JsonUtils.getString(data, "input_encoding"));
      String input_pad_character = JsonUtils.getString(data, "input_pad_character");
      if (input_pad_character != null && input_pad_character.length() == 1) {
        rec.setInputPadCharacter(input_pad_character.charAt(0));
      }

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
      ArrayList<DatasetPassthroughRule> rules = new  ArrayList<DatasetPassthroughRule>();

      if (passthrough_rules != null && !passthrough_rules.isJsonNull() && passthrough_rules.isJsonArray()) {
        JsonArray arr = passthrough_rules.getAsJsonArray();
        for (JsonElement rule : arr) {
          DatasetPassthroughRule element = new DatasetPassthroughRule();
          JsonObject obj = rule.getAsJsonObject();
          element.Type = JsonUtils.getString(obj,"type");
          element.Priority = JsonUtils.getNumber(obj,"priority").intValue();
          JsonElement value = obj.get("value");
          if (value.getAsJsonPrimitive().isString()) {
            element.Value = JsonUtils.getString(obj,"value");
          } else {
            element.Value = JsonUtils.getNumber(obj,"value").intValue();
          }
          rules.add(element);
        }
      }
      rec.setPassthrough_Rules(rules);

      JsonElement cfg = data.get("data_type_config");
      if (cfg != null && !cfg.isJsonNull() && cfg.isJsonObject()) {
        rec.setDataTypeConfig(com.ubiqsecurity.DataTypeConfig.parse(cfg));
      }

      rec.completeDeserialization();
      return rec;
    }
}