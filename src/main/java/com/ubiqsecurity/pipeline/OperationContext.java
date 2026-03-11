package com.ubiqsecurity.pipeline;
import java.util.Objects;
import java.util.HashMap;
import com.ubiqsecurity.FFS_Record;
import com.ubiqsecurity.FFXCache;

public class OperationContext {
  protected FFS_Record dataset;
  protected Integer keyNumber;
  protected String originalValue;
  protected String currentValue;
  protected Boolean isEncrypt;
  protected byte[] userSuppliedTweak;
  protected FFXCache ffxCache;
  protected HashMap<String, String> data = new HashMap<>();

  public FFXCache getFfxCache() {
    return this.ffxCache;
  }

  public void setFfxCache(FFXCache ffxCache) {
    this.ffxCache = ffxCache;
  }

  public OperationContext() {
  }

  public FFS_Record getDataset() {
    return this.dataset;
  }

  public void setDataset(FFS_Record dataset) {
    this.dataset = dataset;
  }

  public Integer getKeyNumber() {
    return this.keyNumber;
  }

  public void setKeyNumber(Integer keyNumber) {
    this.keyNumber = keyNumber;
  }

  public String getOriginalValue() {
    return this.originalValue;
  }

  public void setOriginalValue(String originalValue) {
    this.originalValue = originalValue;
  }

  public String getCurrentValue() {
    return this.currentValue;
  }

  public void setCurrentValue(String currentValue) {
    this.currentValue = currentValue;
  }

  public Boolean getIsEncrypt() {
    return this.isEncrypt;
  }

  public void setIsEncrypt(Boolean isEncrypt) {
    this.isEncrypt = isEncrypt;
  }

  public byte[] getUserSuppliedTweak() {
    return this.userSuppliedTweak;
  }

  public void setUserSuppliedTweak(byte[] userSuppliedTweak) {
    this.userSuppliedTweak = userSuppliedTweak;
  }

  public HashMap<String,String> getData() {
    return this.data;
  }

  public void setData(HashMap<String,String> data) {
    this.data = data;
  }


}
