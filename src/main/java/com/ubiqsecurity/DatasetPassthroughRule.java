package com.ubiqsecurity;

import com.google.gson.annotations.SerializedName;

public class DatasetPassthroughRule {

  @SerializedName("type")
  String Type;

  @SerializedName("priority")
  Integer Priority;

  @SerializedName("value")
  Object Value;

  public String getType() {
    return this.Type;
  }

  public void setType(String Type) {
    this.Type = Type;
  }

  public void setPriority(Integer Priority) {
    this.Priority = Priority;
  }

  public Object getValue() {
    return this.Value;
  }

  public void setValue(Object Value) {
    this.Value = Value;
  }

  public Integer getPriority() {
    return Priority;
  }
}
