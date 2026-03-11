package com.ubiqsecurity;

import java.time.OffsetDateTime;
import com.google.gson.annotations.SerializedName;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;

import com.ubiqsecurity.JsonUtils;

public class DataTypeConfig {

  void setSize(Long size) {
    this.size = size;
  }
  Long getSize() {
    return size;
  }

  void setMinInputIntValue(Long minInputIntValue) {
    this.minInputIntValue = minInputIntValue;
  }
  Long getMinInputIntValue() {
    return minInputIntValue;
  }

  void setMaxInputIntValue(Long maxInputIntValue) {
    this.maxInputIntValue = maxInputIntValue;
  }
  Long getMaxInputIntValue() {
    return maxInputIntValue;
  }

  void setEpoch(OffsetDateTime epoch) {
    this.epoch = epoch;
  }
  OffsetDateTime getEpoch() {
    return epoch;
  }

  void setMinInputDateValue(OffsetDateTime minInputDateValue) {
    this.minInputDateValue = minInputDateValue;
  }
  OffsetDateTime getMinInputDateValue() {
    return minInputDateValue;
  }

  void setMaxInputDateValue(OffsetDateTime maxInputDateValue) {
    this.maxInputDateValue = maxInputDateValue;
  }
  OffsetDateTime getMaxInputDateValue() {
    return maxInputDateValue;
  }

  @SerializedName("size")
  Long size;

  @SerializedName("min_input_int_value")
  Long minInputIntValue;

  @SerializedName("max_input_int_value")
  Long maxInputIntValue;

  @SerializedName("epoch")
  OffsetDateTime epoch;

  @SerializedName("min_input_date_value")
  OffsetDateTime minInputDateValue;

  @SerializedName("max_input_date_value")
  OffsetDateTime maxInputDateValue;

  public static DataTypeConfig parse(JsonElement data) /*throws Exception*/{
      DataTypeConfig rec = new DataTypeConfig();
      if (data != null && !data.isJsonNull() && data.isJsonObject()) {
        JsonObject d = data.getAsJsonObject();
        rec.setSize(JsonUtils.getNumber(d, "size"));
        rec.setMinInputIntValue(JsonUtils.getNumber(d,"min_input_int_value"));
        rec.setMaxInputIntValue(JsonUtils.getNumber(d,"max_input_int_value"));
        rec.setMinInputDateValue(JsonUtils.getDateTime(d, "min_input_date_value"));
        rec.setMaxInputDateValue(JsonUtils.getDateTime(d, "max_input_date_value"));
        rec.setEpoch(JsonUtils.getDateTime(d, "epoch"));
      }
      return rec;
  }

}
