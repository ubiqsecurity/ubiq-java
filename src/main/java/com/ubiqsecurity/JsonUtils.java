package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;

import com.ubiqsecurity.structured.FF1;
import java.math.BigInteger;

import java.util.HashSet;
import java.util.Set;
import java.util.Arrays;
import java.time.OffsetDateTime ;

import java.time.format.DateTimeParseException;

public class JsonUtils {

  private static boolean verbose = false;

    public static String getString(JsonObject data, String key) {
      String ret = null;
      JsonElement value = data.get(key);
      if (value != null && value.isJsonPrimitive() && !value.isJsonNull()) {
          ret = value.getAsString();
      }
      return ret;
    }

    public static Long getNumber(JsonObject data, String key) {
      Long ret = null;
      JsonElement value = data.get(key);
      if (value != null && value.isJsonPrimitive() && !value.isJsonNull()) {
        ret = value.getAsNumber().longValue();
      }
      return ret;
    }

    public static OffsetDateTime getDateTime(JsonObject data, String key) throws DateTimeParseException {
      OffsetDateTime ret = null;
      JsonElement value = data.get(key);
      if (value != null && value.isJsonPrimitive() && !value.isJsonNull()) {
        String val = value.getAsString();
        ret = OffsetDateTime.parse(val);
      }
      return ret;
    }

  }
