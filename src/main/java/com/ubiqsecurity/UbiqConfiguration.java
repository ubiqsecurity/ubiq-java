package com.ubiqsecurity;

import java.io.IOException;
import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.File;
import java.time.temporal.ChronoUnit;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class UbiqConfiguration {

  Configuration config = null;

  class EventReporting {
    @SerializedName("minimum_count")
    Integer minimumCount = 50;

    @SerializedName("flush_interval")
    Integer flushInterval = 10;

    @SerializedName("wake_interval")
    Integer wakeInterval = 1;

    @SerializedName("timestamp_granularity")
    ChronoUnit timestampGranularity = ChronoUnit.NANOS;

    @SerializedName("trap_exceptions")
    Boolean trapExceptions = false;

  }

  class KeyCaching {
    @SerializedName("unstructured")
    Boolean unstructured = true;

    @SerializedName("encrypt")
    Boolean encrypt = false;

    @SerializedName("ttl_seconds")
    Integer ttlSeconds = 1800;

    @SerializedName("structured")
    Boolean structured = true;

  }

  class Configuration {
    @SerializedName("debug")
    Boolean debug = false;

    @SerializedName("event_reporting")
    EventReporting eventReporting;

    @SerializedName("key_caching")
    KeyCaching keyCaching;
  }


    UbiqConfiguration(
      Integer eventReportingWakeInterval,
      Integer eventReportingMinimumCount,
      Integer eventReportingFlushInterval,
      Boolean eventReportingTrapExceptions,
      ChronoUnit eventReportingTimestampGranularity,
      Boolean cacheEncryptKeys,
      Boolean cacheStructuredKeys,
      Boolean cacheUnstructuredKeys,
      Integer cacheTtlSeconds ) {

        // Create configuration with defaults
        config = new Configuration();
        config.keyCaching = new UbiqConfiguration.KeyCaching();
        config.eventReporting = new UbiqConfiguration.EventReporting();

        if (eventReportingWakeInterval != null) {
          config.eventReporting.wakeInterval = eventReportingWakeInterval;
        }
        if (eventReportingMinimumCount != null) {
          config.eventReporting.minimumCount = eventReportingMinimumCount;
        }
        if (eventReportingFlushInterval != null) {
          config.eventReporting.flushInterval = eventReportingFlushInterval;
        }
        if (eventReportingTrapExceptions != null) {
          config.eventReporting.trapExceptions = eventReportingTrapExceptions;
        }
        if (eventReportingTimestampGranularity != null) {
          config.eventReporting.timestampGranularity = eventReportingTimestampGranularity;
        }
        if (cacheEncryptKeys != null) {
          config.keyCaching.encrypt = cacheEncryptKeys;
        }
        if (cacheStructuredKeys != null) {
          config.keyCaching.structured = cacheStructuredKeys;
        }
        if (cacheUnstructuredKeys != null) {
          config.keyCaching.unstructured = cacheUnstructuredKeys;
        }
        if (cacheTtlSeconds != null) {
          config.keyCaching.ttlSeconds = cacheTtlSeconds;
        }
    }

    ChronoUnit findEventReportingGranularity(String granularity) {
      ChronoUnit ret = ChronoUnit.NANOS;
      switch (granularity.toUpperCase()) {
        case "DAYS":
          ret = ChronoUnit.DAYS;
          break;
        case "HALF_DAYS":
          ret = ChronoUnit.HALF_DAYS;
          break;
        case "HOURS":
          ret = ChronoUnit.HOURS;
          break;
        case "MINUTES":
          ret = ChronoUnit.MINUTES;
          break;
        case "SECONDS":
          ret = ChronoUnit.SECONDS;
          break;
        case "MILLIS":
          ret = ChronoUnit.MILLIS;
          break;
        default:
          ret = ChronoUnit.NANOS;
          break;
      }
      return ret;
    }

    // TODO - Going to rewrite this to deserialize to pojo after getting the ttl_seconds change out the door
    UbiqConfiguration(String pathname) throws IOException {

      JsonObject cfgObject;
      JsonObject tmpObject;
      JsonElement tmpElement;
      JsonParser parser = new JsonParser();

        if ((pathname == null) || pathname.isEmpty()) {
          pathname = String.format("%s/.ubiq/configuration", System.getProperty("user.home"));
        }

        // Create configuration with defaults

        config = new Configuration();
        config.keyCaching = new UbiqConfiguration.KeyCaching();
        config.eventReporting = new UbiqConfiguration.EventReporting();

        // Only load if file exists, otherwise use default values
        File temp = new File(pathname);
        if (!temp.exists()) {
          throw new IllegalArgumentException(String.format("file does not exist: %s", pathname));
        }
        
        try {
          tmpElement = parser.parse(new FileReader(pathname));

          Gson gson = new GsonBuilder().setPrettyPrinting().create();

          // Parse the file and override any values in the config file but leave
          // unset values at their default value.
          Configuration tmpConfig = gson.fromJson(new FileReader(pathname), UbiqConfiguration.Configuration.class);
          if (tmpConfig == null) {
            // Nothing necessary, default is fine
          } else {
            if (tmpConfig.debug != null) {
              config.debug = tmpConfig.debug;
            }

            if (tmpConfig.eventReporting != null) {
              if (tmpConfig.eventReporting.wakeInterval != null) {
                config.eventReporting.wakeInterval = tmpConfig.eventReporting.wakeInterval;
              }
              if (tmpConfig.eventReporting.minimumCount != null) {
                config.eventReporting.minimumCount = tmpConfig.eventReporting.minimumCount;
              }
              if (tmpConfig.eventReporting.flushInterval != null) {
                config.eventReporting.flushInterval = tmpConfig.eventReporting.flushInterval;
              }
              if (tmpConfig.eventReporting.trapExceptions != null) {
                config.eventReporting.trapExceptions = tmpConfig.eventReporting.trapExceptions;
              }
              if (tmpConfig.eventReporting.timestampGranularity != null) {
                config.eventReporting.timestampGranularity = tmpConfig.eventReporting.timestampGranularity;
              }
            }
            if (tmpConfig.keyCaching != null) {
              if (tmpConfig.keyCaching.encrypt != null) {
                config.keyCaching.encrypt = tmpConfig.keyCaching.encrypt;
              }
              if (tmpConfig.keyCaching.unstructured != null) {
                config.keyCaching.unstructured = tmpConfig.keyCaching.unstructured;
              }
              if (tmpConfig.keyCaching.structured != null) {
                config.keyCaching.structured = tmpConfig.keyCaching.structured;
              }
              if (tmpConfig.keyCaching.ttlSeconds != null) {
                config.keyCaching.ttlSeconds = tmpConfig.keyCaching.ttlSeconds;
              }
            }
          }

        } catch (IOException e) {
          throw new IllegalArgumentException(String.format("file parsing error: %s", pathname));
        } catch (JsonSyntaxException e) {
          throw new IllegalArgumentException(String.format("file parsing error: %s", pathname));
        }
    }
      
    public Integer getEventReportingWakeInterval() {
        return config.eventReporting.wakeInterval;
    }

    public Integer getEventReportingMinimumCount() {
        return config.eventReporting.minimumCount;
    }

    public Integer getEventReportingFlushInterval() {
        return config.eventReporting.flushInterval;
    }

    public Boolean getEventReportingTrapExceptions() {
      return config.eventReporting.trapExceptions;
    }

    public ChronoUnit getEventReportingTimestampGranularity() {
      return config.eventReporting.timestampGranularity;
    }

    public Boolean getKeyCacheEncryptKeys() {
      return config.keyCaching.encrypt;
    }

    public Boolean getKeyCacheUnstructuredKeys() {
      return config.keyCaching.unstructured;
    }

    public Boolean getKeyCacheStructuredKeys() {
      return config.keyCaching.structured;
    }

    public Integer getKeyCacheTtlSeconds() {
      return config.keyCaching.ttlSeconds;
  }
}
