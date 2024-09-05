package com.ubiqsecurity;

import java.io.IOException;
import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.File;
import java.time.temporal.ChronoUnit;

public class UbiqConfiguration {
    // Configuration Element names
    private final String EVENT_REPORTING = "event_reporting";
    private final String WAKE_INTERVAL = "wake_interval";
    private final String MINIMUM_COUNT = "minimum_count";
    private final String FLUSH_INTERVAL = "flush_interval";
    private final String TRAP_EXCEPTIONS = "trap_exceptions";
    private final String TIMESTAMP_GRANULARITY = "timestamp_granularity";

    private final String KEY_CACHING = "key_caching";
    private final String TTL_SECONDS = "ttl_seconds";
    private final String ENCRYPT = "encrypt";
    private final String UNSTRUCTURED = "unstructured";

    /**
     * eventReportingWakeInterval is how many seconds elapse between when the event processor wakes up and sees what is 
     * available to send to the server.
     * 
     * eventReportingMinimumCount is how many billing events need to be queued before they will be sent.  
     * A billing event is based on the combination of API key, dataset, dataset_group, key_number, and encrypt / decrypt action.
     * So if a single library is used to encrypt 1M records using the same combination of these fields, this will only count 
     * as 1 billing event with a count of 1M.
     * 
     * eventReportingFlushInterval addresses the issue above where a single combination of data is used to 
     * encrypt 1M records but the billing event isn't sent because it is only one billing event. 
     * When this interval (seconds) is reached, all billing events will be sent.
     */

    private Integer eventReportingWakeInterval = 1;
    private Integer eventReportingMinimumCount = 50;
    private Integer eventReportingFlushInterval = 10;
    private Boolean eventReportingTrapExceptions = false;
    private ChronoUnit eventReportingTimestampGranularity = ChronoUnit.NANOS;
    private boolean cacheEncryptKeys = false;
    private boolean cacheUnstructuredKeys = false;
    private Integer cacheTtlSeconds = 1800; // 30 minutes


    UbiqConfiguration(
      Integer eventReportingWakeInterval,
      Integer eventReportingMinimumCount,
      Integer eventReportingFlushInterval,
      Boolean eventReportingTrapExceptions,
      ChronoUnit eventReportingTimestampGranularity,
      Boolean cacheEncryptKeys,
      Boolean cacheUnstructuredKeys,
      Integer cacheTtlSeconds ) {

        if (eventReportingWakeInterval != null) {
          this.eventReportingWakeInterval = eventReportingWakeInterval;
        }

        if (eventReportingMinimumCount != null) {
          this.eventReportingMinimumCount = eventReportingMinimumCount;
        }

        if (eventReportingFlushInterval != null) {
          this.eventReportingFlushInterval = eventReportingFlushInterval;
        }
        if (eventReportingTrapExceptions != null) {
          this.eventReportingTrapExceptions = eventReportingTrapExceptions;
        }
        if (eventReportingTimestampGranularity != null) {
          this.eventReportingTimestampGranularity = eventReportingTimestampGranularity;
        }
        if (cacheEncryptKeys != null) {
          this.cacheEncryptKeys = cacheEncryptKeys;
        }
        if (cacheUnstructuredKeys != null) {
          this.cacheUnstructuredKeys = cacheUnstructuredKeys;
        }
        if (cacheTtlSeconds != null) {
          this.cacheTtlSeconds = cacheTtlSeconds;
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

        // Only load if file exists, otherwise use default values
        File temp = new File(pathname);
        if (!temp.exists()) {
          throw new IllegalArgumentException(String.format("file does not exist: %s", pathname));
        }
        
        try {
          tmpElement = parser.parse(new FileReader(pathname));
        } catch (IOException e) {
          throw new IllegalArgumentException(String.format("file parsing error: %s", pathname));

        } catch (JsonSyntaxException e) {
          throw new IllegalArgumentException(String.format("file parsing error: %s", pathname));
        }

        if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonObject()) {
          cfgObject = tmpElement.getAsJsonObject();
          tmpElement = cfgObject.get(EVENT_REPORTING);

          if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonObject()) {
            JsonObject eventObject;
            eventObject = tmpElement.getAsJsonObject();

            tmpElement = eventObject.get(WAKE_INTERVAL);
            if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonPrimitive()) {
              eventReportingWakeInterval = tmpElement.getAsInt();
            }
            tmpElement = eventObject.get(MINIMUM_COUNT);
            if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonPrimitive()) {
              eventReportingMinimumCount = tmpElement.getAsInt();
            }
            tmpElement = eventObject.get(FLUSH_INTERVAL);
            if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonPrimitive()) {
              eventReportingFlushInterval = tmpElement.getAsInt();
            }
            tmpElement = eventObject.get(TRAP_EXCEPTIONS);
            if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonPrimitive()) {
              eventReportingTrapExceptions = tmpElement.getAsBoolean();
            }
            tmpElement = eventObject.get(TIMESTAMP_GRANULARITY);
            if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonPrimitive()) {
              eventReportingTimestampGranularity = findEventReportingGranularity(tmpElement.getAsString());
            }
          } // EVENT_REPORTING object

          tmpElement = cfgObject.get(KEY_CACHING);
          if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonObject()) {
            JsonObject cachingObject;
            cachingObject = tmpElement.getAsJsonObject();

            tmpElement = cachingObject.get(TTL_SECONDS);
            if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonPrimitive()) {
              cacheTtlSeconds = tmpElement.getAsInt();
            }
            tmpElement = cachingObject.get(ENCRYPT);
            if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonPrimitive()) {
              cacheEncryptKeys = tmpElement.getAsBoolean();
            }
            tmpElement = cachingObject.get(UNSTRUCTURED);
            if (tmpElement != null && !tmpElement.isJsonNull() && tmpElement.isJsonPrimitive()) {
              cacheUnstructuredKeys = tmpElement.getAsBoolean();
            }
          } // KEY_CACHING object
        } // Configuration object
    }
      
    public Integer getEventReportingWakeInterval() {
        return eventReportingWakeInterval;
    }

    public Integer getEventReportingMinimumCount() {
        return eventReportingMinimumCount;
    }

    public Integer getEventReportingFlushInterval() {
        return eventReportingFlushInterval;
    }

    public Boolean getEventReportingTrapExceptions() {
      return eventReportingTrapExceptions;
    }

    public ChronoUnit getEventReportingTimestampGranularity() {
      return eventReportingTimestampGranularity;
    }

    public Boolean getKeyCacheEncryptKeys() {
      return cacheEncryptKeys;
    }

    public Boolean getKeyCacheUnstructuredKeys() {
      return cacheUnstructuredKeys;
    }

    public Integer getKeyCacheTtlSeconds() {
      return cacheTtlSeconds;
  }
}
