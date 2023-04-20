package com.ubiqsecurity;

import java.io.IOException;
import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.File;

public class UbiqConfiguration {
    // Configuration Element names
    private final String EVENT_REPORTING = "event_reporting";
    private final String WAKE_INTERVAL = "wake_interval";
    private final String MINIMUM_COUNT = "minimum_count";
    private final String FLUSH_INTERVAL = "flush_interval";
    private final String TRAP_EXCEPTIONS = "trap_exceptions";

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
    private Integer eventReportingMinimumCount = 5;
    private Integer eventReportingFlushInterval = 10;
    private Boolean eventReportingTrapExceptions = false;

    UbiqConfiguration(
      Integer eventReportingWakeInterval,
      Integer eventReportingMinimumCount,
      Integer eventReportingFlushInterval,
      Boolean eventReportingTrapExceptions) {

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
    }

    UbiqConfiguration(String pathname) throws IOException {
      JsonObject cfgObject;
      JsonObject eventObject;
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
            }
          }
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
}
