package com.ubiqsecurity;

import java.io.IOException;
import java.time.temporal.ChronoUnit;

public abstract class UbiqFactory {
    private static final String DEFAULT_UBIQ_HOST = "api.ubiqsecurity.com";

    public static UbiqCredentials createCredentials(String accessKeyId, String secretSigningKey,
            String secretCryptoAccessKey, String host) {
        if ((host == null) || host.isEmpty()) {
            host = DEFAULT_UBIQ_HOST;
        }
        return new UbiqCredentials(accessKeyId, secretSigningKey, secretCryptoAccessKey, host);
    }

    public static UbiqCredentials readCredentialsFromFile(String pathname, String profile) throws IOException {
        return new UbiqCredentials(pathname, profile, DEFAULT_UBIQ_HOST);
    }

    public static UbiqConfiguration defaultConfiguration() {
      UbiqConfiguration cfg;
      try {
        cfg = readConfigurationFromFile(null);
      } catch (IllegalArgumentException e) {
        cfg = createConfiguration(null,null,null,null,null);
      } catch (IOException e) {
        cfg = createConfiguration(null,null,null,null,null);
      }
      return cfg;
    }

    public static UbiqConfiguration createConfiguration(
      Integer eventReportingWakeInterval,
      Integer eventReportingMinimumCount,
      Integer eventReportingFlushInterval,
      Boolean eventReportingTrapExceptions) {
        return createConfiguration(eventReportingWakeInterval, eventReportingMinimumCount,
          eventReportingFlushInterval, eventReportingTrapExceptions, ChronoUnit.NANOS);
      }

    public static UbiqConfiguration createConfiguration(
      Integer eventReportingWakeInterval,
      Integer eventReportingMinimumCount,
      Integer eventReportingFlushInterval,
      Boolean eventReportingTrapExceptions,
      ChronoUnit eventReportingTimestampGranularity) {
        
      return new UbiqConfiguration(eventReportingWakeInterval, eventReportingMinimumCount, 
          eventReportingFlushInterval, eventReportingTrapExceptions, eventReportingTimestampGranularity);
    }


    public static UbiqConfiguration readConfigurationFromFile(String pathname) throws IOException {
        return new UbiqConfiguration(pathname);
    }


}
