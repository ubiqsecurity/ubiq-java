package com.ubiqsecurity;

import java.io.IOException;
import java.time.temporal.ChronoUnit;

public abstract class UbiqFactory {

    public static UbiqCredentials createCredentials(String accessKeyId, String secretSigningKey,
            String secretCryptoAccessKey, String host) {
        return new UbiqCredentials(accessKeyId, secretSigningKey, secretCryptoAccessKey, host);
    }

    public static UbiqCredentials readCredentialsFromFile(String pathname, String profile) throws IOException {
        return new UbiqCredentials(pathname, profile);
    }

    public static UbiqCredentials defaultCredentials() {
      UbiqCredentials creds;
      try {
        creds = readCredentialsFromFile(null,null);
      } catch (IllegalArgumentException| IOException e) {
        creds = createCredentials(null,null,null,null);
      }
      return creds;
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
          eventReportingFlushInterval, eventReportingTrapExceptions, ChronoUnit.NANOS, 
          null, null, null, null);
      }

    public static UbiqConfiguration createConfiguration(
      Integer eventReportingWakeInterval,
      Integer eventReportingMinimumCount,
      Integer eventReportingFlushInterval,
      Boolean eventReportingTrapExceptions,
      ChronoUnit eventReportingTimestampGranularity) {
        
      return new UbiqConfiguration(eventReportingWakeInterval, eventReportingMinimumCount, 
          eventReportingFlushInterval, eventReportingTrapExceptions, eventReportingTimestampGranularity,
          null, null, null, null);
    }

    public static UbiqConfiguration createConfiguration(
      Integer eventReportingWakeInterval,
      Integer eventReportingMinimumCount,
      Integer eventReportingFlushInterval,
      Boolean eventReportingTrapExceptions,
      ChronoUnit eventReportingTimestampGranularity,
      Boolean cacheEncryptKeys,
      Boolean cacheUnstructuredKeys,
      Integer cacheTtlSeconds ) {
        return new UbiqConfiguration(eventReportingWakeInterval, eventReportingMinimumCount, 
        eventReportingFlushInterval, eventReportingTrapExceptions, eventReportingTimestampGranularity,
        cacheEncryptKeys, null, cacheUnstructuredKeys, cacheTtlSeconds);
      }

    public static UbiqConfiguration createConfiguration(
      Integer eventReportingWakeInterval,
      Integer eventReportingMinimumCount,
      Integer eventReportingFlushInterval,
      Boolean eventReportingTrapExceptions,
      ChronoUnit eventReportingTimestampGranularity,
      Boolean cacheEncryptKeys,
      Boolean cacheStructuredKeys,
      Boolean cacheUnstructuredKeys,
      Integer cacheTtlSeconds ) {

      return new UbiqConfiguration(eventReportingWakeInterval, eventReportingMinimumCount,
          eventReportingFlushInterval, eventReportingTrapExceptions, eventReportingTimestampGranularity,
          cacheEncryptKeys, cacheStructuredKeys, cacheUnstructuredKeys, cacheTtlSeconds);
    }


    public static UbiqConfiguration readConfigurationFromFile(String pathname) throws IOException {
        return new UbiqConfiguration(pathname);
    }


}
