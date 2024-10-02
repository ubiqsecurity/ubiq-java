package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.IOException;

import java.util.Arrays;
import com.ubiqsecurity.UbiqFactory;

import java.util.concurrent.ExecutionException;


import java.util.*;
import org.junit.rules.ExpectedException;
import java.io.File;
import java.io.FileWriter;
import java.time.temporal.ChronoUnit;

public class UbiqConfigurationTest
{




    @Test
    public void defaultCfg() {

      UbiqConfiguration cfg = UbiqFactory.defaultConfiguration();

      assertNotNull(cfg);
      assertEquals(cfg.getEventReportingWakeInterval().compareTo(1),0);
      assertEquals(cfg.getEventReportingMinimumCount().compareTo(50),0);
      assertEquals(cfg.getEventReportingFlushInterval().compareTo(10),0);
      assertEquals(cfg.getEventReportingTrapExceptions(), false);
      assertEquals(cfg.getKeyCacheEncryptKeys(), false);
      assertEquals(cfg.getKeyCacheUnstructuredKeys(), true);
      assertEquals(cfg.getKeyCacheStructuredKeys(), true);
      assertEquals(cfg.getKeyCacheTtlSeconds().compareTo(1800), 0);
    }

    @Test()
    public void missingFile() {
      Throwable exception = assertThrows(IllegalArgumentException.class, () -> UbiqFactory.readConfigurationFromFile("/tmp/junk"));
    }

    @Test()
    public void emptyFile() throws IOException {
      File file;
      file = File.createTempFile("temp", null);
      file.deleteOnExit();
      UbiqConfiguration cfg = UbiqFactory.readConfigurationFromFile(file.getAbsolutePath());
      UbiqConfiguration cfg_default = UbiqFactory.defaultConfiguration();

      assertNotNull(cfg);
      assertEquals(cfg.getEventReportingWakeInterval().compareTo(cfg_default.getEventReportingWakeInterval()),0);
      assertEquals(cfg.getEventReportingMinimumCount().compareTo(cfg_default.getEventReportingMinimumCount()),0);
      assertEquals(cfg.getEventReportingFlushInterval().compareTo(cfg_default.getEventReportingFlushInterval()),0);
      assertEquals(cfg.getEventReportingTrapExceptions(), cfg_default.getEventReportingTrapExceptions());

      assertEquals(cfg.getKeyCacheEncryptKeys(), cfg_default.getKeyCacheEncryptKeys());
      assertEquals(cfg.getKeyCacheUnstructuredKeys(), cfg_default.getKeyCacheUnstructuredKeys());
      assertEquals(cfg.getKeyCacheTtlSeconds().compareTo(cfg_default.getKeyCacheTtlSeconds()),0);
    }

    @Test()
    public void explicitCfg()  {
      UbiqConfiguration cfg = UbiqFactory.createConfiguration(1,2,3,true, ChronoUnit.NANOS, true, true, 3600);

      assertNotNull(cfg);
      assertEquals(cfg.getEventReportingWakeInterval().compareTo(1),0);
      assertEquals(cfg.getEventReportingMinimumCount().compareTo(2),0);
      assertEquals(cfg.getEventReportingFlushInterval().compareTo(3),0);
      assertEquals(cfg.getEventReportingTrapExceptions(), true);

      assertEquals(cfg.getKeyCacheEncryptKeys(), true);
      assertEquals(cfg.getKeyCacheUnstructuredKeys(), true);
      assertEquals(cfg.getKeyCacheTtlSeconds().compareTo(3600), 0);
    }

    @Test()
    public void writeFile() throws IOException {
      File file;
      file = File.createTempFile("temp", null);

      FileWriter myWriter = new FileWriter(file.getAbsolutePath());
      
      myWriter.write("{");
      myWriter.write("\"event_reporting\" : { ");
      myWriter.write("\"wake_interval\" : 110,");
      myWriter.write("\"minimum_count\" : 250,");
      myWriter.write("\"flush_interval\" : 390,");
      myWriter.write("\"trap_exceptions\" : true");
      myWriter.write("},");
      myWriter.write("\"key_caching\" : { ");
      myWriter.write("\"ttl_seconds\" : 2400,");
      myWriter.write("\"encrypt\" : true,");
      myWriter.write("\"unstructured\" : false,");
      myWriter.write("\"structured\" : false");
      myWriter.write("}}");
      myWriter.close();

      UbiqConfiguration cfg = UbiqFactory.readConfigurationFromFile(file.getAbsolutePath());

      assertNotNull(cfg);
      assertEquals(cfg.getEventReportingWakeInterval().compareTo(110),0);
      assertEquals(cfg.getEventReportingMinimumCount().compareTo(250),0);
      assertEquals(cfg.getEventReportingFlushInterval().compareTo(390),0);
      assertEquals(cfg.getEventReportingTrapExceptions(), true);
      assertEquals(cfg.getKeyCacheEncryptKeys(), true);
      assertEquals(cfg.getKeyCacheUnstructuredKeys(), false);
      assertEquals(cfg.getKeyCacheStructuredKeys(), false);
      assertEquals(cfg.getKeyCacheTtlSeconds().compareTo(2400), 0);
      file.deleteOnExit();
     
    }

    @Test()
    public void incorrectFileFormat() throws IOException {
      File file;
      file = File.createTempFile("temp", null);

      FileWriter myWriter = new FileWriter(file.getAbsolutePath());
      
      myWriter.write("{");
      myWriter.write("\"BAD_event_reporting\" : { ");
      myWriter.write("\"minimum_count\" : 250");
      myWriter.write("},");
      myWriter.write("\"BAD_key_caching\" : { ");
      myWriter.write("\"ttl_seconds\" : 2400");
      myWriter.write("}}");
      myWriter.close();

      UbiqConfiguration cfg = UbiqFactory.readConfigurationFromFile(file.getAbsolutePath());
      UbiqConfiguration defaultCfg = UbiqFactory.defaultConfiguration();
      assertNotNull(cfg);

      assertEquals(cfg.getEventReportingWakeInterval().compareTo(defaultCfg.getEventReportingWakeInterval()),0);
      assertEquals(cfg.getEventReportingMinimumCount().compareTo(defaultCfg.getEventReportingMinimumCount()),0);
      assertEquals(cfg.getEventReportingFlushInterval().compareTo(defaultCfg.getEventReportingFlushInterval()),0);
      assertEquals(cfg.getEventReportingTrapExceptions(), defaultCfg.getEventReportingTrapExceptions());

      assertEquals(cfg.getKeyCacheEncryptKeys(), defaultCfg.getKeyCacheEncryptKeys());
      assertEquals(cfg.getKeyCacheUnstructuredKeys(), defaultCfg.getKeyCacheUnstructuredKeys());
      assertEquals(cfg.getKeyCacheTtlSeconds().compareTo(defaultCfg.getKeyCacheTtlSeconds()),0);

      file.deleteOnExit();
     
    }

    @Test()
    public void partialFileFormat() throws IOException {
      File file;
      file = File.createTempFile("temp", null);

      FileWriter myWriter = new FileWriter(file.getAbsolutePath());
      
      myWriter.write("{");
      myWriter.write("\"event_reporting\" : { ");
      myWriter.write("\"minimum_count\" : 250");
      myWriter.write("},");
      myWriter.write("\"key_caching\" : { ");
      myWriter.write("\"ttl_seconds\" : 2400");
      myWriter.write("}}");
      myWriter.close();

      UbiqConfiguration cfg = UbiqFactory.readConfigurationFromFile(file.getAbsolutePath());
      UbiqConfiguration defaultCfg = UbiqFactory.defaultConfiguration();
      assertNotNull(cfg);

      assertEquals(cfg.getEventReportingWakeInterval().compareTo(defaultCfg.getEventReportingWakeInterval()),0);
      assertEquals(cfg.getEventReportingMinimumCount().compareTo(250),0);
      assertEquals(cfg.getEventReportingFlushInterval().compareTo(defaultCfg.getEventReportingFlushInterval()),0);
      assertEquals(cfg.getEventReportingTrapExceptions(), defaultCfg.getEventReportingTrapExceptions());

      assertEquals(cfg.getKeyCacheEncryptKeys(), defaultCfg.getKeyCacheEncryptKeys());
      assertEquals(cfg.getKeyCacheUnstructuredKeys(), defaultCfg.getKeyCacheUnstructuredKeys());
      assertEquals(cfg.getKeyCacheStructuredKeys(), defaultCfg.getKeyCacheStructuredKeys());
      assertEquals(cfg.getKeyCacheTtlSeconds().compareTo(2400), 0);


      file.deleteOnExit();
     
    }

    @Test()
    public void notJson() throws IOException {
      File file;
      file = File.createTempFile("temp", null);

      FileWriter myWriter = new FileWriter(file.getAbsolutePath());
      
      myWriter.write("{");
      myWriter.write("\"event_reporting\" : { ");
      myWriter.write("\"minimum_count\" : 250,");
      myWriter.write("},}");
      myWriter.close();


      Throwable exception = assertThrows(IllegalArgumentException.class, () -> UbiqFactory.readConfigurationFromFile(file.getAbsolutePath()));

      file.deleteOnExit();
     
    }

}
