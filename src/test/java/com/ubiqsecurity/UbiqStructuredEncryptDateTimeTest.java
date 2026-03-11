package com.ubiqsecurity;

import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.junit.Test;
import static org.junit.Assert.*;

import com.google.gson.*;

import com.ubiqsecurity.structured.FF1;
import com.ubiqsecurity.UbiqFactory;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.time.ZonedDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;

import java.math.BigInteger;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import java.util.*;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;


public class UbiqStructuredEncryptDateTimeTest
{


    @Test
    public void encryptStructured_ValidDateTime() {
      try {
        UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

         List<OffsetDateTime> dt = Arrays.asList(
          OffsetDateTime.parse("1653-02-10T06:13:21.000+00:00"),
          OffsetDateTime.now().truncatedTo(ChronoUnit.SECONDS),
          OffsetDateTime.now(ZoneId.of("UTC")).truncatedTo(ChronoUnit.SECONDS),
          OffsetDateTime.parse("1970-01-01T00:00:00Z"),
          OffsetDateTime.now(ZoneId.of("America/New_York")).truncatedTo(ChronoUnit.SECONDS),
          OffsetDateTime.now(ZoneId.of("America/Los_Angeles")).truncatedTo(ChronoUnit.SECONDS),
          OffsetDateTime.parse("2286-11-20T17:46:39.000+00:00")
         );

        byte[] tweak = null;

        try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

          for (int i = 0; i < dt.size(); i++) {
            OffsetDateTime ct = ubiqEncryptDecrypt.encryptDateTime("datetime", dt.get(i), tweak);
            OffsetDateTime pt = ubiqEncryptDecrypt.decryptDateTime("datetime", ct, tweak);
            assertEquals(dt.get(i), pt);
            OffsetDateTime[] ct_arr = ubiqEncryptDecrypt.encryptDateTimeForSearch("datetime", dt.get(i), tweak);
            Boolean found = false;
            for (int j = 0; j < ct_arr.length; j++) {
              // System.out.printf("CT_arr %s   ct %s\n", ct_arr[j].toString(), ct.toString());
              if (ct_arr[j].equals(ct)) {
                found = true;
              }
              OffsetDateTime d = ubiqEncryptDecrypt.decryptDateTime("datetime", ct, tweak);
              assertEquals(dt.get(i), d);
            }
            assertEquals(found, true);
            if (ct_arr.length > 1) {
              assertEquals(ct_arr[0] == ct_arr[1], false);
            }
            // System.out.println("PT: " + dt.get(i) + "   CT: " + ct + "  PT: " + pt);
          }

        }
      } catch (Exception e) {
        e.printStackTrace();
        assertEquals(false, true);
      }
    }

  }