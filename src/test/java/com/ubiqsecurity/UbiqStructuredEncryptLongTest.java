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

import javax.crypto.Cipher;



public class UbiqStructuredEncryptLongTest
{


    @Test
    public void encryptStructured_ValidInt() {
      try {
        UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        Boolean verbose = false;

         List<Long> dt = Arrays.asList(
          -9999999999999999L,
          -1L,
          0L,
          1L,
          9999999999999999L
         );

        byte[] tweak = null;

        try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

          for (int i = 0; i < dt.size(); i++) {
            long ct = ubiqEncryptDecrypt.encryptLong("integer64", dt.get(i).longValue(), tweak);
            // System.out.printf("i(%d) dt(%d) ct(%d)\n", i, dt.get(i).longValue(), ct);
            long pt = ubiqEncryptDecrypt.decryptLong("integer64", ct, tweak);
            // System.out.printf("  pt(%d)\n", pt);
            assertEquals(dt.get(i).longValue(), pt);
            long[] ct_arr = ubiqEncryptDecrypt.encryptLongForSearch("integer64", dt.get(i).longValue(), tweak);
            Boolean found = false;
            for (int j = 0; j < ct_arr.length; j++) {
              if (ct_arr[j] == ct) {
                found = true;
              }
              long x = ubiqEncryptDecrypt.decryptLong("integer64", ct_arr[j], tweak);
              assertEquals(x, pt);
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