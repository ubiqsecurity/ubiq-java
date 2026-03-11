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


public class UbiqStructuredEncryptGenericStringTest
{


    @Test
    public void encryptStructured_ValidGeneric32() {
        UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

         List<String> dt = Arrays.asList(
          "",
          "123",
          "ABC",
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
         );

        byte[] tweak = null;

        try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

          for (int i = 0; i < dt.size(); i++) {
            String ct = ubiqEncryptDecrypt.encrypt("generic_string_32", dt.get(i), tweak);
            String pt = ubiqEncryptDecrypt.decrypt("generic_string_32", ct, tweak);
            assertEquals(dt.get(i), pt);

            String[] ct_arr = ubiqEncryptDecrypt.encryptForSearch("generic_string_32", dt.get(i), tweak);

            Boolean found = false;
            for (int j = 0; j < ct_arr.length; j++) {
              if (ct_arr[j].equals(ct)) {
                found = true;
              }
              String x = ubiqEncryptDecrypt.decrypt("generic_string_32", ct_arr[j], tweak);
              assertEquals(pt, x);
            }
            assertEquals(found, true);
            if (ct_arr.length > 1) {
              assertEquals(ct_arr[0] == ct_arr[1], false);
            }
            // System.out.printf("%s  PT: '%s'  CT '%s'\n", Thread.currentThread().getStackTrace()[1].getMethodName(),  dt.get(i), ct );
          }

        }
    }

    @Test
    public void encryptStructured_ValidGeneric64() {
        UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

         List<String> dt = Arrays.asList(
          "",
          "123",
          "ABC",
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
         );

        byte[] tweak = null;

        try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

          for (int i = 0; i < dt.size(); i++) {
            String ct = ubiqEncryptDecrypt.encrypt("generic_string_64", dt.get(i), tweak);
            String pt = ubiqEncryptDecrypt.decrypt("generic_string_64", ct, tweak);
            assertEquals(dt.get(i), pt);

            String[] ct_arr = ubiqEncryptDecrypt.encryptForSearch("generic_string_64", dt.get(i), tweak);

            Boolean found = false;
            for (int j = 0; j < ct_arr.length; j++) {
              if (ct_arr[j].equals(ct)) {
                found = true;
              }
              String x = ubiqEncryptDecrypt.decrypt("generic_string_64", ct_arr[j], tweak);
              assertEquals(pt, x);
            }
            assertEquals(found, true);
            if (ct_arr.length > 1) {
              assertEquals(ct_arr[0] == ct_arr[1], false);
            }

            // System.out.printf("%s  PT: '%s'  CT '%s'\n", Thread.currentThread().getStackTrace()[1].getMethodName(),  dt.get(i), ct );

          }

        }
    }

  }