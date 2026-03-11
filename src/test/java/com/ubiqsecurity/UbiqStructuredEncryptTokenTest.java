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


public class UbiqStructuredEncryptTokenTest
{


    @Test
    public void encryptStructured_ValidToken64() {
        UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

         List<String> dt = Arrays.asList(
          "123",
          "ABC",
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 40 characters => 64 base32
          ""
         );

        byte[] tweak = null;

        try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

          for (int i = 0; i < dt.size(); i++) {
            String ct = ubiqEncryptDecrypt.encrypt("token64", dt.get(i), tweak);
            String pt = ubiqEncryptDecrypt.decrypt("token64", ct, tweak);
            assertEquals(dt.get(i), pt);
            assertEquals(ct.length(), 64);

            String[] ct_arr = ubiqEncryptDecrypt.encryptForSearch("token64", dt.get(i), tweak);

            Boolean found = false;
            for (int j = 0; j < ct_arr.length; j++) {
              // System.out.printf("j(%d) ct_arr[%d] %s  CT %s \n", j, j, ct_arr[j], ct);
              if (ct_arr[j].equals(ct)) {
                found = true;
              }
              String x = ubiqEncryptDecrypt.decrypt("token64", ct_arr[j], tweak);
              assertEquals(pt, x);
            }
            assertEquals(found, true);
            if (ct_arr.length > 1) {
              assertEquals(ct_arr[0] == ct_arr[1], false);
            }
            // System.out.println("PT: " + dt.get(i) + "   CT: " + ct + "  PT: " + pt);
          }

        }
    }

    @Test
    public void encryptStructured_ValidToken128() {
        UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

         List<String> dt = Arrays.asList(
          "123",
          "ABC",
          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 80 characters => 128 base32
          ""
         );

        byte[] tweak = null;

        try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

          for (int i = 0; i < dt.size(); i++) {
            String ct = ubiqEncryptDecrypt.encrypt("token128", dt.get(i), tweak);
            String pt = ubiqEncryptDecrypt.decrypt("token128", ct, tweak);
            assertEquals(dt.get(i), pt);
            assertEquals(ct.length(), 128);

            String[] ct_arr = ubiqEncryptDecrypt.encryptForSearch("token128", dt.get(i), tweak);

            Boolean found = false;
            for (int j = 0; j < ct_arr.length; j++) {
              // System.out.printf("j(%d) ct_arr[%d] %s  CT %s \n", j, j, ct_arr[j], ct);

              if (ct_arr[j].equals(ct)) {
                found = true;
              }
              String x = ubiqEncryptDecrypt.decrypt("token128", ct_arr[j], tweak);
              assertEquals(pt, x);
            }
            assertEquals(found, true);
            if (ct_arr.length > 1) {
              assertEquals(ct_arr[0] == ct_arr[1], false);
            }

            // System.out.println("PT: " + dt.get(i) + "   CT: " + ct + "  PT: " + pt);
          }

        }
    }

  }