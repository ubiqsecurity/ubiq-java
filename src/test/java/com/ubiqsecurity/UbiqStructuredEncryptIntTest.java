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



public class UbiqStructuredEncryptIntTest
{


    @Test
    public void encryptStructured_ValidInt() {
      try {
        UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

         List<Integer> dt = Arrays.asList(
          -99999999,
          -1,
          0,
          1,
          99999999
         );

        byte[] tweak = null;

        try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

          for (int i = 0; i < dt.size(); i++) {
            int ct = ubiqEncryptDecrypt.encryptInt("integer32", dt.get(i).intValue(), tweak);
            int pt = ubiqEncryptDecrypt.decryptInt("integer32", ct, tweak);
            assertEquals(dt.get(i).intValue(), pt);
            int[] ct_arr = ubiqEncryptDecrypt.encryptIntForSearch("integer32", dt.get(i).intValue(), tweak);
            Boolean found = false;
            for (int j = 0; j < ct_arr.length; j++) {
              if (ct_arr[j] == ct) {
                found = true;
              }
              int x = ubiqEncryptDecrypt.decryptInt("integer32", ct_arr[j], tweak);
              assertEquals(pt, x);
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