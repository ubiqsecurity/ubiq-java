package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;
import java.math.BigInteger;
import java.util.Arrays;
import com.ubiqsecurity.structured.FF1;
import com.ubiqsecurity.UbiqFactory;
import java.util.concurrent.ExecutionException;
import java.util.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import java.io.IOException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import com.google.gson.*;
import java.time.temporal.ChronoUnit;

import java.util.concurrent.TimeUnit;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.text.DateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;


import java.util.concurrent.atomic.AtomicInteger;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Arrays;

import java.security.SecureRandom;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.Iterator;
import java.lang.Thread;

import java.time.Duration;
import java.time.Instant;

class Multithreading implements Runnable {
      UbiqStructuredEncryptDecrypt encrypt;
      UbiqStructuredEncryptDecrypt decrypt;
      SecureRandom random;
      static String datasetName = "base64_with_pad";

      Multithreading(UbiqStructuredEncryptDecrypt encrypt, UbiqStructuredEncryptDecrypt decrypt, SecureRandom random) {
        this.encrypt = encrypt;
        this.decrypt = decrypt;
        this.random = random;
      }

        public void run()
        {
            try {
              long len = random.nextInt(20) + 1;
              byte bytes[] = new byte[(int)len];
              random.nextBytes(bytes);

              String encoded = Base64.getEncoder().encodeToString(bytes);
              String encodedNoPad = encoded;

              if(encoded.length() < 6){
                  encoded = encoded.concat(String.format("%" + (6 - encoded.length()) + "s", "").replace(' ', '!'));
              }
              String strToEncrypt=encoded;

              String ubiqEncrypt = encrypt.encrypt(datasetName, strToEncrypt, null);

              String urlEncoded = Base64.getUrlEncoder().encodeToString(ubiqEncrypt.getBytes(StandardCharsets.UTF_8));

              if (urlEncoded.indexOf('\\') >= 0) {
                System.out.println("urlEncoded string contains slash(\\): " + urlEncoded);
              }

              Object s = urlEncoded;

              String toDecrypt = s.toString();

              String urlDecode = new String (Base64.getUrlDecoder().decode(toDecrypt),StandardCharsets.UTF_8);
              String ubiqDecrypt = decrypt.decrypt(datasetName, urlDecode, null);

              String ubiqDecryptNoPad = ubiqDecrypt.replace("!","");

              byte dec[] = Base64.getDecoder().decode(ubiqDecryptNoPad);

              assertEquals(Arrays.equals(dec, bytes), true);
              assertEquals(encodedNoPad, ubiqDecryptNoPad);

            }
            catch (Exception e) {
                
                // Throwing an exception
                System.out.println("Exception is caught " + e.getMessage());
            }

        }
    }

public class UbiqStructuredMultithreadTest
{

    @Test
    public void multithread() {
    UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
    UbiqStructuredEncryptDecrypt encrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials);
    UbiqStructuredEncryptDecrypt decrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials);
    SecureRandom random = new SecureRandom();

    Collection<Thread> syncCollection = Collections.synchronizedCollection(new ArrayList<>());
    Instant s = Instant.now();

    int n = 20; // Number of threads
      for (int j = 0; j < 10000; j++) {
        for (int i = 0; i < n; i++) {
            Thread object = new Thread(new Multithreading(encrypt, decrypt, random));
            object.start();
            syncCollection.add(object);
        }
        try {
        Thread.sleep(1);
        Iterator<Thread> iterator = syncCollection.iterator();
        while (iterator.hasNext()) {
          iterator.next().join();
        // Use the element
        }}
        catch (InterruptedException e) {

        }
        syncCollection.clear();
      }
      encrypt.close();
      decrypt.close();
      Instant e = Instant.now();

      System.out.println("Elapsed Time: (nanos)" + Duration.between(s, e).toNanos());
  }
}
