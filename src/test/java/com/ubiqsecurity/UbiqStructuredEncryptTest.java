package com.ubiqsecurity;

import java.time.Duration;
import java.time.Instant;

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

public class UbiqStructuredEncryptTest
{
    private final String UBIQ_UNITTEST_ENCRYPTED_PRIVATE_KEY = "UBIQ_UNITTEST_ENCRYPTED_PRIVATE_KEY";

    static void testCycleEncryption(String dataset_name, String plainText, UbiqCredentials ubiqCredentials) {

        try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
            String result = ubiqEncryptDecrypt.encrypt(dataset_name, plainText, null);
            result = ubiqEncryptDecrypt.decrypt(dataset_name, result, null);
        }
    }


    static void testRt(String dataset_name, String plainText, String expectedCt) 
    {
      UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

      final byte[] tweak = null;

      try {
        testBatchRt(dataset_name, plainText, expectedCt, ubiqCredentials, tweak);
      }
     catch (Exception ex) {
      System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
      ex.printStackTrace();
      fail(ex.toString());
    }

  }


    static void testBatchRt(String dataset_name, String plainText, String expectedCt, UbiqCredentials ubiqCredentials,  byte[] tweak)
      throws IOException, InvalidCipherTextException{

        UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials);

          String ct = ubiqEncryptDecrypt.encrypt(dataset_name, plainText, null);
          String pt = ubiqEncryptDecrypt.decrypt(dataset_name, ct, null);
          assertEquals(plainText, pt);

          pt = ubiqEncryptDecrypt.decrypt(dataset_name, expectedCt, null);
          assertEquals(plainText, pt);

          String[] ct_arr = ubiqEncryptDecrypt.encryptForSearch(dataset_name, plainText, tweak);

          Boolean foundCt = false;
          for (String x : ct_arr) {
            foundCt = foundCt || (expectedCt.equals(x));
            pt = ubiqEncryptDecrypt.decrypt(dataset_name, x, tweak);
            assertEquals(plainText, pt);
          }
          assertEquals(foundCt, true);

      }

    @Test
    public void encryptStructured_ALPHANUM_SSN() {
            testRt("ALPHANUM_SSN", ";0123456-789ABCDEF|", ";!!!E7`+-ai1ykOp8r|");
    }

    @Test
    public void encryptStructured_BIRTH_DATE() {
      testRt("BIRTH_DATE", ";01\\02-1960|", ";!!\\!!-oKzi|");
    }

    @Test
    public void encryptStructured_SSN() {
      testRt("SSN", "-0-1-2-3-4-5-6-7-8-9-", "-0-0-0-0-1-I-L-8-j-D-");
    }

    @Test
    public void encryptStructured_UTF8_STRING_COMPLEX() {
      testRt("UTF8_STRING_COMPLEX", "ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ", "ÑÒÓにΪΪΪΪΪΪ3ÔÕoeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはʑʒʓÏRϼĶufÝK3MXaʔʕ");
    }

    @Test
    public void encryptStructured_UTF8_STRING_COMPLEX_2() {
      testRt("UTF8_STRING_COMPLEX", "ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ", "にΪΪΪΪΪΪ3oeϽΫAÛMĸOZphßÚdyÌô0ÝϼPtĸTtSKにVÊϾέÛはÏRϼĶufÝK3MXa");
    }

    @Test
    public void encryptStructured_TEST_CACHING() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

            String pt_generic = ";0123456-789ABCDEF|";
            String ct_generic = "";

            String pt_alphanum = ";01\\02-1960|";
            String ct_alphanum = "";

            try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
                ct_generic = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", pt_generic, null);
            }

            try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
                ct_alphanum = ubiqEncryptDecrypt.encrypt("BIRTH_DATE", pt_alphanum, null);
            }

            try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

              ubiqEncryptDecrypt.addReportingUserDefinedMetadata("{ \"att_encryption_wrapper\" : true }");
              String ct_generic_2 = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", pt_generic, null);
              String ct_alphanum_2 = ubiqEncryptDecrypt.encrypt("BIRTH_DATE", pt_alphanum, null);

              String pt_generic_2 = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", ct_generic, null);
              String pt_alphanum_2 = ubiqEncryptDecrypt.decrypt("BIRTH_DATE", ct_alphanum, null);


              assertEquals(ct_generic, ct_generic_2);
              assertEquals(ct_alphanum_2, ct_alphanum);

              assertEquals(pt_generic, pt_generic_2);
              assertEquals(pt_alphanum, pt_alphanum_2);
            }

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }


    @Test
    public void encryptSearch() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

            String pt_generic = "123456789";
            String ct_generic = "";
            String pt_alphanum = "123456789789ABCDEF";
            String ct_alphanum = "";

            boolean match = false;
            UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials);
            ct_generic = ubiqEncryptDecrypt.encrypt("SSN", pt_generic, null);
            ct_alphanum = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", pt_alphanum, null);

            String ct_generic_array[] = ubiqEncryptDecrypt.encryptForSearch("SSN", pt_generic, null);
            String ct_alphanum_array[] = ubiqEncryptDecrypt.encryptForSearch("ALPHANUM_SSN", pt_alphanum, null);

            match = false;
            for (String ct : ct_generic_array) {
              match = match || (ct.equals(ct_generic));
            }

            if (!match) {
              fail("Unable to find matching value for '" + pt_generic + "'");
            }

            match = false;
            for (String ct : ct_alphanum_array) {
              match = match || (ct.equals(ct_alphanum));
            }

            if (!match) {
              fail("Unable to find matching value for '" + pt_alphanum + "'");
            }
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }

    @Test
    public void loadCache() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
            UbiqConfiguration cfg = UbiqFactory.createConfiguration(
              1800,
              1800,
              1800,
              true,
              ChronoUnit.MINUTES,
              false,
              true,
              true,
              3);

            String pt_generic = "123456789";
            String ct_generic = "";
            String pt_alphanum = "123456789789ABCDEF";
            String ct_alphanum = "";

            boolean match = false;

            UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials, cfg);

            System.out.println("To verify - Change LoadSearchKeys verbose to True");
            System.out.println("Before first Hydrate Call");
            ubiqEncryptDecrypt.loadCache("ALPHANUM_SSN");
            System.out.println("Before Second updateCache Call");
            ubiqEncryptDecrypt.loadCache("ALPHANUM_SSN");
            System.out.println("After Second Hydrate Call");

            System.out.println("Sleep for 6 but should cause cache to be expired");
            Thread.sleep(6000);
            ubiqEncryptDecrypt.loadCache("ALPHANUM_SSN");
            System.out.println("Sleep for 2 but should cause cache TTL to reset");
            Thread.sleep(2000);
            ubiqEncryptDecrypt.loadCache("ALPHANUM_SSN");
            System.out.println("Sleep for 2 but should cause cache TTL to reset");
            Thread.sleep(2000);
            ubiqEncryptDecrypt.loadCache("ALPHANUM_SSN");
            System.out.println("Sleep for 2 but should cause cache TTL to reset");
            Thread.sleep(2000);
            ubiqEncryptDecrypt.loadCache("ALPHANUM_SSN");
            System.out.println("Sleep for 4 so cache should be expired");
            Thread.sleep(4000);
            ubiqEncryptDecrypt.loadCache("ALPHANUM_SSN");

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }

        @Test
    public void loadCacheMultipleDatasets() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
            UbiqConfiguration cfg = UbiqFactory.createConfiguration(
              1800,
              1800,
              1800,
              true,
              ChronoUnit.MINUTES,
              false,
              true,
              true,
              3);

            final byte[] tweak = null;


            String[] datasets = {"BIRTH_DATE", "ALPHANUM_SSN", "bad"};
            String dataset = "ALPHANUM_SSN";
            String pt = "121-34-5678";
            String ct = "";

            Long uncached_encrypt;
            Long cached_encrypt;

            boolean match = false;

            {
              UbiqStructuredEncryptDecrypt ubiqEncrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials, cfg);

              Instant s = Instant.now();
              ct = ubiqEncrypt.encrypt(dataset, pt, tweak);
              Instant e = Instant.now();
              uncached_encrypt = Duration.between(s, e).toNanos();
            }

            UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials, cfg);

            System.out.println("To verify - Change LoadSearchKeys verbose to True");
            System.out.println("Before first Hydrate Call");
            ubiqEncryptDecrypt.loadCache(datasets);

            {
              Instant s = Instant.now();
              ct = ubiqEncryptDecrypt.encrypt(dataset, pt, tweak);
              Instant e = Instant.now();
              cached_encrypt =  Duration.between(s, e).toNanos();
              assertTrue(Duration.between(s, e).toNanos() < uncached_encrypt);
            }

            System.out.println("Before Second updateCache Call");
            ubiqEncryptDecrypt.loadCache(datasets);
            System.out.println("After Second Hydrate Call");

            System.out.println("Sleep for 6 but should cause cache to be expired");
            Thread.sleep(6000);
            {
              Instant s = Instant.now();
              ct = ubiqEncryptDecrypt.encrypt(dataset, pt, tweak);
              Instant e = Instant.now();
              assertTrue(Duration.between(s, e).toNanos() > cached_encrypt);
            }

            ubiqEncryptDecrypt.loadCache(datasets);
            System.out.println("Sleep for 2 but should cause cache TTL to reset");
            Thread.sleep(2000);
            ubiqEncryptDecrypt.loadCache(datasets);
            {
              Instant s = Instant.now();
              ct = ubiqEncryptDecrypt.encrypt(dataset, pt, tweak);
              Instant e = Instant.now();
              cached_encrypt =  Duration.between(s, e).toNanos();
              assertTrue(Duration.between(s, e).toNanos() < uncached_encrypt);
            }

            System.out.println("Sleep for 2 but should cause cache TTL to reset");
            Thread.sleep(2000);
            ubiqEncryptDecrypt.loadCache(datasets);
            {
              Instant s = Instant.now();
              ct = ubiqEncryptDecrypt.encrypt(dataset, pt, tweak);
              Instant e = Instant.now();
              cached_encrypt =  Duration.between(s, e).toNanos();
              assertTrue(Duration.between(s, e).toNanos() < uncached_encrypt);
            }
            System.out.println("Sleep for 2 but should cause cache TTL to reset");
            Thread.sleep(2000);
            ubiqEncryptDecrypt.loadCache(datasets);
            {
              Instant s = Instant.now();
              ct = ubiqEncryptDecrypt.encrypt(dataset, pt, tweak);
              Instant e = Instant.now();
              cached_encrypt =  Duration.between(s, e).toNanos();
              assertTrue(Duration.between(s, e).toNanos() < uncached_encrypt);
            }
            System.out.println("Sleep for 4 so cache should be expired");
            Thread.sleep(4000);
            {
              Instant s = Instant.now();
              ct = ubiqEncryptDecrypt.encrypt(dataset, pt, tweak);
              Instant e = Instant.now();
              assertTrue(Duration.between(s, e).toNanos() > cached_encrypt);
            }
            ubiqEncryptDecrypt.loadCache(datasets);

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            ex.printStackTrace();
            fail(ex.toString());
        }
    }

    @Test
    public void encryptStructured_MultipleCachedKeys() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };

            try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
                String original = "123-45-6789";
                String pt_generic =  ";01\\02-1960|";

                String cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                String cipher2 = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                // clear the key cache and force going back to server

                ubiqEncryptDecrypt.clearKeyCache();
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                // clear the key cache and force going back to server
                ubiqEncryptDecrypt.clearKeyCache();
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);
                String cipher_generic = ubiqEncryptDecrypt.encrypt("BIRTH_DATE", pt_generic, tweakFF1);
                cipher = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", original, tweakFF1);

                assertEquals(cipher, cipher2);

                String decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                String decrypted2 = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                // clear the key cache and force going back to server
                ubiqEncryptDecrypt.clearKeyCache();
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("BIRTH_DATE", cipher_generic, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", cipher, tweakFF1);

                assertEquals(decrypted, decrypted2);

                assertEquals(original, decrypted);
            }

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
          ex.printStackTrace();
            fail(ex.toString());

        }
    }

/*
    @Test
    public void encryptStructured_Speed() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            String pt_generic = "A STRING OF AT LEAST 15 UPPER CHARACTERS";
            String ct_generic = "";
            String tmp = "";

            String pt_alphanum = "ABCD";
            String ct_alphanum = "";

            
            try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
              long start = System.nanoTime();
              int count = 1000000;
              for (int i = 0; i < count; i++) {
                ct_generic = ubiqEncryptDecrypt.encrypt("GENERIC_STRING", pt_generic, null);
              }
              long finish = System.nanoTime();
              System.out.println(String.format("Encrypt %s %d records in %.4f seconds or %.4f ms/rec", "GENERIC_STRING", count,  ((finish - start) / 1000000000.0), ((finish - start) / 1000000.0)/count));

              start = System.nanoTime();
              for (int i = 0; i < count; i++) {
                tmp = ubiqEncryptDecrypt.decrypt("GENERIC_STRING", ct_generic, null);
              }
              finish = System.nanoTime();
              System.out.println(String.format("Decrypt %s %d records in %.4f seconds or %.4f ms/rec", "GENERIC_STRING", count,  ((finish - start) / 1000000000.0), ((finish - start) / 1000000.0)/count));
              assertEquals(pt_generic, tmp);

            }

            try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
              long start = System.nanoTime();
              int count = 1000000;
              for (int i = 0; i < count; i++) {
                ct_alphanum = ubiqEncryptDecrypt.encrypt("SO_ALPHANUM_PIN", pt_alphanum, null);
              }
              long finish = System.nanoTime();
              System.out.println(String.format("Encrypt %s %d records in %.4f seconds or %.4f ms/rec", "SO_ALPHANUM_PIN", count,  ((finish - start) / 1000000000.0), ((finish - start) / 1000000.0)/ count));

              start = System.nanoTime();
              for (int i = 0; i < count; i++) {
                tmp = ubiqEncryptDecrypt.decrypt("SO_ALPHANUM_PIN", ct_alphanum, null);
              }
              finish = System.nanoTime();
              System.out.println(String.format("Decrypt %s %d records in %.4f seconds or %.4f ms/rec", "SO_ALPHANUM_PIN", count,  ((finish - start) / 1000000000.0), ((finish - start) / 1000000.0)/ count));
              assertEquals(pt_alphanum, tmp);
            }

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }
 */



    @Test(expected = Exception.class)
    public void encryptStructured_InvalidDataset() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        testCycleEncryption("ERROR Dataset", "ABCDEFGHI", ubiqCredentials);
    }



    @Test(expected = Exception.class)
    public void encryptStructured_InvalidCredentials() {
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.createCredentials("a","b","c", "d");
        } catch (Exception ex) {
        }

        testCycleEncryption("ALPHANUM_SSN", "ABCDEFGHI", ubiqCredentials);
    }



    @Test(expected = Exception.class)
    public void encryptStructured_Invalid_PT_CT() {
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        testCycleEncryption("SSN", " 123456789$", ubiqCredentials);
    }

    @Test(expected = Exception.class)
    public void encryptStructured_Invalid_LEN_1() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        testCycleEncryption("SSN", " 1234", ubiqCredentials);
    }

    @Test(expected = Exception.class)
    public void encryptStructured_Invalid_LEN_2() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        testCycleEncryption("SSN", " 12345678901234567890", ubiqCredentials);
    }


    @Test(expected = Exception.class)
    public void encryptStructured_Invalid_specific_creds_1() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
          ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId().substring(0, 1),
                                                            ubiqCredentials.getSecretSigningKey(),
                                                            ubiqCredentials.getSecretCryptoAccessKey(),
                                                            ubiqCredentials.getHost() );
        } catch (Exception ex) {
        }

        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);
    }


    @Test(expected = Exception.class)
    public void encryptStructured_Invalid_specific_creds_2() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
          ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId(),
                                                            ubiqCredentials.getSecretSigningKey().substring(0, 1),
                                                            ubiqCredentials.getSecretCryptoAccessKey(),
                                                            ubiqCredentials.getHost() );
        } catch (Exception ex) {
        }

        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);
    }


    @Test(expected = Exception.class)
    public void encryptStructured_Invalid_specific_creds_3() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
          ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId(),
                                                            ubiqCredentials.getSecretSigningKey(),
                                                            ubiqCredentials.getSecretCryptoAccessKey().substring(0, 1),
                                                            ubiqCredentials.getHost() );
        } catch (Exception ex) {
        }

        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);
    }


    @Test(expected = Exception.class)
    public void encryptStructured_Invalid_specific_creds_4() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
          ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId(),
                                                            ubiqCredentials.getSecretSigningKey(),
                                                            ubiqCredentials.getSecretCryptoAccessKey(),
                                                            "pi.ubiqsecurity.com" );
        } catch (Exception ex) {
        }

        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);
    }


    @Test(expected = Exception.class)
    public void encryptStructured_Invalid_specific_creds_5() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
          ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId(),
                                                            ubiqCredentials.getSecretSigningKey(),
                                                            ubiqCredentials.getSecretCryptoAccessKey(),
                                                            "ps://api.ubiqsecurity.com" );
        } catch (Exception ex) {
        }

        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);
    }

    @Test(expected = Exception.class)
    public void encryptStructured_Invalid_specific_creds_6() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
          ubiqCredentials = UbiqFactory.createCredentials(ubiqCredentials.getAccessKeyId(),
                                                            ubiqCredentials.getSecretSigningKey(),
                                                            ubiqCredentials.getSecretCryptoAccessKey(),
                                                            "https://google.com" );
        } catch (Exception ex) {
        }

        testCycleEncryption("ALPHANUM_SSN", " 123456789", ubiqCredentials);
    }


    @Test(expected = Exception.class)
    public void encryptStructured_Invalid_keynum() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
                String cipher = ubiqEncryptDecrypt.encrypt("SSN", " 0123456789", null);
                StringBuilder newcipher = new StringBuilder(cipher);
                newcipher.setCharAt(0, '}');
                String decrypted = ubiqEncryptDecrypt.decrypt("SSN", newcipher.toString(), null);
        }
    }


    @Test(expected = Exception.class)
    public void encryptStructured_Error_handling_invalid_dataset() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        testCycleEncryption("ERROR_MSG", " 01121231231231231& 1 &2311200 ", ubiqCredentials);
    }

    @Test
    public void addReportingUserDefinedMetadataTest() {
      UbiqCredentials ubiqCredentials= null;
      try {
        ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
      } catch (Exception ex) {
      }

      try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {


      Throwable exception = assertThrows(IllegalArgumentException.class, () -> ubiqEncryptDecrypt.addReportingUserDefinedMetadata(""));
      exception = assertThrows(IllegalArgumentException.class, () -> ubiqEncryptDecrypt.addReportingUserDefinedMetadata(null));
      exception = assertThrows(IllegalArgumentException.class, () -> ubiqEncryptDecrypt.addReportingUserDefinedMetadata("null"));
      ubiqEncryptDecrypt.addReportingUserDefinedMetadata("{\"long\" : \"" + String.format("%-5s", "a") + "\"}"); // To prove short format works
      exception = assertThrows(IllegalArgumentException.class, () -> ubiqEncryptDecrypt.addReportingUserDefinedMetadata("{\"long\" : \"" + String.format("%-1025s", "a") + "\"}"));
      }
    }

    @Test
    public void loadDataset() {
      UbiqCredentials ubiqCredentials= null;
      String datasetName = "SomeName";
      try {
        ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
      } catch (Exception ex) {
      }

      try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
        JsonObject obj = new JsonObject();
        obj.addProperty("name", datasetName);
        obj.addProperty("salt", "TgTgXcV10ZWaTSo1UgLPvIx29QWLF6A6jpq7MZJt24c=");
        obj.addProperty("min_input_length",6);
        obj.addProperty("max_input_length",255);
        obj.addProperty("tweak_source","constant");
        obj.addProperty("encryption_algorithm","FF1");
        obj.addProperty("passthrough","-");
        obj.addProperty("input_character_set","0123456789");
        obj.addProperty("output_character_set","0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
        obj.addProperty("msb_encoding_bits",0);
        obj.addProperty("tweak_min_len",6);
        obj.addProperty("tweak_max_len",32);
        obj.addProperty("tweak","adBSmNHICAz4miOwJQaqWxdHn1TlPzPu3bs7ZTpBZ50=");
        obj.addProperty("fpe_definable_type","EfpeDefinition");
        obj.add("passthrough_rules", new JsonArray());

        System.out.println(obj.toString());
       String name = ubiqEncryptDecrypt.loadDataset(obj.toString());
       assertEquals(name, datasetName);

      }catch (Exception ex) {
        System.out.println("In Exception 1");
        assertEquals(false, true);
      }
    }

    @Test
    public void loadKeyDef() {
      String datasetName = "SomeName";
      UbiqCredentials ubiqCredentials= null;
      String encrypted_private_key = System.getenv(UBIQ_UNITTEST_ENCRYPTED_PRIVATE_KEY);

      try {
        ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
      } catch (Exception ex) {
      }

      try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

        JsonObject obj = new JsonObject();
        obj.addProperty("name", datasetName);
        obj.addProperty("salt", "TgTgXcV10ZWaTSo1UgLPvIx29QWLF6A6jpq7MZJt24c=");
        obj.addProperty("min_input_length",6);
        obj.addProperty("max_input_length",255);
        obj.addProperty("tweak_source","constant");
        obj.addProperty("encryption_algorithm","FF1");
        obj.addProperty("passthrough","-");
        obj.addProperty("input_character_set","0123456789");
        obj.addProperty("output_character_set","0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
        obj.addProperty("msb_encoding_bits",0);
        obj.addProperty("tweak_min_len",6);
        obj.addProperty("tweak_max_len",32);
        obj.addProperty("tweak","adBSmNHICAz4miOwJQaqWxdHn1TlPzPu3bs7ZTpBZ50=");
        obj.addProperty("fpe_definable_type","EfpeDefinition");
        obj.add("passthrough_rules", new JsonArray());

       String name = ubiqEncryptDecrypt.loadDataset(obj.toString());

        obj = new JsonObject();
        obj.addProperty("encrypted_private_key",encrypted_private_key);
        obj.addProperty("key_number","1");
        obj.addProperty("wrapped_data_key","Ep/LbXUfDj2LwuFB6ytNcacXsHHZvXjbWzBLxFekKZipFKKXUwtR694T4OUzlYBxai8DRU84NBqMk2syRN8yX4g/TRCjAC12lmUFavKEXGhqeBilej2WqaZ/yjN4g/uKohQCD3IQCIM2Fs5vXv4hFR6ZXOtqwoVtndlKYsFjuMNxKQ8PwhMVy2XQxJK70oZZm9Sf+6PPoxBhVLBj2Wr2SIalA8TqS8x/SZn17QqB0pdSVkxrtlH5eRqAKI3MswWzDlt9RYkPcGPmmt+utM3GTXkN1d8rI2+J9pqdceOyyu2mtyg89XezzJCiUV/qGJedmFqwfN5MBPZg+4bSMgnFLXBPcrpKJUzBAWyzw4RdCWkqbDXQA9jNIFT3Rnu05Kp/bitULuZZngOqiogf1yLnFfU8yk/aAcxyAqw6z1LnUUC3cCMr3b9mVlssjxJDMQ1Dk7X5HgWtyaZ/ZDXmk05SRL1kuibhswckyeI/bGTe48TU5Kqle/n+AC4vocZ/Vcc4mkTxu5laGzG88onEVX7OpXgoH98t1wyXYFGzZUVJkUjtr3Uzp4wMLKU20GQNPzSVnppxY9CI6S6UG+POBLJM9Y4bF+STv0RM4Y2blkFJsCJ7aooAdQUF/jaZKag0jv2z6tk6OTMB+goF2MN1QCXfOsvS3M0uvnXKieadsOCRq6U=");

        // LoadKeyDef requires the dataset to be loaded first
         ubiqEncryptDecrypt.loadKeyDef(datasetName, obj.toString(), true);
         assertEquals(true, true);

      } catch (Exception ex) {
        assertEquals(false, true);
      }
    }

    @Test
    public void loadDatasetDef() {
      String datasetName = "SomeName";

      String encrypted_private_key = System.getenv(UBIQ_UNITTEST_ENCRYPTED_PRIVATE_KEY);


      UbiqCredentials ubiqCredentials= null;
      try {
        ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
      } catch (Exception ex) {
      }

      try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {

      JsonObject element = new JsonObject();
      JsonObject obj = new JsonObject();

      element.addProperty("name", datasetName);
      element.addProperty("salt", "TgTgXcV10ZWaTSo1UgLPvIx29QWLF6A6jpq7MZJt24c=");
      element.addProperty("min_input_length", 6);
      element.addProperty("max_input_length", 255);
      element.addProperty("tweak_source", "constant");
      element.addProperty("encryption_algorithm", "FF1");
      element.addProperty("passthrough", "-");
      element.addProperty("input_character_set", "0123456789");
      element.addProperty("output_character_set", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
      element.addProperty("msb_encoding_bits", 0);
      element.addProperty("tweak_min_len", 6);
      element.addProperty("tweak_max_len", 32);
      element.addProperty("tweak", "adBSmNHICAz4miOwJQaqWxdHn1TlPzPu3bs7ZTpBZ50=");
      element.addProperty("fpe_definable_type", "EfpeDefinition");
      element.add("passthrough_rules", new JsonArray());

      obj.add("ffs", element);
      obj.addProperty("encrypted_private_key",encrypted_private_key);
      obj.addProperty("current_key_number", 1);
      obj.addProperty("retrieved", 1729122658);

      JsonArray keys = new JsonArray();
      keys.add("bswyRl9OaC8CskDo89pYhrXrlySUOq+mpG7sSVzD/cZV0ohdYhwCfI5Y+or8j91B/WBEUdNTb52vm1aHM6lWgzmLyzMSzJgkXNJZqA/RC0org+04M822AQKRYK36LgLYdtjUAO4lxRDSZ+sd/kHs25NlRjN8OQZtfSI+TcbhQVBlBEpsx/GAFhikX1EkJdbOCxy7Ht+o96sEfO68oq3pVPmxb3Atu5homqcd8IBg6hHW/w7jr8MRyHNeu91CQnl5fmig3ev+p4jLnhgo1aZc/VOghrwlauhn8QUsEykXwYCQ39c26oRown2u4IMi8bCK9DJ2gZIMeK6kRz7UYiVJ84K1elWElf1ctxllfn0cZQ7jI3Lp2eeheev7FHHUG3dolxruxmBp/MDdEAfpywzXni2LuxTDjoz4zZIo797c6vtfmxjf1RiVNLPPYqQUkwIPuw/DjBu3mwQmHIMmky+vzniJhwwqXh7MYva+5J5tLJsTCEsba0bKkqQUezUEJAFRxNovL7xvCY7SJ8lgeFuwsydEt/TjelNoftqahCXI55dh9NhDzhNQT0ekn2GwPz16XrCeNjASep8r0x3IesVt/ZwVhlrQcvFV3K8GswxCO8OBVmlJS+gtL1zJHrWg+IvmMUQ6t8maE1Jj1pCsPZP21lZ6O6pkdqJlHaVSXmuGvxE=");
      keys.add("c5rfv5SxqSEu7rRAxZdY35cl6RcZWzfl2WhSLlU4siFKPjnO+5sOkLDW8xeYMrwyTMjnLHUVOnVR55jAJ9xLPxKzP6CYLhIN55mxM4ZOpCGg7WNsXjAI6Wz2wOLnr8xhdMyQv3LF6zPM3ZloSydYL32hQW8RRwqLXSLAX0w/rTSG+XVAZogmWN6fiwqFCfnQYX2kxYwF0x90C6bj17w5Lb03xGf6MqnZN9fOuUJMQSDDc/6Fk5hDL3XPm5CUC4h4AfMndhdxhsMUGdP7QVREMHirsiRvHoJkEPuiXAwNJDH6WffG0KurrLygyNOxYKgcHRjrx9gBVx0KEx0Bp55WF0BMYHiYtsBp4CN3JQpBBHN72OgvDsLyzbonx4jjCAKpIC5vLIUR7vO+ZwOkULPXI96Z6Xk0/kYD/yXHi/h/eW7WU/HWCGlpkfjB3j5CUxjOIveVPGOj+j3VvfcJT5Fq0P2S1YTdfuZiYcIRftLEC89QLtb8YmVIs1wlTYws+BJpM3XuiRNmoqJlg76qUci2jKWn44+IRkp5OhHqWevH5Ehl66ujp4RUMl5UxPgGkidTYTO2YFtMm2tXUvc6I2GYHnZkCs1zsCwyEgQysnD7D43bK+17CyVN8aG3K2y2SGrWOjtp1Znnip/rYNHV3hbvHE5itI8MHD0/gKW+t5F20+s=");
      obj.add("keys", keys);

      String name = ubiqEncryptDecrypt.loadDatasetDef(obj.toString());
      assertEquals(name, datasetName);

      } catch (Exception ex) {
        System.out.println("Ex:" + ex.getMessage());
        assertEquals(false, true);
      }

    }


/* Test works fine when run by itself but often fails when run with others - timing issue
    @Test
    public void encryptStructured_getUsageReporting() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
            // Use long interval to make sure early records aren't flushed before test finishes
            UbiqConfiguration cfg = UbiqFactory.createConfiguration(1000,1000,1000,true, ChronoUnit.NANOS);

            String pt_generic = "0123456789ABCDEF";

            try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials, cfg)) {
                String ct_generic = ubiqEncryptDecrypt.encrypt("ALPHANUM_SSN", pt_generic, null);
                pt_generic = ubiqEncryptDecrypt.decrypt("ALPHANUM_SSN", ct_generic, null);
                // Wait for billing events to get caught up
                TimeUnit.SECONDS.sleep(1);

                // Get usage twice to show that it has not been reset
                String usage = ubiqEncryptDecrypt.getCopyOfUsage();
                assertEquals(usage, ubiqEncryptDecrypt.getCopyOfUsage());
                System.out.println("usage 1: " + usage);

                JsonArray firstArray = (new JsonParser()).parse(usage).getAsJsonObject().getAsJsonArray("usage");
                assertEquals(usage, 2, firstArray.size());
                // Make ure to get different usage records
                ct_generic = ubiqEncryptDecrypt.encrypt("BIRTH_DATE", "01-02-3456", null);
                pt_generic = ubiqEncryptDecrypt.decrypt("BIRTH_DATE", ct_generic, null);
                // Wait for billing events to get caught up
                TimeUnit.SECONDS.sleep(1);

                usage = ubiqEncryptDecrypt.getCopyOfUsage();
                System.out.println("usage 2: " + usage);
                JsonArray secondArray = (new JsonParser()).parse(usage).getAsJsonObject().getAsJsonArray("usage");
                assertEquals(usage, 4, secondArray.size());

            }


        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }
 */    
}
