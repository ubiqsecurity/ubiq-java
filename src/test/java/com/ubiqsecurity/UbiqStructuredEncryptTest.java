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

public class UbiqStructuredEncryptTest
{

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