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

import javax.crypto.Cipher;
import java.io.StringReader;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import java.security.spec.RSAPublicKeySpec;
import java.security.KeyFactory;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import java.security.PublicKey;
import java.security.PrivateKey;
import org.bouncycastle.openssl.PEMParser;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;



public class UbiqFPEEncryptTest
{
    private final String UBIQ_UNITTEST_ENCRYPTED_PRIVATE_KEY = "UBIQ_UNITTEST_ENCRYPTED_PRIVATE_KEY";
    private final String UBIQ_SECRET_CRYPTO_ACCESS_KEY = "UBIQ_SECRET_CRYPTO_ACCESS_KEY";

    static void testCycleEncryption(String dataset_name, String plainText, UbiqCredentials ubiqCredentials) {

        try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
            String result = ubiqEncryptDecrypt.encryptFPE(dataset_name, plainText, null);
            result = ubiqEncryptDecrypt.decryptFPE(dataset_name, result, null);
        }
    }


    static void testRt(String dataset_name, String plainText, String expectedCt) 
    {
      UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

      final byte[] tweak = null;

      try {
        // testRt("ALPHANUM_SSN", ";0123456-789ABCDEF|", ";!!!E7`+-ai1ykOp8r|");

      testSimpleRt(dataset_name, plainText, expectedCt, ubiqCredentials, tweak);
      testBatchRt(dataset_name, plainText, expectedCt, ubiqCredentials, tweak);
      }
     catch (Exception ex) {
      System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
      ex.printStackTrace();
      fail(ex.toString());
    }

  }


    static void testSimpleRt(String dataset_name, String plainText, String expectedCt, UbiqCredentials ubiqCredentials,  byte[] tweak) 
    throws IOException, InvalidCipherTextException{
        String ct = UbiqFPEEncryptDecrypt.encryptFPE(ubiqCredentials, dataset_name, plainText, tweak);
        String pt = UbiqFPEEncryptDecrypt.decryptFPE(ubiqCredentials, dataset_name, ct, tweak);
        assertEquals(plainText, pt);

        if (expectedCt != null) {
          pt = UbiqFPEEncryptDecrypt.decryptFPE(ubiqCredentials, dataset_name, expectedCt, tweak);
          assertEquals(plainText, pt);
        }

        String[] ct_arr = UbiqFPEEncryptDecrypt.encryptForSearch(ubiqCredentials, dataset_name, plainText, tweak);

        if (expectedCt != null) {
          ct = expectedCt;
        }

        Boolean foundCt = false;
        for (String x : ct_arr) {
          foundCt = foundCt || (ct.equals(x));
          pt = UbiqFPEEncryptDecrypt.decryptFPE(ubiqCredentials, dataset_name, x, tweak);
          assertEquals(plainText, pt);
        }
        assertEquals(foundCt, true);

  }

    static void testBatchRt(String dataset_name, String plainText, String expectedCt, UbiqCredentials ubiqCredentials,  byte[] tweak)
      throws IOException, InvalidCipherTextException{

        UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials);

          String ct = ubiqEncryptDecrypt.encryptFPE(dataset_name, plainText, null);
          String pt = ubiqEncryptDecrypt.decryptFPE(dataset_name, ct, null);
          assertEquals(plainText, pt);


          if (expectedCt != null) {
            pt = ubiqEncryptDecrypt.decryptFPE(dataset_name, expectedCt, null);
            assertEquals(plainText, pt);
          }

          String[] ct_arr = ubiqEncryptDecrypt.encryptForSearch(dataset_name, plainText, tweak);

          if (expectedCt != null) {
            ct = expectedCt;
          }

          Boolean foundCt = false;
          for (String x : ct_arr) {
            foundCt = foundCt || (ct.equals(x));
            pt = ubiqEncryptDecrypt.decryptFPE(dataset_name, x, tweak);
            assertEquals(plainText, pt);
          }
          assertEquals(foundCt, true);

      }

    @Test
    public void encryptFPE_ALPHANUM_SSN() {
            testRt("ALPHANUM_SSN", ";0123456-789ABCDEF|", null);
    }

    @Test
    public void encryptFPE_BIRTH_DATE() {
      testRt("BIRTH_DATE", ";01\\02-1960|", null);
    }

    @Test
    public void encryptFPE_SSN() {
      testRt("SSN", "-0-1-2-3-4-5-6-7-8-9-", null);
    }

    @Test
    public void encryptFPE_UTF8_STRING_COMPLEX() {
      testRt("UTF8_STRING_COMPLEX", "ÑÒÓķĸĹϺϻϼϽϾÔÕϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊʑʒʓËÌÍÎÏðñòóôĵĶʔʕ", null);
    }

    @Test
    public void encryptFPE_UTF8_STRING_COMPLEX_2() {
      testRt("UTF8_STRING_COMPLEX", "ķĸĹϺϻϼϽϾϿは世界abcdefghijklmnopqrstuvwxyzこんにちÊËÌÍÎÏðñòóôĵĶ", null);
    }

    @Test
    public void encryptFPE_TEST_CACHING() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

            String pt_generic = ";0123456-789ABCDEF|";
            String ct_generic = "";

            String pt_alphanum = ";01\\02-1960|";
            String ct_alphanum = "";

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                ct_generic = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", pt_generic, null);
            }

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                ct_alphanum = ubiqEncryptDecrypt.encryptFPE("BIRTH_DATE", pt_alphanum, null);
            }

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {

              ubiqEncryptDecrypt.addReportingUserDefinedMetadata("{ \"att_encryption_wrapper\" : true }");
              String ct_generic_2 = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", pt_generic, null);
              String ct_alphanum_2 = ubiqEncryptDecrypt.encryptFPE("BIRTH_DATE", pt_alphanum, null);

              String pt_generic_2 = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", ct_generic, null);
              String pt_alphanum_2 = ubiqEncryptDecrypt.decryptFPE("BIRTH_DATE", ct_alphanum, null);


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
    public void encryptFPE_Simple() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

            String pt_generic = ";0123456-789ABCDEF|";
            String ct_generic = "";
            String ct_generic_2 = "";
            String pt_generic_2 = "";

            {
              try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                  ct_generic = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", pt_generic, null);
              }
            }

            ct_generic_2 = UbiqFPEEncryptDecrypt.encryptFPE(ubiqCredentials, "ALPHANUM_SSN", pt_generic, null);
            pt_generic_2 = UbiqFPEEncryptDecrypt.decryptFPE(ubiqCredentials, "ALPHANUM_SSN", ct_generic, null);

            assertEquals(ct_generic, ct_generic_2);
            assertEquals(pt_generic, pt_generic_2);

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
            UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials);
            ct_generic = ubiqEncryptDecrypt.encryptFPE("SSN", pt_generic, null);
            ct_alphanum = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", pt_alphanum, null);

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
    public void encryptSearchSimple() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

            String pt_generic = "123456789";
            String ct_generic = "";
            String pt_alphanum = "123456789789ABCDEF";
            String ct_alphanum = "";

            boolean match = false;
            {
              UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials);
              ct_generic = ubiqEncryptDecrypt.encryptFPE("SSN", pt_generic, null);
              ct_alphanum = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", pt_alphanum, null);
            }

            String ct_generic_array[] =  UbiqFPEEncryptDecrypt.encryptForSearch(ubiqCredentials, "SSN", pt_generic, null);
            String ct_alphanum_array[] =  UbiqFPEEncryptDecrypt.encryptForSearch(ubiqCredentials, "ALPHANUM_SSN", pt_alphanum, null);

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
    public void encryptFPE_MultipleCachedKeys() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "123-45-6789";
                String pt_generic =  ";01\\02-1960|";

                String cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                String cipher2 = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                // clear the key cache and force going back to server

                ubiqEncryptDecrypt.clearKeyCache();
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                // clear the key cache and force going back to server
                ubiqEncryptDecrypt.clearKeyCache();
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                String cipher_generic = ubiqEncryptDecrypt.encryptFPE("BIRTH_DATE", pt_generic, tweakFF1);
                cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);

                assertEquals(cipher, cipher2);

                String decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                String decrypted2 = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                // clear the key cache and force going back to server
                ubiqEncryptDecrypt.clearKeyCache();
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("BIRTH_DATE", cipher_generic, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);

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
    public void encryptFPE_Speed() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            String pt_generic = "A STRING OF AT LEAST 15 UPPER CHARACTERS";
            String ct_generic = "";
            String tmp = "";

            String pt_alphanum = "ABCD";
            String ct_alphanum = "";

            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
              long start = System.nanoTime();
              int count = 1000000;
              for (int i = 0; i < count; i++) {
                ct_generic = ubiqEncryptDecrypt.encryptFPE("GENERIC_STRING", pt_generic, null);
              }
              long finish = System.nanoTime();
              System.out.println(String.format("Encrypt %s %d records in %.4f seconds or %.4f ms/rec", "GENERIC_STRING", count,  ((finish - start) / 1000000000.0), ((finish - start) / 1000000.0)/count));

              start = System.nanoTime();
              for (int i = 0; i < count; i++) {
                tmp = ubiqEncryptDecrypt.decryptFPE("GENERIC_STRING", ct_generic, null);
              }
              finish = System.nanoTime();
              System.out.println(String.format("Decrypt %s %d records in %.4f seconds or %.4f ms/rec", "GENERIC_STRING", count,  ((finish - start) / 1000000000.0), ((finish - start) / 1000000.0)/count));
              assertEquals(pt_generic, tmp);

            }

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
              long start = System.nanoTime();
              int count = 1000000;
              for (int i = 0; i < count; i++) {
                ct_alphanum = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", pt_alphanum, null);
              }
              long finish = System.nanoTime();
              System.out.println(String.format("Encrypt %s %d records in %.4f seconds or %.4f ms/rec", "SO_ALPHANUM_PIN", count,  ((finish - start) / 1000000000.0), ((finish - start) / 1000000.0)/ count));

              start = System.nanoTime();
              for (int i = 0; i < count; i++) {
                tmp = ubiqEncryptDecrypt.decryptFPE("SO_ALPHANUM_PIN", ct_alphanum, null);
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
    public void encryptFPE_InvalidFFS() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        testCycleEncryption("ERROR FFS", "ABCDEFGHI", ubiqCredentials);
    }



    @Test(expected = Exception.class)
    public void encryptFPE_InvalidCredentials() {
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.createCredentials("a","b","c", "d");
        } catch (Exception ex) {
        }

        testCycleEncryption("ALPHANUM_SSN", "ABCDEFGHI", ubiqCredentials);
    }



    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_PT_CT() {
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        testCycleEncryption("SSN", " 123456789$", ubiqCredentials);
    }

    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_LEN_1() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        testCycleEncryption("SSN", " 1234", ubiqCredentials);
    }

    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_LEN_2() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        testCycleEncryption("SSN", " 12345678901234567890", ubiqCredentials);
    }


    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_specific_creds_1() {
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
    public void encryptFPE_Invalid_specific_creds_2() {
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
    public void encryptFPE_Invalid_specific_creds_3() {
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
    public void encryptFPE_Invalid_specific_creds_4() {
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
    public void encryptFPE_Invalid_specific_creds_5() {
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
    public void encryptFPE_Invalid_specific_creds_6() {
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
    public void encryptFPE_Invalid_keynum() {
        UbiqCredentials ubiqCredentials= null;
        try {
          ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        } catch (Exception ex) {
        }

        try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String cipher = ubiqEncryptDecrypt.encryptFPE("SSN", " 0123456789", null);
                StringBuilder newcipher = new StringBuilder(cipher);
                newcipher.setCharAt(0, '}');
                String decrypted = ubiqEncryptDecrypt.decryptFPE("SSN", newcipher.toString(), null);
        }
    }


    @Test(expected = Exception.class)
    public void encryptFPE_Error_handling_invalid_ffs() {
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

      try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {


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

      try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
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
       assertEquals(name, datasetName);

      }catch (Exception ex) {
      }
    }

    @Test
    public void loadKeyDef() {
      String datasetName = "SomeName";
      String encrypted_private_key = System.getenv(UBIQ_UNITTEST_ENCRYPTED_PRIVATE_KEY);
      String secretCryptoAccessKey = System.getenv(UBIQ_SECRET_CRYPTO_ACCESS_KEY);

      UbiqCredentials ubiqCredentials= null;
      try {
        ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
      } catch (Exception ex) {
      }

      try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {

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
        obj.addProperty("wrapped_data_key", wrapDataKey2("1234567890123456".getBytes(), encrypted_private_key, secretCryptoAccessKey));


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

      try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {

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
      String secretCryptoAccessKey = System.getenv(UBIQ_SECRET_CRYPTO_ACCESS_KEY);

      obj.addProperty("current_key_number", 1);
      obj.addProperty("retrieved", 1729122658);

      JsonArray keys = new JsonArray();
      keys.add(wrapDataKey2("1234567890123456".getBytes(), encrypted_private_key, secretCryptoAccessKey));
      keys.add(wrapDataKey2("abcdefghijklmnop".getBytes(), encrypted_private_key, secretCryptoAccessKey));
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
    public void encryptFPE_getUsageReporting() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
            // Use long interval to make sure early records aren't flushed before test finishes
            UbiqConfiguration cfg = UbiqFactory.createConfiguration(1000,1000,1000,true, ChronoUnit.NANOS);

            String pt_generic = "0123456789ABCDEF";

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, cfg)) {
                String ct_generic = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", pt_generic, null);
                pt_generic = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", ct_generic, null);
                // Wait for billing events to get caught up
                TimeUnit.SECONDS.sleep(1);

                // Get usage twice to show that it has not been reset
                String usage = ubiqEncryptDecrypt.getCopyOfUsage();
                assertEquals(usage, ubiqEncryptDecrypt.getCopyOfUsage());
                System.out.println("usage 1: " + usage);

                JsonArray firstArray = (new JsonParser()).parse(usage).getAsJsonObject().getAsJsonArray("usage");
                assertEquals(usage, 2, firstArray.size());
                // Make ure to get different usage records
                ct_generic = ubiqEncryptDecrypt.encryptFPE("BIRTH_DATE", "01-02-3456", null);
                pt_generic = ubiqEncryptDecrypt.decryptFPE("BIRTH_DATE", ct_generic, null);
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

    private String wrapDataKey2(byte[] key, String encrypted_private_key, String secretCryptoAccessKey) throws Exception{


      BouncyCastleProvider bcProvider;
      
      String base64Ciphertext = null;
      bcProvider = new BouncyCastleProvider();

      try (PEMParser pemParser = new PEMParser(new StringReader(encrypted_private_key))) {

            Object object = pemParser.readObject();
            if (!(object instanceof PKCS8EncryptedPrivateKeyInfo)) {
                throw new RuntimeException("Unrecognized Encrypted Private Key format");
            }

            JceOpenSSLPKCS8DecryptorProviderBuilder builder = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(bcProvider);
            // Decrypt the private key using our secret key
            InputDecryptorProvider decryptProvider  = builder.build(secretCryptoAccessKey.toCharArray());

            PKCS8EncryptedPrivateKeyInfo keyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
            PrivateKeyInfo privateKeyInfo = keyInfo.decryptPrivateKeyInfo(decryptProvider);

            JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider(bcProvider);
            PrivateKey privateKey = keyConverter.getPrivateKey(privateKeyInfo);

            if (!(privateKey instanceof BCRSAPrivateCrtKey)) {
                throw new RuntimeException("Unrecognized Private Key format: " + privateKey.getClass().getName() + " " );
            }
            
            BCRSAPrivateKey rsaPrivateKey = (BCRSAPrivateKey)privateKey;

             RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                rsaPrivateKey.getModulus(),
                 BigInteger.valueOf(65537)
             );

            KeyFactory keyFactory = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            RSAPublicKey rsaPub = (RSAPublicKey) publicKey;

            byte[] ciphertext = encrypt(key, publicKey);
            base64Ciphertext = Base64.getEncoder().encodeToString(ciphertext);

            // 3. Decrypt
            byte[] decodedCipher = Base64.getDecoder().decode(base64Ciphertext);
            byte[] decrypted2 = decrypt2(decodedCipher, privateKey);
        }
        return base64Ciphertext;
    }

    private byte[] encrypt(byte[] data, PublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(data);
    }

    private byte[] decrypt2(byte[] cipherText, PrivateKey privKey) throws Exception {

      BCRSAPrivateKey rsaPrivateKey = (BCRSAPrivateKey)privKey;

      RSAKeyParameters cipherParams = new RSAKeyParameters(
                  true,
                  rsaPrivateKey.getModulus(),
                  rsaPrivateKey.getPrivateExponent());

      OAEPEncoding rsaEngine = new OAEPEncoding(
                    new RSAEngine(),
                    new SHA1Digest(),
                    new SHA1Digest(),
                    null);

      rsaEngine.init(false, cipherParams);

            // 'UnwrappedDataKey' is used for local encryptions
      byte[] unwrappedDataKey = rsaEngine.processBlock(cipherText, 0, cipherText.length);
      return unwrappedDataKey;
    }



}
