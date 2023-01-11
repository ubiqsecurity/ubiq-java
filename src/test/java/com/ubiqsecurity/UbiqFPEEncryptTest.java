package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;
import java.math.BigInteger;
import java.util.Arrays;
import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;
import com.ubiqsecurity.UbiqFactory;
import java.util.concurrent.ExecutionException;
import java.util.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;



public class UbiqFPEEncryptTest
{

    static void testCycleEncryption(String ffs_name, String plainText, UbiqCredentials ubiqCredentials) {
        try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
            String result = ubiqEncryptDecrypt.encryptFPE(ffs_name, plainText, null);
            result = ubiqEncryptDecrypt.decryptFPE(ffs_name, result, null);
        }
    }



    @Test
    public void encryptFPE_1() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "123-45-6789";
                String cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                String decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);

                assertEquals(original, decrypted);
            }

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            ex.printStackTrace();
            fail(ex.toString());
        }
    }


    @Test
    public void encryptFPE_2() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = " 01&23-456-78-90";
                String cipher = ubiqEncryptDecrypt.encryptFPE("ALPHANUM_SSN", original, tweakFF1);
                String decrypted = ubiqEncryptDecrypt.decryptFPE("ALPHANUM_SSN", cipher, tweakFF1);

                assertEquals(original, decrypted);
            }

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }






    @Test
    public void encryptFPE_BIRTH_DATE_1() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "2006-05-01";
                String cipher = ubiqEncryptDecrypt.encryptFPE("BIRTH_DATE", original, tweakFF1);
                String decrypted = ubiqEncryptDecrypt.decryptFPE("BIRTH_DATE", cipher, tweakFF1);

                assertEquals(original, decrypted);
            }

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }


    @Test
    public void encryptFPE_GENERIC_STRING() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x32,
            };

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "A STRING OF AT LEAST 15 UPPER CHARACTERS";
                String cipher = ubiqEncryptDecrypt.encryptFPE("GENERIC_STRING", original, tweakFF1);
                String decrypted = ubiqEncryptDecrypt.decryptFPE("GENERIC_STRING", cipher, tweakFF1);

                assertEquals(original, decrypted);
            }

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }


    @Test
    public void encryptFPE_SO_ALPHANUM_PIN_1() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x32,
            };

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "1234";
                String cipher = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", original, tweakFF1);
                String decrypted = ubiqEncryptDecrypt.decryptFPE("SO_ALPHANUM_PIN", cipher, tweakFF1);

                assertEquals(original, decrypted);
            }

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }


    @Test
    public void encryptFPE_SO_ALPHANUM_PIN_2() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x32,
            };

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "ABCDE";
                String cipher = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", original, tweakFF1);
                String decrypted = ubiqEncryptDecrypt.decryptFPE("SO_ALPHANUM_PIN", cipher, tweakFF1);

                assertEquals(original, decrypted);
            }

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }



    @Test
    public void encryptFPE_SO_ALPHANUM_PIN_3() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30, (byte)0x32,
            };

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "ABCD";
                String cipher = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", original, tweakFF1);
                String decrypted = ubiqEncryptDecrypt.decryptFPE("SO_ALPHANUM_PIN", cipher, tweakFF1);

                assertEquals(original, decrypted);
            }

        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
        }
    }


    @Test
    public void encryptFPE_TEST_CACHING() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            String pt_generic = "A STRING OF AT LEAST 15 UPPER CHARACTERS";
            String ct_generic = "";

            String pt_alphanum = "ABCD";
            String ct_alphanum = "";

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                ct_generic = ubiqEncryptDecrypt.encryptFPE("GENERIC_STRING", pt_generic, null);
            }

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                ct_alphanum = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", pt_alphanum, null);
            }

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {

              String ct_generic_2 = ubiqEncryptDecrypt.encryptFPE("GENERIC_STRING", pt_generic, null);
              String ct_alphanum_2 = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", pt_alphanum, null);

              String pt_generic_2 = ubiqEncryptDecrypt.decryptFPE("GENERIC_STRING", ct_generic, null);
              String pt_alphanum_2 = ubiqEncryptDecrypt.decryptFPE("SO_ALPHANUM_PIN", ct_alphanum, null);


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
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            String pt_generic = "A STRING OF AT LEAST 15 UPPER CHARACTERS";
            String ct_generic = "";
            String ct_generic_2 = "";
            String pt_generic_2 = "";

            {
              try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                  ct_generic = ubiqEncryptDecrypt.encryptFPE("GENERIC_STRING", pt_generic, null);
              }
            }

            ct_generic_2 = UbiqFPEEncryptDecrypt.encryptFPE(ubiqCredentials, "GENERIC_STRING", pt_generic, null);
            pt_generic_2 = UbiqFPEEncryptDecrypt.decryptFPE(ubiqCredentials, "GENERIC_STRING", ct_generic, null);

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
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            String pt_generic = "A STRING OF AT LEAST 15 UPPER CHARACTERS";
            String ct_generic = "";
            String pt_alphanum = "ABCD";
            String ct_alphanum = "";

            boolean match = false;
            UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials);
            ct_generic = ubiqEncryptDecrypt.encryptFPE("GENERIC_STRING", pt_generic, null);
            ct_alphanum = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", pt_alphanum, null);

            String ct_generic_array[] = ubiqEncryptDecrypt.encryptForSearch("GENERIC_STRING", pt_generic, null);
            String ct_alphanum_array[] = ubiqEncryptDecrypt.encryptForSearch("SO_ALPHANUM_PIN", pt_alphanum, null);

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
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            String pt_generic = "A STRING OF AT LEAST 15 UPPER CHARACTERS";
            String ct_generic = "";
            String pt_alphanum = "ABCD";
            String ct_alphanum = "";

            boolean match = false;
            {
              UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials);
              ct_generic = ubiqEncryptDecrypt.encryptFPE("GENERIC_STRING", pt_generic, null);
              ct_alphanum = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", pt_alphanum, null);
            }

            String ct_generic_array[] =  UbiqFPEEncryptDecrypt.encryptForSearch(ubiqCredentials, "GENERIC_STRING", pt_generic, null);
            String ct_alphanum_array[] =  UbiqFPEEncryptDecrypt.encryptForSearch(ubiqCredentials, "SO_ALPHANUM_PIN", pt_alphanum, null);

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
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };

            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String original = "123-45-6789";
                String pt_generic = "A STRING OF AT LEAST 15 UPPER CHARACTERS";

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
                String cipher_generic = ubiqEncryptDecrypt.encryptFPE("GENERIC_STRING", pt_generic, tweakFF1);
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
                decrypted = ubiqEncryptDecrypt.decryptFPE("GENERIC_STRING", cipher_generic, tweakFF1);
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
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
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
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        }

        testCycleEncryption("SSN", " 123456789$", ubiqCredentials);
    }

    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_LEN_1() {
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        }

        testCycleEncryption("SSN", " 1234", ubiqCredentials);
    }

    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_LEN_2() {
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        }

        testCycleEncryption("SSN", " 12345678901234567890", ubiqCredentials);
    }


    @Test(expected = Exception.class)
    public void encryptFPE_Invalid_specific_creds_1() {
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
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
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
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
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
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
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
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
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
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
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
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
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        }

        try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
                String cipher = ubiqEncryptDecrypt.encryptFPE("SO_ALPHANUM_PIN", " 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", null);
                StringBuilder newcipher = new StringBuilder(cipher);
                newcipher.setCharAt(0, '}');
                String decrypted = ubiqEncryptDecrypt.decryptFPE("SO_ALPHANUM_PIN", newcipher.toString(), null);
        }
    }


    @Test(expected = Exception.class)
    public void encryptFPE_Error_handling_invalid_ffs() {
        UbiqCredentials ubiqCredentials= null;
        try {
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");
        } catch (Exception ex) {
        }

        testCycleEncryption("ERROR_MSG", " 01121231231231231& 1 &2311200 ", ubiqCredentials);
    }


}
