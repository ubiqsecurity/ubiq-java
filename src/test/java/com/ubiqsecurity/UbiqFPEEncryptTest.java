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




public class UbiqFPEEncryptTest
{

    @Test
    public void encryptFPE_1() {
        try {
            UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile("credentials", "default");

            final byte[] tweakFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 100)) {
                String original = "123-45-6789";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "ALPHANUM_SSN", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "ALPHANUM_SSN", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
            //ex.printStackTrace();
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
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 100)) {
                //System.out.println("\nSSN First run");
                String original = " 01&23-456-78-90";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "ALPHANUM_SSN", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "ALPHANUM_SSN", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
            //ex.printStackTrace();
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
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 100)) {
                String original = "2006-05-01";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "BIRTH_DATE", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "BIRTH_DATE", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
            //ex.printStackTrace();
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
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 100)) {
                String original = "A STRING OF AT LEAST 15 UPPER CHARACTERS";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "GENERIC_STRING", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "GENERIC_STRING", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
            //ex.printStackTrace();
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
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 100)) {
                String original = "1234";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "SO_ALPHANUM_PIN", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "SO_ALPHANUM_PIN", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
            //ex.printStackTrace();
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
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 100)) {
                String original = "ABCDE";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "SO_ALPHANUM_PIN", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "SO_ALPHANUM_PIN", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
            //ex.printStackTrace();
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
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 100)) {
                String original = "ABCD";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "SO_ALPHANUM_PIN", original, tweakFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "SO_ALPHANUM_PIN", cipher, tweakFF1);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
            //ex.printStackTrace();
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
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 100)) {
                String original = "123-45-6789";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "ALPHANUM_SSN", original, tweakFF1); 
                String cipher2 = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "ALPHANUM_SSN", original, tweakFF1); 
                // clear the key cache and force going back to server
                ubiqEncryptDecrypt.clearKeyCache();
                cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "ALPHANUM_SSN", original, tweakFF1); 
                // clear the key cache and force going back to server
                ubiqEncryptDecrypt.clearKeyCache();
                cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "ALPHANUM_SSN", original, tweakFF1); 
                cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "ALPHANUM_SSN", original, tweakFF1); 
                
                assertEquals(cipher, cipher2);  
                
                String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "ALPHANUM_SSN", cipher, tweakFF1);
                String decrypted2 = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "ALPHANUM_SSN", cipher, tweakFF1);
                decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "ALPHANUM_SSN", cipher, tweakFF1);
                // clear the key cache and force going back to server
                ubiqEncryptDecrypt.clearKeyCache();
                decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "ALPHANUM_SSN", cipher, tweakFF1);
                
                assertEquals(decrypted, decrypted2);
            
                assertEquals(original, decrypted);  
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
            fail(ex.toString());
            //ex.printStackTrace();
        }    
    }

















// Disable the masking tests until we decide to utilize the FPEMask module

//     @Test
//     public void testMask1() {
//         
//         String original = "123-45-6789";
//         String regex = "(\\d{3})-(\\d{2})-(\\d{4})";
//         
//         FPEMask mask = new FPEMask(original, regex);
//         System.out.println("original: " + original + "  using regex: " + regex);
//         
//         String cipher = "987654321";  // assume that this is the result of the fpe encrypt for the encryptable part
//         String encryptable = mask.getEncryptablePart();
//         System.out.println("FPEMask determined encryptable part: " + encryptable);
//         System.out.println("Lets assume this 'encrypts' to cipher: " + cipher);
//                 
//         String withInsertion = mask.insertEncryptedPart(cipher);
//         System.out.println("FPEMask applies insertion of cipher: " + withInsertion);
//         
//         String redacted = mask.getRedacted();
//         System.out.println("FPEMask returns redacted: " + redacted);
//         
//         assertEquals(true, true);  // TODO - Determine appropriate test
//     }
// 
// 
// 
//     @Test
//     public void testMask2() {
// 
//         String original = "123-45-6789";
//         String regex = "(\\d{3})-(\\d{2})-\\d{4}";
//         
//         FPEMask mask = new FPEMask(original, regex);
//         System.out.println("original: " + original + "  using regex: " + regex);
//       
//         String encryptable = mask.getEncryptablePart();
//         String cipher = "00000";  // assume that this is the result of the fpe encrypt for the encryptable part
//         System.out.println("FPEMask determined encryptable part: " + encryptable);
//         System.out.println("Lets assume this 'encrypts' to cipher: " + cipher);
//                 
//         String withInsertion = mask.insertEncryptedPart(cipher);
//         System.out.println("FPEMask applies insertion of cipher: " + withInsertion);
//         
//         String redacted = mask.getRedacted();
//         System.out.println("FPEMask returns redacted: " + redacted);
//         
//             
//         assertEquals(true, true);  // TODO - Determine appropriate test
//     }








}
