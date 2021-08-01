package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;
import java.math.BigInteger;


import java.util.Arrays;
import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;






import com.ubiqsecurity.UbiqFPEDecrypt;
import com.ubiqsecurity.UbiqFPEEncrypt;
import com.ubiqsecurity.UbiqFactory;



public class UbiqFPEEncryptTest
{
    private void testFF1(final byte[] key, final byte[] twk,
                      final String PT, final String CT,
                      final int radix) {
        String out;
        FF1 ctx;

        assertEquals(PT.length(), CT.length());
        
        
//         UbiqCredentials ubiqCredentials;
//         if (options.credentials == null) {
//             // no file specified, so fall back to ENV vars and default host, if any
//             ubiqCredentials = UbiqFactory.createCredentials(null, null, null, null);
//         } else {
//             // read credentials from caller-specified section of specified config file
//             ubiqCredentials = UbiqFactory.readCredentialsFromFile(options.credentials, options.profile);
//         }
            
//         System.out.println("\n@@@@@@@@@    simpleEncryptionFF1");
//         String cipher = simpleEncryptionFF1("0123456789", ubiqCredentials);
//         System.out.println("    cipher= " + cipher);
// 
//         System.out.println("\n@@@@@@@@@    simpleDecryptionFF1");
//         String plaintext = simpleDecryptionFF1(cipher, ubiqCredentials);
//         System.out.println("    plaintext= " + plaintext);
            
            
            

        ctx = new FF1(key, twk, 0, 0, radix);

        out = ctx.encrypt(PT);
        assertEquals(CT, out);

        out = ctx.decrypt(CT);
        assertEquals(PT, out);
    }


    private void testFF3_1(final byte[] key, final byte[] twk,
                      final String PT, final String CT,
                      final int radix) {
        String out;
        FF3_1 ctx;

        assertEquals(PT.length(), CT.length());

        ctx = new FF3_1(key, twk, radix);

        out = ctx.encrypt(PT);
        assertEquals(CT, out);

        out = ctx.decrypt(CT);
        assertEquals(PT, out);
    }
    
        
    private final byte[] key_FF1 = {
        (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
        (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
        (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
        (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c,
        (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
        (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
        (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
        (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
    };
    private final byte[] key_FF3_1 = {
        (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
        (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
        (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
        (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
        (byte)0x3b, (byte)0x80, (byte)0x6a, (byte)0xeb,
        (byte)0x63, (byte)0x08, (byte)0x27, (byte)0x1f,
        (byte)0x65, (byte)0xcf, (byte)0x33, (byte)0xc7,
        (byte)0x39, (byte)0x1b, (byte)0x27, (byte)0xf7,
    };

    private final byte[] twk1_FF1 = {};
    private final byte[] twk2_FF1 = {
        (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
        (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
        (byte)0x31, (byte)0x30,
    };
    private final byte[] twk3_FF1 = {
        (byte)0x37, (byte)0x37, (byte)0x37, (byte)0x37,
        (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73,
        (byte)0x37, (byte)0x37, (byte)0x37,
    };

    private final byte[] twk1_FF3_1 = {
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00,
    };
    private final byte[] twk2_FF3_1 = {
        (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
        (byte)0x35, (byte)0x34, (byte)0x33,
    };
    private final byte[] twk3_FF3_1 = {
        (byte)0x37, (byte)0x37, (byte)0x37, (byte)0x37,
        (byte)0x70, (byte)0x71, (byte)0x72,
    };
    
    private final String[] PT_FF1 = {
        "0123456789", "0123456789abcdefghi"
    };
    private final String[] PT_FF3_1 = {
        "890121234567890000", "89012123456789abcde"
    };
    
    
//     @Test
//     public void encryptDecryptFF1() {
//         this.testFF1(Arrays.copyOf(this.key_FF1, 16),
//                   this.twk2_FF1,
//                   PT_FF1[0], "6124200773", 10);
//     }
// 
//     @Test
//     public void encryptDecryptFF3_1() {
//         this.testFF3_1(Arrays.copyOf(this.key_FF3_1, 16),
//                   this.twk1_FF3_1,
//                   PT_FF3_1[0], "075870132022772250", 10);
//     }
// 
// 
// 
// 
// 
// 
// 
//     @Test
//     public void encryptDecrypt1() {
//     
//     
//     
//         try {
//             UbiqCredentials ubiqCredentials;
//             
//             // TODO - setup a set of standard credentials, for now hardcode some here
//             ubiqCredentials = UbiqFactory.createCredentials(
//                     "J07/KueP1k07rsJjRwFBfJpF",
//                     "GMmrma7+4D7I1ymYUqInvuHmFjrhQ70zslDQ+EZbVHfS",
//                     "bkEyHxQZ5/mq+pu3vHA22fSgKUSKKgUaTKn5KGIFTUhv",
//                     "https://dev.koala.ubiqsecurity.com");
// 
//             ////// TEST 1 - ENCRYPT AND DECRYPT
//             final byte[] tweekFF1 = {
//                 (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
//                 (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
//                 (byte)0x31, (byte)0x30,
//             };
//             
//             
//             
//             
//             String original = "0123456789";
//             String cipher = UbiqFPEEncrypt.encryptFPE(ubiqCredentials, "FF1", original, tweekFF1, "LDAP"); 
//             String decrypted = UbiqFPEDecrypt.decryptFPE(ubiqCredentials, "FF1", cipher, tweekFF1, "LDAP");
//             
//             assertEquals(original, decrypted);
//     
//         } catch (Exception ex) {
//             System.out.println(String.format("Exception: %s", ex.getMessage()));
//             ex.printStackTrace();
//             System.exit(1);
//         }    
//     
//     
// 
//     }
// 
// 
// 
// 
// 
// 
// 
//     @Test
//     public void encryptDecrypt2() {
//     
//     
//     
//         try {
//             UbiqCredentials ubiqCredentials;
//             
//             // TODO - setup a set of standard credentials, for now hardcode some here
//             ubiqCredentials = UbiqFactory.createCredentials(
//                     "J07/KueP1k07rsJjRwFBfJpF",
//                     "GMmrma7+4D7I1ymYUqInvuHmFjrhQ70zslDQ+EZbVHfS",
//                     "bkEyHxQZ5/mq+pu3vHA22fSgKUSKKgUaTKn5KGIFTUhv",
//                     "https://dev.koala.ubiqsecurity.com");
// 
//             ////// TEST 1 - ENCRYPT AND DECRYPT
//             final byte[] tweekFF1 = {
//                 (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
//                 (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
//                 (byte)0x31, (byte)0x30,
//             };
//             String original = "0123456789";
//             String cipher = UbiqFPEEncrypt.encryptFPE(ubiqCredentials, "FF1", original, tweekFF1, "LDAP"); 
//             String decrypted = UbiqFPEDecrypt.decryptFPE(ubiqCredentials, "FF1", cipher, tweekFF1, "LDAP");
//             
//             assertEquals(original, decrypted);
//     
//         } catch (Exception ex) {
//             System.out.println(String.format("Exception: %s", ex.getMessage()));
//             ex.printStackTrace();
//             System.exit(1);
//         }    
//     
//     
// 
//     }





    @Test
    public void encryptDecryptCaching() {
    
    
    
        try {
            UbiqCredentials ubiqCredentials;
            
            // TODO - setup a set of standard credentials, for now hardcode some here
            ubiqCredentials = UbiqFactory.createCredentials(
                    "J07/KueP1k07rsJjRwFBfJpF",
                    "GMmrma7+4D7I1ymYUqInvuHmFjrhQ70zslDQ+EZbVHfS",
                    "bkEyHxQZ5/mq+pu3vHA22fSgKUSKKgUaTKn5KGIFTUhv",
                    "https://dev.koala.ubiqsecurity.com");

            ////// TEST 1 - ENCRYPT AND DECRYPT
            final byte[] tweekFF1 = {
                (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
                (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
                (byte)0x31, (byte)0x30,
            };
            final byte[] tweekFF3_1 = {
                 (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                 (byte)0x00, (byte)0x00, (byte)0x00,
            };
            
            
            
            // setup the cached FFS so that the ffs data may persist between encrypt/decrypt calls
            FFS ffs = new FFS();
            
            
            
            System.out.println("FF1 First run");
            String original = "0123456789";
            String cipher = UbiqFPEEncrypt.encryptFPE(ubiqCredentials, "FF1", "SSN", original, tweekFF1, "LDAP", ffs); 
            String decrypted = UbiqFPEDecrypt.decryptFPE(ubiqCredentials, "FF1", "SSN", cipher, tweekFF1, "LDAP", ffs);
            
            
            System.out.println("FF1 Second run");
            cipher = UbiqFPEEncrypt.encryptFPE(ubiqCredentials, "FF1", "SSN", original, tweekFF1, "LDAP", ffs); 
            decrypted = UbiqFPEDecrypt.decryptFPE(ubiqCredentials, "FF1", "SSN", cipher, tweekFF1, "LDAP", ffs);
            
            System.out.println("FF1 Third run");
            cipher = UbiqFPEEncrypt.encryptFPE(ubiqCredentials, "FF1", "SSN", original, tweekFF1, "LDAP", ffs); 
            decrypted = UbiqFPEDecrypt.decryptFPE(ubiqCredentials, "FF1", "SSN", cipher, tweekFF1, "LDAP", ffs);
            

            System.out.println("FF3_1 New first run");
            cipher = UbiqFPEEncrypt.encryptFPE(ubiqCredentials, "FF3_1", "SSN", original, tweekFF3_1, "LDAP", ffs); 
            decrypted = UbiqFPEDecrypt.decryptFPE(ubiqCredentials, "FF3_1", "SSN", cipher, tweekFF3_1, "LDAP", ffs);

            System.out.println("FF3_1 New Second run");
            cipher = UbiqFPEEncrypt.encryptFPE(ubiqCredentials, "FF3_1", "SSN", original, tweekFF3_1, "LDAP", ffs); 
            decrypted = UbiqFPEDecrypt.decryptFPE(ubiqCredentials, "FF3_1", "SSN", cipher, tweekFF3_1, "LDAP", ffs);

            System.out.println("FF1 Back to original run");
            cipher = UbiqFPEEncrypt.encryptFPE(ubiqCredentials, "FF1", "SSN", original, tweekFF1, "LDAP", ffs); 
            decrypted = UbiqFPEDecrypt.decryptFPE(ubiqCredentials, "FF1", "SSN", cipher, tweekFF1, "LDAP", ffs);

            
            
            assertEquals(original, decrypted);
    
        } catch (Exception ex) {
            System.out.println(String.format("Exception: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }    
    
    

    }










}
