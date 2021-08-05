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
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class UbiqFPEEncryptTest
{





//     @Test
//     public void encrypt() {
//     
//         try {
//             UbiqCredentials ubiqCredentials;
//             ubiqCredentials = UbiqFactory.createCredentials(
//                     "aox5ZRptLg8B758xllfEFsNG",
//                     "fhxmkk4lB/l6bnuKUxT2gYpdMoiSk+1AwUUIyD/ghQPu",
//                     "YvNtl2+G3v5d3OeIz5ORuut8wZgsUChcTHBy3Uew9NiR",
//                     "http://localhost:8443");
//                     
//     
//             System.out.println("\nSimple Encrypt");
//             final byte[] plainBytes = {
//                     (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
//                     (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
//                     (byte)0x31, (byte)0x30,
//                 };
//             byte[] cipherBytes = UbiqEncrypt.encrypt(ubiqCredentials, plainBytes);
//             
//             
//         } catch (Exception ex) {
//             System.out.println(String.format("Exception: %s", ex.getMessage()));
//             ex.printStackTrace();
//             System.exit(1);
//         }  
//     }        
        
        




    @Test
    public void encryptFPE() {
    
        try {
        
            // TODO - setup a set of standard credentials, for now hardcode some here
            UbiqCredentials ubiqCredentials;
                                
            ubiqCredentials = UbiqFactory.createCredentials(
                    "aox5ZRptLg8B758xllfEFsNG",
                    "fhxmkk4lB/l6bnuKUxT2gYpdMoiSk+1AwUUIyD/ghQPu",
                    "YvNtl2+G3v5d3OeIz5ORuut8wZgsUChcTHBy3Uew9NiR",
                    "http://localhost:8443");




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
            
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 1)) {
            
            
            
                System.out.println("\nSSN First run");
                String original = "0123456789";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "SSN", original, tweekFF1, "LDAP"); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "SSN", cipher, tweekFF1, "LDAP");
            
        
                System.out.println("\nSSN Second run");
                cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "SSN", original, tweekFF1, "LDAP"); 
                decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "SSN", cipher, tweekFF1, "LDAP");
                
                System.out.println("\nSSN Third run");
                cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "SSN", original, tweekFF1, "LDAP"); 
                decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "SSN", cipher, tweekFF1, "LDAP");
            

                System.out.println("\nPIN New first run");
                cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "PIN", original, tweekFF3_1, "LDAP"); 
                decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "PIN", cipher, tweekFF3_1, "LDAP");

                System.out.println("\nPIN New Second run");
                cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "PIN", original, tweekFF3_1, "LDAP"); 
                decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "PIN", cipher, tweekFF3_1, "LDAP");

                System.out.println("\nSSN Back to original run");
                cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "SSN", original, tweekFF1, "LDAP"); 
                decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "SSN", cipher, tweekFF1, "LDAP");
            

                System.out.println("\noriginal= " + original + "   decrypted= " + decrypted);
                assertEquals(original, decrypted);
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("Exception: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }    
    
    

    }






//     @Test
//     public void testRegex() {
//     
//         try {
//             FFS ffs = new FFS("SSN", "ldap");
//         
//             FFS_Record FFScaching = ffs.FFSCache.get("testkey");
//         
//             String encryption_algorithm = FFScaching.getAlgorithm();
//         
//         
//             String socsec = "123-45-6789";
//             String stripped = FFScaching.stripFormatCharacters(socsec);
//             System.out.println("socsec= " + socsec + "   stripped= " + stripped);
//             
//             
//             
//             System.out.println("################");
//             
//             String str = "123-45-6789";
//             String regex = "(\\d{3})-(\\d{2})-(\\d{4})";
//             List<String> matches = new ArrayList<String>();
//             Matcher m = Pattern.compile(regex).matcher(str);
// 
//             while (m.find()) {
//                 matches.add(m.group());
//             }
// 
//             System.out.println(matches);
// 
// 
// 
// 
//         
// 
//             assertEquals(true, true);
//         
//         } catch (ExecutionException e) {
//             e.printStackTrace();
//         }
//     }
// 












}
