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
    public void encryptFPE() {
    
        try {
        
            // TODO - setup a set of standard credentials, for now hardcode some here
            UbiqCredentials ubiqCredentials;
                                
//             ubiqCredentials = UbiqFactory.createCredentials(
//                     "aox5ZRptLg8B758xllfEFsNG",
//                     "fhxmkk4lB/l6bnuKUxT2gYpdMoiSk+1AwUUIyD/ghQPu",
//                     "YvNtl2+G3v5d3OeIz5ORuut8wZgsUChcTHBy3Uew9NiR",
//                     "http://localhost:8443");

//             ubiqCredentials = UbiqFactory.createCredentials(
//                     "sxGesRB8KMwqhiy6k7xC2WL/",
//                     "OpaJ+YXu1IoRw7be/B21kWIB6taN5L9KhRVFTur3C9UE",
//                     "cIFQf1MsRn2T9YHLWZFt/z0Yb1zQj0mQdvA74gw8SQHe",
//                     "https://koala.ubiqsecurity.com");
                    
            ubiqCredentials = UbiqFactory.readCredentialsFromFile("/Users/anthonyiasi/ubiq-java/credentials", "default");
 

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
            
            
            try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 100)) {
            
            
                System.out.println("\nSSN First run");
                String original = "01$23-456-78-90";
                String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "FFS Name", original, tweekFF1); 
                String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "FFS Name", cipher, tweekFF1);
            
            
                assertEquals(original, decrypted);  
            
            
            
            
//                 System.out.println("\nSSN First run");
//                 String original = "123-45-6789";
//                 String cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "FFS Name", original, tweekFF1, "LDAP"); 
//                 String decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "FFS Name", cipher, tweekFF1, "LDAP");
//             
//         
//                 System.out.println("\nSSN Second run");
//                 cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "FFS Name", original, tweekFF1, "LDAP"); 
//                 decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "FFS Name", cipher, tweekFF1, "LDAP");
//                 
//                 System.out.println("\nSSN Third run");
//                 cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "SSN", original, tweekFF1, "LDAP"); 
//                 decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "SSN", cipher, tweekFF1, "LDAP");
//             
// 
//                 System.out.println("\nPIN New first run");
//                 cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "PIN", original, tweekFF3_1, "LDAP"); 
//                 decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "PIN", cipher, tweekFF3_1, "LDAP");
// 
//                 System.out.println("\nPIN New Second run");
//                 cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "PIN", original, tweekFF3_1, "LDAP"); 
//                 decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "PIN", cipher, tweekFF3_1, "LDAP");
// 
//                 System.out.println("\nSSN Back to original run");
//                 cipher = ubiqEncryptDecrypt.encryptFPE(ubiqCredentials, "SSN", original, tweekFF1, "LDAP"); 
//                 decrypted = ubiqEncryptDecrypt.decryptFPE(ubiqCredentials, "SSN", cipher, tweekFF1, "LDAP");
//             
// 
//                 System.out.println("\noriginal= " + original + "   decrypted= " + decrypted);
//                 
//                 
//                 assertEquals(original, decrypted);  
                
                //assertEquals(true, true);    // for now, update later
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("Exception: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }    
    
    

    }








//  getEncryptablePart("123-45-6789", "(\\d{3})-(\\d{2})-\\d{4}");   ---> 12345  XXX-XX-6789
//  encrypt(12345) --> 88888
//  insertEncryptedPart(String original, String regex, String insertion)   ---> 888-88-6789
//  getDisplayable(String encrypted, String regex)     888-88-6789 ---> XXX-XX-6789






    @Test
    public void testMask1() {
        
        String original = "123-45-6789";
        String regex = "(\\d{3})-(\\d{2})-(\\d{4})";
        
        FPEMask mask = new FPEMask(original, regex);
        System.out.println("original: " + original + "  using regex: " + regex);
        
        String cipher = "987654321";  // assume that this is the result of the fpe encrypt for the encryptable part
        String encryptable = mask.getEncryptablePart();
        System.out.println("FPEMask determined encryptable part: " + encryptable);
        System.out.println("Lets assume this 'encrypts' to cipher: " + cipher);
                
        String withInsertion = mask.insertEncryptedPart(cipher);
        System.out.println("FPEMask applies insertion of cipher: " + withInsertion);
        
        String redacted = mask.getRedacted();
        System.out.println("FPEMask returns redacted: " + redacted);
        
        assertEquals(true, true);  // TODO - Determine appropriate test
    }



    @Test
    public void testMask2() {

        String original = "123-45-6789";
        String regex = "(\\d{3})-(\\d{2})-\\d{4}";
        
        FPEMask mask = new FPEMask(original, regex);
        System.out.println("original: " + original + "  using regex: " + regex);
      
        String encryptable = mask.getEncryptablePart();
        String cipher = "00000";  // assume that this is the result of the fpe encrypt for the encryptable part
        System.out.println("FPEMask determined encryptable part: " + encryptable);
        System.out.println("Lets assume this 'encrypts' to cipher: " + cipher);
                
        String withInsertion = mask.insertEncryptedPart(cipher);
        System.out.println("FPEMask applies insertion of cipher: " + withInsertion);
        
        String redacted = mask.getRedacted();
        System.out.println("FPEMask returns redacted: " + redacted);
        
            
        assertEquals(true, true);  // TODO - Determine appropriate test
    }








}
