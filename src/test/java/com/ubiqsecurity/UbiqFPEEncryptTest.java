package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;
import java.math.BigInteger;


import java.util.Arrays;
import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;
import com.ubiqsecurity.UbiqFactory;



public class UbiqFPEEncryptTest
{







    @Test
    public void encryptFPE() {
    
        try {
        
            // TODO - setup a set of standard credentials, for now hardcode some here
            UbiqCredentials ubiqCredentials;
//             ubiqCredentials = UbiqFactory.createCredentials(
//                     "J07/KueP1k07rsJjRwFBfJpF",
//                     "GMmrma7+4D7I1ymYUqInvuHmFjrhQ70zslDQ+EZbVHfS",
//                     "bkEyHxQZ5/mq+pu3vHA22fSgKUSKKgUaTKn5KGIFTUhv",
//                     "https://dev.koala.ubiqsecurity.com");                    
            ubiqCredentials = UbiqFactory.createCredentials(
                    "0cxsgl9sL2QLGlBpm6D3s6KG",
                    "ZBkJQWe8Ylz6TBa3avYkc4zUb5tEk62wsya7wBZM8aDC",
                    "RzF9gvqFp7H0a1pzRpLBfBavQSNyqJJJ0yWrwWtWGvIS",
                    "https://stg.koala.ubiqsecurity.com");
                    
 
// note: "0cxsgl9sL2QLGlBpm6D3s6KG" is the <credentials.papi>  (this.accessKeyId)



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
            

            
                assertEquals(original, decrypted);
            }
    
        } catch (Exception ex) {
            System.out.println(String.format("Exception: %s", ex.getMessage()));
            ex.printStackTrace();
            System.exit(1);
        }    
    
    

    }




















}
