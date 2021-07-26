package com.ubiqsecurity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;


import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;



import org.bouncycastle.crypto.InvalidCipherTextException;

public class UbiqFPEDecrypt implements AutoCloseable {
    private UbiqWebServices ubiqWebServices; // null on close

    private CipherHeader cipherHeader; // extracted from beginning of ciphertext
    private ByteQueue byteQueue;
    private DecryptionKeyResponse decryptionKey;
    private AesGcmBlockCipher aesGcmBlockCipher;

    public UbiqFPEDecrypt(UbiqCredentials ubiqCredentials) {
        this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);
    }

    public void close() {
        if (this.ubiqWebServices != null) {
            // reports decryption key usage to server, if applicable
            reset();

            this.ubiqWebServices = null;
        }
    }







    // Reset the internal state of the decryption object.
    // This function can be called at any time to abort an existing
    // decryption operation.  It is also called by internal functions
    // when a new decryption requires a different key than the one
    // used by the previous decryption.
    private void reset() {
        assert this.ubiqWebServices != null;

        if (decryptionKey != null) {
            if (decryptionKey.KeyUseCount > 0) {
                this.ubiqWebServices.updateDecryptionKeyUsage(this.decryptionKey.KeyUseCount,
                        this.decryptionKey.KeyFingerprint, this.decryptionKey.EncryptionSession);
            }

            this.decryptionKey = null;
        }

        this.aesGcmBlockCipher = null;
    }
    
 
 
     public static String decryptFF1(UbiqCredentials ubiqCredentials, byte[] tweek, int radix, String CipherText)
            throws IllegalStateException, InvalidCipherTextException {
            
            
        // STUB - For now, hardcode a key    
        final byte[] key = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c,
            (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
            (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
            (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
            (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
        };
        
        // STUB - tweek ranges
        final long twkmin= 0;
        final long twkmax= 0;
        
            
        //try (UbiqFPEDecrypt ubiqDecrypt = new UbiqFPEDecrypt(ubiqCredentials)) {
        try (UbiqDecrypt ubiqDecrypt = new UbiqDecrypt(ubiqCredentials)) {
            FF1 ctx;
            ctx = new FF1(Arrays.copyOf(key, 16), tweek, twkmin, twkmax, radix); 
            String output = ctx.decrypt(CipherText);
        
            System.out.println("decryptFF1 CipherText= " + CipherText);
            System.out.println("decryptFF1 output= " + output);
        
        
            return output;
        }
    }
    
    
    
    


     public static String decryptFF3_1(UbiqCredentials ubiqCredentials, byte[] tweek, int radix, String CipherText)
            throws IllegalStateException, InvalidCipherTextException {
            
            
        // STUB - For now, hardcode a key    
        final byte[] key = {
            (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
            (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
            (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
            (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
            (byte)0x3b, (byte)0x80, (byte)0x6a, (byte)0xeb,
            (byte)0x63, (byte)0x08, (byte)0x27, (byte)0x1f,
            (byte)0x65, (byte)0xcf, (byte)0x33, (byte)0xc7,
            (byte)0x39, (byte)0x1b, (byte)0x27, (byte)0xf7,
        };
        
            
        //try (UbiqFPEDecrypt ubiqDecrypt = new UbiqFPEDecrypt(ubiqCredentials)) {
        try (UbiqDecrypt ubiqDecrypt = new UbiqDecrypt(ubiqCredentials)) {
            FF3_1 ctx;
            ctx = new FF3_1(Arrays.copyOf(key, 16), tweek, radix); 
            String output = ctx.decrypt(CipherText);
        
            System.out.println("decryptFF3_1 CipherText= " + CipherText);
            System.out.println("decryptFF3_1 output= " + output);
        
        
            return output;
        }
    }
    
    
        
    
    
//     public static String decryptFF1(String CipherText) {
//         final byte[] key = {
//             (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
//             (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
//             (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
//             (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c,
//             (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
//             (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
//             (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
//             (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
//         };
//         final byte[] twk = {
//             (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
//             (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
//             (byte)0x31, (byte)0x30,
//         };
//         final long twkmin= 0;
//         final long twkmax= 0;
//         final int radix= 10;
//         
//         FF1 ctx;
//         ctx = new FF1(Arrays.copyOf(key, 16), twk, twkmin, twkmax, radix); 
//         String output = ctx.decrypt(CipherText);
//         
//         
//         
//         System.out.println("decryptFF1 CipherText= " + CipherText);
//         System.out.println("decryptFF1 output= " + output);
//         
//         
//         return output;
//     }
//     
//     
//     
//     public static String decryptFF3_1(String CipherText) {
//         final byte[] key = {
//             (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
//             (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
//             (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
//             (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
//             (byte)0x3b, (byte)0x80, (byte)0x6a, (byte)0xeb,
//             (byte)0x63, (byte)0x08, (byte)0x27, (byte)0x1f,
//             (byte)0x65, (byte)0xcf, (byte)0x33, (byte)0xc7,
//             (byte)0x39, (byte)0x1b, (byte)0x27, (byte)0xf7,
//         };
//         final byte[] twk = {
//             (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
//             (byte)0x00, (byte)0x00, (byte)0x00,
//         };
//         final int radix= 10;
//         
//         FF3_1 ctx;
//         ctx = new FF3_1(Arrays.copyOf(key, 16), twk, radix); 
//         String output = ctx.decrypt(CipherText);
//         
//         
//         
//         System.out.println("decryptFF3_1 CipherText= " + CipherText);
//         System.out.println("decryptFF3_1 output= " + output);
//         
//         
//         return output;
//     }
//     
//     
    
    
    
}
