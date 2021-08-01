package com.ubiqsecurity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;


import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;

import java.util.concurrent.ExecutionException;






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
    
 
 
 
 
 
    // STUB - temporary key
    // The cipher API requires an encryption key. For now lets hardcode here but later comes from backend
    public byte[] TEMP_getAKey(FFS_Record ffs) {
       final byte[] keyFF1 = {
            (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
            (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
            (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c,
            (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
            (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
            (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
            (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94
        };
        final byte[] keyFF3_1 = {
            (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
            (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
            (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
            (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
            (byte)0x3b, (byte)0x80, (byte)0x6a, (byte)0xeb,
            (byte)0x63, (byte)0x08, (byte)0x27, (byte)0x1f,
            (byte)0x65, (byte)0xcf, (byte)0x33, (byte)0xc7,
            (byte)0x39, (byte)0x1b, (byte)0x27, (byte)0xf7,
        };

        byte[] key;
        String encryption_algorithm = ffs.getAlgorithm();
        switch(encryption_algorithm) {
            case "FF1":
                key= keyFF1;
            break;
            case "FF3_1":
                key= keyFF3_1;
            break;
            default:
                throw new RuntimeException("Unknown FPE Algorithm: " + encryption_algorithm);
        }
        return key;
    }





    
    
    
 
 
 
    public static String decryptFPE(UbiqCredentials ubiqCredentials, String FPEAlgorithm, String FPEName, String CipherText, byte[] tweek, String LDAP, FFS FFScaching) 
        throws IllegalStateException, InvalidCipherTextException {
        
        
            String PlainText = "";
        
            // STUB - tweek ranges
            final long twkmin= 0;
            final long twkmax= 10;
            int radix = 10;
        
        
        
            try (UbiqFPEDecrypt ubiqDecrypt = new UbiqFPEDecrypt(ubiqCredentials)) {
             
                // attempt to load the FPEAlgorithm from the local cache
                try {
                    String cachingKey = FPEAlgorithm + "-" + FPEName;
                    System.out.println("Loading for...." + cachingKey);
                    FFS_Record ffs = FFScaching.FFSCache.get(cachingKey);
                    
                    
                    // Obtain encryption key information
                    if (ubiqDecrypt.ubiqWebServices == null) {
                        throw new IllegalStateException("object closed");
                    } else if (ubiqDecrypt.aesGcmBlockCipher != null) {
                        throw new IllegalStateException("decryption in progress");
                    }
            
                    
                    // STUB - get the encryption key
                    byte[] key = ubiqDecrypt.TEMP_getAKey(ffs);
                    
                    
                    
                    
                    

                    // decrypt based on the specified cipher
                    String encryption_algorithm = ffs.getAlgorithm();
                    switch(encryption_algorithm) {
                        case "FF1":
                            FF1 ctxFF1 = new FF1(Arrays.copyOf(key, 16), tweek, twkmin, twkmax, radix); 
                            PlainText = ctxFF1.decrypt(CipherText);
                        break;
                        case "FF3_1":
                            FF3_1 ctxFF3_1 = new FF3_1(Arrays.copyOf(key, 16), tweek, radix); 
                            PlainText = ctxFF3_1.decrypt(CipherText);
                        break;
                        default:
                            throw new RuntimeException("Unknown FPE Algorithm: " + encryption_algorithm);
                    }
            




                } catch (ExecutionException e) {
                        e.printStackTrace();
                }
                
            
            
            
            
            
            }  // try        
        
        return PlainText;
    }









   
    

    
    
    
}
