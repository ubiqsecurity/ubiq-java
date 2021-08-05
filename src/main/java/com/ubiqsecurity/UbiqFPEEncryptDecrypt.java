package com.ubiqsecurity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import com.google.gson.Gson;

import java.util.Arrays;
import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;
import java.math.BigInteger;
import ubiqsecurity.fpe.Bn;

import java.util.concurrent.ExecutionException;
 



import org.bouncycastle.crypto.InvalidCipherTextException;

public class UbiqFPEEncryptDecrypt implements AutoCloseable {
    private int usesRequested;
    private UbiqWebServices ubiqWebServices; // null when closed
    private int useCount;
    private EncryptionKeyResponse encryptionKey;
    private DecryptionKeyResponse decryptionKey;
    private AesGcmBlockCipher aesGcmBlockCipher;
    private Gson FFSdata;
    private FFS ffs;
 

    public UbiqFPEEncryptDecrypt(UbiqCredentials ubiqCredentials, int usesRequested) {
        this.usesRequested = usesRequested;
        this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);
        this.FFSdata = new Gson();
    }
    

    public void close() {
        if (this.ubiqWebServices != null) {
            if (this.encryptionKey != null) {
                // if key was used less times than requested, notify the server.
                if (this.useCount < this.usesRequested) {
// TODO - Does not work. Need to update this call since KeyFingerprint and EncryptionSession is not provided.
                    System.out.println(String.format("UbiqFPEEncryptDecrypt.close: reporting key usage: %d of %d", this.useCount,
                            this.usesRequested));
                    this.ubiqWebServices.updateEncryptionKeyUsage(this.useCount, this.usesRequested,
                            this.encryptionKey.KeyFingerprint, this.encryptionKey.EncryptionSession);
                }
            }
            this.ubiqWebServices = null;
        }
    }


    // STUB - scrub the PlainText using regex and passthrough filtering
    public String scrubPlaintext(FFS_Record ffs, String PlainText) {
        String scrubbed = "";
        
        scrubbed = ffs.stripFormatCharacters(PlainText);
        System.out.println("scrubPlaintext:    PlainText= " + PlainText + "   scrubbed= " + scrubbed);

        return scrubbed;
    }


    // STUB - convert to output radix
    public String convertToOutputRadix(FFS_Record ffs, String rawtext) {
        
        // convert a given string to a numerical location based on a given Input_character_set
        BigInteger r1 = Bn.__bigint_set_str(rawtext, ffs.getInput_character_set());
//         System.out.println("BigInteger r1= " + r1);
//         System.out.println("ffs.getInput_character_set()= " + ffs.getInput_character_set()  + "   ffs.getOutput_character_set()= " + ffs.getOutput_character_set());
        
        // convert a numerical location code to a string based on its location in an Output_character_set
        String output = Bn.__bigint_get_str(ffs.getOutput_character_set(), r1);
        System.out.println("convertToOutputRadix:    rawtext= " + rawtext  + "   output= " + output);
        

        return output;
    }
    
    
    // STUB - given the output radix, return the original string
    public String restoreFromRadix(FFS_Record ffs, String convertedToRadix) {
    
        // convert a given string to a numerical location based on a given Input_character_set
        BigInteger r1 = Bn.__bigint_set_str(convertedToRadix, ffs.getOutput_character_set());
        System.out.println("BigInteger r1= " + r1);
        
        // convert a numerical location code to a string based on its location in an Output_character_set
        String output = Bn.__bigint_get_str(ffs.getInput_character_set(), r1);
        System.out.println("restoreFromRadix:    convertedToRadix= " + convertedToRadix  + "   output= " + output);
        
        
        

        return output;
    }
    
    
    
    //public static String encryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String PlainText, byte[] tweek, String ldap) 
    // PlainText --> SSN, trim out 
    // 111-22-3333   --> 111223333
    //    fpeencrypt
    //    convert to output radix
    // restore passthrough  decrypt xxyyzzzz ---> xx-yy-zzzz
    // 
    


    public String encryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String PlainText, byte[] tweek, String ldap) 
        throws IllegalStateException, InvalidCipherTextException {
      
            // check for FFS cache 
            //    else call server for FFD (aka FFS)  --- from UbiqFPEEncrypt(ubiqCredentials, 1) eevntually return JSON obkect for JP's model def
            
            // Based on FFS, determine if PT match this specification (radix, passthrough, regex), we will create algorithm to do this
            
            // From FFS get encryption algorithm (FF1 or FF3_1)
            
            // Validate ldap request (later)
            
            // Validate does FFS spec require/supply tweek.   Generated-random, constant, calculated, user-supplied
            //   May be embedded in FFS, or externally provided by user
            // Plaintext needs to be trimmed (passthrough characters e.g. dashes)  ---> santizedPlainText
            
            // Radix in FFS (list of valid chars) 
            
            // check cache for encyrption key...   else separate webservice call to api/v0/fpe/key/papi (part of credentials) --- data key needed for FPE
            //   if (this.encryptionKey == null) {
            // JIT: request encryption key from server
            //      this.encryptionKey = this.ubiqWebServices.getFPEEncryptionKey(this.usesRequested);  (API, ldap, FFS)    based on spec of 7/27/21 from Gary 
            //   }
            // decrypt key using credentials (already in standard code)
            
            
            // input radix conversion
            // call encryptFF1/encryptFF3_1 depending on FFS    ctx = getContext(   ((new FF1(Arrays.copyOf(key, 16), tweek, twkmin, twkmax, radix)))    )
            
            //ctx.encrypt(santizedPlainText)
            
            //  FFS may have both input radix and output radix
            /// convert to output radix, radix conversion
            
            // report billing updater
            
            
            
            
            
            String convertedToRadix = "";
            String cipher = "";
            
            
            // key for the cache is <credentials.papi>-<name>
            
            
            try (UbiqFPEEncryptDecrypt ubiqEncrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 1)) {
            
                // setup the cached FFS so that the ffs data may persist between encrypt/decrypt calls
                if (ffs == null) {
                    ffs = new FFS(this.ubiqWebServices, ffs_name, ldap);
                }
                
                
                
                
                // attempt to load the FPEAlgorithm from the local cache
                try {
                    String cachingKey = ubiqCredentials.getAccessKeyId() + "-" + ffs_name;   // <AccessKeyId>-<FFS Name> 
                    System.out.println("Loading for FFS record: " + cachingKey);
                    FFS_Record FFScaching = ffs.FFSCache.get(cachingKey);
                    
                    
                    // Obtain encryption key information
                    if (this.ubiqWebServices == null) {
                        throw new IllegalStateException("object closed");
                    } else if (this.aesGcmBlockCipher != null) {
                        throw new IllegalStateException("encryption in progress");
                    }

                    if (this.encryptionKey == null) {
                        this.encryptionKey = this.ubiqWebServices.getFPEEncryptionKey(ffs_name, ldap, this.usesRequested);
                    }

                    
                    // check key 'usage count' against server-specified limit
                    //if (this.useCount > this.encryptionKey.MaxUses) {
                        //throw new RuntimeException("maximum key uses exceeded:  " + this.useCount);    // TODO - Uncomment this line in production to allow checking for usage limit (2)
                    //}

                    
                    this.useCount++;
            
            
            
                    // get the encryption key
                    byte[] key = this.encryptionKey.UnwrappedDataKey;
                    
                    
                    
                    // STUB - scrub the PlainText using regex and passthrough filtering
                    String scrubbedText = scrubPlaintext(FFScaching, PlainText); 
                    System.out.println("scrubbedText = " + scrubbedText);
                    
                    
            
            
            
            
                    // set the tweek range and radix based on the FFS record
                    final long twkmin= FFScaching.getMin_input_length();
                    final long twkmax= FFScaching.getMax_input_length();
                    final int inputradix = FFScaching.getInput_character_set().length();
                    final int onputradix = FFScaching.getOutput_character_set().length();
            
            
            
                    // encrypt based on the specified cipher
                    String encryption_algorithm = FFScaching.getAlgorithm();
                    switch(encryption_algorithm) {
                        case "FF1":
                            FF1 ctxFF1 = new FF1(Arrays.copyOf(key, 16), tweek, twkmin, twkmax, inputradix); 
                            cipher = ctxFF1.encrypt(scrubbedText);
                            
                            // STUB - convert to output radix
                            convertedToRadix = convertToOutputRadix(FFScaching, cipher); 
            

                        break;
                        case "FF3_1":
                            FF3_1 ctxFF3_1 = new FF3_1(Arrays.copyOf(key, 16), tweek, inputradix); 
                            cipher = ctxFF3_1.encrypt(scrubbedText);
                            
                            // STUB - convert to output radix
                            convertedToRadix = convertToOutputRadix(FFScaching, cipher); 
                            
                        break;
                        default:
                            throw new RuntimeException("Unknown FPE Algorithm: " + encryption_algorithm);
                    }
                    System.out.println("cipher = " + cipher + "    convertedToRadix = " + convertedToRadix);
                    
                    
                    System.out.println("restored = " + restoreFromRadix(FFScaching, convertedToRadix));
                    
                   
                    
                } catch (ExecutionException e) {
                    e.printStackTrace();
                }
            
            }  // try
            return convertedToRadix;
    }
      
      
      
      
      
      
      
      
      

 
 
    public  String decryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String CipherText, byte[] tweek, String ldap) 
        throws IllegalStateException, InvalidCipherTextException {
        
        
            String PlainText = "";
            String restoredFromRadix = "";
        
        
            try (UbiqFPEEncryptDecrypt ubiqDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 1)) {
            
                // setup the cached FFS so that the ffs data may persist between encrypt/decrypt calls
                if (ffs == null) {
                    ffs = new FFS(this.ubiqWebServices, ffs_name, ldap);
                }
             
                // attempt to load the FPEAlgorithm from the local cache
                try {
                    String cachingKey = ubiqCredentials.getAccessKeyId() + "-" + ffs_name; // <AccessKeyId>-<FFS Name> 
                    System.out.println("Loading for: " + cachingKey);
                    FFS_Record FFScaching = ffs.FFSCache.get(cachingKey);
                    
                    
                    // Obtain encryption key information
                    if (this.ubiqWebServices == null) {
                        throw new IllegalStateException("object closed");
                    } else if (this.aesGcmBlockCipher != null) {
                        throw new IllegalStateException("decryption in progress");
                    }
                    
                    
                    
                    // If needed, use the header info to fetch the decryption key.
//                     if (ubiqDecrypt.decryptionKey == null) {
//                         // JIT: request encryption key from server
//                         ubiqDecrypt.decryptionKey = ubiqDecrypt.ubiqWebServices.getDecryptionKey(ubiqDecrypt.cipherHeader.encryptedDataKeyBytes);
//                     }
//                     if (ubiqDecrypt.decryptionKey != null) {
//                         ubiqDecrypt.reset();
//                         ubiqDecrypt.decryptionKey = ubiqDecrypt.ubiqWebServices.getDecryptionKey(ubiqDecrypt.cipherHeader.encryptedDataKeyBytes);
//                         ubiqDecrypt.decryptionKey.KeyUseCount++;
//                     }
                    
                    
                    if (this.decryptionKey == null) {
                        int key_number = 0;
                        
                        this.decryptionKey = this.ubiqWebServices.getFPEDecryptionKey(ffs_name, "ldap", key_number);
                        System.out.println("this.decryptionKey: " + this.decryptionKey);
                    }


            
                    
                    // get the encryption key
                    byte[] key = this.decryptionKey.UnwrappedDataKey;
                    
                    
                    
                    // set the tweek range and radix based on the FFS record
                    final long twkmin= FFScaching.getMin_input_length();
                    final long twkmax= FFScaching.getMax_input_length();
                    final int inputradix = FFScaching.getInput_character_set().length();
                    final int onputradix = FFScaching.getOutput_character_set().length();


                    // restore the cipher from the radix 
                    restoredFromRadix = restoreFromRadix(FFScaching, CipherText); 

                    // decrypt based on the specified cipher
                    String encryption_algorithm = FFScaching.getAlgorithm();
                    switch(encryption_algorithm) {
                        case "FF1":
                            FF1 ctxFF1 = new FF1(Arrays.copyOf(key, 16), tweek, twkmin, twkmax, inputradix); 
                            PlainText = ctxFF1.decrypt(restoredFromRadix);
                        break;
                        case "FF3_1":
                            FF3_1 ctxFF3_1 = new FF3_1(Arrays.copyOf(key, 16), tweek, inputradix); 
                            PlainText = ctxFF3_1.decrypt(restoredFromRadix);
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
