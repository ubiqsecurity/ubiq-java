package com.ubiqsecurity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import com.google.gson.Gson;

import java.util.Arrays;
import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;

import java.util.Base64;


import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;

import java.util.concurrent.ExecutionException;
 



import org.bouncycastle.crypto.InvalidCipherTextException;

public class UbiqFPEEncrypt implements AutoCloseable {
    private int usesRequested;

    private UbiqWebServices ubiqWebServices; // null when closed
    private int useCount;
    private EncryptionKeyResponse encryptionKey;
    private AesGcmBlockCipher aesGcmBlockCipher;
    
    private Gson FFSdata;
    
    
    
    private LoadingCache<String, FFS> FFSCache;
    

    public UbiqFPEEncrypt(UbiqCredentials ubiqCredentials, int usesRequested) {
        this.usesRequested = usesRequested;
        this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);
        
        this.FFSdata = new Gson();
        
        System.out.println("NEW OBJECT UbiqFPEEncrypt");
        
        
        
        //create a cache for FFS based on the encryption_algorithm
        //LoadingCache<String, FFS> FFSCache =
        FFSCache = 
            CacheBuilder.newBuilder()
            .maximumSize(100)                             // maximum 100 records can be cached
            .expireAfterAccess(30, TimeUnit.MINUTES)      // cache will expire after 30 minutes of access
            .build(new CacheLoader<String, FFS>() {  // build the cacheloader

                @Override
                public FFS load(String encryption_algorithm) throws Exception {
                   //make the expensive call
                   return getFFSFromDatabase(encryption_algorithm);
                } 
         });
         
         
    }
    
    private  FFS getFFSFromDatabase(String encryption_algorithm) {
//         String jsonStr= "{'encryption_algorithm': 'FF1'}";
//         Gson gson = FFSdata;        
//         FFS ffs = gson.fromJson(jsonStr, FFS.class);
        
        FFS ffs = TEMP_preloadFFSwithData1();
        
        System.out.println("----- getFFSFromDatabase");
        
        return ffs;
    }


    public void close() {
        if (this.ubiqWebServices != null) {
            if (this.encryptionKey != null) {
                // if key was used less times than requested, notify the server.
                if (this.useCount < this.usesRequested) {
                    System.out.println(String.format("UbiqFPEEncrypt.close: reporting key usage: %d of %d", this.useCount,
                            this.usesRequested));
                    this.ubiqWebServices.updateEncryptionKeyUsage(this.useCount, this.usesRequested,
                            this.encryptionKey.KeyFingerprint, this.encryptionKey.EncryptionSession);
                }
            }

            this.ubiqWebServices = null;
        }
    }



    // STUB - temporary key
    public byte[] TEMP_getAKey(FFS ffs) {
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


    // STUB - FFS data
    public FFS TEMP_preloadFFSwithData1() {
        System.out.println("----- TEMP_preloadFFSwithData1");
        
        String jsonStr= "{'encryption_algorithm': 'FF1'}";
        Gson gson = FFSdata;        
        FFS ffs = gson.fromJson(jsonStr, FFS.class);
        
        ffs.setName("SSN");
        ffs.setRegex("(\\d{3})-(\\d{2})-(\\d{4})");
        ffs.setTweak_source("generated");
        ffs.setMin_input_length(9);
        ffs.setMax_input_length(9);
        ffs.setFpe_definable(true);
        
	    return ffs;
    }



    // STUB - FFS data
    public FFS TEMP_preloadFFSwithData2() {
        System.out.println("----- TEMP_preloadFFSwithData2");
        
        String jsonStr= "{'encryption_algorithm': 'FF3_1'}";
        Gson gson = FFSdata;        
        FFS ffs = gson.fromJson(jsonStr, FFS.class);
        
        ffs.setName("SSN");
        ffs.setRegex("(\\d{3})-(\\d{2})-(\\d{4})");
        ffs.setTweak_source("generated");
        ffs.setMin_input_length(9);
        ffs.setMax_input_length(9);
        ffs.setFpe_definable(true);
	    
	    return ffs;
    }
    
    
    
    
    public FFS getFFS(String FPEAlgorithm) {
        String FFScontent = "";
        
        System.out.println("----- getFFS for: " + FPEAlgorithm);
        
        
        // STUB - for now preload the hardcoded FFS JSON data
        FFS ffs;
        switch(FPEAlgorithm) {
            case "FF1":
                ffs = TEMP_preloadFFSwithData1();
            break;
            case "FF3_1":
                ffs = TEMP_preloadFFSwithData2();
            break;
            default:
                throw new RuntimeException("Unknown FPE Algorithm: " + FPEAlgorithm);
        }
        
        

        
        
        return ffs;
    }
    
    
    
    
    
    
    



    public static String encryptFPE(UbiqCredentials ubiqCredentials, String FPEAlgorithm, String PlainText, byte[] tweek, String LDAP) 
        throws IllegalStateException, InvalidCipherTextException {
      
            // check for FFS cache 
            //    else call server for FFD (aka FFS)  --- from UbiqFPEEncrypt(ubiqCredentials, 1) eevntually return JSON obkect for JP's model def
            
            // Based on FFS, determine if PT match this specification (radix, passthrough, regex), we will create algorithm to do this
            
            // From FFS get encryption algorithm (FF1 or FF3_1)
            
            // Validate LDAP request (later)
            
            // Validate does FFS spec require/supply tweek.   Generated-random, constant, calculated, user-supplied
            //   May be embedded in FFS, or externally provided by user
            // Plaintext needs to be trimmed (passthrough characters e.g. dashes)  ---> santizedPlainText
            
            // Radix in FFS (list of valid chars) 
            
            // check cache for encyrption key...   else separate webservice call to api/v0/fpe/key/papi (part of credentials) --- data key needed for FPE
            //   if (this.encryptionKey == null) {
            // JIT: request encryption key from server
            //      this.encryptionKey = this.ubiqWebServices.getFPEEncryptionKey(this.usesRequested);  (API, LDAP, FFS)    based on spec of 7/27/21 from Gary 
            //   }
            // decrypt key using credentials (already in standard code)
            
            
            // input radix conversion
            // call encryptFF1/encryptFF3_1 depending on FFS    ctx = getContext(   ((new FF1(Arrays.copyOf(key, 16), tweek, twkmin, twkmax, radix)))    )
            
            //ctx.encrypt(santizedPlainText)
            
            //  FFS may have both input radix and output radix
            /// convert to output radix, radix conversion
            
            // report billing updater
            
            
            
            
            
            
            String cipher = "";
            
            // STUB - For now, hardcode a key    
            // STUB - tweek ranges
            final long twkmin= 0;
            final long twkmax= 10;
            int radix = 10;
          
            
            
            
            
            try (UbiqFPEEncrypt ubiqEncrypt = new UbiqFPEEncrypt(ubiqCredentials, 1)) {
            
                System.out.println("Running encryptFPE");
                
                
                
                // attempt to load the FPEAlgorithm from the local cache
                try {
                    //System.out.println(ubiqEncrypt.FFSCache.get("FF1"));
                    
                    
                    System.out.println("First FF1 load....");
                    FFS ffs = ubiqEncrypt.FFSCache.get("FF1");
                    System.out.println("    ffs.getAlgorithm()= " + ffs.getAlgorithm());
                    System.out.println("    ffs.getUser()= " + ffs.getUser());
                    System.out.println("    ffs.getCustomer()= " + ffs.getCustomer());
                    System.out.println("    ffs.getName()= " + ffs.getName());
                    System.out.println("    ffs.getRegex()= " + ffs.getRegex());
                    System.out.println("    ffs.getTweak_source()= " + ffs.getTweak_source());
                    System.out.println("    ffs.getMin_input_length()= " + ffs.getMin_input_length());
                    System.out.println("    ffs.getMax_input_length()= " + ffs.getMax_input_length());
                    System.out.println("    ffs.getFpe_definable()= " + ffs.getFpe_definable());
                    
                    
                    System.out.println("Second FF1 load....");
                    ffs = ubiqEncrypt.FFSCache.get("FF1");
                    System.out.println("    ffs.getAlgorithm()= " + ffs.getAlgorithm());
                    System.out.println("    ffs.getUser()= " + ffs.getUser());
                    System.out.println("    ffs.getCustomer()= " + ffs.getCustomer());
                    System.out.println("    ffs.getName()= " + ffs.getName());
                    System.out.println("    ffs.getRegex()= " + ffs.getRegex());
                    System.out.println("    ffs.getTweak_source()= " + ffs.getTweak_source());
                    System.out.println("    ffs.getMin_input_length()= " + ffs.getMin_input_length());
                    System.out.println("    ffs.getMax_input_length()= " + ffs.getMax_input_length());
                    System.out.println("    ffs.getFpe_definable()= " + ffs.getFpe_definable());
                    
                    System.out.println("First FF3_1 load....");
                    ffs = ubiqEncrypt.FFSCache.get("FF3_1");
                    System.out.println("    ffs.getAlgorithm()= " + ffs.getAlgorithm());
                    System.out.println("    ffs.getUser()= " + ffs.getUser());
                    System.out.println("    ffs.getCustomer()= " + ffs.getCustomer());
                    System.out.println("    ffs.getName()= " + ffs.getName());
                    System.out.println("    ffs.getRegex()= " + ffs.getRegex());
                    System.out.println("    ffs.getTweak_source()= " + ffs.getTweak_source());
                    System.out.println("    ffs.getMin_input_length()= " + ffs.getMin_input_length());
                    System.out.println("    ffs.getMax_input_length()= " + ffs.getMax_input_length());
                    System.out.println("    ffs.getFpe_definable()= " + ffs.getFpe_definable());
                    
                    
                    System.out.println("Second FF3_1 load....");
                    ffs = ubiqEncrypt.FFSCache.get("FF3_1");
                    System.out.println("    ffs.getAlgorithm()= " + ffs.getAlgorithm());
                    System.out.println("    ffs.getUser()= " + ffs.getUser());
                    System.out.println("    ffs.getCustomer()= " + ffs.getCustomer());
                    System.out.println("    ffs.getName()= " + ffs.getName());
                    System.out.println("    ffs.getRegex()= " + ffs.getRegex());
                    System.out.println("    ffs.getTweak_source()= " + ffs.getTweak_source());
                    System.out.println("    ffs.getMin_input_length()= " + ffs.getMin_input_length());
                    System.out.println("    ffs.getMax_input_length()= " + ffs.getMax_input_length());
                    System.out.println("    ffs.getFpe_definable()= " + ffs.getFpe_definable());

                    System.out.println("Original FF1 load....");
                    ffs = ubiqEncrypt.FFSCache.get("FF1");
                    System.out.println("    ffs.getAlgorithm()= " + ffs.getAlgorithm());
                    System.out.println("    ffs.getUser()= " + ffs.getUser());
                    System.out.println("    ffs.getCustomer()= " + ffs.getCustomer());
                    System.out.println("    ffs.getName()= " + ffs.getName());
                    System.out.println("    ffs.getRegex()= " + ffs.getRegex());
                    System.out.println("    ffs.getTweak_source()= " + ffs.getTweak_source());
                    System.out.println("    ffs.getMin_input_length()= " + ffs.getMin_input_length());
                    System.out.println("    ffs.getMax_input_length()= " + ffs.getMax_input_length());
                    System.out.println("    ffs.getFpe_definable()= " + ffs.getFpe_definable());


                    
                    
                } catch (ExecutionException e) {
                    e.printStackTrace();
                }
            
            
                FFS ffs = ubiqEncrypt.getFFS(FPEAlgorithm);
                FFS ffs2 = ubiqEncrypt.getFFS(FPEAlgorithm);
                FFS ffs3 = ubiqEncrypt.getFFS(FPEAlgorithm);
 
            
            
            
            
            
                // Obtain encryption key information
                if (ubiqEncrypt.ubiqWebServices == null) {
                    throw new IllegalStateException("object closed");
                } else if (ubiqEncrypt.aesGcmBlockCipher != null) {
                    throw new IllegalStateException("encryption in progress");
                }

                if (ubiqEncrypt.encryptionKey == null) {
                    // JIT: request encryption key from server
                    ubiqEncrypt.encryptionKey = ubiqEncrypt.ubiqWebServices.getEncryptionKey(ubiqEncrypt.usesRequested);
                }

                // check key 'usage count' against server-specified limit
                if (ubiqEncrypt.useCount > ubiqEncrypt.encryptionKey.MaxUses) {
                    throw new RuntimeException("maximum key uses exceeded");
                }

                ubiqEncrypt.useCount++;
            
            
            
                // STUB - get the encryption key
                byte[] key = ubiqEncrypt.TEMP_getAKey(ffs);
                
            
            
            
                // encrypt based on the specified cipher
                String encryption_algorithm = ffs.getAlgorithm();
                switch(encryption_algorithm) {
                    case "FF1":
                        FF1 ctxFF1 = new FF1(Arrays.copyOf(key, 16), tweek, twkmin, twkmax, radix); 
                        cipher = ctxFF1.encrypt(PlainText);
                    break;
                    case "FF3_1":
                        FF3_1 ctxFF3_1 = new FF3_1(Arrays.copyOf(key, 16), tweek, radix); 
                        cipher = ctxFF3_1.encrypt(PlainText);
                    break;
                    default:
                        throw new RuntimeException("Unknown FPE Algorithm: " + encryption_algorithm);
                }
            
            
            
            
            }  // try
            
            
            
            
            return cipher;
            
    }
      
      
      
      
      
      
      
      
      





        

    
        
    
    
    
}
