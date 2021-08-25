package com.ubiqsecurity;

import com.google.gson.Gson;
import java.util.Arrays;
import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;
import java.math.BigInteger;
import ubiqsecurity.fpe.Bn;
import java.util.concurrent.ExecutionException;
import org.bouncycastle.crypto.InvalidCipherTextException;



public class UbiqFPEEncryptDecrypt implements AutoCloseable {
    private boolean verbose= true;
    private int usesRequested;
    private UbiqWebServices ubiqWebServices; // null when closed
    private int useCount;
    private EncryptionKeyResponse encryptionKey;
    private DecryptionKeyResponse decryptionKey;
    private AesGcmBlockCipher aesGcmBlockCipher;
    private Gson FFSdata;
    private FFS ffs;
    
    private String formatted_dest;
    private String trimmed;
    
    private String base10_charset = "0123456789";
    
    
 

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
//                     System.out.println(String.format("UbiqFPEEncryptDecrypt.close: reporting key usage: %d of %d", this.useCount,
//                             this.usesRequested));
//                     this.ubiqWebServices.updateEncryptionKeyUsage(this.useCount, this.usesRequested,
//                             this.encryptionKey.KeyFingerprint, this.encryptionKey.EncryptionSession);
                }
            }
            this.ubiqWebServices = null;
        }
    }
    
    
    
    
    
    public void ubiq_platform_fpe_string_parse(
        FFS_Record ffs, 
        long conversion_direction, // Positive (1) means input to output, negative (-1) means output to input
        String source_string)    
    {
        String src_char_set= "";
        char dest_zeroth_char= '0';
        char source_zeroth_char= '0';
        
    
        if (conversion_direction > 0) { // input to output 
            src_char_set= ffs.getInput_character_set();
            dest_zeroth_char = ffs.getOutput_character_set().charAt(0);
        } else {
            src_char_set= ffs.getOutput_character_set();
            dest_zeroth_char = ffs.getInput_character_set().charAt(0);
        }
        
        
        source_zeroth_char = src_char_set.charAt(0);
        String trimmed_output = Parsing.createString(source_string.length(), String.valueOf(source_zeroth_char));
        String empty_formatted_output = Parsing.createString(source_string.length(), String.valueOf(dest_zeroth_char));  
     
        try (Parsing parsing = new Parsing(trimmed_output, empty_formatted_output)) {

            int status = parsing.ubiq_platform_efpe_parsing_parse_input(source_string, src_char_set, ffs.getPassthrough_character_set()); 
            
            this.trimmed= parsing.get_trimmed_characters();
            this.formatted_dest= parsing.get_empty_formatted_output();
         }
    }
    
    
    // merge to formatted output
    public void merge_to_formatted_output(FFS_Record ffs, String convertedToRadix) {
        int d = this.formatted_dest.length() - 1;
        int s = convertedToRadix.length() - 1;
        
        //if (verbose) System.out.println("@@@@ this.formatted_dest= " + this.formatted_dest); 
        //if (verbose) System.out.println("    convertedToRadix= " + convertedToRadix); 
        
        // Merge PT to formatted output
        while (s >= 0 && d >= 0) {
            // Find the first available destination character
            while (d >=0 && this.formatted_dest.charAt(d) != ffs.getOutput_character_set().charAt(0)) {
                d--;
            }

            // Copy the encrypted text into the formatted output string
            if (d >= 0) {
                this.formatted_dest = Parsing.replaceChar(this.formatted_dest, convertedToRadix.charAt(s), d);
            }        
            s = s - 1;
            d = d - 1;
        }
        
        //if (verbose) System.out.println("    AFTER this.formatted_dest= " + this.formatted_dest); 
        //if (verbose) System.out.println("    AFTER convertedToRadix= " + convertedToRadix); 
        return;
    }
    
 

    // convert to output radix
    public String str_convert_radix(FFS_Record ffs, String rawtext, String input_radix, String output_radix) {
        // convert a given string to a numerical location based on a given Input_character_set
        BigInteger r1 = Bn.__bigint_set_str(rawtext, input_radix);
        
        // convert a numerical location code to a string based on its location in an Output_character_set
        String output = Bn.__bigint_get_str(output_radix, r1);
        
        return output;
    }
    


 
 
        

    public String encryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String PlainText, byte[] tweek) 
        throws IllegalStateException, InvalidCipherTextException {
            
            //if (verbose) System.out.println("\n@@@@@@@@@@ STARTING ENCRYPT @@@@@@@@@@");
            if (verbose) System.out.println("\nEncrypting PlainText: " + PlainText);
            
            String convertedToRadix = "";
            String cipher = "";
            String withInsertion = "";
            
            
            // key for the cache is <credentials.papi>-<name>
            try (UbiqFPEEncryptDecrypt ubiqEncrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 1)) {
            
                // setup the cached FFS so that the ffs data may persist between encrypt/decrypt calls
                if (ffs == null) {
                    ffs = new FFS(this.ubiqWebServices, ffs_name);
                }
                
                // attempt to load the FPEAlgorithm from the local cache
                try {
                    String cachingKey = ubiqCredentials.getAccessKeyId() + "-" + ffs_name;   // <AccessKeyId>-<FFS Name> 
                    FFS_Record FFScaching = ffs.FFSCache.get(cachingKey);
                    
                    // Obtain encryption key information
                    if (this.ubiqWebServices == null) {
                        throw new IllegalStateException("object closed");
                    } else if (this.aesGcmBlockCipher != null) {
                        throw new IllegalStateException("encryption in progress");
                    }

                    if (this.encryptionKey == null) {
                        int key_number = FFScaching.getCurrent_key();
                        // key_number = 0; 
                        key_number = 5;    // DONT NEED TO PASS IN KEY NUMBER IN getFPEEncryptionKey, ONLY IN getFPEDecryptionKey()
                        System.out.println("    key_number: " + key_number);
                        this.encryptionKey = this.ubiqWebServices.getFPEEncryptionKey(ffs_name, this.usesRequested, key_number);
                    }

                    
                    // check key 'usage count' against server-specified limit
                    //if (this.useCount > this.encryptionKey.MaxUses) {
                        //throw new RuntimeException("maximum key uses exceeded:  " + this.useCount);    // TODO - Uncomment this line in production to allow checking for usage limit (2)
                    //}

                    
                    this.useCount++;
            
                    // get the encryption key
                    byte[] key = this.encryptionKey.UnwrappedDataKey;
                    
                    
                    ubiq_platform_fpe_string_parse(FFScaching, 1, PlainText);


                    convertedToRadix = str_convert_radix(FFScaching, this.trimmed, FFScaching.getInput_character_set(), base10_charset);
                    if (verbose) System.out.println("    converted to base10= " + convertedToRadix);
                    

                    // set the tweek range and radix based on the FFS record
                    final long twkmin= FFScaching.getMin_input_length();
                    final long twkmax= FFScaching.getMax_input_length();
                    //final int inputradix = FFScaching.getInput_character_set().length();
                    final int inputradix = base10_charset.length();
                    final int onputradix = FFScaching.getOutput_character_set().length();

            
                    String encryption_algorithm = FFScaching.getAlgorithm();
                    switch(encryption_algorithm) {
                        case "FF1":
                            //System.out.println("     \ndoing ff1_encrypt"); 
                            FF1 ctxFF1 = new FF1(Arrays.copyOf(key, 16), tweek, twkmin, twkmax, inputradix); 
                            cipher = ctxFF1.encrypt(convertedToRadix);
                            if (verbose) System.out.println("    cipher= " + cipher);   
                        break;
                        case "FF3_1":
                            //System.out.println("     doing FF3_1_encrypt"); 
                            FF3_1 ctxFF3_1 = new FF3_1(Arrays.copyOf(key, 16), tweek, inputradix); 
                            cipher = ctxFF3_1.encrypt(convertedToRadix);
                            if (verbose) System.out.println("     cipher= " + cipher);   
                            
                        break;
                        default:
                            throw new RuntimeException("Unknown FPE Algorithm: " + encryption_algorithm);
                    }
                    
                    
                    
                    convertedToRadix = str_convert_radix(FFScaching, cipher, base10_charset, FFScaching.getOutput_character_set());
                    if (verbose) System.out.println("    converted to output char set= " + convertedToRadix);
                    if (verbose) System.out.println("    formatted destination= " + this.formatted_dest);
                    merge_to_formatted_output(FFScaching, convertedToRadix);
                    if (verbose) System.out.println("    encrypted and formatted= " + this.formatted_dest);
                    
                    
                     // scrub the PlainText using regex and passthrough filtering
//                     FPEMask mask = new FPEMask(PlainText, FFScaching.getRegex());
//                     String encryptableText = mask.getEncryptablePart();
//                     System.out.println("ENCRYPT encryptablePlaintext:    PlainText= " + PlainText + "   encryptableText= " + encryptableText + "   FFScaching.getRegex()= " + FFScaching.getRegex());
           

                    
                } catch (ExecutionException e) {
                    e.printStackTrace();
                }
            
            }  // try
            return this.formatted_dest;
    }
      
      
      

 
 
    public  String decryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String CipherText, byte[] tweek) 
        throws IllegalStateException, InvalidCipherTextException {
            String PlainText = "";
            String restoredFromRadix = "";
            String restoredPlainText = "";
            
            
            
            //System.out.println("\n@@@@@@@@@@ STARTING DECRYPT @@@@@@@@@@");
            if (verbose) System.out.println("\nDecrypting CipherText: " + CipherText);
            
        
            try (UbiqFPEEncryptDecrypt ubiqDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials, 1)) {
            
                // setup the cached FFS so that the ffs data may persist between encrypt/decrypt calls
                if (ffs == null) {
                    ffs = new FFS(this.ubiqWebServices, ffs_name);
                }
             
                // attempt to load the FPEAlgorithm from the local cache
                try {
                    String cachingKey = ubiqCredentials.getAccessKeyId() + "-" + ffs_name; // <AccessKeyId>-<FFS Name> 
                    FFS_Record FFScaching = ffs.FFSCache.get(cachingKey);
                    
                    // Obtain encryption key information
                    if (this.ubiqWebServices == null) {
                        throw new IllegalStateException("object closed");
                    } else if (this.aesGcmBlockCipher != null) {
                        throw new IllegalStateException("decryption in progress");
                    }
                                        
                    
                    if (this.decryptionKey == null) {
                        int key_number = FFScaching.getCurrent_key();
                        //key_number = 0;
                        key_number = 5;    // THIS KEY NUMBER WILL BE COMING FROM THE KEY ENCODED BYTE, HARDCODE FOR NOW
                        System.out.println("    key_number: " + key_number);
                        this.decryptionKey = this.ubiqWebServices.getFPEDecryptionKey(ffs_name, key_number);
                    }

                    
                    // get the encryption key
                    byte[] key = this.decryptionKey.UnwrappedDataKey;
                    
                    
                    ubiq_platform_fpe_string_parse(FFScaching, -1, CipherText);
                    
                    restoredFromRadix = str_convert_radix(FFScaching, this.trimmed, FFScaching.getOutput_character_set(), base10_charset);
                    if (verbose) System.out.println("    converted to base10= " + restoredFromRadix);
                    
                    
                    final long twkmin= FFScaching.getMin_input_length();
                    final long twkmax= FFScaching.getMax_input_length();
                    final int inputradix = base10_charset.length();
                    final int onputradix = FFScaching.getOutput_character_set().length();
                    
                    
                    // decrypt based on the specified cipher
                    String encryption_algorithm = FFScaching.getAlgorithm();
                    switch(encryption_algorithm) {
                        case "FF1":
                            //System.out.println("     \ndoing ff1_decrypt"); 
                            FF1 ctxFF1 = new FF1(Arrays.copyOf(key, 16), tweek, twkmin, twkmax, inputradix); 
                            PlainText = ctxFF1.decrypt(restoredFromRadix);
                            if (verbose) System.out.println("    PlainText= " + PlainText);   
                        break;
                        case "FF3_1":
                            //System.out.println("     \ndoing FF3_1_decrypt"); 
                            FF3_1 ctxFF3_1 = new FF3_1(Arrays.copyOf(key, 16), tweek, inputradix); 
                            PlainText = ctxFF3_1.decrypt(restoredFromRadix);
                            if (verbose) System.out.println("    PlainText= " + PlainText);   
                        break;
                        default:
                            throw new RuntimeException("Unknown FPE Algorithm: " + encryption_algorithm);
                    }                    
                    
                    restoredFromRadix = str_convert_radix(FFScaching, PlainText, base10_charset, FFScaching.getInput_character_set());
                    if (verbose) System.out.println("    converted to input char set= " + restoredFromRadix);
                    if (verbose) System.out.println("    formatted destination= " + this.formatted_dest);
                    merge_to_formatted_output(FFScaching, restoredFromRadix);
                    if (verbose) System.out.println("    decrypted and formatted= " + this.formatted_dest);
                    

                    
                    
                    // restore the CipherText using regex and passthrough filtering
//                     FPEMask mask = new FPEMask(CipherText, FFScaching.getRegex());
//                     String decryptableText = mask.getEncryptablePart();
//                     System.out.println("DECRYPT decryptableText:    CipherText= " + CipherText + "   decryptableText= " + decryptableText);
        

                } catch (ExecutionException e) {
                    e.printStackTrace();
                }
            
            }  // try        
        
        return this.formatted_dest;
    }








        

    
        
    
    
    
}
