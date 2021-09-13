package com.ubiqsecurity;

import com.google.gson.Gson;
import java.util.Arrays;
import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;
import java.math.BigInteger;
import ubiqsecurity.fpe.Bn;
import java.util.concurrent.ExecutionException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import java.lang.Math;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.UUID;
import java.time.Instant;


public class UbiqFPEEncryptDecrypt implements AutoCloseable {
    private boolean verbose= false;
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
    private String base2_charset = "01";
    private int FF1_base2_min_length = 20; // NIST requirement ceil(log2(1000000))
    private FFSKeyCache ffsKeyCache;
    private FPEProcessor executor;
    private int encryptCount;
    private int decryptCount;
    private FPETransactions bill;
 

    public UbiqFPEEncryptDecrypt(UbiqCredentials ubiqCredentials, int usesRequested) {
        if (verbose) System.out.println("+++++++ NEW OBJECT UbiqFPEEncryptDecrypt +++++++" ); 
        
        
        this.usesRequested = usesRequested;
        this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);
        this.FFSdata = new Gson();
        
        // TESTING ONLY--- 
        encryptCount = 0;
        decryptCount = 0;
        bill = new FPETransactions();
        
        executor = new FPEProcessor(this, ubiqWebServices, bill);
        executor.startAsync();
        //Thread.sleep(10000);
        
        
        
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
            
            if (verbose) System.out.println("+++++++ IN close()" ); 
            
            clearKeyCache();
            
            // this stops any remaining backround billing processing since we'll make an explicit final call now
            executor.stopAsync();
            
            
            
            
            //bill.getTransactionAsJSON();
            // TESTING ONLY--- ADD FAKE RECORDS
//             String timestamp= Instant.now().toString();
//             bill.createBillableItem("b94a18d6-00df-4233-9c28-3c61eea512d6", "encrypt", "ALPHANUM_SSN", timestamp, 1);
//             bill.createBillableItem("716365fc-329d-4b27-a285-4016a95867fa", "encrypt", "ALPHANUM_SSN", timestamp, 1);
//             //bill.createBillableItem("BAD-RECORD", "encrypt", "UNKNOWN_FFS", timestamp, 1);
//             bill.createBillableItem("d5009ee4-339b-4e3b-a668-a4e276627d6d", "encrypt", "ALPHANUM_SSN", timestamp, 1);
//             
//             // TESTING ONLY--- DELETE A RECORD
//             bill.deleteBillableItems("b94a18d6-00df-4233-9c28-3c61eea512d6");
                    
                    
                    
                    
            // Perform a final bill  processing for items that may not have been done by the async executor        
            bill.processCurrentBills(ubiqWebServices);        
            
            
            
            
                    
//             String payload= bill.getTransactionAsJSON();
//             System.out.println("1) payload=" + payload);
//             String lastItemIDToProcess= bill.getLastItemInList();
//             
//             FPEBillingResponse fpeBillingResponse;
//             fpeBillingResponse= this.ubiqWebServices.sendBilling(payload);
//             if (fpeBillingResponse.status == 201) {
//                 // all submitted records have been processed by backend so OK to clear the local list
//                 System.out.println("Payload successfully received and processed by backend.");
//                 bill.deleteBillableItems(lastItemIDToProcess);
//             } else {
//                 System.out.println("WARNING: Backend stopped processing after UUID:"  + fpeBillingResponse.last_valid.id);
//                 
//                 // delete our local list up to and including the last record processed by the backend
//                 String newTopRecord= bill.deleteBillableItems(fpeBillingResponse.last_valid.id);
//                 payload= bill.getTransactionAsJSON();
//                 System.out.println("2) payload=" + payload); 
//                 
//                 // move the bad record to the end of the list so it won't block the next billing cycle (in case it was a bad record)
//                 if (newTopRecord.equals("") == false) {
//                     bill.deprioritizeBadBillingItem(newTopRecord);
//                     
//                     payload= bill.getTransactionAsJSON();
//                     System.out.println("3) payload=" + payload); 
//                 }
//             }
            
            
            
            
            // TESTING ONLY -- DELETE ALL RECORDS UP UNTIL ANY NEW UNPROCESSED ONES
//             bill.createBillableItem("1117fb22-6004-4603-99b7-0459e6018b6e", "encrypt", "ALPHANUM_SSN", timestamp, 1);
//             String payload= bill.getTransactionAsJSON();
//             String lastItemIDToProcess= bill.getLastItemInList();
//             System.out.println("4) payload=" + payload); 
//             
//             bill.deleteBillableItems("");
//             
//             payload= bill.getTransactionAsJSON();
//             lastItemIDToProcess= bill.getLastItemInList();
//             System.out.println("5) payload=" + payload);    
//             
//             bill.deleteBillableItems(""); 
//             payload= bill.getTransactionAsJSON();  
//             System.out.println("6) payload=" + payload);   
                    



            this.ubiqWebServices = null;
            
        }
    }
    


/*

[{“id”: “<GUID>”, "action": "encrypt", "ffs_name": <name>, "timestamp": ISO8601, "count" : number},

{“id”: “<GUID>”, "action": "decrypt", "ffs_name": <name>, "timestamp": ISO8601, "count": number }]

*/    



    public String printbytes(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        sb.append("[ ");
        for (byte b : bytes) {
            sb.append(String.format("0x%02X ", b));
        }
        sb.append("]");
        return sb.toString();
    }

    

    /**
    * Checks if an array of Objects is empty or <code>null</code>.
    *
    * @param array  the array to test
    * @return <code>true</code> if the array is empty or <code>null</code>
    * @since 2.1
    */
    public static boolean isEmpty(char[] array) {
      if (array == null || array.length == 0) {
          return true;
      }
      return false;
    }
  
    /**
       * Checks if a String is empty ("") or null.
       *
       * @param str  the String to check, may be null
       * @return <code>true</code> if the String is empty or null
       */
    public static boolean isEmpty(String str) {
      return str == null || str.length() == 0;
    }



    /**
    * Search a String to find the first index of any
    * character not in the given set of characters.
    *
    * @param str  the String to check, may be null
    * @param searchChars  the chars to search for, may be null
    * @return the index of any of the chars, -1 if no match or null input
    * @since 2.0
    */
    public int findFirstIndexExclusive(String str, String searchChars) {
      if (isEmpty(str) || isEmpty(searchChars)) {
          return -1;
      }
      for (int i = 0; i < str.length(); i++) {
          if (searchChars.indexOf(str.charAt(i)) < 0) {
              return i;
          }
      }
      return -1;
    }
  
      
      
    public String encode_keynum(FFS_Record ffs, int key_number, String str, int position) {
        String buf= "";
        if (position < 0) position = 0;
        
        char charBuf = str.charAt(position);
      
        int ct_value = ffs.getOutput_character_set().indexOf(charBuf);
        if (verbose) System.out.println("ct_value: " + ct_value);
        
        //int key_number = ffs.getCurrent_key();
        long msb_encoding_bits = ffs.getMsb_encoding_bits();
        
        ct_value =  ct_value + (key_number << msb_encoding_bits);
        
        char ch= ffs.getOutput_character_set().charAt(ct_value);
        buf= Parsing.replaceChar(str, ch, position);
        
        return buf;
    }
    

    public int decode_keynum(FFS_Record ffs, String str, int position) {
        int key_num = 0;
        if (position < 0) position = 0;
        
        char charBuf = str.charAt(position);
        int encoded_value = ffs.getOutput_character_set().indexOf(charBuf);
        
        long msb_encoding_bits = ffs.getMsb_encoding_bits();
        key_num =  encoded_value >> msb_encoding_bits;        
         
        char ch= ffs.getOutput_character_set().charAt(encoded_value - (key_num << msb_encoding_bits));
        this.trimmed= Parsing.replaceChar(str, ch, position);
              
        return key_num;
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
    
    
    // merge to formatted output for encrypt
    public void merge_to_formatted_output(FFS_Record ffs, String convertedToRadix, String characterSet) {
        int d = this.formatted_dest.length() - 1;
        int s = convertedToRadix.length() - 1;
        
        // Merge PT to formatted output
        while (s >= 0 && d >= 0) {
            // Find the first available destination character
            while (d >=0 && this.formatted_dest.charAt(d) != characterSet.charAt(0)) {
                d--;
            }

            // Copy the encrypted text into the formatted output string
            if (d >= 0) {
                this.formatted_dest = Parsing.replaceChar(this.formatted_dest, convertedToRadix.charAt(s), d);
            }        
            s = s - 1;
            d = d - 1;
        }
        
        return;
    }
 
 
     
 

    // convert to output radix
    public String str_convert_radix(String rawtext, String input_radix, String output_radix) {
        // convert a given string to a numerical location based on a given Input_character_set
        BigInteger r1 = Bn.__bigint_set_str(rawtext, input_radix);
        
        // convert a numerical location code to a string based on its location in an Output_character_set
        String output = Bn.__bigint_get_str(output_radix, r1);
        
        return output;
    }
    

 
    
    public String pad_text(String inputString, double length) {
        if (inputString.length() >= length) {
            return inputString;
        }
        StringBuilder sb = new StringBuilder();
        while (sb.length() < length - inputString.length()) {
            sb.append('0');
        }
        sb.append(inputString);

        return sb.toString();
    }


    public double log2(int x) {
        return (double)(Math.log(x) / Math.log(2));
    }
       
       
 
    // allows user to forceably clear the encryption key cache resulting in a subsequent server access when key is needed
    public void clearKeyCache() {
        if (this.ffsKeyCache != null) {
            if (verbose) System.out.println("++++++++++++ clearing KeyCache" ); 
            this.ffsKeyCache.invalidateAllCache();
        }
        if (this.ffs != null) {
            if (verbose) System.out.println("++++++++++++ clearing FFSCache" ); 
            this.ffs.invalidateAllCache();
        }
    }

        
 
    public String encryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String PlainText, byte[] tweak) 
        throws IllegalStateException, InvalidCipherTextException {
            
            //if (verbose) System.out.println("\n@@@@@@@@@@ STARTING ENCRYPT @@@@@@@@@@");
            if (verbose) System.out.println("\nEncrypting PlainText: " + PlainText);
            
            String convertedToRadix = "";
            String cipher = "";
            String withInsertion = "";
            long twkmin= 0;
            long twkmax= 0;
            
            
            
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
                

                if (ffsKeyCache == null) {
                        ffsKeyCache = new FFSKeyCache(this.ubiqWebServices, FFScaching, ffs_name);
                }
                FFS_KeyRecord FFSKeycaching = ffsKeyCache.FFSKeyCache.get(cachingKey);
                
                
                // decrypt the datakey from the keys found in the cache
                String EncryptedPrivateKey = FFSKeycaching.getEncryptedPrivateKey();
                String WrappedDataKey = FFSKeycaching.getWrappedDataKey();
                byte[] key = this.ubiqWebServices.getUnwrappedKey(EncryptedPrivateKey, WrappedDataKey);
                
                if (verbose) System.out.println("    key bytes = " + printbytes(key));

                
                // check key 'usage count' against server-specified limit
                //if (this.useCount > this.encryptionKey.MaxUses) {
                    //throw new RuntimeException("maximum key uses exceeded:  " + this.useCount);    // TODO - Uncomment this line in production to allow checking for usage limit (2)
                //}

                
                this.useCount++;
        
                
                ubiq_platform_fpe_string_parse(FFScaching, 1, PlainText);


                convertedToRadix = str_convert_radix(this.trimmed, FFScaching.getInput_character_set(), base2_charset);
                if (verbose) System.out.println("    converted to base2= " + convertedToRadix);
                
                // Figure out how long to pad the binary string.  Formula is input_radix^len = 2^Y which is log2(input_radix) * len
                // Due to FF1 constraints, the there is a minimum length for a base2 string, so make sure to be at least that long too
                // or fpe will fail
                double padlen = Math.ceil( Math.max(FF1_base2_min_length, log2(  FFScaching.getInput_character_set().length()  ) * this.trimmed.length()       ));
                if (verbose) System.out.println("    padlen= " + padlen);   
                
                convertedToRadix = pad_text(convertedToRadix, padlen);
                if (verbose) System.out.println("    convertedToRadix (padded base2)= " + convertedToRadix);  
                
                // determine the tweak. Use the one in the FFS, if present, or default to the one user passed in as a parameter
                if (FFScaching.getTweak_source().equals("constant")) {
                    // these have been explicitly set based on the FFS model
                    if (verbose) System.out.println("    Using tweak from FFS record= " + FFScaching.getTweak());  
                    //if (verbose) System.out.println("                          Bytes= " + Base64.getDecoder().decode(FFScaching.getTweak()) );
                    twkmin= FFScaching.getMin_tweak_length();
                    twkmax= FFScaching.getMax_tweak_length();
                    tweak= Base64.getDecoder().decode(FFScaching.getTweak());
                    if (verbose) System.out.println("    tweak bytes = " + printbytes(tweak));
                } else {
                    // For now, the default case is to use the values in the FFS cache for min/max
                    // and use the tweak that the user passed in as a parameter. Later may need to revise this.
                    if (verbose) System.out.println("    Using tweak specified by user= " + tweak);  
                    twkmin= FFScaching.getMin_tweak_length();
                    twkmax= FFScaching.getMax_tweak_length();
                }
                 
               
                final int inputradix = base2_charset.length();
                final int onputradix = FFScaching.getOutput_character_set().length();

        
                String encryption_algorithm = FFScaching.getAlgorithm();
                switch(encryption_algorithm) {
                    case "FF1":
                        if (verbose) System.out.println("    twkmin= " + twkmin + "    twkmax= " + twkmax +   "    tweak.length= " + tweak.length +   "    key.length= " + key.length);   
                        FF1 ctxFF1 = new FF1(key, tweak, twkmin, twkmax, inputradix); 
                        cipher = ctxFF1.encrypt(convertedToRadix);
                        if (verbose) System.out.println("    cipher= " + cipher);   
                    break;
                    case "FF3_1":
                        FF3_1 ctxFF3_1 = new FF3_1(key, tweak, inputradix); 
                        cipher = ctxFF3_1.encrypt(convertedToRadix);
                        if (verbose) System.out.println("     cipher= " + cipher);   
                        
                    break;
                    default:
                        throw new RuntimeException("Unknown FPE Algorithm: " + encryption_algorithm);
                }
                
                
                
                convertedToRadix = str_convert_radix(cipher, base2_charset, FFScaching.getOutput_character_set());
                if (verbose) System.out.println("    converted to output char set= " + convertedToRadix);
                if (verbose) System.out.println("    formatted destination= " + this.formatted_dest);
                merge_to_formatted_output(FFScaching, convertedToRadix, FFScaching.getOutput_character_set());
                if (verbose) System.out.println("    encrypted and formatted= " + this.formatted_dest);
                
                
                // Since ct_trimmed may not include empty leading characters, Need to walk through the formated_dest_buf and find
                // first non-pass through character.  Could be char 0 or MSB with some actual CT
                int firstNonPassthrough= findFirstIndexExclusive(this.formatted_dest, FFScaching.getPassthrough_character_set());
                if (verbose) System.out.println("   firstNonPassthrough= " + firstNonPassthrough);
                
                
                int key_number = FFSKeycaching.getKeyNumber();
                if (verbose) System.out.println("   KeyNumber= " + key_number);
                
                
                // encode the key into the cipher
                this.formatted_dest = encode_keynum(FFScaching, key_number, this.formatted_dest, firstNonPassthrough);
                
                // create the billing record
                UUID uuid = UUID.randomUUID();
                String timestamp= Instant.now().toString();
                bill.createBillableItem(uuid.toString(), "encrypt", FFScaching.getName(), timestamp, 1);
                
                

                
     
                 // scrub the PlainText using regex and passthrough filtering
//                     FPEMask mask = new FPEMask(PlainText, FFScaching.getRegex());
//                     String encryptableText = mask.getEncryptablePart();
//                     System.out.println("ENCRYPT encryptablePlaintext:    PlainText= " + PlainText + "   encryptableText= " + encryptableText + "   FFScaching.getRegex()= " + FFScaching.getRegex());
       

                
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        
        return this.formatted_dest;
    }
      
      
      

 
 
    public  String decryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String CipherText, byte[] tweak) 
        throws IllegalStateException, InvalidCipherTextException {
            String PlainText = "";
            String restoredFromRadix = "";
            String restoredPlainText = "";
            long twkmin= 0;
            long twkmax= 0;
            
            
            //System.out.println("\n@@@@@@@@@@ STARTING DECRYPT @@@@@@@@@@");
            if (verbose) System.out.println("\nDecrypting CipherText: " + CipherText);
            
        
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
                                    
                
                
                ubiq_platform_fpe_string_parse(FFScaching, -1, CipherText);
                if (verbose) System.out.println("    this.trimmed= " + this.trimmed);
                
                
                int key_number = decode_keynum(FFScaching, this.trimmed, 0);
                if (verbose) System.out.println("    decode_keynum returns key_number= " + key_number);

               
                if (ffsKeyCache == null) {
                    ffsKeyCache = new FFSKeyCache(this.ubiqWebServices, FFScaching, ffs_name);
                }
                
                
                cachingKey = ubiqCredentials.getAccessKeyId() + "-" + ffs_name + "-key_number=" + String.valueOf(key_number); 
                if (verbose) System.out.println("    cachingKey= " + cachingKey); 
                FFS_KeyRecord FFSKeycaching = ffsKeyCache.FFSKeyCache.get(cachingKey);
                
                
                // decrypt the datakey from the keys found in the cache
                String EncryptedPrivateKey = FFSKeycaching.getEncryptedPrivateKey();
                String WrappedDataKey = FFSKeycaching.getWrappedDataKey();
                byte[] key = this.ubiqWebServices.getUnwrappedKey(EncryptedPrivateKey, WrappedDataKey);
                
                if (verbose) System.out.println("    key bytes = " +  printbytes(key));

                    
                                    
                restoredFromRadix = str_convert_radix(this.trimmed, FFScaching.getOutput_character_set(), base2_charset);
                if (verbose) System.out.println("    converted to base2= " + restoredFromRadix);
                
                
                
                double padlen = Math.ceil( Math.max(FF1_base2_min_length, log2(  FFScaching.getInput_character_set().length()  ) * this.trimmed.length()    ) );
                if (verbose) System.out.println("    padlen= " + padlen);   
                
                restoredFromRadix = pad_text(restoredFromRadix, padlen);
                if (verbose) System.out.println("    restoredFromRadix= " + restoredFromRadix);  
                
                
                // determine the tweak. Use the one in the FFS, if present, or default to the one user passed in as a parameter
                if (FFScaching.getTweak_source().equals("constant")) {
                    // these have been explicitly set based on the FFS model
                    if (verbose) System.out.println("    Using tweak from FFS record= " + FFScaching.getTweak()); 
                    //if (verbose) System.out.println("                          Bytes= " + Base64.getDecoder().decode(FFScaching.getTweak()) );      
                    twkmin= FFScaching.getMin_tweak_length();
                    twkmax= FFScaching.getMax_tweak_length();
                    tweak= Base64.getDecoder().decode(FFScaching.getTweak());
                    if (verbose) System.out.println("    tweak bytes = " + printbytes(tweak));
                } else {
                    // For now, the default case is to use the values in the FFS cache for min/max
                    // and use the tweak that the user passed in as a parameter. Later may need to revise this.
                    if (verbose) System.out.println("    Using tweak specified by user= " + tweak);  
                    twkmin= FFScaching.getMin_tweak_length();
                    twkmax= FFScaching.getMax_tweak_length();
                }

                

                final int inputradix = base2_charset.length();
                final int onputradix = FFScaching.getOutput_character_set().length();
                
                
                // decrypt based on the specified cipher
                String encryption_algorithm = FFScaching.getAlgorithm();
                switch(encryption_algorithm) {
                    case "FF1":
                        if (verbose) System.out.println("    twkmin= " + twkmin + "    twkmax= " + twkmax +   "    tweak.length= " + tweak.length +   "    key.length= " + key.length ); 
                        FF1 ctxFF1 = new FF1(key, tweak, twkmin, twkmax, inputradix); 
                        PlainText = ctxFF1.decrypt(restoredFromRadix);
                        if (verbose) System.out.println("    PlainText (pt base2)= " + PlainText);   
                    break;
                    case "FF3_1":
                        FF3_1 ctxFF3_1 = new FF3_1(key, tweak, inputradix); 
                        PlainText = ctxFF3_1.decrypt(restoredFromRadix);
                        if (verbose) System.out.println("    PlainText= " + PlainText);   
                    break;
                    default:
                        throw new RuntimeException("Unknown FPE Algorithm: " + encryption_algorithm);
                }                    
                
                restoredFromRadix = str_convert_radix(PlainText, base2_charset, FFScaching.getInput_character_set());
                if (verbose) System.out.println("    converted to input char set= " + restoredFromRadix);
                if (verbose) System.out.println("    formatted destination= " + this.formatted_dest);
                merge_to_formatted_output(FFScaching, restoredFromRadix, FFScaching.getInput_character_set());
                if (verbose) System.out.println("    decrypted and formatted= " + this.formatted_dest);
                
                
                // create the billing record
                UUID uuid = UUID.randomUUID();
                String timestamp= Instant.now().toString();
                bill.createBillableItem(uuid.toString(), "decrypt", FFScaching.getName(), timestamp, 1);

                
                // restore the CipherText using regex and passthrough filtering
//                     FPEMask mask = new FPEMask(CipherText, FFScaching.getRegex());
//                     String decryptableText = mask.getEncryptablePart();
//                     System.out.println("DECRYPT decryptableText:    CipherText= " + CipherText + "   decryptableText= " + decryptableText);
    

            } catch (ExecutionException e) {
                e.printStackTrace();
            }
            
        
        return this.formatted_dest;
    }








        

    
        
    
    
    
}
