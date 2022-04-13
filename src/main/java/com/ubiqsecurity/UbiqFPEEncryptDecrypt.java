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


/**
 * Provides Format Preserving Encryption capability for a variety of field format models (aka FFS models)
 * This capability must be enabled and configured with FFS models on a per-user account basis.
 */
public class UbiqFPEEncryptDecrypt implements AutoCloseable {
    private boolean verbose= false;
    private UbiqWebServices ubiqWebServices; // null when closed
    private EncryptionKeyResponse encryptionKey;
    private DecryptionKeyResponse decryptionKey;
    private FFS ffs;
    private String formatted_dest;
    private String trimmed;
    private String base2_charset = "01";
    private int FF1_base2_min_length = 20; // NIST requirement ceil(log2(1000000))
    private FFSKeyCache ffsKeyCache;
    private FPEProcessor executor;
    private FPETransactions bill;
    private UbiqCredentials ubiqCredentials;

    /**
     * UbiqFPEEncryptDecrypt constructor
     * Sets up the webservices API, task scheduler, and transaction processor
     *
     * @param ubiqCredentials   used to specify the API key credentials of the user
     *
     */
    public UbiqFPEEncryptDecrypt(UbiqCredentials ubiqCredentials) {
        if (verbose) System.out.println("+++++++ NEW OBJECT UbiqFPEEncryptDecrypt +++++++" );
        if (ubiqCredentials == null) {
            System.out.println("Credentials have not been specified.");
            return;
        }
        this.ubiqCredentials = ubiqCredentials;
        this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);
        bill = new FPETransactions();
        executor = new FPEProcessor(ubiqWebServices, bill, 1);
        executor.startAsync();
    }


    /**
     * Runs when object is going away. Clears the caches, stops
     * scheduler, and runs through any remaining bills left in the transaction list.
     *
     */
    public void close() {
        if (this.ubiqWebServices != null) {
            clearKeyCache();

            // this stops any remaining background billing processing since we'll make an explicit final call now
            executor.stopAsync();

            // Perform a final bill  processing for items that may not have been done by the async executor
            bill.processCurrentBills(ubiqWebServices);
            this.ubiqWebServices = null;
        }
    }


    /**
    * Checks if an array of Objects is empty or null
    *
    * @param array  the array to test
    * @return true if the array is empty or null
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
       * @return true if the String is empty or null
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
    */
    public int findFirstIndexExclusive(String str, String searchChars) {
      if (isEmpty(str)) {
          return -1;
      }
      for (int i = 0; i < str.length(); i++) {
          if (searchChars.indexOf(str.charAt(i)) < 0) {
              return i;
          }
      }
      return -1;
    }


    /**
    * Performs encoding operation within a str at a position. Uses the
    * output character set found in the model.
    *
    * @param ffs  The FFS record model
    * @param key_number  The value to be encoded
    * @param str  The given string to receive the encoding
    * @param position  The location within the string to encode
    *
    * @return the updated string
    */
    public String encode_keynum(FFS_Record ffs, int key_number, String str, int position) {
        String buf= "";
        if (position < 0) {
            // if a valid non-passthrough location cannot be found then the original string is bad
            throw new RuntimeException("Bad String encoding position for: " + str);
        }

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


    /**
    * Performs decoding operation of a str at a position. Uses the
    * output character set found in the model.
    *
    * @param ffs  The FFS record model
    * @param str  The given string to decode
    * @param position  The location within the string for the decode
    *
    * @return the value decoded
    */
    public int decode_keynum(FFS_Record ffs, String str, int position) {
        int key_num = 0;
        if (position < 0) {
            // if caller passed an invalid position
            throw new RuntimeException("Bad String decoding position for: " + str);
        }

        char charBuf = str.charAt(position);
        int encoded_value = ffs.getOutput_character_set().indexOf(charBuf);

        long msb_encoding_bits = ffs.getMsb_encoding_bits();
        key_num =  encoded_value >> msb_encoding_bits;

        char ch= ffs.getOutput_character_set().charAt(encoded_value - (key_num << msb_encoding_bits));
        this.trimmed= Parsing.replaceChar(str, ch, position);

        return key_num;
    }


    /**
    * Parses a given string using the FFS model. Handles the case where the first chraracter
    * may be "0". The results of the operation will be recorded in the class variables
    * "trimmed" which is the new string and "formatted_dest" which is the destination
    * pattern for the string to be eventually applied to.
    *
    * @param ffs  The FFS record model
    * @param conversion_direction  Positive (1) means input to output, negative (-1) means output to input
    * @param source_string  The string to parse
    *
    */
    public void ubiq_platform_fpe_string_parse(
        FFS_Record ffs,
        long conversion_direction,
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



    /**
    * Merges the given string into the  "formatted_dest" pattern using the
    * set of provided characters.
    *
    * @param ffs  The FFS record model
    * @param convertedToRadix  The string to be placed in the formatted_dest
    * @param characterSet  The set of characters to use in the final formatted_dest
    *
    */
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

    }




    /**
    * Converts a given string using input/output radix conversion
    *
    * @param rawtext  The original string
    * @param input_radix  The set of radix characters used on the input conversion
    * @param output_radix  The set of radix characters used on the output conversion
    *
    * @return the converted string
    *
    */
    public String str_convert_radix(String rawtext, String input_radix, String output_radix) {
        // convert a given string to a numerical location based on a given Input_character_set
        BigInteger r1 = Bn.__bigint_set_str(rawtext, input_radix);

        // convert a numerical location code to a string based on its location in an Output_character_set
        String output = Bn.__bigint_get_str(output_radix, r1);

        return output;
    }



    /**
    * Pads a given string with 0 characters at least as long as specified length
    *
    * @param inputString  The original string
    * @param length  The desired length of the new string
    *
    * @return the padded string
    *
    */
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


    /**
    * Performs a log base 2 operation
    *
    * @param x  The input value
    *
    * @return the output value
    *
    */
    public double log2(int x) {
        return (double)(Math.log(x) / Math.log(2));
    }



    /**
    * Clears the encryption key and FFS model cache
    *
    */
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


    /**
    * Performs an FPE encryption for a given string based on a given FFS model
    *
    * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
    * @param PlainText  the plain text to be encrypted
    * @param tweak  the tweak bytes which are only applied if not already overriden by the FFS model
    *
    * @return the encrypted output string
    *
    */
    public String encryptFPE(String ffs_name, String PlainText, byte[] tweak)
        throws IllegalStateException  {
            if (verbose) System.out.println("\nEncrypting PlainText: " + PlainText);
            UbiqCredentials ubiqCredentials= this.ubiqCredentials;
            String convertedToRadix = "";
            String cipher = "";
            String withInsertion = "";
            long twkmin= 0;
            long twkmax= 0;

            // setup the cached FFS so that the ffs data may persist between encrypt/decrypt calls
            if (ffs == null) {
                ffs = new FFS(this.ubiqWebServices);
            }

            // attempt to load the FPEAlgorithm from the local cache
            try {
                FFS_Record FFScaching = ffs.FFSCache.get(ffs_name);

                // Obtain encryption key information
                if (this.ubiqWebServices == null) {
                    throw new IllegalStateException("object closed");
                }
                if (ffsKeyCache == null) {
                        ffsKeyCache = new FFSKeyCache(this.ubiqWebServices);
                }
                FFS_KeyId keyId = new FFS_KeyId(ffs_name, null);
                FFS_KeyRecord FFSKeycaching = ffsKeyCache.FFSKeyCache.get(keyId);

                // decrypt the datakey from the keys found in the cache
                String EncryptedPrivateKey = FFSKeycaching.getEncryptedPrivateKey();
                String WrappedDataKey = FFSKeycaching.getWrappedDataKey();
                byte[] key = this.ubiqWebServices.getUnwrappedKey(EncryptedPrivateKey, WrappedDataKey);


                ubiq_platform_fpe_string_parse(FFScaching, 1, PlainText);

                if ((this.trimmed.length() < FFScaching.getMin_input_length()) ||
                    (this.trimmed.length() > FFScaching.getMax_input_length())) {
                    throw new RuntimeException("Input length does not match FFS parameters.");
                }

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
                    twkmin= FFScaching.getMin_tweak_length();
                    twkmax= FFScaching.getMax_tweak_length();
                    tweak= Base64.getDecoder().decode(FFScaching.getTweak());
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

            } catch (ExecutionException e) {
                e.printStackTrace();
            }

        return this.formatted_dest;
    }





    /**
    * Performs an FPE decryption for a given string based on a given FFS model
    *
    * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
    * @param CipherText  the encrypted text to be decrypted
    * @param tweak  the tweak bytes which are only applied if not already overriden by the FFS model
    *
    * @return the decrypted output string
    *
    */
    public String decryptFPE(String ffs_name, String CipherText, byte[] tweak)
        throws IllegalStateException {
            UbiqCredentials ubiqCredentials= this.ubiqCredentials;
            String PlainText = "";
            String restoredFromRadix = "";
            String restoredPlainText = "";
            long twkmin= 0;
            long twkmax= 0;

            //System.out.println("\n@@@@@@@@@@ STARTING DECRYPT @@@@@@@@@@");
            if (verbose) System.out.println("\nDecrypting CipherText: " + CipherText);

            // setup the cached FFS so that the ffs data may persist between encrypt/decrypt calls
            if (ffs == null) {
                ffs = new FFS(this.ubiqWebServices);
            }

            // attempt to load the FPEAlgorithm from the local cache
            try {
                FFS_Record FFScaching = ffs.FFSCache.get(ffs_name);

                // Obtain encryption key information
                if (this.ubiqWebServices == null) {
                    throw new IllegalStateException("object closed");
                }

                ubiq_platform_fpe_string_parse(FFScaching, -1, CipherText);
                if (verbose) System.out.println("    this.trimmed= " + this.trimmed);

                if ((this.trimmed.length() < FFScaching.getMin_input_length()) ||
                    (this.trimmed.length() > FFScaching.getMax_input_length())) {
                    throw new RuntimeException("Input length does not match FFS parameters.");
                }

                int key_number = decode_keynum(FFScaching, this.trimmed, 0);
                if (verbose) System.out.println("    decode_keynum returns key_number= " + key_number);

                if (ffsKeyCache == null) {
                    ffsKeyCache = new FFSKeyCache(this.ubiqWebServices);
                }

                FFS_KeyId keyId = new FFS_KeyId(ffs_name, key_number);
                if (verbose) System.out.println("    cachingKey= " + keyId.ffs_name + " " + keyId.key_number);
                FFS_KeyRecord FFSKeycaching = ffsKeyCache.FFSKeyCache.get(keyId);

                // decrypt the datakey from the keys found in the cache
                String EncryptedPrivateKey = FFSKeycaching.getEncryptedPrivateKey();
                String WrappedDataKey = FFSKeycaching.getWrappedDataKey();
                byte[] key = this.ubiqWebServices.getUnwrappedKey(EncryptedPrivateKey, WrappedDataKey);

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

            } catch (ExecutionException e) {
                e.printStackTrace();
            }


        return this.formatted_dest;
    }















}
