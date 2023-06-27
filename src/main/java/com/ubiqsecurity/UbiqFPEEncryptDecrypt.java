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
import java.io.IOException;


/**
 * Provides Format Preserving Encryption capability for a variety of field format models (aka FFS models)
 * This capability must be enabled and configured with FFS models on a per-user account basis.
 */
public class UbiqFPEEncryptDecrypt implements AutoCloseable {
    private boolean verbose= false;
    private UbiqWebServices ubiqWebServices; // null when closed
    private FFS ffs;
    private FFXCache ffxCache;
    private BillingEventsProcessor executor;
    private BillingEvents billing_events;
    private UbiqCredentials ubiqCredentials;
    private UbiqConfiguration ubiqConfiguration;


    class ParsedData {
      String formatted_dest;
      String trimmed;

      ParsedData(String formatted_dest, String trimmed) {
        this.formatted_dest = formatted_dest;
        this.trimmed = trimmed;
      }
    }

    /**
     * UbiqFPEEncryptDecrypt constructor
     * Sets up the webservices API, task scheduler, and transaction processor
     *
     * @param ubiqCredentials   used to specify the API key credentials of the user
     *
     */
    public UbiqFPEEncryptDecrypt(UbiqCredentials ubiqCredentials) {
      this(ubiqCredentials, UbiqFactory.defaultConfiguration());
    }


    public UbiqFPEEncryptDecrypt(UbiqCredentials ubiqCredentials, UbiqConfiguration ubiqConfiguration) {
      if (verbose) System.out.println("+++++++ NEW OBJECT UbiqFPEEncryptDecrypt +++++++" );
      if (ubiqCredentials == null) {
          System.out.println("Credentials have not been specified.");
          return;
      }
      this.ubiqConfiguration = ubiqConfiguration;
      this.ubiqCredentials = ubiqCredentials;
      this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);
      this.billing_events = new BillingEvents(this.ubiqConfiguration);
      this.ffxCache = new FFXCache(this.ubiqWebServices);
      this.ffs = new FFS(this.ubiqWebServices);
      executor = new BillingEventsProcessor(this.ubiqWebServices, this.billing_events, this.ubiqConfiguration);
      executor.startAsync();
      // executor.startUp();
  }


    /**
     * Runs when object is going away. Clears the caches, stops
     * scheduler, and runs through any remaining bills left in the transaction list.
     *
     */
    public void close() {
      if (verbose) System.out.println("Close");
      if (this.ubiqWebServices != null) {
            clearKeyCache();

            // this stops any remaining background billing processing since we'll make an explicit final call now
            // executor.stopAsync();
            executor.shutDown();

            // Perform a final billing_events  processing for items that may not have been done by the async executor
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
    *
    * @return the updated string
    */
    public String encode_keynum(FFS_Record ffs, int key_number, String str) {
        String buf= "";

        char charBuf = str.charAt(0);

        int ct_value = ffs.getOutput_character_set().indexOf(charBuf);
        if (verbose) System.out.println("ct_value: " + ct_value);

        //int key_number = ffs.getCurrent_key();
        long msb_encoding_bits = ffs.getMsb_encoding_bits();

        ct_value =  ct_value + (key_number << msb_encoding_bits);

        char ch= ffs.getOutput_character_set().charAt(ct_value);
        buf= Parsing.replaceChar(str, ch, 0);

        return buf;
    }


    /**
    * Performs decoding operation of a str at a position. Uses the
    * output character set found in the model.
    *
    * @param ffs  The FFS record model
    * @param parsed_data  The given string to decode
    * @param position  The location within the string for the decode
    *
    * @return the value decoded
    */
    public int decode_keynum(final FFS_Record ffs, ParsedData parsed_data, final int position) {
        int key_num = 0;
        if (position < 0) {
            // if caller passed an invalid position
            throw new RuntimeException("Bad String decoding position for: " + parsed_data.trimmed);
        }

        char charBuf = parsed_data.trimmed.charAt(position);
        int encoded_value = ffs.getOutput_character_set().indexOf(charBuf);

        long msb_encoding_bits = ffs.getMsb_encoding_bits();
        key_num =  encoded_value >> msb_encoding_bits;

        char ch= ffs.getOutput_character_set().charAt(encoded_value - (key_num << msb_encoding_bits));
        parsed_data.trimmed = Parsing.replaceChar(parsed_data.trimmed, ch, position);

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
    * @return A parsed data structured containing the trimmed string and the formatted output string
    */
    public ParsedData ubiq_platform_fpe_string_parse(
        FFS_Record ffs,
        long conversion_direction,
        String source_string)
    {
        String src_char_set= "";
        char dest_zeroth_char= '0';
        char source_zeroth_char= '0';

        ParsedData ret = null;

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

            ret = new ParsedData(parsing.get_empty_formatted_output(), parsing.get_trimmed_characters());
            // this.trimmed= parsing.get_trimmed_characters();
            // this.formatted_dest= parsing.get_empty_formatted_output();
         }
         return ret;
    }



    /**
    * Merges the given string into the  "formatted_dest" pattern using the
    * set of provided characters.
    *
    * @param ffs  The FFS record model
    * @param formatted_dest The formatted destination string 
    * @param convertedToRadix  The string to be placed in the formatted_dest
    * @param characterSet  The set of characters to use in the final formatted_dest
    *
    * @return the correctly formatted output string
    */
    public String merge_to_formatted_output(FFS_Record ffs, final String formatted_dest, final String convertedToRadix, final String characterSet) {
      String ret = formatted_dest;
      int d = ret.length() - 1;
        int s = convertedToRadix.length() - 1;

        // Merge PT to formatted output
        while (s >= 0 && d >= 0) {
            // Find the first available destination character
            while (d >=0 && ret.charAt(d) != characterSet.charAt(0)) {
                d--;
            }

            // Copy the encrypted text into the formatted output string
            if (d >= 0) {
                ret = Parsing.replaceChar(ret, convertedToRadix.charAt(s), d);
            }
            s = s - 1;
            d = d - 1;
        }
      return ret;
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
    public String str_convert_radix(final String rawtext, final String input_radix, final String output_radix) {
      boolean verbose = false;
      if (verbose) System.out.println("rawtext: '" + rawtext + "'");
      if (verbose) System.out.println("input_radix: '" + input_radix + "'");
      if (verbose) System.out.println("output_radix: '" + output_radix + "'");

        // convert a given string to a numerical location based on a given Input_character_set
        BigInteger r1 = FF1.number(rawtext, input_radix);

        if (verbose) System.out.println("r1: '" + r1.toString(10) + "'");


        // Convert to output string - making sure to pad to original length
        String output = FF1.str(rawtext.length(), output_radix, r1);

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
        if (this.ffs != null) {
            if (verbose) System.out.println("++++++++++++ clearing FFSCache" );
            this.ffs.invalidateAllCache();
        }
        if (this.ffxCache != null) {
          if (verbose) System.out.println("++++++++++++ clearing FFXCache" );
          this.ffxCache.invalidateAllCache();
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
            String cipher = "";

            try {

              FFS_Record FFScaching = getFFS(ffs_name);
              FFX_Ctx ctx = getCtx(FFScaching, null);

              cipher = encryptData(FFScaching, ctx, PlainText, tweak);

            } catch (ExecutionException e) {
                e.printStackTrace();
            }

        return cipher;
    }

    /**
     * Local encrypt function where the FFS and the CTX are loaded.
     * TODO - Need to change to make skip any instance variables.
     */
    private String encryptData(final FFS_Record FFScaching, final FFX_Ctx cfx, final String PlainText, byte[] tweak)
      throws IllegalStateException, ExecutionException  {
        if (verbose) System.out.println("\nEncrypting PlainText: " + PlainText);
        String convertedToRadix = "";
        String cipher = "";
        String formatted_dest = "";

        // attempt to load the FPEAlgorithm from the local cache
        ParsedData parsedData = ubiq_platform_fpe_string_parse(FFScaching, 1, PlainText);

        // Make sure the trimmed string is valid for the FFS
        if ((parsedData.trimmed.length() < FFScaching.getMin_input_length()) ||
            (parsedData.trimmed.length() > FFScaching.getMax_input_length())) {
            throw new RuntimeException("Input length does not match FFS parameters.");
        }

        // Encrypt the data
        switch(FFScaching.getAlgorithm()) {
            case "FF1":
                cipher = cfx.getFF1().encrypt(parsedData.trimmed, tweak);
            break;
            case "FF3_1":
                cipher = cfx.getFF3_1().encrypt(parsedData.trimmed, tweak);
            break;
            default:
                throw new RuntimeException("Unknown FPE Algorithm: " + FFScaching.getAlgorithm());
        }

        // Convert to output character set
        convertedToRadix = str_convert_radix(cipher, FFScaching.getInput_character_set(), FFScaching.getOutput_character_set());
        if (verbose) System.out.println("    converted to output char set= " + convertedToRadix);
        if (verbose) System.out.println("    formatted destination= " + parsedData.formatted_dest);

        // Encode the key number since it will be the first character.
        int key_number = cfx.getKeyNumber();
        if (verbose) System.out.println("   KeyNumber= " + key_number);
        String encoded_value = encode_keynum(FFScaching, key_number, convertedToRadix);

        formatted_dest = merge_to_formatted_output(FFScaching, parsedData.formatted_dest, encoded_value, FFScaching.getOutput_character_set());
        if (verbose) System.out.println("    encrypted and formatted= " + formatted_dest);

        // create the billing record
        billing_events.addBillingEvent(ubiqCredentials.getAccessKeyId(), FFScaching.getName(), "", BillingEvents.BillingAction.ENCRYPT, BillingEvents.DatasetType.STRUCTURED, key_number,1);

        return formatted_dest;
    }


    public String[] encryptForSearch(final String ffs_name, final String PlainText, byte[] tweak)
        throws IllegalStateException  {
          boolean verbose= false;

          String[] ret = null;

          // Load the search keys for this Dataset (FFS)
          LoadSearchKeys.loadKeys(this.ubiqCredentials, this.ubiqWebServices, this.ffs, this.ffxCache, ffs_name);

          if (verbose) System.out.println("\nencryptForSearch: " + PlainText);

          try {
            // Get the FFS for the FFS_Name and the CTX which will have the current key_number - Everything should
            // already be loaded into the cache because of the load search keys function above.
            FFS_Record FFScaching = getFFS(ffs_name);

            FFX_Ctx ctx = getCtx(FFScaching, null);
            
            int current_key_number = ctx.getKeyNumber();
            ret = new String[current_key_number + 1];

            for (int key = 0; key <= current_key_number; key++) {
              ctx = ffxCache.FFXCache.get(new FFS_KeyId(FFScaching, key));
              ret[key] = encryptData(FFScaching, ctx, PlainText, tweak);
            }

          } catch (ExecutionException e) {
            e.printStackTrace();
          }

          return ret;
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
    public String decryptFPE(final String ffs_name, final String CipherText, byte[] tweak)
        throws IllegalStateException {
          boolean verbose = false;
            String PlainText = "";
            String restoredFromRadix = "";
            String formatted_dest = "";

            if (verbose) System.out.println("\nDecrypting CipherText: " + CipherText);

            // attempt to load the FPEAlgorithm from the local cache
            try {
                FFS_Record FFScaching = getFFS(ffs_name);

                // Parse the cipher text into trimmed and formatted output
                ParsedData parsed_data = ubiq_platform_fpe_string_parse(FFScaching, -1, CipherText);
                if (verbose) System.out.println("    parsed_data.trimmed= " + parsed_data.trimmed);
                if (verbose) System.out.println("    parsed_data.formatted_dest= " + parsed_data.formatted_dest);

                // Make sure the trimmed string is valid for the FFS
                if ((parsed_data.trimmed.length() < FFScaching.getMin_input_length()) ||
                    (parsed_data.trimmed.length() > FFScaching.getMax_input_length())) {
                    throw new RuntimeException("Input length does not match FFS parameters.");
                }

                // Get the key number from the cipher text
                int key_number = decode_keynum(FFScaching, parsed_data, 0);
                if (verbose) System.out.println("    decode_keynum returns key_number= " + key_number);

                FFX_Ctx cfx = getCtx(FFScaching, key_number);

                if (verbose) System.out.println("    cachingKey= " + FFScaching.getName() + " " + cfx.getKeyNumber());

                restoredFromRadix = str_convert_radix(parsed_data.trimmed, FFScaching.getOutput_character_set(), FFScaching.getInput_character_set());
                if (verbose) System.out.println("    converted to input character set= " + restoredFromRadix);

                // Encrypt the data
                switch(FFScaching.getAlgorithm()) {
                  case "FF1":
                    PlainText = cfx.getFF1().decrypt(restoredFromRadix, tweak);
                  break;
                  case "FF3_1":
                    PlainText = cfx.getFF3_1().decrypt(restoredFromRadix, tweak);
                  break;
                  default:
                      throw new RuntimeException("Unknown FPE Algorithm: " + FFScaching.getAlgorithm());
                }

                formatted_dest = merge_to_formatted_output(FFScaching, parsed_data.formatted_dest, PlainText, FFScaching.getInput_character_set());
                if (verbose) System.out.println("    decrypted and formatted= " + formatted_dest);

                // create the billing record

                billing_events.addBillingEvent(ubiqCredentials.getAccessKeyId(), ffs_name, "", BillingEvents.BillingAction.DECRYPT, BillingEvents.DatasetType.STRUCTURED, key_number,1);


            } catch (ExecutionException e) {
                e.printStackTrace();
            }

        return formatted_dest;
    }

    private FFS_Record getFFS(final String ffs_name)
      throws IllegalStateException, ExecutionException {
        if (this.ffs == null || this.ffs.FFSCache == null) {
          throw new IllegalStateException("object closed");
        }

        // Get the FFS definition based on the supplied name.
        return this.ffs.FFSCache.get(ffs_name);
    }

    private FFX_Ctx getCtx(final FFS_Record ffsRecord, final Integer key_number) 
      throws IllegalStateException, ExecutionException {
        if (this.ffxCache == null || this.ffxCache.FFXCache == null) {
          throw new IllegalStateException("object closed");
        }

        return this.ffxCache.FFXCache.get(new FFS_KeyId(ffsRecord, key_number));
    }

    public static String encryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String PlainText, byte[] tweak)
            throws IOException, InvalidCipherTextException, IllegalStateException {

      try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
          return ubiqEncryptDecrypt.encryptFPE(ffs_name, PlainText, tweak);
      }
    }

    public static String decryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String CipherText, byte[] tweak)
            throws IOException, InvalidCipherTextException, IllegalStateException {

      try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
          return ubiqEncryptDecrypt.decryptFPE(ffs_name, CipherText, tweak);
      }
    }

    public static String[] encryptForSearch(UbiqCredentials ubiqCredentials, String ffs_name, String PlainText, byte[] tweak)
            throws IOException, InvalidCipherTextException, IllegalStateException {

      try (UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials)) {
          return ubiqEncryptDecrypt.encryptForSearch(ffs_name, PlainText, tweak);
      }
    }
    
}
