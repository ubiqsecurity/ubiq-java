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
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.*;
import java.util.List;

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
      String prefix;
      String suffix;
      // Integer formatted_first_empty_idx;

      ParsedData(String formatted_dest, String trimmed, String prefix, String suffix) {
        this.formatted_dest = formatted_dest;
        this.trimmed = trimmed;
        this.prefix = prefix;
        this.suffix = suffix;
        // this.formatted_first_empty_idx = formatted_first_empty_idx;
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
      this.ffxCache = new FFXCache(this.ubiqWebServices,this.ubiqConfiguration);
      this.ffs = new FFS(this.ubiqWebServices,this.ubiqConfiguration);
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

        int ct_value = ffs.getOutputCharacterSet().indexOf(charBuf);
        if (verbose) System.out.println("ct_value: " + ct_value);

        //int key_number = ffs.getCurrent_key();
        long msb_encoding_bits = ffs.getMsbEncodingBits();

        ct_value =  ct_value + (key_number << msb_encoding_bits);

        char ch= ffs.getOutputCharacterSet().charAt(ct_value);
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
        int encoded_value = ffs.getOutputCharacterSet().indexOf(charBuf);

        long msb_encoding_bits = ffs.getMsbEncodingBits();
        key_num =  encoded_value >> msb_encoding_bits;

        char ch= ffs.getOutputCharacterSet().charAt(encoded_value - (key_num << msb_encoding_bits));
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
        boolean verbose = false;
        String src_char_set= "";
        char dest_zeroth_char= '0';

        ParsedData ret = null;

        if (conversion_direction > 0) { // input to output
            src_char_set= ffs.getInputCharacterSet();
            dest_zeroth_char = ffs.getOutputCharacterSet().charAt(0);
        } else {
            src_char_set= ffs.getOutputCharacterSet();
            dest_zeroth_char = ffs.getInputCharacterSet().charAt(0);
        }

        try (Parsing parsing = new Parsing(source_string, src_char_set, 
          ffs.getPassthroughCharacterSet(), dest_zeroth_char)) {

          for (FFS.PASSTHROUGH_RULES_TYPE priority : ffs.getPassthrough_rules_priority()) {
            if (priority.equals(FFS.PASSTHROUGH_RULES_TYPE.PASSTHROUGH)) {
              int status = parsing.ubiq_platform_efpe_parsing_parse_input();
              if (verbose) System.out.println("Passthrough Processed: \n\t" + parsing.get_trimmed_characters() + "\n\t" + parsing.get_formatted_output());
            } else if (priority.equals(FFS.PASSTHROUGH_RULES_TYPE.PREFIX)) {
              parsing.process_prefix(ffs.getPrefixPassthroughLength());
              if (verbose) System.out.println("PREFIX Processed: \n\t" + parsing.get_trimmed_characters() + "\n\t" + parsing.get_formatted_output() + "\n\t" + ffs.getPrefixPassthroughLength());
            }else if (priority.equals(FFS.PASSTHROUGH_RULES_TYPE.SUFFIX)) {
              parsing.process_suffix(ffs.getSuffixPassthroughLength());
              if (verbose) System.out.println("SUFFIX Processed: \n\t" + parsing.get_trimmed_characters() + "\n\t" + parsing.get_formatted_output() + "\n\t" + ffs.getSuffixPassthroughLength());
            }
          }

          ret = new ParsedData(parsing.get_formatted_output(), parsing.get_trimmed_characters(), parsing.get_prefix_string(), parsing.get_suffix_string());
         }
         return ret;
    }



    /*
    * Merges the given string into the  "formatted_dest" pattern using the
    * set of provided characters.
    *
    * @param ffs  The FFS record model
    * @param formatted_dest The formatted destination string 
    + @param first_empty_idx The first empty location in formatted string
    * @param convertedToRadix  The string to be placed in the formatted_dest
    * @param passthrough_character_set  The set of characters to use in the final formatted_dest
    *
    * @return the correctly formatted output string
    */
    public String merge_to_formatted_output(FFS_Record ffs, ParsedData parsed_data, final String convertedToRadix, final String passthrough_character_set) {
      StringBuilder ret = new StringBuilder(parsed_data.formatted_dest);

      // Format the encrypted section and then add the prefix and suffix strings, which could be empty or also include formatted output
      int d = 0;
      for (int i = 0; i < convertedToRadix.length(); i++) {
        while (d < ret.length() && -1 != passthrough_character_set.indexOf(ret.charAt(d))) {
          d++;
        }
        if (d >= ret.length()) {
          System.out.println("Throw Exception");
          break;
        }
        ret.setCharAt(d, convertedToRadix.charAt(i));
        d++;
      }
      ret.insert(0, parsed_data.prefix);
      ret.append(parsed_data.suffix);

      return ret.toString();
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
        boolean verbose = false;
        if (verbose) System.out.println("\nEncrypting PlainText: " + PlainText);
        String convertedToRadix = "";
        String cipher = "";
        String formatted_dest = "";

        // attempt to load the FPEAlgorithm from the local cache
        ParsedData parsedData = ubiq_platform_fpe_string_parse(FFScaching, 1, PlainText);

        if (verbose) System.out.println("parsedData.trimmed.length(): " + parsedData.trimmed.length());
        if (verbose) System.out.println("getMinInputLength: " + FFScaching.getMinInputLength());
        if (verbose) System.out.println("getMaxInputLength: " + FFScaching.getMaxInputLength());

        // Make sure the trimmed string is valid for the FFS
        if ((parsedData.trimmed.length() < FFScaching.getMinInputLength()) ||
            (parsedData.trimmed.length() > FFScaching.getMaxInputLength())) {
            throw new RuntimeException("Input length does not match FFS parameters.");
        }

        // Encrypt the data
        switch(FFScaching.getEncryptionAlgorithm()) {
            case "FF1":
                cipher = cfx.getFF1().encrypt(parsedData.trimmed, tweak);
            break;
            case "FF3_1":
                cipher = cfx.getFF3_1().encrypt(parsedData.trimmed, tweak);
            break;
            default:
                throw new RuntimeException("Unknown FPE Algorithm: " + FFScaching.getEncryptionAlgorithm());
        }

        // Convert to output character set
        convertedToRadix = str_convert_radix(cipher, FFScaching.getInputCharacterSet(), FFScaching.getOutputCharacterSet());
        if (verbose) System.out.println("    converted to output char set= " + convertedToRadix);
        if (verbose) System.out.println("    formatted destination= " + parsedData.formatted_dest);

        // Encode the key number since it will be the first character.
        int key_number = cfx.getKeyNumber();
        if (verbose) System.out.println("   KeyNumber= " + key_number);
        String encoded_value = encode_keynum(FFScaching, key_number, convertedToRadix);

        formatted_dest = merge_to_formatted_output(FFScaching, parsedData, encoded_value, FFScaching.getPassthroughCharacterSet());
        if (verbose) System.out.println("    encrypted and formatted= " + formatted_dest);

        // create the billing record
        billing_events.addBillingEvent(ubiqCredentials.getAccessKeyId(), FFScaching.getName(), "", BillingEvents.BillingAction.ENCRYPT, BillingEvents.DatasetType.STRUCTURED, key_number,1);

        return formatted_dest;
    }


    public String[] encryptForSearch(final String ffs_name, final String PlainText, byte[] tweak)
        throws IllegalStateException  {
          boolean verbose = false;

          String[] ret = null;

          try {

            // Load the search keys for this Dataset (FFS)
            LoadSearchKeys.loadKeys(this.ubiqCredentials, this.ubiqWebServices, this.ffs, this.ffxCache, ffs_name);

            if (verbose) System.out.println("\nencryptForSearch: " + PlainText);

            // Get the FFS for the FFS_Name and the CTX which will have the current key_number - Everything should
            // already be loaded into the cache because of the load search keys function above.
            FFS_Record FFScaching = getFFS(ffs_name);
            if (verbose) System.out.println("\n after getFFS: " + FFScaching.getName());

            FFX_Ctx ctx = getCtx(FFScaching, null);
            if (verbose) System.out.println("\n after getCtx: ");
            
            int current_key_number = ctx.getKeyNumber();
            if (verbose) System.out.println("\n after getKeyNumber" + current_key_number);
            ret = new String[current_key_number + 1];

            for (int key = 0; key <= current_key_number; key++) {
              ctx = ffxCache.FFXCache.get(new FFS_KeyId(FFScaching, key));
              if (verbose) System.out.println("\n after ffxCache.FFXCache.get key: " + key);

              ret[key] = encryptData(FFScaching, ctx, PlainText, tweak);
              if (verbose) System.out.println("\n after encryptData: " + ret[key]);

            }

          } catch (ExecutionException e) {
            System.out.println("ExecutionException: " + e.getMessage());
          } catch (Exception e) {
            System.out.println("ExecutionException: " + e.getMessage());
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
                if ((parsed_data.trimmed.length() < FFScaching.getMinInputLength()) ||
                    (parsed_data.trimmed.length() > FFScaching.getMaxInputLength())) {
                    throw new RuntimeException("Input length does not match FFS parameters.");
                }

                // Get the key number from the cipher text
                int key_number = decode_keynum(FFScaching, parsed_data, 0);
                if (verbose) System.out.println("    decode_keynum returns key_number= " + key_number);

                FFX_Ctx cfx = getCtx(FFScaching, key_number);

                if (verbose) System.out.println("    cachingKey= " + FFScaching.getName() + " " + cfx.getKeyNumber());

                restoredFromRadix = str_convert_radix(parsed_data.trimmed, FFScaching.getOutputCharacterSet(), FFScaching.getInputCharacterSet());
                if (verbose) System.out.println("    converted to input character set= " + restoredFromRadix);

                // Encrypt the data
                switch(FFScaching.getEncryptionAlgorithm()) {
                  case "FF1":
                    PlainText = cfx.getFF1().decrypt(restoredFromRadix, tweak);
                  break;
                  case "FF3_1":
                    PlainText = cfx.getFF3_1().decrypt(restoredFromRadix, tweak);
                  break;
                  default:
                      throw new RuntimeException("Unknown FPE Algorithm: " + FFScaching.getEncryptionAlgorithm());
                }

                formatted_dest = merge_to_formatted_output(FFScaching, parsed_data, PlainText, FFScaching.getPassthroughCharacterSet());
                if (verbose) System.out.println("    decrypted and formatted= " + formatted_dest);

                // create the billing record

                billing_events.addBillingEvent(ubiqCredentials.getAccessKeyId(), ffs_name, "", BillingEvents.BillingAction.DECRYPT, BillingEvents.DatasetType.STRUCTURED, key_number,1);


            } catch (ExecutionException e) {
                e.printStackTrace();
            }

        return formatted_dest;
    }

    // Dataset and Keys - Same payload as api/v0/fpe/def_keys
    public String loadDatasetDef(final String dataset_def) {
      JsonParser parser = new JsonParser();
      JsonObject dataset_data = parser.parse(dataset_def).getAsJsonObject();

      try {
        String dataset_name = LoadSearchKeys.loadKeys(
          this.ubiqCredentials,
          this.ubiqWebServices,
          dataset_data,
          this.ffs,
          this.ffxCache);

        return dataset_name;
      } catch (Exception e) {
        System.out.println("loadDatsetDef Exception: " + e.getMessage());
        return "";
      }
    }

    // Dataset - same payload as api/v0/ffs
    public String loadDataset(final String dataset_def) {
      JsonParser parser = new JsonParser();
      JsonObject dataset_data = parser.parse(dataset_def).getAsJsonObject();

      try {
        String dataset_name = LoadSearchKeys.loadDataset(
          this.ubiqCredentials,
          this.ubiqWebServices,
          dataset_data,
          this.ffs);

        return dataset_name;
      } catch (Exception e) {
        System.out.println("loadDatsetDef Exception: " + e.getMessage());
        return "";
      }
    }


      // FPE Key - same payload as api/v0/fpe/key which includes key number
      public void loadKeyDef(final String dataset_name, final String key_def, final Boolean current_key_flag) {
      JsonParser parser = new JsonParser();
      JsonObject key_data = parser.parse(key_def).getAsJsonObject();

      LoadSearchKeys.loadKeyDef(
        this.ubiqCredentials,
        this.ubiqWebServices,
        key_data,
        current_key_flag,
        dataset_name,
        this.ffs,
        this.ffxCache);
    }

    // Returns base64 encoded key

    public String decryptKey(final String key_def) {
      JsonParser parser = new JsonParser();
      JsonObject key_data = parser.parse(key_def).getAsJsonObject();

      return LoadSearchKeys.unwrapKey(
        this.ubiqWebServices,
        key_data);
    }

    // data is in base 64, encryption key is in base 64
    public static JsonObject encryptData(final byte[] data, final String encryption_key) {

      return LoadSearchKeys.encryptKey(
        data,
        encryption_key);
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

    public void addReportingUserDefinedMetadata(String jsonString) {
      billing_events.addUserDefinedMetadata(jsonString);
    }

    public String getCopyOfUsage() {
     return billing_events.getSerializedData();
    }
  }
