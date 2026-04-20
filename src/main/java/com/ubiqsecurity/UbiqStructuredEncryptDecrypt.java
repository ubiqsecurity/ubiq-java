package com.ubiqsecurity;

import com.google.gson.Gson;
import java.util.Arrays;
import com.ubiqsecurity.structured.FF1;
import java.math.BigInteger;
import com.ubiqsecurity.structured.Bn;

import java.util.concurrent.ExecutionException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import java.lang.Math;
import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.UUID;
import java.time.Instant;
import java.io.IOException;
import java.net.URISyntaxException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.*;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.time.ZoneOffset;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;

import com.ubiqsecurity.pipeline.*;
import com.ubiqsecurity.*;

import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.operator.OperatorCreationException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

/**
 * Provides Format Preserving Encryption capability for a variety of field format models (aka FFS models)
 * This capability must be enabled and configured with FFS models on a per-user account basis.
 */
public class UbiqStructuredEncryptDecrypt implements AutoCloseable {
    private boolean verbose = false;
    private UbiqWebServices ubiqWebServices = null; // null when closed
    private FFS ffs = null;
    private FFXCache ffxCache = null;
    private BillingEventsProcessor executor = null;
    private BillingEvents billing_events = null;
    private UbiqCredentials ubiqCredentials = null;
    private UbiqConfiguration ubiqConfiguration = null;


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
    public UbiqStructuredEncryptDecrypt(UbiqCredentials ubiqCredentials) {
      this(ubiqCredentials, UbiqFactory.defaultConfiguration());
    }


    public UbiqStructuredEncryptDecrypt(UbiqCredentials ubiqCredentials, UbiqConfiguration ubiqConfiguration) {
      if (verbose) System.out.println("+++++++ NEW OBJECT UbiqFPEEncryptDecrypt +++++++" );
      if (ubiqCredentials == null) {
          System.out.println("Credentials have not been specified.");
          return;
      }
      this.ubiqConfiguration = ubiqConfiguration;
      this.ubiqCredentials = ubiqCredentials;
      this.ubiqWebServices = new UbiqWebServices(ubiqCredentials, this.ubiqConfiguration);
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
      String csu = "close";
      if (verbose) System.out.println(csu);
      if (this.ubiqWebServices != null) {
            clearKeyCache();

            // this stops any remaining background billing processing
            try {
              if (executor != null) {
                executor.stopAsync().awaitTerminated(5, TimeUnit.SECONDS);
              }
            } catch (Exception e) { // has getJavaOptionsAlwaysBubbleExceptions
              if (this.ubiqConfiguration.getJavaOptionsAlwaysBubbleExceptions()) {
                throw new RuntimeException(e.getMessage(), e.getCause());
              }
              System.out.printf("%s   : %s Exception %s  messasge: %s\n", csu,new java.util.Date(),  e.getClass().getName(), e.getMessage());
            }
            // executor.shutDown();

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

    String encryptPipeline(FFS_Record dataset, Integer keyNumber, FFXCache ffxCache, String plaintext, byte[] tweak)
     throws ExecutionException {
      OperationContext context = new OperationContext();
      context.setDataset(dataset);
      context.setKeyNumber(keyNumber);
      context.setOriginalValue(plaintext);
      context.setCurrentValue(plaintext);
      context.setIsEncrypt(true);
      context.setUserSuppliedTweak(tweak);
      context.setFfxCache(ffxCache);

      StructuredPipeline pipeline = new EncryptionPipeline(dataset);
      String results = pipeline.Invoke(context);

      billing_events.addBillingEvent(ubiqCredentials.getAccessKeyId(), dataset.getName(), "", BillingEvents.BillingAction.ENCRYPT, BillingEvents.DatasetType.STRUCTURED, context.getKeyNumber(),1);

      return results;
    }

    String decryptPipeline(FFS_Record dataset, FFXCache ffxCache, String ciphertext, byte[] tweak)
     throws ExecutionException {
      OperationContext context = new OperationContext();
      context.setDataset(dataset);
      context.setKeyNumber(null);
      context.setOriginalValue(ciphertext);
      context.setCurrentValue(ciphertext);
      context.setIsEncrypt(false);
      context.setUserSuppliedTweak(tweak);
      context.setFfxCache(ffxCache);

      StructuredPipeline pipeline = new DecryptionPipeline(dataset);
      String results = pipeline.Invoke(context);

      billing_events.addBillingEvent(ubiqCredentials.getAccessKeyId(), dataset.getName(), "", BillingEvents.BillingAction.DECRYPT, BillingEvents.DatasetType.STRUCTURED, context.getKeyNumber(),1);

      return results;
    }
    /**
    * Performs an FPE encryption for a given string based on a given FFS model
    *
    * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
    * @param plainText  the plain text to be encrypted
    * @param tweak  the tweak bytes which are only applied if not already overriden by the FFS model
    *
    * @return the encrypted output string
    *
    */
    public String encrypt(String ffs_name, String plainText, byte[] tweak)
        throws IllegalStateException  {
            if (verbose) System.out.println("\nEncrypting plainText: " + plainText);
            String cipher = "";
            try {

              FFS_Record dataset = getFFS(ffs_name);
              if (!dataset.canEncrypt()) {
                throw new RuntimeException("API Key does not have encrypt rights for dataset '" + ffs_name + "'");
              }

              // Fatal out if this is not specifically a String type.
              switch (dataset.getDataType()) {
                case "integer":
                case "date":
                case "datetime":
                  // Unchecked exception
                  throw new RuntimeException("Dataset '" + ffs_name + "' is for '" + dataset.getDataType() + "' and not Strings.  Use the appropriate method for this type");
                default:
                  cipher = encryptPipeline(dataset, null, ffxCache, plainText, tweak);
              }

            } catch (ExecutionException e) { // has getJavaOptionsAlwaysBubbleExceptions
              if (this.ubiqConfiguration.getJavaOptionsAlwaysBubbleExceptions()) {
                throw new RuntimeException(e.getMessage(), e.getCause());
              }
            }

        return cipher;
    }

    // Get latest information from the server for the dataset
    // Does not resets the TTL for all the cache elements
    // These are external and should make sure exceptions are more general than specific to bouncy castle or similar
    public void loadCache(final String dataset_name)
      throws IllegalStateException, ExecutionException {
      String csu = "loadCache";

      String[] names = {dataset_name};

      loadCache(names);
    }

    // These are external and should resolve some of the library specific
    // exceptions to more generic ones
    public void loadCache(final String[] dataset_names)
      throws IllegalStateException, ExecutionException {
      String csu = "loadCache";

      // Load the search keys for this Dataset (FFS)
      try {
        loadCacheEx(dataset_names);
        // Convert very obscure dependent library exceptions to a more generic one for public use
      } catch (org.bouncycastle.operator.OperatorCreationException | org.bouncycastle.pkcs.PKCSException | org.bouncycastle.crypto.InvalidCipherTextException e) {
        throw new ExecutionException(e.getMessage(), e.getCause());
      } catch (IOException | URISyntaxException | InterruptedException | NoSuchAlgorithmException | InvalidKeyException e) {
        throw new ExecutionException(e.getMessage(), e.getCause());
      }

    }

    private void loadCacheEx(final String[] dataset_names)
      throws IllegalStateException, ExecutionException, IOException, URISyntaxException, InterruptedException, org.bouncycastle.operator.OperatorCreationException, org.bouncycastle.pkcs.PKCSException, org.bouncycastle.crypto.InvalidCipherTextException, java.security.NoSuchAlgorithmException, InvalidKeyException {
      String csu = "loadCache";

      // Load the search keys for this Dataset (FFS)
      LoadSearchKeys.loadKeys(this.ubiqWebServices, this.ffs, this.ffxCache, dataset_names);
    }


    public String[] encryptForSearch(final String ffs_name, final String PlainText, byte[] tweak)
        throws IllegalStateException  {
          boolean verbose = false;

          String[] ret = null;

          try {

            // Load the search keys for this Dataset (FFS) - Does not reset the TTL
            // of the data in case the dataset has already been loaded.
            loadCache(ffs_name);

            if (verbose) System.out.println("\nencryptForSearch: " + PlainText);

            // Get the FFS for the FFS_Name and the CTX which will have the current key_number - Everything should
            // already be loaded into the cache because of the load search keys function above.
            FFS_Record dataset = getFFS(ffs_name);
            if (verbose) System.out.println("\n after getFFS: " + dataset.getName());
            if (!dataset.canEncrypt()) {
              throw new RuntimeException("API Key does not have encrypt rights for dataset '" + ffs_name + "'");
            }

            // Fatal out if this is not specifically a String type.
            switch (dataset.getDataType()) {
              case "integer":
              case "date":
              case "datetime":
                // Unchecked exception
                throw new RuntimeException("Dataset '" + ffs_name + "' is for '" + dataset.getDataType() + "' and not Strings.  Use the appropriate method for this type");
              default:
                break;
            }

            FFX_Ctx ctx = getCtx(dataset, null);
            if (verbose) System.out.println("\n after getCtx: ");

            int current_key_number = ctx.getKeyNumber();
            if (verbose) System.out.println("\n after getKeyNumber" + current_key_number);
            ret = new String[current_key_number + 1];

            for (int key = 0; key <= current_key_number; key++) {

              ret[key] = encryptPipeline(dataset, key, ffxCache, PlainText, tweak);
            }

          } catch (RuntimeException e) {  // Has check for getJavaOptionsAlwaysBubbleExceptions
            throw e;
          } catch (Exception e) { // Has check for getJavaOptionsAlwaysBubbleExceptions
            // Bubble up all other exception as a Runtime exception
            if (this.ubiqConfiguration.getJavaOptionsAlwaysBubbleExceptions()) {
              throw new RuntimeException(e.getMessage(), e.getCause());
            }
          }

          return ret;
    }


    /**
    * Performs an FPE decryption for a given string based on a given FFS model
    *
    * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
    * @param cipherText  the encrypted text to be decrypted
    * @param tweak  the tweak bytes which are only applied if not already overriden by the FFS model
    *
    * @return the decrypted output string
    *
    */
    public String decrypt(final String ffs_name, final String cipherText, byte[] tweak)
      throws IllegalStateException {
          String plainText = "";
        try {
          boolean verbose = false;
          String restoredFromRadix = "";
          String formatted_dest = "";

          if (verbose) System.out.println("\nDecrypting CipherText: " + cipherText);

          FFS_Record dataset = getFFS(ffs_name);
          if (!dataset.canDecrypt()) {
            throw new RuntimeException("API Key does not have decrypt rights for dataset '" + ffs_name + "'");
          }
          // Fatal out if this is not specifically a String type.
          switch (dataset.getDataType()) {
            case "integer":
            case "date":
            case "datetime":
              // Unchecked exception
              throw new RuntimeException("Dataset '" + ffs_name + "' is for '" + dataset.getDataType() + "' and not Strings.  Use the appropriate method for this type");
            default:
              plainText = decryptPipeline(dataset, ffxCache, cipherText, tweak);
          }

        } catch (ExecutionException e) { // Has check for getJavaOptionsAlwaysBubbleExceptions
          if (this.ubiqConfiguration.getJavaOptionsAlwaysBubbleExceptions()) {
            throw new RuntimeException(e.getMessage(), e.getCause());
          }
          // e.printStackTrace();
          } catch (RuntimeException e) {
              throw e;
          } catch (Exception e) {
              throw new RuntimeException(e.getMessage(), e.getCause());
          }

      return plainText;
    }

    // Dataset and Keys - Same payload as api/v0/fpe/def_keys
    public String loadDatasetDef(final String dataset_def) {
      JsonObject dataset_data =  JsonParser.parseString(dataset_def).getAsJsonObject();

      try {
        String dataset_name = LoadSearchKeys.loadKeys(
          this.ubiqCredentials,
          this.ubiqWebServices,
          dataset_data,
          this.ffs,
          this.ffxCache);

        return dataset_name;
      } catch (Exception e) { // Has check for getJavaOptionsAlwaysBubbleExceptions
        if (this.ubiqConfiguration.getJavaOptionsAlwaysBubbleExceptions()) {
          throw new RuntimeException(e.getMessage(), e.getCause());
        } else {
          System.out.println("loadDatsetDef Exception: " + e.getMessage());
        }
        return "";
      }
    }

    // Dataset - same payload as api/v0/ffs
    public String loadDataset(final String dataset_def) {
      JsonObject dataset_data =  JsonParser.parseString(dataset_def).getAsJsonObject();

      try {
        String dataset_name = LoadSearchKeys.loadDataset(
          this.ubiqCredentials,
          this.ubiqWebServices,
          dataset_data,
          this.ffs);

        return dataset_name;
      } catch (Exception e) { // Has check for getJavaOptionsAlwaysBubbleExceptions
        if (this.ubiqConfiguration.getJavaOptionsAlwaysBubbleExceptions()) {
          throw new RuntimeException(e.getMessage(), e.getCause());
        }
        return "";
      }
    }


      // FPE Key - same payload as api/v0/fpe/key which includes key number
    public boolean loadKeyDef(final String dataset_name, final String key_def, final Boolean current_key_flag) {
      JsonObject key_data =  JsonParser.parseString(key_def).getAsJsonObject();

      boolean ret = false;
      try {
        ret = LoadSearchKeys.loadKeyDef(
          this.ubiqCredentials,
          this.ubiqWebServices,
          key_data,
          current_key_flag,
          dataset_name,
          this.ffs,
          this.ffxCache);
      } catch (IOException | InvalidCipherTextException | OperatorCreationException | PKCSException e) {
        if (this.ubiqConfiguration.getJavaOptionsAlwaysBubbleExceptions()) {
          throw new RuntimeException(e.getMessage(), e.getCause());
        }
      }
      return ret;
    }

    // Returns base64 encoded key

    public String decryptKey(final String key_def)
      throws IOException, InvalidCipherTextException, OperatorCreationException, PKCSException {
      JsonObject key_data =  JsonParser.parseString(key_def).getAsJsonObject();

      return LoadSearchKeys.unwrapKey(
        this.ubiqWebServices,
        key_data);
    }

    // data is in base 64, encryption key is in base 64
    // Used by Apigee - no configuration so need to catch exceptions
    public static JsonObject encryptData(final byte[] data, final String encryption_key) {

      try {
        return LoadSearchKeys.encryptKey(
          data,
          encryption_key);
        } catch (org.bouncycastle.crypto.InvalidCipherTextException e) {
          return new JsonObject();
        }
    }

    private FFS_Record getFFS(final String ffs_name)
     throws ExecutionException {
        if (this.ffs == null || this.ffs.FFSCache == null) {
          System.out.println("Objects null");
          throw new IllegalStateException("object closed");
        }

        // The google LoadCache object will catch and convert some exceptions
        // Therefore our code where this is called, catches and processes some
        // checked exceptions and converts to runtimeException first.
        FFS_Record ret = this.ffs.FFSCache.get(ffs_name);
        return ret;
    }

    private FFX_Ctx getCtx(final FFS_Record ffsRecord, final Integer key_number)
      throws IllegalStateException, ExecutionException {
        if (this.ffxCache == null || this.ffxCache.FFXCache == null) {
          throw new IllegalStateException("object closed");
        }

        return this.ffxCache.FFXCache.get(new FFS_KeyId(ffsRecord, key_number));
    }

    public void addReportingUserDefinedMetadata(String jsonString) {
      billing_events.addUserDefinedMetadata(jsonString);
    }

    public String getCopyOfUsage() {
     return billing_events.getSerializedData();
    }

    /***
     * Encrypt a date time value
     *
     * @param datasetName used to specify the dataset for encrypting date time values
     * @param plainDate the date time to encrypt
     * @param tweak the tweak to use when encrypting the data.  Pass empty array to use the dataset specific tweak
     *
     * @return the encrypted date time value
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */
    public OffsetDateTime encryptDateTime(final String datasetName, OffsetDateTime plainDate, byte[] tweak)
       throws ExecutionException {

      OffsetDateTime ret = null;

      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canEncrypt()) {
        throw new RuntimeException("API Key does not have encrypt rights for dataset '" + datasetName + "'");
      }
      ret = encryptDateTimePipeline(dataset, null, ffxCache, plainDate, tweak);
      return ret;
    }

    /***
     * Decrypt a date time value
     *
     * @param datasetName used to specify the dataset for decrypting date times
     * @param cipherDate the date time to decrypt
     * @param tweak the tweak to use when decrypting the data.  Must be the same tweak that was used to encrypt the value.
     * Pass empty array to use the dataset specific tweak
     *
     * @return the decrypted date time value
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */

    public OffsetDateTime decryptDateTime(final String datasetName, OffsetDateTime cipherDate, byte[] tweak)
      throws ExecutionException {

      OffsetDateTime ret = null;

      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canDecrypt()) {
        throw new RuntimeException("API Key does not have decrypt rights for dataset '" + datasetName + "'");
      }
      ret = decryptDateTimePipeline(dataset, ffxCache, cipherDate, tweak);
      return ret;

    }

   /***
     * Encrypt a date time value for all previously used keys
     *
     * @param datasetName used to specify the dataset for encrypting date time values
     * @param plainDate the date time to encrypt
     * @param tweak the tweak to use when encrypting the data.  Pass empty array to use the dataset specific tweak
     *
     * @return an array of encrypted date time values for all the previously used keys
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */

   public OffsetDateTime[] encryptDateTimeForSearch(final String datasetName, OffsetDateTime plainDate, byte[] tweak)
      throws ExecutionException {

      OffsetDateTime[] ret = null;

      loadCache(datasetName);

      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canEncrypt()) {
        throw new RuntimeException("API Key does not have encrypt rights for dataset '" + datasetName + "'");
      }

      FFX_Ctx ctx = getCtx(dataset, null);
      int current_key_number = ctx.getKeyNumber();
      if (verbose) System.out.println("\n after getKeyNumber" + current_key_number);
      ret = new OffsetDateTime[current_key_number + 1];

      for (int key = 0; key <= current_key_number; key++) {
        ret[key] = encryptDateTimePipeline(dataset, key, ffxCache, plainDate, tweak);
      }

      return ret;

    }


    private OffsetDateTime encryptDateTimePipeline(final FFS_Record dataset, Integer keyNumber, FFXCache ffxCache, final OffsetDateTime plainDate, byte[] tweak)
     throws ExecutionException {
      final String csu = "encryptDateTimePipeline";

      boolean verbose = false;
      DataTypeConfig cfg = null;

      if (!dataset.getDataType().equals("datetime")) {
        throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is not a 'datetime' dataset.");
      }

      cfg = dataset.getDataTypeConfig();
      if (cfg == null) {
        throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is not a 'datetime' dataset.");
      }

      OffsetDateTime utcPlainDateTime = plainDate.atZoneSameInstant(ZoneId.of("UTC")).toOffsetDateTime();

      if (plainDate.isAfter(cfg.getMaxInputDateValue())) {
        throw new IllegalArgumentException(plainDate + " plainDateTime must be <= " + cfg.getMaxInputDateValue());
      }
      if (plainDate.isBefore(cfg.getMinInputDateValue())) {
        throw new IllegalArgumentException(plainDate + " plainDateTime must be >= " + cfg.getMinInputDateValue());
      }

      ZoneOffset offset = plainDate.getOffset();

      // Start, end # negative if end is AFTER start
      long secondsOffset = ChronoUnit.SECONDS.between(utcPlainDateTime, plainDate);
      if (verbose) System.out.printf("%s   : %s secondsOffset: %d\n", csu, new java.util.Date(), secondsOffset);

      // positive Number of seconds utcPlainDateTime is AFTER epoch, negative if end is before epoch
      Long secondsToEpoch = ChronoUnit.SECONDS.between(cfg.getEpoch(), utcPlainDateTime);
      Boolean isNegative = secondsToEpoch < 0;
      String plainText = String.valueOf(Math.abs(secondsToEpoch));
      plainText = StringUtils.convertRadix(plainText, "0123456789", dataset.getInputCharacterSet(), true, false );
      plainText = StringUtils.padLeft(dataset.getInputCharacterSet().charAt(0), dataset.getMinInputLength(), plainText);

      String cipherText = encryptPipeline(dataset, keyNumber, ffxCache, plainText, tweak);

      if (verbose) System.out.printf("%s   : %s plainText: %s  cipherText: %s\n", csu,new java.util.Date(),  plainText, cipherText);
      if (verbose) System.out.printf("%s   : %s asBase10: %s\n", csu,new java.util.Date(),  StringUtils.convertRadix(cipherText, dataset.getOutputCharacterSet(), "0123456789", true, false ));
      // Left pad since covert will return empty if string is considered zero
      Long encryptedSecondsToEpoch = Long.parseLong(StringUtils.convertRadix(cipherText, dataset.getOutputCharacterSet(), "0123456789", true, true ));

      if (isNegative) {
        encryptedSecondsToEpoch *= -1;
      }
      if (verbose) System.out.printf("%s   : %s secondsToEpoch: %d plainText: %s   cipherText: %s  encryptedSecondsToEpoch: %d\n", csu,new java.util.Date(),  secondsToEpoch, plainText, cipherText, encryptedSecondsToEpoch);

      ZonedDateTime r = cfg.getEpoch().toZonedDateTime().plusSeconds(encryptedSecondsToEpoch);

      return r.toOffsetDateTime().withOffsetSameInstant(offset);
    }

    private OffsetDateTime decryptDateTimePipeline(final FFS_Record dataset, FFXCache ffxCache, final OffsetDateTime cipherDate, byte[] tweak)
      throws ExecutionException {

      final String csu = "decryptDateTimePipeline";


      boolean verbose = false;
      DataTypeConfig cfg = null;

      if (!dataset.getDataType().equals("datetime")) {
        throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is not a 'datetime' dataset.");
      }

      cfg = dataset.getDataTypeConfig();
      if (cfg == null) {
        throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is not a 'datetime' dataset.");
      }

      ZoneOffset offset = cipherDate.getOffset();

      OffsetDateTime utcCipherDateTime = cipherDate.atZoneSameInstant(ZoneId.of("UTC")).toOffsetDateTime();
      long secondsOffset = ChronoUnit.SECONDS.between(utcCipherDateTime, cipherDate);


      Long encryptedSecondsToEpoch = ChronoUnit.SECONDS.between(cfg.getEpoch(), cipherDate);
      Boolean isNegative = encryptedSecondsToEpoch < 0;
      String cipherText = StringUtils.convertRadix(String.valueOf(Math.abs(encryptedSecondsToEpoch)), "0123456789", dataset.getOutputCharacterSet(), true, false);

      cipherText = StringUtils.padLeft(dataset.getOutputCharacterSet().charAt(0), dataset.getMinInputLength(), cipherText);

      String plainText = decryptPipeline(dataset, ffxCache, cipherText, tweak);
      // Left pad in case string is considered 0, which can return an empty string
      String c = StringUtils.convertRadix(plainText, dataset.getInputCharacterSet(), "0123456789", true, true);
      if (verbose) System.out.printf("%s   : %s plainText: %s dataset.getInputCharacterSet: %s convertRadix: '%s' %d\n", csu,new java.util.Date(), plainText, dataset.getInputCharacterSet(), c, c.length());
      Long plainSecondsToEpoch = Long.parseLong(c);
      if (verbose) System.out.printf("%s   : %s plainSecondsToEpoch: %d \n", csu,new java.util.Date(), plainSecondsToEpoch);
      if (isNegative) {
        plainSecondsToEpoch *= -1;
      }
      if (verbose) System.out.printf("%s   : %s encryptedSecondsToEpoch: %d cipherText: %s  plainText: %s  plainSecondsToEpoch: %d \n", csu,new java.util.Date(), encryptedSecondsToEpoch, cipherText, plainText, plainSecondsToEpoch);

      ZonedDateTime r = cfg.getEpoch().toZonedDateTime().plusSeconds(plainSecondsToEpoch);

      return r.toOffsetDateTime().withOffsetSameInstant(offset);
    }

    /***
     * Encrypt a date value
     *
     * @param datasetName used to specify the dataset for encrypting dates
     * @param plainDate the date to encrypt
     * @param tweak the tweak to use when encrypting the data.  Pass empty array to use the dataset specific tweak
     *
     * @return the encrypted date
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */
    public OffsetDateTime encryptDate(final String datasetName, OffsetDateTime plainDate, byte[] tweak)
      throws ExecutionException {

      OffsetDateTime ret = null;

      if (verbose) System.out.println("plainDate: " + plainDate);

      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canEncrypt()) {
        throw new RuntimeException("API Key does not have encrypt rights for dataset '" + datasetName + "'");
      }
      ret = encryptDatePipeline(dataset, null, ffxCache, plainDate, tweak);
      return ret;
    }

    /***
     * Decrypt a date value
     *
     * @param datasetName used to specify the dataset for decrypting dates
     * @param cipherDate the date to decrypt
     * @param tweak the tweak to use when decrypting the data.  Must be the same tweak that was used to encrypt the value.
     * Pass empty array to use the dataset specific tweak
     *
     * @return the decrypted date
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */

    public OffsetDateTime decryptDate(final String datasetName, OffsetDateTime cipherDate, byte[] tweak)
      throws ExecutionException {

      OffsetDateTime ret = null;

      if (verbose) System.out.println("cipherDate: " + cipherDate);
      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canDecrypt()) {
        throw new RuntimeException("API Key does not have decrypt rights for dataset '" + datasetName + "'");
      }
      ret = decryptDatePipeline(dataset, ffxCache, cipherDate, tweak);
      return ret;
    }

    /***
     * Encrypt a date value for all previously used keys
     *
     * @param datasetName used to specify the dataset for encrypting dates
     * @param plainDate the date to encrypt
     * @param tweak the tweak to use when encrypting the data.  Pass empty array to use the dataset specific tweak
     *
     * @return an array of encrypted dates for all the previously used keys
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */

    public OffsetDateTime[] encryptDateForSearch(final String datasetName, OffsetDateTime plainDate, byte[] tweak)
       throws ExecutionException {

      OffsetDateTime[] ret = null;

      loadCache(datasetName);

      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canEncrypt()) {
        throw new RuntimeException("API Key does not have encrypt rights for dataset '" + datasetName + "'");
      }

      FFX_Ctx ctx = getCtx(dataset, null);
      int current_key_number = ctx.getKeyNumber();
      if (verbose) System.out.println("\n after getKeyNumber" + current_key_number);
      ret = new OffsetDateTime[current_key_number + 1];

      for (int key = 0; key <= current_key_number; key++) {
        ret[key] = encryptDatePipeline(dataset, key, ffxCache, plainDate, tweak);
      }

      return ret;
    }


    private OffsetDateTime encryptDatePipeline(final FFS_Record dataset, Integer keyNumber, FFXCache ffxCache, final OffsetDateTime plainDate, byte[] tweak)
      throws ExecutionException {
      final String csu = "encryptDatePipeline";

      boolean verbose = false;
      DataTypeConfig cfg = null;

      if (!dataset.getDataType().equals("date")) {
        throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is not a 'date' dataset.");
      }

      cfg = dataset.getDataTypeConfig();
      if (cfg == null) {
        throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is missing data_type_config.");
      }

      if (plainDate.getOffset().getTotalSeconds() != 0) {
        throw new IllegalArgumentException("plainDate must be UTC but was passed in as " + plainDate.getOffset().getId());
      }

      if (plainDate.isAfter(cfg.getMaxInputDateValue())) {
        throw new IllegalArgumentException(plainDate + " plainDate must be <= " + cfg.getMaxInputDateValue());
      }
      if (plainDate.isBefore(cfg.getMinInputDateValue())) {
        throw new IllegalArgumentException(plainDate + " plainDate must be >= " + cfg.getMinInputDateValue());
      }

      // positive Number of seconds utcPlainDateTime is AFTER epoch, negative if end is before epoch
      Long daysToEpoch = ChronoUnit.DAYS.between(cfg.getEpoch(), plainDate);
      Boolean isNegative = daysToEpoch < 0;

      String plainText = String.valueOf(Math.abs(daysToEpoch));
      plainText = StringUtils.convertRadix(plainText, "0123456789", dataset.getInputCharacterSet(), true, false );

      plainText = StringUtils.padLeft(dataset.getInputCharacterSet().charAt(0), dataset.getMinInputLength(), plainText);

      if (verbose) System.out.printf("%s   : %s daysToEpoch: %d plainText: %s \n", csu, new java.util.Date(), daysToEpoch, plainText);

      String cipherText = encryptPipeline(dataset, keyNumber, ffxCache, plainText, tweak);

      // Need to convert from output character set (including encoding) to base 10 since that is a number that can be parsed and added to epoch.
      // Dont need to run two steps on OCS -> ICS -> base 10, just go straight to base 10

      // Left pad since covert will return empty if string is considered zero

      Long encryptedDaysToEpoch = Long.parseLong(StringUtils.convertRadix(cipherText, dataset.getOutputCharacterSet(), "0123456789", true, true ));
      if (isNegative) {
        encryptedDaysToEpoch *= -1;
      }
      if (verbose) System.out.printf("%s   : %s daysaysToEpoch: %d plainText: %s   cipherText: %s  encryptedDaysToEpoch: %d\n", csu,new java.util.Date(),  daysToEpoch, plainText, cipherText, encryptedDaysToEpoch);

      OffsetDateTime r = cfg.getEpoch().toZonedDateTime().plusDays(encryptedDaysToEpoch).toOffsetDateTime();

      return r;
    }

    private OffsetDateTime decryptDatePipeline(final FFS_Record dataset, FFXCache ffxCache, final OffsetDateTime cipherDate, byte[] tweak)
      throws ExecutionException {
      final String csu = "decryptDatePipeline";

      boolean verbose = false;
      DataTypeConfig cfg = null;

      if (!dataset.getDataType().equals("date")) {
        throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is not a 'date' dataset.");
      }

      cfg = dataset.getDataTypeConfig();
      if (cfg == null) {
        throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is missing data_type_config.");
      }

      if (cipherDate.getOffset().getTotalSeconds() != 0) {
        throw new IllegalArgumentException("cipherDate must be UTC but was passed in as " + cipherDate.getOffset().getId());
      }

      // positive Number of days cipherDate is BEFORE epoch, negative if end is AFTER epoch
      Long daysFromEpoch = ChronoUnit.DAYS.between(cfg.getEpoch(), cipherDate);

      Boolean isNegative = daysFromEpoch < 0;
      // Need to convert from base10 to OCS
      String cipherText = StringUtils.convertRadix(String.valueOf(Math.abs(daysFromEpoch)), "0123456789", dataset.getOutputCharacterSet(), true, false);
      // String.valueOf(Math.abs(daysFromEpoch));
      cipherText = StringUtils.padLeft(dataset.getOutputCharacterSet().charAt(0), dataset.getMinInputLength(), cipherText);

      if (verbose) System.out.printf("%s   : %s daysFromEpoch: %d cipherText: %s \n", csu, new java.util.Date(), daysFromEpoch, cipherText);

      String plainText = decryptPipeline(dataset, ffxCache, cipherText, tweak);

      // plain text will be in ICS, not necessarily base 10
      // Left pad since covert will return empty if string is considered zero

      Long plainDaysFromEpoch = Long.parseLong(StringUtils.convertRadix(plainText, dataset.getInputCharacterSet(), "0123456789", true, true));
      if (isNegative) {
        plainDaysFromEpoch *= -1;
      }
      if (verbose) System.out.printf("%s   : %s daysaysToEpoch: %d plainText: %s   cipherText: %s  plainDaysFromEpoch: %d\n", csu,new java.util.Date(),  daysFromEpoch, plainText, cipherText, plainDaysFromEpoch);

      OffsetDateTime r = cfg.getEpoch().toZonedDateTime().plusDays(plainDaysFromEpoch).toOffsetDateTime();

      return r;
    }

    /***
     * Encrypt a integer 32 value
     *
     * @param datasetName used to specify the dataset for encrypting the value
     * @param plainInt the value to encrypt
     * @param tweak the tweak to use when encrypting the data.  Pass empty array to use the dataset specific tweak
     *
     * @return the encrypted integer 32 value
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */

    public int encryptInt(final String datasetName, int plainInt, byte[] tweak)
      throws ExecutionException {//}, java.io.IOException, java.net.URISyntaxException, java.security.NoSuchAlgorithmException, java.lang.InterruptedException, java.security.InvalidKeyException {

      final String csu = "encryptInt";
      Integer ret = null;
      if (verbose) System.out.printf("%s   : %s  plainInt: '%d'\n",csu, new java.util.Date(), plainInt);

      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canEncrypt()) {
        throw new RuntimeException("API Key does not have encrypt rights for dataset '" + datasetName + "'");
      }
      ret = encryptIntPipeline(dataset, null, ffxCache, plainInt, tweak);
      return ret.intValue();
    }

    /***
     * Decrypt an integer 32 value
     *
     * @param datasetName used to specify the dataset for decrypting the value
     * @param cipherInt the value to decrypt
     * @param tweak the tweak to use when decrypting the data.  Must be the same tweak that was used to encrypt the value.
     * Pass empty array to use the dataset specific tweak
     *
     * @return the decrypted integer 32 value
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */
    public int decryptInt(final String datasetName, int cipherInt, byte[] tweak)
      throws ExecutionException {

      final String csu = "decryptInt";

      Integer ret = null;
      if (verbose) System.out.printf("%s   : %s  cipherInt: '%d'\n",csu, new java.util.Date(), cipherInt);

      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canDecrypt()) {
        throw new RuntimeException("API Key does not have decrypt rights for dataset '" + datasetName + "'");
      }
      ret = decryptIntPipeline(dataset, ffxCache, cipherInt, tweak);
      return ret.intValue();
    }

     /***
     * Encrypt an integer 32 value for all previously used keys
     *
     * @param datasetName used to specify the dataset for encrypting the value
     * @param plainInt the value to encrypt
     * @param tweak the tweak to use when encrypting the data.  Pass empty array to use the dataset specific tweak
     *
     * @return an array of encrypted integer 32 values for all the previously used keys
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries

     */

    public int[] encryptIntForSearch(final String datasetName, int plainInt, byte[] tweak)
       throws  ExecutionException {

      int[] ret = null;

      loadCache(datasetName);

      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canEncrypt()) {
        throw new RuntimeException("API Key does not have encrypt rights for dataset '" + datasetName + "'");
      }

      FFX_Ctx ctx = getCtx(dataset, null);
      int current_key_number = ctx.getKeyNumber();
      if (verbose) System.out.println("\n after getKeyNumber" + current_key_number);
      ret = new int[current_key_number + 1];

      for (int key = 0; key <= current_key_number; key++) {
        ret[key] = encryptIntPipeline(dataset, key, ffxCache, plainInt, tweak);
      }

      return ret;

    }

    private int encryptIntPipeline(final FFS_Record dataset, Integer keyNumber, FFXCache ffxCache, final int plainInt, byte[] tweak)
      throws ExecutionException {
        final String csu = "encryptIntPipelineAsync";

        DataTypeConfig cfg = null;
        boolean verbose = false;
        if (!dataset.getDataType().equals("integer"))
        {
            throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is not an 'integer' dataset.");
        }

        cfg = dataset.getDataTypeConfig();
        if (cfg == null) {
          throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is missing data_type_config.");
        }

        if (cfg.getSize() != 32) {
            throw new IllegalArgumentException("dataset '" + dataset.getName() + "'' does not have a 32-bit DataSize");
        }

        if (plainInt > cfg.getMaxInputIntValue())
        {
            throw new IllegalArgumentException("Integer '" + plainInt + "'  <= " + cfg.getMaxInputIntValue());
        }

        if (plainInt < cfg.getMinInputIntValue())
        {
            throw new IllegalArgumentException("Integer '" + plainInt + "'  >= " + cfg.getMinInputIntValue());
        }

        // convert to string and pad to min_input_length after the negative sign
        Boolean isNegative = plainInt < 0;
        String plainText = String.valueOf(Math.abs(plainInt));
        plainText = StringUtils.padLeft('0', dataset.getMinInputLength(), plainText);
        if (verbose) System.out.printf("%s   : %s plainInt: %d plainText: %s \n", csu, new java.util.Date(), plainInt, plainText);

        // encrypted output will contain base14 characters (0-9a-d)
        String cipherText = encryptPipeline(dataset, keyNumber, ffxCache, plainText, tweak);
        String tmp = StringUtils.convertRadix(cipherText, dataset.getOutputCharacterSet(), dataset.getInputCharacterSet(), true, false);
        if (verbose) System.out.printf("%s   : %s cipherText: %s tmp: %s \n", csu, new java.util.Date(), cipherText, tmp);


        int base10Int = (Integer.valueOf(StringUtils.convertRadix(cipherText, dataset.getOutputCharacterSet(), dataset.getInputCharacterSet(), true, false))).intValue();
        if (isNegative) {
          base10Int *= -1;
        }
        if (verbose) System.out.printf("%s   : %s cipherText: %s base10Int: %d \n", csu, new java.util.Date(), cipherText, base10Int);

        return base10Int;
    }

    private int decryptIntPipeline(final FFS_Record dataset, FFXCache ffxCache, final int cipherInt, byte[] tweak)
      throws ExecutionException {
        final String csu = "decryptIntPipeline";

        DataTypeConfig cfg = null;
        boolean verbose = false;
        if (!dataset.getDataType().equals("integer"))
        {
            throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is not an 'integer' dataset.");
        }

        cfg = dataset.getDataTypeConfig();
        if (cfg == null) {
          throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is missing data_type_config.");
        }

        if (cfg.getSize() != 32) {
            throw new IllegalArgumentException("dataset '" + dataset.getName() + "'' does not have a 32-bit DataSize");
        }
        if (verbose) System.out.printf("%s   : %s START: cipherInt: %d \n", csu, new java.util.Date(), cipherInt);

        // convert to string and pad to min_input_length after the negative sign
        Boolean isNegative = cipherInt < 0;
        String cipherText = StringUtils.convertRadix(String.valueOf(Math.abs(cipherInt)), dataset.getInputCharacterSet(), dataset.getOutputCharacterSet(), true, false);
        cipherText = StringUtils.padLeft('0', dataset.getMinInputLength(), cipherText);
        if (isNegative) {
          cipherText = "-" + cipherText;
        }

        // plain text output will contain base10 characters
        if (verbose) System.out.printf("%s   : %s cipherText: %s \n", csu, new java.util.Date(), cipherText);
        String plainText = decryptPipeline(dataset, ffxCache, cipherText, tweak);
        int plainInt = (Integer.valueOf(plainText)).intValue();
        if (verbose) System.out.printf("%s   : %s END: cipherInt: %d plainInt %d plainText: %s \n", csu, new java.util.Date(), cipherInt, plainInt, plainText);

        return plainInt;
    }

   /***
     * Encrypt a integer 64 value
     *
     * @param datasetName used to specify the dataset for encrypting the value
     * @param plainLong the value to encrypt
     * @param tweak the tweak to use when encrypting the data.  Pass empty array to use the dataset specific tweak
     *
     * @return the encrypted integer 64 value
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */

    public long encryptLong(final String datasetName, long plainLong, byte[] tweak)
      throws ExecutionException {
      final String csu = "encryptLong";

      Long ret = null;
      if (verbose) System.out.printf("%s   : %s  plainLong: '%d'\n",csu, new java.util.Date(), plainLong);

      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canEncrypt()) {
        throw new RuntimeException("API Key does not have encrypt rights for dataset '" + datasetName + "'");
      }
      ret = encryptLongPipeline(dataset, null, ffxCache, plainLong, tweak);
      return ret.longValue();
    }

    /***
     * Decrypt an integer 64 value
     *
     * @param datasetName used to specify the dataset for decrypting the value
     * @param cipherLong the value to decrypt
     * @param tweak the tweak to use when decrypting the data.  Must be the same tweak that was used to encrypt the value.
     * Pass empty array to use the dataset specific tweak
     *
     * @return the decrypted integer 64 value
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */
    public long decryptLong(final String datasetName, long cipherLong, byte[] tweak)
      throws ExecutionException {

      final String csu = "decryptLong";

      Long ret = null;
      if (verbose) System.out.printf("%s   : %s  cipherLong: '%d'\n",csu, new java.util.Date(), cipherLong);
      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canDecrypt()) {
        throw new RuntimeException("API Key does not have decrypt rights for dataset '" + datasetName + "'");
      }
      ret = decryptLongPipeline(dataset, ffxCache, cipherLong, tweak);
      return ret.longValue();
    }

    /***
     * Encrypt an integer 64 value for all previously used keys
     *
     * @param datasetName used to specify the dataset for encrypting the value
     * @param plainLong the value to encrypt
     * @param tweak the tweak to use when encrypting the data.  Pass empty array to use the dataset specific tweak
     *
     * @return an array of encrypted integer 64 values for all the previously used keys
     * @throws ExecutionException if errors are encountered during processing and are bubbled up from included libraries
     */

    public long[] encryptLongForSearch(final String datasetName, long plainLong, byte[] tweak)
    throws ExecutionException {

      long[] ret = null;

      loadCache(datasetName);

      FFS_Record dataset = getFFS(datasetName);
      if (!dataset.canEncrypt()) {
        throw new RuntimeException("API Key does not have encrypt rights for dataset '" + datasetName + "'");
      }

      FFX_Ctx ctx = getCtx(dataset, null);
      int current_key_number = ctx.getKeyNumber();
      if (verbose) System.out.println("\n after getKeyNumber" + current_key_number);
      ret = new long[current_key_number + 1];

      for (int key = 0; key <= current_key_number; key++) {
          ret[key] = encryptLongPipeline(dataset, key, ffxCache, plainLong, tweak);
        }

      return ret;
    }

    private long encryptLongPipeline(final FFS_Record dataset, Integer keyNumber, FFXCache ffxCache, final long plainLong, byte[] tweak)
      throws ExecutionException {
        final String csu = "encryptLongPipeline";

        DataTypeConfig cfg = null;
        boolean verbose = false;
        if (!dataset.getDataType().equals("integer"))
        {
            throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is not an 'integer' dataset.");
        }

        cfg = dataset.getDataTypeConfig();
        if (cfg == null) {
          throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is missing data_type_config.");
        }

        if (cfg.getSize() != 64) {
            throw new IllegalArgumentException("dataset '" + dataset.getName() + "'' does not have a 64-bit DataSize");
        }

        if (plainLong > cfg.getMaxInputIntValue())
        {
            throw new IllegalArgumentException("Long '" + plainLong + "'  <= " + cfg.getMaxInputIntValue());
        }

        if (plainLong < cfg.getMinInputIntValue())
        {
            throw new IllegalArgumentException("Long '" + plainLong + "'  >= " + cfg.getMinInputIntValue());
        }

        // convert to string and pad to min_input_length after the negative sign
        Boolean isNegative = plainLong < 0;
        String plainText = String.valueOf(Math.abs(plainLong));
        plainText = StringUtils.padLeft('0', dataset.getMinInputLength(), plainText);
        if (verbose) System.out.printf("%s   : %s plainLong: %d plainText: %s \n", csu, new java.util.Date(), plainLong, plainText);

        // encrypted output will contain base14 characters (0-9a-d)
        String cipherText = encryptPipeline(dataset, keyNumber, ffxCache, plainText, tweak);
        String tmp = StringUtils.convertRadix(cipherText, dataset.getOutputCharacterSet(), dataset.getInputCharacterSet(), true, false);
        if (verbose) System.out.printf("%s   : %s cipherText: %s tmp: %s \n", csu, new java.util.Date(), cipherText, tmp);


        long base10Long = (Long.valueOf(StringUtils.convertRadix(cipherText, dataset.getOutputCharacterSet(), dataset.getInputCharacterSet(), true, false))).longValue();
        if (isNegative) {
          base10Long *= -1;
        }
        if (verbose) System.out.printf("%s   : %s cipherText: %s base10Long: %d \n", csu, new java.util.Date(), cipherText, base10Long);

        return base10Long;
    }

    private long decryptLongPipeline(final FFS_Record dataset, FFXCache ffxCache, final long cipherLong, byte[] tweak)
      throws ExecutionException {
        final String csu = "decryptLongPipeline";

        DataTypeConfig cfg = null;
        boolean verbose = false;
        if (!dataset.getDataType().equals("integer"))
        {
            throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is not an 'integer' dataset.");
        }

        cfg = dataset.getDataTypeConfig();
        if (cfg == null) {
          throw new IllegalArgumentException(dataset.getDataType() + " dataset '" + dataset.getName() + "' is missing data_type_config.");
        }

        if (cfg.getSize() != 64) {
            throw new IllegalArgumentException("dataset '" + dataset.getName() + "'' does not have a 32-bit DataSize");
        }


        if (verbose) System.out.printf("%s   : %s  cipherLong(%d) Abs(%d)\n", csu, new java.util.Date(), cipherLong, Math.abs(cipherLong));
        // convert to string and pad to min_input_length after the negative sign
        Boolean isNegative = cipherLong < 0;
        String cipherText = StringUtils.convertRadix(String.valueOf(Math.abs(cipherLong)), dataset.getInputCharacterSet(), dataset.getOutputCharacterSet(), true, false);
        cipherText = StringUtils.padLeft('0', dataset.getMinInputLength(), cipherText);
        if (isNegative) {
          cipherText = "-" + cipherText;
        }

        // plain text output will contain base10 characters
        String plainText = decryptPipeline(dataset, ffxCache, cipherText, tweak);
        long plainLong = (Long.valueOf(plainText)).longValue();
        if (verbose) System.out.printf("%s   : %s cipherLong: %d plainLong %d plainText: %s \n", csu, new java.util.Date(), cipherLong, plainLong, plainText);

        return plainLong;
    }

}