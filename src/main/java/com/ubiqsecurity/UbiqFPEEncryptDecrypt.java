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
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.*;
import java.util.List;

/**
 * Provides Format Preserving Encryption capability for a variety of field format models (aka FFS models)
 * This capability must be enabled and configured with FFS models on a per-user account basis.
 */
@Deprecated
public class UbiqFPEEncryptDecrypt implements AutoCloseable {
    private UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt;

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
      ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials, ubiqConfiguration);
    }


    /**
     * Runs when object is going away. Clears the caches, stops
     * scheduler, and runs through any remaining bills left in the transaction list.
     *
     */
    public void close() {
      ubiqEncryptDecrypt.close();
      ubiqEncryptDecrypt = null;
    }



    /**
    * Clears the encryption key and FFS model cache
    *
    */
    public void clearKeyCache() {
      ubiqEncryptDecrypt.clearKeyCache();
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
          return ubiqEncryptDecrypt.encrypt(ffs_name, PlainText, tweak);
    }


    public String[] encryptForSearch(final String ffs_name, final String PlainText, byte[] tweak)
        throws IllegalStateException  {
          return ubiqEncryptDecrypt.encryptForSearch(ffs_name, PlainText, tweak);
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
          return ubiqEncryptDecrypt.decrypt(ffs_name, CipherText, tweak);

    }



    /**
     * Performs structured encryption but does not take advantage of key caching
     *
     * @param ubiqCredentials  the credentials necessary to authenticate and authorize with the Ubiq platform
     * @param ffs_name the Dataset name
     * @param PlainText the plain text string to be encrypted
     * @param tweak  an optional tweak to provide additional input to the encryption algorithm
     *
     * @return the encrypted string
     *
     * @throws IOException  If an input or output exception occurred
     * @throws IllegalStateException if the object have not been initialized correctly
     * @throws InvalidCipherTextException if an exception was encountered while encrypting the data
     * @deprecated use instance method encryptFPE() instead.  
     */
    @Deprecated
    public static String encryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String PlainText, byte[] tweak)
            throws IOException, InvalidCipherTextException, IllegalStateException {

      try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
          return ubiqEncryptDecrypt.encrypt(ffs_name, PlainText, tweak);
      }
    }

   /**
     * Performs structured decryption but does not take advantage of key caching
     *
     * @param ubiqCredentials  the credentials necessary to authenticate and authorize with the Ubiq platform
     * @param ffs_name the Dataset name
     * @param CipherText the cipher text string to be decrypted
     * @param tweak  an optional tweak to provide additional input to the decryption algorithm
     *
     * @return the plain text string
     *
     * @throws IOException  If an input or output exception occurred
     * @throws IllegalStateException if the object have not been initialized correctly
     * @throws InvalidCipherTextException if an exception was encountered while decrypting the data
     * @deprecated use instance method decryptFPE() instead.  
     */
    // @Deprecated
    public static String decryptFPE(UbiqCredentials ubiqCredentials, String ffs_name, String CipherText, byte[] tweak)
            throws IOException, InvalidCipherTextException, IllegalStateException {

      try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
          return ubiqEncryptDecrypt.decrypt(ffs_name, CipherText, tweak);
      }
    }

   /**
     * Performs structured decryption but does not take advantage of key caching
     *
     * @param ubiqCredentials  the credentials necessary to authenticate and authorize with the Ubiq platform
     * @param ffs_name the Dataset name
     * @param PlainText the plain text string to be encrypted
     * @param tweak  an optional tweak to provide additional input to the encryption algorithm
     *
     * @return An array of cipher text strings for the various rotated keys
     *
     * @throws IOException  If an input or output exception occurred
     * @throws IllegalStateException if the object have not been initialized correctly
     * @throws InvalidCipherTextException if an exception was encountered while decrypting the data
     * @deprecated use instance method encryptForSearch() instead.  
     */
    @Deprecated
     public static String[] encryptForSearch(UbiqCredentials ubiqCredentials, String ffs_name, String PlainText, byte[] tweak)
            throws IOException, InvalidCipherTextException, IllegalStateException {

      try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
          return ubiqEncryptDecrypt.encryptForSearch(ffs_name, PlainText, tweak);
      }
    }

    public void addReportingUserDefinedMetadata(String jsonString) {
      ubiqEncryptDecrypt.addReportingUserDefinedMetadata(jsonString);
    }

    public String getCopyOfUsage() {
    return ubiqEncryptDecrypt.getCopyOfUsage();
    }

    public String loadDatasetDef(final String dataset_def) {
      return ubiqEncryptDecrypt.loadDatasetDef(dataset_def);
    }

    public String loadDataset(final String dataset_def) {
      return ubiqEncryptDecrypt.loadDataset(dataset_def);
    }

    public void loadKeyDef(final String dataset_name, final String key_def, final Boolean current_key_flag) {
      ubiqEncryptDecrypt.loadKeyDef(dataset_name, key_def, current_key_flag);
    }

  }
