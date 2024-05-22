package com.ubiqsecurity;

import com.google.gson.Gson;
import com.google.common.base.MoreObjects;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;
import com.google.gson.annotations.SerializedName;
import com.google.gson.*;
import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;
import java.util.Base64;
import java.security.SecureRandom;

class LoadSearchKeys  {
    private static boolean verbose= false;

    // Load the encryption keys

    private static String print(byte[] bytes) {
      StringBuilder sb = new StringBuilder();
      sb.append("[ ");
      for (byte b : bytes) {
          sb.append(String.format("0x%02X ", b));
      }
      sb.append("]");
      return sb.toString();
   }
  

    public static void loadKeys(
      UbiqCredentials ubiqCredentials,
      UbiqWebServices ubiqWebServices,
      FFS ffs,
      FFXCache ffxCache,
      String ffs_name) throws Exception {
      String csu = "loadKeys";

      // Call the web services to get the search keys

      if (verbose) System.out.println(String.format("%s started  \n", csu));

      JsonObject fpe_search_keys = ubiqWebServices.getFpeDefKeys(ffs_name);

      if (verbose) System.out.println(String.format("%s before top_level  \n", csu));

      JsonObject top_level = fpe_search_keys.get(ffs_name).getAsJsonObject();

      if (verbose) System.out.println(String.format("%s before dataset  \n", csu));
      
      JsonObject dataset = top_level.get("ffs").getAsJsonObject();

      // If Dataset (FFS) is not already in the FFS Cache, add it.

     FFS_Record ffsRecord = FFS_Record.parse(dataset);

      if (verbose) System.out.println(String.format("%s ffsRecord %s  \n", csu, (new Gson()).toJson(ffsRecord)));

      if (verbose) System.out.println(String.format("%s tweak %s  \n", csu, ffsRecord.getTweak()));
      if (!ffs.FFSCache.asMap().containsKey(ffs_name)) {
        if (verbose) System.out.println(String.format("%s FFSCache miss %s  \n", csu, ffs_name));
        ffs.FFSCache.put(ffs_name, ffsRecord);
      } else {
        if (verbose) System.out.println(String.format("%s FFSCache HIT %s  \n", csu, ffs_name));
      }

      if (verbose) System.out.println(String.format("%s before encrypted_private_key  \n", csu));
      String encrypted_private_key = top_level.get("encrypted_private_key").getAsString();
      
      if (verbose) System.out.println(String.format("%s encrypted_private_key  %s\n", csu, encrypted_private_key));

      Integer current_key_number =top_level.get("current_key_number").getAsInt();
      if (verbose) System.out.println(String.format("%s current_key_number  %d\n", csu, current_key_number));

      JsonArray keys = top_level.get("keys").getAsJsonArray();

      if (verbose) System.out.println(String.format("%s arrayCount  %d\n", csu, keys.size()));
      
      // Loop over the keys.  If not alraedy

      for (int i = 0; i < keys.size(); i++) {
        byte[] tweak = null;

        FFS_KeyId keyId = new FFS_KeyId(ffsRecord, i);

        if (!ffxCache.FFXCache.asMap().containsKey(keyId)) {
          if (verbose) System.out.println(String.format("%s  FFXCache does not contain key for %d\n", csu, i));
          byte[] key = ubiqWebServices.getUnwrappedKey(encrypted_private_key, keys.get(i).getAsString());

          if (verbose) System.out.println(String.format("%s byte[] key %d\n", csu, key.length));

          FFX_Ctx ctx = new FFX_Ctx();
          if (keyId.ffs.getTweakSource().equals("constant")) {
            if (verbose) System.out.println(String.format("%s  tweak source %s\n", csu,keyId.ffs.getTweakSource()));
            String s = keyId.ffs.getTweak();
            if (verbose) System.out.println(String.format("%s  tweak  %s\n", csu, s));

            if (verbose) System.out.println(String.format("%s getting tweak %d\n", csu, keyId.ffs.getTweak().length()));
            tweak= Base64.getDecoder().decode(keyId.ffs.getTweak());
            if (verbose) System.out.println(String.format("%s byte[] tweak %d\n", csu, tweak.length));
          }

          if (verbose) System.out.println(String.format("%s FFX_Ctx ctx %s\n", csu, "after"));

          ctx.setFF1(new FF1(key, tweak, 
                keyId.ffs.getMinTweakLength(), 
                keyId.ffs.getMaxTweakLength(), 
                keyId.ffs.getInputCharacterSet().length(), keyId.ffs.getInputCharacterSet()), 
                i);

          ffxCache.FFXCache.put(keyId, ctx);
          if (verbose) System.out.println(String.format("%s ffxCache.FFXCache.put(keyId, ctx); %s\n", csu, "after"));

          if (i == current_key_number) {
            FFS_KeyId currentKey = new FFS_KeyId(ffsRecord, null);
            if (!ffxCache.FFXCache.asMap().containsKey(currentKey)) {
              if (verbose) System.out.println(String.format("%s  FFXCache does not contain current_key_number %d\n", csu, current_key_number));

              FFX_Ctx ctx2 = new FFX_Ctx();
              if (currentKey.ffs.getTweakSource().equals("constant")) {
                tweak= Base64.getDecoder().decode(currentKey.ffs.getTweak());
              }
    
              ctx2.setFF1(new FF1(key, tweak, 
                    currentKey.ffs.getMinTweakLength(), 
                    currentKey.ffs.getMaxTweakLength(), 
                    currentKey.ffs.getInputCharacterSet().length(), currentKey.ffs.getInputCharacterSet()), 
                    i);

              ffxCache.FFXCache.put(currentKey, ctx2);
            } else {
              if (verbose) System.out.println(String.format("%s  FFXCache contains current_key_number %d\n", csu, current_key_number));

            }
          }
        } else {
          if (verbose) System.out.println(String.format("%s  FFXCache already exists for %d\n", csu, i));

        }
      }
    }


    public static String loadKeys(
      UbiqCredentials ubiqCredentials,
      UbiqWebServices ubiqWebServices,
      JsonObject fpe_search_keys,
      FFS ffs,
      FFXCache ffxCache)  throws Exception {
      String csu = "loadKeys";

      // Call the web services to get the search keys

      if (verbose) System.out.println(String.format("%s started  \n", csu));

      // JsonObject fpe_search_keys = ubiqWebServices.getFpeDefKeys(ffs_name);

      if (verbose) System.out.println(String.format("%s before top_level  \n", csu));

      // JsonObject top_level = fpe_search_keys.get(dataset_name).getAsJsonObject();

      if (verbose) System.out.println(String.format("%s before dataset  \n", csu));
      
      JsonObject dataset = fpe_search_keys.get("ffs").getAsJsonObject();
      String dataset_name = dataset.get("name").getAsString();

      // If Dataset (FFS) is not already in the FFS Cache, add it.

      FFS_Record ffsRecord = FFS_Record.parse(dataset);

      if (verbose) System.out.println(String.format("%s ffsRecord %s  \n", csu, (new Gson()).toJson(ffsRecord)));

      if (verbose) System.out.println(String.format("%s tweak %s  \n", csu, ffsRecord.getTweak()));
      if (!ffs.FFSCache.asMap().containsKey(dataset_name)) {
        if (verbose) System.out.println(String.format("%s FFSCache miss %s  \n", csu, dataset_name));
        ffs.FFSCache.put(dataset_name, ffsRecord);
      } else {
        if (verbose) System.out.println(String.format("%s FFSCache HIT %s  \n", csu, dataset_name));
      }

      if (verbose) System.out.println(String.format("%s before encrypted_private_key  \n", csu));
      String encrypted_private_key = fpe_search_keys.get("encrypted_private_key").getAsString();
      
      if (verbose) System.out.println(String.format("%s encrypted_private_key  %s\n", csu, encrypted_private_key));

      Integer current_key_number =fpe_search_keys.get("current_key_number").getAsInt();
      if (verbose) System.out.println(String.format("%s current_key_number  %d\n", csu, current_key_number));

      JsonArray keys = fpe_search_keys.get("keys").getAsJsonArray();

      if (verbose) System.out.println(String.format("%s arrayCount  %d\n", csu, keys.size()));
      
      // Loop over the keys.  If not alraedy

      for (int i = 0; i < keys.size(); i++) {
        byte[] tweak = null;

        FFS_KeyId keyId = new FFS_KeyId(ffsRecord, i);

        if (!ffxCache.FFXCache.asMap().containsKey(keyId)) {
          if (verbose) System.out.println(String.format("%s  FFXCache does not contain key for %d\n", csu, i));
          byte[] key = ubiqWebServices.getUnwrappedKey(encrypted_private_key, keys.get(i).getAsString());

          if (verbose) System.out.println(String.format("%s byte[] key %d\n", csu, key.length));

          FFX_Ctx ctx = new FFX_Ctx();
          if (keyId.ffs.getTweakSource().equals("constant")) {
            if (verbose) System.out.println(String.format("%s  tweak source %s\n", csu,keyId.ffs.getTweakSource()));
            String s = keyId.ffs.getTweak();
            if (verbose) System.out.println(String.format("%s  tweak  %s\n", csu, s));

            if (verbose) System.out.println(String.format("%s getting tweak %d\n", csu, keyId.ffs.getTweak().length()));
            tweak= Base64.getDecoder().decode(keyId.ffs.getTweak());
            if (verbose) System.out.println(String.format("%s byte[] tweak %d\n", csu, tweak.length));
          }

          if (verbose) System.out.println(String.format("%s FFX_Ctx ctx %s\n", csu, "after"));

          ctx.setFF1(new FF1(key, tweak, 
                keyId.ffs.getMinTweakLength(), 
                keyId.ffs.getMaxTweakLength(), 
                keyId.ffs.getInputCharacterSet().length(), keyId.ffs.getInputCharacterSet()), 
                i);

          ffxCache.FFXCache.put(keyId, ctx);
          if (verbose) System.out.println(String.format("%s ffxCache.FFXCache.put(keyId, ctx); %s\n", csu, "after"));

          if (i == current_key_number) {
            FFS_KeyId currentKey = new FFS_KeyId(ffsRecord, null);
            if (!ffxCache.FFXCache.asMap().containsKey(currentKey)) {
              if (verbose) System.out.println(String.format("%s  FFXCache does not contain current_key_number %d\n", csu, current_key_number));

              FFX_Ctx ctx2 = new FFX_Ctx();
              if (currentKey.ffs.getTweakSource().equals("constant")) {
                tweak= Base64.getDecoder().decode(currentKey.ffs.getTweak());
              }
    
              ctx2.setFF1(new FF1(key, tweak, 
                    currentKey.ffs.getMinTweakLength(), 
                    currentKey.ffs.getMaxTweakLength(), 
                    currentKey.ffs.getInputCharacterSet().length(), currentKey.ffs.getInputCharacterSet()), 
                    i);

              ffxCache.FFXCache.put(currentKey, ctx2);
            } else {
              if (verbose) System.out.println(String.format("%s  FFXCache contains current_key_number %d\n", csu, current_key_number));

            }
          }
        } else {
          if (verbose) System.out.println(String.format("%s  FFXCache already exists for %d\n", csu, i));

        }
      }
      return dataset_name;
    }

    public static String loadDataset(
      UbiqCredentials ubiqCredentials,
      UbiqWebServices   ubiqWebServices,
      JsonObject dataset,
      FFS ffs)  throws Exception {
        String csu = "loadDataset";

        String dataset_name = dataset.get("name").getAsString();

        if (!ffs.FFSCache.asMap().containsKey(dataset_name)) {
          if (verbose) System.out.println(String.format("%s FFSCache miss %s  \n", csu, dataset_name));

          FFS_Record ffsRecord = FFS_Record.parse(dataset);
          ffs.FFSCache.put(dataset_name, ffsRecord);
        } else {
          if (verbose) System.out.println(String.format("%s FFSCache HIT %s  \n", csu, dataset_name));
        }
        return dataset_name;
    }

    private static FFX_Ctx makeCtx(FFS_Record ffsRecord, byte[] key, Integer key_number) {
      FFX_Ctx ctx = new FFX_Ctx();
      byte[] tweak = null;

      if (ffsRecord.getTweakSource().equals("constant")) {
        tweak= Base64.getDecoder().decode(ffsRecord.getTweak());
      }

      switch(ffsRecord.getEncryptionAlgorithm()) {
        case "FF1":
            if (verbose) System.out.println("    twkmin= " + ffsRecord.getMinTweakLength() + "    twkmax= " + ffsRecord.getMaxTweakLength() +   "    tweak.length= " + ffsRecord.getTweak().length() +   "    key.length= " + key.length );
            ctx.setFF1(new FF1(key, tweak,
            ffsRecord.getMinTweakLength(),
            ffsRecord.getMaxTweakLength(),
            ffsRecord.getInputCharacterSet().length(), ffsRecord.getInputCharacterSet()),
            key_number);
        break;
        case "FF3_1":
            ctx.setFF3_1(new FF3_1(key, 
              tweak,
              ffsRecord.getInputCharacterSet().length(), ffsRecord.getInputCharacterSet()),
              key_number);
        break;
        default:
            throw new RuntimeException("Unknown FPE Algorithm: " + ffsRecord.getEncryptionAlgorithm());
      }
      return ctx;
    }

    public static void loadKeyDef(
      UbiqCredentials ubiqCredentials,
      UbiqWebServices ubiqWebServices,
      JsonObject key_data,
      Boolean current_key_flag,
      String dataset_name,
      FFS ffs,
      FFXCache ffxCache) {
        String csu = "loadKeyDef";
        String unwrapped_data_key = null;
        JsonObject encrypted_data_key = null;

        String encrypted_private_key = key_data.get("encrypted_private_key").getAsString();

        Integer key_number = key_data.get("key_number").getAsInt();
        String wrapped_data_key = key_data.get("wrapped_data_key").getAsString();
        
        JsonElement obj = key_data.get("decrypted_data_key");
        if (obj != null) {
          // Base 64 version of the decrypted data key
          unwrapped_data_key = obj.getAsString();
        }
        obj = key_data.get("encrypted_data_key");
        if (obj != null) {
          // Base 64 version of the data key encrypted using the SECRET_CRYPTO_ACCESS_KEY
          
          encrypted_data_key = obj.getAsJsonObject();
        }
        byte[] key = null;

        if (unwrapped_data_key != null) {
          key = Base64.getDecoder().decode(unwrapped_data_key);
          
        } else if (encrypted_data_key != null) {
          key = Base64.getDecoder().decode(decryptKey(encrypted_data_key, ubiqCredentials.getSecretCryptoAccessKey()));
        } else {
          key = ubiqWebServices.getUnwrappedKey(encrypted_private_key, wrapped_data_key);
          // throw new IllegalStateException("Trying to decrypt data key");

        }

        FFS_Record ffsRecord = ffs.FFSCache.asMap().get(dataset_name);

        // For Decrypt
        FFS_KeyId keyId = new FFS_KeyId(ffsRecord, key_number);
        if (!ffxCache.FFXCache.asMap().containsKey(keyId)) {
          FFX_Ctx ctx= makeCtx(ffsRecord, key, key_number);
          ffxCache.FFXCache.put(keyId, ctx);
          if (verbose) System.out.println(String.format("%s FFXCache MISS %s %d \n", csu, dataset_name, key_number));
        } else {
          if (verbose) System.out.println(String.format("%s FFXCache HIT %s %d \n", csu, dataset_name, key_number));
        }
        // For Encrypt
        if (current_key_flag) {
          FFS_KeyId nullKeyId = new FFS_KeyId(ffsRecord, null);
          if (!ffxCache.FFXCache.asMap().containsKey(nullKeyId)) {
            FFX_Ctx ctx= makeCtx(ffsRecord, key, key_number);
            ffxCache.FFXCache.put(nullKeyId, ctx);
            if (verbose) System.out.println(String.format("%s FFXCache MISS %s %d \n", csu, dataset_name, key_number));
          } else {
            if (verbose) System.out.println(String.format("%s FFXCache HIT %s %d \n", csu, dataset_name, key_number));
          }
        }
    }

    // Base 64 encoded string of decrypted data key
    static String unwrapKey(
      UbiqWebServices ubiqWebServices,
      JsonObject key_data) {
      String csu = "unwrapKey";

      String encrypted_private_key = key_data.get("encrypted_private_key").getAsString();
      String wrapped_data_key = key_data.get("wrapped_data_key").getAsString();

      byte[] key = ubiqWebServices.getUnwrappedKey(encrypted_private_key, wrapped_data_key);
      return new String(Base64.getEncoder().encode(key));
    }

    static byte[] decryptKey(
      final JsonObject data, final String encryption_key) {
      byte[] decrypted_data = null;
      try {

        // System.out.println("data: " + data);
        System.out.println("encryption_key: " + encryption_key);

        AlgorithmInfo alg = new AlgorithmInfo(data.get("alg").getAsString());
        byte[] initVector = Base64.getDecoder().decode(data.get("iv").getAsString());
        byte[] encrypted_data = Base64.getDecoder().decode(data.get("encrypted_data").getAsString());
        byte[] key = Base64.getDecoder().decode(encryption_key);
        byte[] empty = null;

        System.out.println("alg: " + data.get("alg").getAsString());

        if (key.length > alg.getKeyLength()) {
          byte[] tmp = new byte[alg.getKeyLength()];
          System.arraycopy(key, 0, tmp, 0, alg.getKeyLength());
          key = tmp;
        }


        AesGcmBlockCipher aesGcmBlockCipher = new AesGcmBlockCipher(
          false, alg, key,
                  initVector, empty);


        byte[] data1 = aesGcmBlockCipher.update(encrypted_data, 0, encrypted_data.length);
        byte[] data2 = aesGcmBlockCipher.doFinal();
        aesGcmBlockCipher = null;

        decrypted_data = new byte[data1.length + data2.length];
        System.arraycopy(data1,0, decrypted_data, 0, data1.length);
        System.arraycopy(data2,0, decrypted_data, data1.length, data2.length);

        // if (aesGcmBlockCipher == null) throw new IllegalStateException(String.format("decrypted_data.length(%d) encrypted_data.getKeyLength(%d)", decrypted_data.length, encrypted_data.length));

      } catch (IllegalStateException e) {
        System.out.println(String.format("Exception: %s",e.getMessage()));
        throw e;
      }
        catch (Exception e) {

        }
      
      return decrypted_data;

    }

    static JsonObject encryptKey(
      final byte[] data_bytes, final String encryption_key) {
      String csu = "encryptKey";
      String algorithm_name = "AES-256-GCM";
      JsonObject results = new JsonObject();
      try {

      System.out.println("data: " + data_bytes.toString() + "  encryption_key: " + encryption_key);
      AlgorithmInfo alg = new AlgorithmInfo(algorithm_name);
      // byte[] data_bytes = data.getBytes();
      byte[] encrypted_data;
      byte[] empty = null;

      // Create IV
      byte[] initVector = new byte[alg.getInitVectorLength()];
      SecureRandom random = new SecureRandom();
      random.nextBytes(initVector);

      // Will be 33 characters.  Limit to alg.getKeyLength
      byte[] key = Base64.getDecoder().decode(encryption_key);
      System.out.println("tmp.length: " + key.length);

      System.out.println("secretCryptoAccessKey.toCharArray:" + encryption_key.toCharArray().length);

      if (key.length > alg.getKeyLength()) {
        byte[] tmp = new byte[alg.getKeyLength()];
        System.arraycopy(key, 0, tmp, 0, alg.getKeyLength());
        key = tmp;
      }

      // Encrypt data
      AesGcmBlockCipher aesGcmBlockCipher = new AesGcmBlockCipher(
        true, alg, key,
                initVector, empty);

      byte[] data1 = aesGcmBlockCipher.update(data_bytes, 0, data_bytes.length);
      byte[] data2 = aesGcmBlockCipher.doFinal();
      aesGcmBlockCipher = null;

      encrypted_data = new byte[data1.length + data2.length];
      System.arraycopy(data1,0, encrypted_data, 0, data1.length);
      System.arraycopy(data2,0, encrypted_data, data1.length, data2.length);

      // Create JSON of results

      
      results.addProperty("alg", alg.getName());
      results.addProperty("iv",  Base64.getEncoder().encodeToString(initVector));
      results.addProperty("encrypted_data", Base64.getEncoder().encodeToString(encrypted_data));

      } catch (Exception e) {
        System.out.println(String.format("Exception: %s",e.getMessage()));

      }
      // Return string
      return(results);

    }



}
