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
import java.util.Base64;

class LoadSearchKeys  {
    private static boolean verbose= false;

    // Load the encryption keys

    public static void loadKeys(
    UbiqCredentials ubiqCredentials,
    UbiqWebServices ubiqWebServices,
    FFS ffs,
    FFXCache ffxCache,
    String ffs_name) {
    String csu = "loadKeys";

      // Call the web services to get the search keys

      if (verbose) System.out.println(String.format("%s started  \n", csu));

      JsonObject fpe_search_keys = ubiqWebServices.getFpeDefKeys(ffs_name);

      if (verbose) System.out.println(String.format("%s before top_level  \n", csu));

      JsonObject top_level = fpe_search_keys.get(ffs_name).getAsJsonObject();

      if (verbose) System.out.println(String.format("%s before dataset  \n", csu));
      
      JsonObject dataset = top_level.get("ffs").getAsJsonObject();

      // If Dataset (FFS) is not already in the FFS Cache, add it.
      Gson gson = new Gson();
      FFS_Record ffsRecord = gson.fromJson(dataset, FFS_Record.class);

      if (verbose) System.out.println(String.format("%s ffsRecord %s  \n", csu, gson.toJson(ffsRecord)));


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
          if (keyId.ffs.getTweak_source().equals("constant")) {
            if (verbose) System.out.println(String.format("%s  tweak source %s\n", csu,keyId.ffs.getTweak_source()));
            String s = keyId.ffs.getTweak();
            if (verbose) System.out.println(String.format("%s  tweak  %s\n", csu, s));

            if (verbose) System.out.println(String.format("%s getting tweak %d\n", csu, keyId.ffs.getTweak().length()));
            tweak= Base64.getDecoder().decode(keyId.ffs.getTweak());
            if (verbose) System.out.println(String.format("%s byte[] tweak %d\n", csu, tweak.length));
          }

          if (verbose) System.out.println(String.format("%s FFX_Ctx ctx %s\n", csu, "after"));

          ctx.setFF1(new FF1(key, tweak, 
                keyId.ffs.getMin_tweak_length(), 
                keyId.ffs.getMax_tweak_length(), 
                keyId.ffs.getInput_character_set().length(), keyId.ffs.getInput_character_set()), 
                i);

          ffxCache.FFXCache.put(keyId, ctx);
          if (verbose) System.out.println(String.format("%s ffxCache.FFXCache.put(keyId, ctx); %s\n", csu, "after"));

          if (i == current_key_number) {
            FFS_KeyId currentKey = new FFS_KeyId(ffsRecord, null);
            if (!ffxCache.FFXCache.asMap().containsKey(currentKey)) {
              if (verbose) System.out.println(String.format("%s  FFXCache does not contain current_key_number %d\n", csu, current_key_number));

              FFX_Ctx ctx2 = new FFX_Ctx();
              if (currentKey.ffs.getTweak_source().equals("constant")) {
                tweak= Base64.getDecoder().decode(currentKey.ffs.getTweak());
              }
    
              ctx2.setFF1(new FF1(key, tweak, 
                    currentKey.ffs.getMin_tweak_length(), 
                    currentKey.ffs.getMax_tweak_length(), 
                    currentKey.ffs.getInput_character_set().length(), currentKey.ffs.getInput_character_set()), 
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

}
