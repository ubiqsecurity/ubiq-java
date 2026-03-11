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
import java.util.ArrayList;
import java.util.List;
import java.util.Collections;
import java.util.Comparator;
import java.io.IOException;
import java.net.URISyntaxException;


class FFS  {
    private boolean verbose = false;
    public LoadingCache<String, FFS_Record> FFSCache; // FFS Name / Contents of the FFS from the server

    protected enum PASSTHROUGH_RULES_TYPE {
      NONE,
      PASSTHROUGH,
      PREFIX,
      SUFFIX
    }

    /**
     * FFS constructor
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     *
     */
    public FFS(UbiqWebServices ubiqWebServices, UbiqConfiguration configuration) {

        //create a cache for FFS based on the <encryption_algorithm>-<name>
        FFSCache =
            CacheBuilder.newBuilder()
            .maximumSize(100)                               // maximum 100 records can be cached
            .expireAfterWrite(configuration.getKeyCacheTtlSeconds(), TimeUnit.SECONDS)
            .build(new CacheLoader<String, FFS_Record>() {  // build the cacheloader
                @Override
                public FFS_Record load(String ffs_name) {
                   //make the expensive call
                   FFS_Record ret = null;
                   try {
                    // Cachebuilder catches checked and unchecked exceptions and casts them
                    // to specific types.  To avoid this issue, we will simply convert to a Runtime Exception
                    ret = getFFSFromCloudAPI(ubiqWebServices, ffs_name);   // FFS_Name - returns the contents of the FFS
                   } catch (RuntimeException e) {
                    throw e;
                   } catch (Exception e) {
                    throw new RuntimeException(e.getMessage(), e.getCause());
                   }
                   return ret;
                }
         });
    }


    /**
    * Clears the FFS cache
    *
    */
    public void invalidateAllCache() {
        FFSCache.invalidateAll();
    }

    /**
     * Called when FFS data is not in cache and need to make remote call to the server
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param cachingKey  Format <AccessKeyId>-<FFS Name> used as the record locator
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     *
     */
    private  FFS_Record getFFSFromCloudAPI(UbiqWebServices ubiqWebServices, String ffs_name)
    throws java.io.IOException, java.net.URISyntaxException, java.security.NoSuchAlgorithmException, java.lang.InterruptedException, java.security.InvalidKeyException {

        if (verbose) System.out.println("\n****** PERFORMING EXPENSIVE CALL ----- getFFSFromCloudAPI for ffs_name: " + ffs_name);

        FFS_Record ffsRecord;
        ffsRecord= ubiqWebServices.getFFSDefinition(ffs_name);

        Gson gson = new Gson();

        if (verbose) System.out.println(gson.toJson(ffsRecord));

        return ffsRecord;
    }
}


