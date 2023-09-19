package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import com.beust.jcommander.JCommander;
import com.ubiqsecurity.UbiqCredentials;
import com.ubiqsecurity.UbiqFactory;
import com.ubiqsecurity.UbiqFPEEncryptDecrypt;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutionException;
import com.google.gson.annotations.SerializedName;
import com.google.gson.Gson;


public class TestHarness {

    static final String UBIQ_TEST_DATA_FILE = "UBIQ_TEST_DATA_FILE";
    static final String UBIQ_MAX_AVG_ENCRYPT = "UBIQ_MAX_AVG_ENCRYPT";
    static final String UBIQ_MAX_AVG_DECRYPT = "UBIQ_MAX_AVG_DECRYPT";
    static final String UBIQ_MAX_TOTAL_ENCRYPT = "UBIQ_MAX_TOTAL_ENCRYPT";
    static final String UBIQ_MAX_TOTAL_DECRYPT = "UBIQ_MAX_TOTAL_DECRYPT";

    private String getEnv(String existing_value, String env_name) {
        String ret = null;
        if (existing_value == null) {
          ret = System.getenv(env_name);
        }
        return ret;
    }

    private Long getEnv(Long existing_value, String env_name) {
        Long ret = null;
        if (existing_value == null) {
          String tmp = System.getenv(env_name);
          if (tmp != null) {
            ret = Long.parseLong(tmp);
          }
        }
        return ret;
    }

    public void runTest(String[] args) throws IOException, InterruptedException, IllegalStateException, ExecutionException{
        CmdArgs cmdArgs = new CmdArgs();
        JCommander jCommander = JCommander.
                newBuilder().
                addObject(cmdArgs).
                build();
        jCommander.parse(args);

        // check if --help was passed in args
        if (cmdArgs.help) {
            jCommander.usage();
            System.exit(0);
        }

        // making credentials object
        UbiqCredentials ubiqCredentials =  null;
        byte[] tweak = null;
        Boolean failed = false;

        if (cmdArgs.credentials != null) {
          ubiqCredentials = UbiqFactory.readCredentialsFromFile(cmdArgs.credentials, cmdArgs.profile);
        } else {
           ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
        }

        cmdArgs.inputFileName = getEnv(cmdArgs.inputFileName, UBIQ_TEST_DATA_FILE);
        cmdArgs.max_avg_encrypt = getEnv(cmdArgs.max_avg_encrypt, UBIQ_MAX_AVG_ENCRYPT);
        cmdArgs.max_avg_decrypt = getEnv(cmdArgs.max_avg_decrypt, UBIQ_MAX_AVG_DECRYPT);
        cmdArgs.max_total_encrypt = getEnv(cmdArgs.max_total_encrypt, UBIQ_MAX_TOTAL_ENCRYPT);
        cmdArgs.max_total_decrypt = getEnv(cmdArgs.max_total_decrypt, UBIQ_MAX_TOTAL_DECRYPT);

        UbiqFPEEncryptDecrypt ubiqEncryptDecrypt = new UbiqFPEEncryptDecrypt(ubiqCredentials);

        JsonArray test_data = JSONHelper.parseDataArrayFile(cmdArgs.inputFileName);

        List<DataRecord> errors = new ArrayList<DataRecord>();

        Gson gson = new Gson();
        Map<String, Long> dataset_counts = new HashMap<String, Long>();
        Map<String, Long> timing_encrypt = new HashMap<String, Long>();
        Map<String, Long> timing_decrypt = new HashMap<String, Long>();

        for (JsonElement obj : test_data) {
          DataRecord data = gson.fromJson(obj, DataRecord.class);

          if (!dataset_counts.containsKey(data.dataset)) {
            // Initialize the hashes for the datasets
            dataset_counts.put(data.dataset, (long) 0);
            timing_encrypt.put(data.dataset, (long) 0);
            timing_decrypt.put(data.dataset, (long) 0);
            String ct = ubiqEncryptDecrypt.encryptFPE(data.dataset, data.plaintext, tweak);
            String pt = ubiqEncryptDecrypt.decryptFPE(data.dataset, data.ciphertext, tweak);
            }

          Instant s = Instant.now();
          String ct = ubiqEncryptDecrypt.encryptFPE(data.dataset, data.plaintext, tweak);
          Instant e = Instant.now();
          String pt = ubiqEncryptDecrypt.decryptFPE(data.dataset, data.ciphertext, tweak);
          Instant d = Instant.now();

          timing_encrypt.put(data.dataset, timing_encrypt.get(data.dataset) + Duration.between(s, e).toNanos());
          timing_decrypt.put(data.dataset, timing_decrypt.get(data.dataset) + Duration.between(e, d).toNanos());
          dataset_counts.put(data.dataset, dataset_counts.get(data.dataset) + 1);

          if (!ct.equals(data.ciphertext) || !pt.equals(data.plaintext)) {
            System.out.println("Encrypt / Decrypt error");
            errors.add(data);
          }
        }


        ubiqEncryptDecrypt.close();

        // Set failed flag if there are encrypt / decrypt errors
        failed = (errors.size() != 0);

        if (errors.size() == 0) {
          System.out.println("All data validated");
          long encryptTotal = 0;
          long decryptTotal = 0;
          System.out.println("Encrypt records count: " + test_data.size() + ".  Times in (microseconds)");

          for (Map.Entry<String, Long> e : timing_encrypt.entrySet()) {
            System.out.println("\tDataset: " + e.getKey() + ", record count: " + dataset_counts.get(e.getKey()) + ", Average: " + e.getValue() / 1000 / dataset_counts.get(e.getKey()) + ", Total: " + e.getValue() / 1000);
            encryptTotal += e.getValue();
          }
          System.out.println("\t  Total: Average: " + encryptTotal / 1000 / test_data.size() + ", Total: " + encryptTotal / 1000);

          System.out.println("\nDecrypt records count: " + test_data.size() + ".  Times in (microseconds)");
          for (Map.Entry<String, Long> e : timing_decrypt.entrySet()) {
            System.out.println("\tDataset: " + e.getKey() +  ", record count: " + dataset_counts.get(e.getKey()) + ", Average: " + e.getValue() / 1000 /  dataset_counts.get(e.getKey()) + ", Total: " + e.getValue() / 1000);
            decryptTotal += e.getValue();
          }
          System.out.println("\t  Total: Average: " + decryptTotal / 1000 / test_data.size() + ", Total: " + decryptTotal / 1000);

          if (cmdArgs.max_avg_encrypt != null) {
            if (encryptTotal / 1000 / test_data.size() >= cmdArgs.max_avg_encrypt) {
              System.out.println("FAILED: Exceeded maximum allowed average encrypt threshold of " + cmdArgs.max_avg_encrypt + " microseconds");
              failed = true;
            } else {
              System.out.println("PASSED: Maximum allowed average encrypt threshold of " + cmdArgs.max_avg_encrypt + " microseconds");
            }
          } else {
              System.out.println("NOTE: No maximum allowed average encrypt threshold supplied");
          }

          if (cmdArgs.max_avg_decrypt != null) {
            if (encryptTotal / 1000 / test_data.size() >= cmdArgs.max_avg_decrypt) {
              System.out.println("FAILED: Exceeded maximum allowed average decrypt threshold of " + cmdArgs.max_avg_decrypt + " microseconds");
              failed = true;
            } else {
              System.out.println("PASSED: Maximum allowed average decrypt threshold of " + cmdArgs.max_avg_decrypt + " microseconds");
            }
          } else {
            System.out.println("NOTE: No maximum allowed average decrypt threshold supplied");
        }

          if (cmdArgs.max_total_encrypt != null) {
            if (decryptTotal / 1000  >= cmdArgs.max_total_encrypt) {
              System.out.println("FAILED: Exceeded maximum allowed total encrypt threshold of " + cmdArgs.max_total_encrypt + " microseconds");
              failed = true;
            } else {
              System.out.println("PASSED: Maximum allowed total encrypt threshold of " + cmdArgs.max_total_encrypt + " microseconds");
            }
          } else {
            System.out.println("NOTE: No maximum allowed total encrypt threshold supplied");
        }

          if (cmdArgs.max_total_decrypt != null) {
            if (encryptTotal / 1000 / test_data.size() >= cmdArgs.max_total_decrypt) {
              System.out.println("FAILED: Exceeded maximum allowed total decrypt threshold of " + cmdArgs.max_total_decrypt + " microseconds");
              failed = true;
            } else {
              System.out.println("PASSED: Maximum allowed total decrypt threshold of " + cmdArgs.max_total_decrypt + " microseconds");
            }
          } else {
            System.out.println("NOTE: No maximum allowed total decrypt threshold supplied");
        }
      }

      assertEquals(failed, false);

    }

    @Test
    public void runTestHarness() {
      String[] args = {};

      try {
        new TestHarness().runTest(args);
      }
      catch (Exception ex) {
        System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
        ex.printStackTrace();
        fail(ex.toString());
      }

    }

}


class DataRecord {
  public 
  @SerializedName("dataset")
  String dataset;

  @SerializedName("plaintext")
  String plaintext;

  @SerializedName("ciphertext")
  String ciphertext;

}




