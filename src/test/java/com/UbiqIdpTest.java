package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;
import java.io.IOException;

import java.util.Arrays;
import com.ubiqsecurity.UbiqFactory;

import java.util.concurrent.ExecutionException;


import java.util.*;
import org.junit.rules.ExpectedException;
import java.io.File;
import java.nio.file.Files;
import java.io.FileWriter;

import com.google.gson.JsonObject;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.nio.file.Paths;

public class UbiqIdpTest {
  
  private final String UBIQ_UNITTEST_IDP_TYPE = "UBIQ_UNITTEST_IDP_TYPE";
  private final String UBIQ_UNITTEST_IDP_CUSTOMER_ID = "UBIQ_UNITTEST_IDP_CUSTOMER_ID";
  private final String UBIQ_UNITTEST_IDP_TOKEN_ENDPOINT_URL = "UBIQ_UNITTEST_IDP_TOKEN_ENDPOINT_URL";
  private final String UBIQ_UNITTEST_IDP_TENANT_ID = "UBIQ_UNITTEST_IDP_TENANT_ID";
  private final String UBIQ_UNITTEST_IDP_CLIENT_SECRET = "UBIQ_UNITTEST_IDP_CLIENT_SECRET";

  private final String UBIQ_UNITTEST_IDP_SERVER = "UBIQ_UNITTEST_IDP_SERVER";
  private final String UBIQ_UNITTEST_IDP_USERNAME = "UBIQ_UNITTEST_IDP_USERNAME";
  private final String UBIQ_UNITTEST_IDP_PASSWORD = "UBIQ_UNITTEST_IDP_PASSWORD";

  private String writeConfigFile() throws IOException {
    File file;
    file = File.createTempFile("temp", null);

    FileWriter myWriter = new FileWriter(file.getAbsolutePath());

    JsonObject obj = new JsonObject();
    JsonObject idp = new JsonObject();

    idp.addProperty("provider", System.getenv(UBIQ_UNITTEST_IDP_TYPE));
    idp.addProperty("ubiq_customer_id", System.getenv(UBIQ_UNITTEST_IDP_CUSTOMER_ID));
    idp.addProperty("idp_token_endpoint_url", System.getenv(UBIQ_UNITTEST_IDP_TOKEN_ENDPOINT_URL));
    idp.addProperty("idp_tenant_id", System.getenv(UBIQ_UNITTEST_IDP_TENANT_ID));
    idp.addProperty("idp_client_secret", System.getenv(UBIQ_UNITTEST_IDP_CLIENT_SECRET));

    obj.add("idp", idp);
    
    Gson gson = new GsonBuilder().setPrettyPrinting().create();

    myWriter.write(gson.toJson(obj));//obj.toString());
    myWriter.close();

    return file.getAbsolutePath();
  }

  private String writeCredentialsFile() throws IOException {
    File file;
    file = File.createTempFile("temp", null);

    FileWriter myWriter = new FileWriter(file.getAbsolutePath());

    myWriter.write("[default]\n");
    myWriter.write(String.format("SERVER=%s\n", System.getenv(UBIQ_UNITTEST_IDP_SERVER)));
    myWriter.write(String.format("IDP_USERNAME=%s\n", System.getenv(UBIQ_UNITTEST_IDP_USERNAME)));
    myWriter.write(String.format("IDP_PASSWORD=%s\n", System.getenv(UBIQ_UNITTEST_IDP_PASSWORD)));
    myWriter.close();
      
    return file.getAbsolutePath();
  }

@Test
public void encrypt_SSN() {
  try {

    String credentials = writeCredentialsFile();
    String config = writeConfigFile();

    UbiqCredentials ubiqCredentials = UbiqFactory.readCredentialsFromFile(credentials, "default");
    UbiqConfiguration ubiqConfig = UbiqFactory.readConfigurationFromFile(config);

    if (ubiqConfig != null) {
      ubiqCredentials.init(ubiqConfig);
    }

    String plainText = "123-45-6789";
    String dataset_name = "SSN";

    try (UbiqStructuredEncryptDecrypt ubiqEncryptDecrypt = new UbiqStructuredEncryptDecrypt(ubiqCredentials)) {
        String result = ubiqEncryptDecrypt.encrypt(dataset_name, plainText, null);
        String pt = ubiqEncryptDecrypt.decrypt(dataset_name, result, null);

        assertEquals(plainText, pt);

        String[] cts = ubiqEncryptDecrypt.encryptForSearch(dataset_name, plainText, null);

        Boolean found = false;
        for (String c : cts) {
          if (result.equals(c)) {
            found = true;
          }
        }
        assertEquals(found, true);

    }

    byte[] pt = "this is a test".getBytes();
    byte[] ct = UbiqEncrypt.encrypt(ubiqCredentials, pt);
    byte[] pt2 = UbiqDecrypt.decrypt(ubiqCredentials, ct);

    assertArrayEquals(pt, pt2);









    Files.deleteIfExists(Paths.get(credentials));
    Files.deleteIfExists(Paths.get(config));

  } catch (Exception e) {
    System.out.println("Error: " + e.getMessage());
    fail(e.toString());
  }
  

}

}
