package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.util.concurrent.ExecutionException;

import java.util.*;
import org.junit.rules.ExpectedException;



public class BillingTest
{


    @Test
    public void simple() {
      BillingEvent b = new BillingEvent("apikey","dataset","dataset_group", BillingEvents.BillingAction.ENCRYPT, BillingEvents.DatasetType.STRUCTURED, 0, 5);
      String s = b.serialize();
      String s2 = b.serialize(null);

      JsonElement element = (new JsonParser()).parse(s2);
      JsonObject obj = element.getAsJsonObject().getAsJsonObject("user_defined");
      assertNull(obj);
      assertEquals(s, s2);

      s2 = b.serialize("{}");
      element = (new JsonParser()).parse(s2);
      obj = element.getAsJsonObject().getAsJsonObject("user_defined");
      assertNotNull(obj);
      
      assertNotEquals(s, s2);
    }

    @Test
    public void simpleMeta() {
      BillingEvent b = new BillingEvent("apikey","dataset","dataset_group", BillingEvents.BillingAction.ENCRYPT, BillingEvents.DatasetType.STRUCTURED, 0, 5);
      String s = b.serialize("{ \"att_encryption_wrapper\" : true }");

      JsonObject element = (new JsonParser()).parse(s).getAsJsonObject();
      JsonObject obj = element.getAsJsonObject("user_defined");
      assertNotNull(obj);
      assertTrue(obj.getAsJsonPrimitive("att_encryption_wrapper").getAsBoolean());
      System.out.println(s);
    }


    @Test
    public void billingEvents() {
      UbiqConfiguration cfg = UbiqFactory.defaultConfiguration();
      BillingEvents b = new BillingEvents(cfg);
      b.addBillingEvent("apikey","dataset","dataset_group", BillingEvents.BillingAction.ENCRYPT, BillingEvents.DatasetType.STRUCTURED, 0, 5);
      b.addBillingEvent("apikey","dataset","dataset_group", BillingEvents.BillingAction.ENCRYPT, BillingEvents.DatasetType.STRUCTURED, 0, 10);
      b.addBillingEvent("apikey","dataset","dataset_group", BillingEvents.BillingAction.DECRYPT, BillingEvents.DatasetType.STRUCTURED, 0, 25);

      String s = b.getAndResetSerializedData();
      System.out.println(s);

    }

    @Test
    public void billingEventsMeta() {
      UbiqConfiguration cfg = UbiqFactory.defaultConfiguration();
      BillingEvents b = new BillingEvents(cfg);

      b.addUserDefinedMetadata("{ \"att_encryption_wrapper\" : true }");

      b.addBillingEvent("apikey","dataset","dataset_group", BillingEvents.BillingAction.ENCRYPT, BillingEvents.DatasetType.STRUCTURED, 0, 5);
      b.addBillingEvent("apikey","dataset","dataset_group", BillingEvents.BillingAction.ENCRYPT, BillingEvents.DatasetType.STRUCTURED, 0, 10);
      b.addBillingEvent("apikey","dataset","dataset_group", BillingEvents.BillingAction.DECRYPT, BillingEvents.DatasetType.STRUCTURED, 0, 25);

      String s = b.getAndResetSerializedData();
      System.out.println(s);

    }

    @Test
    public void billingEventsChecks() {
      UbiqConfiguration cfg = UbiqFactory.defaultConfiguration();
      BillingEvents b = new BillingEvents(cfg);

      Throwable exception = assertThrows(IllegalArgumentException.class, () -> b.addUserDefinedMetadata(""));
      exception = assertThrows(IllegalArgumentException.class, () -> b.addUserDefinedMetadata(null));
      exception = assertThrows(IllegalArgumentException.class, () -> b.addUserDefinedMetadata("null"));
      b.addUserDefinedMetadata("{\"long\" : \"" + String.format("%-5s", "a") + "\"}"); // To prove short format works
      exception = assertThrows(IllegalArgumentException.class, () -> b.addUserDefinedMetadata("{\"long\" : \"" + String.format("%-1025s", "a") + "\"}"));

    }

  


}
