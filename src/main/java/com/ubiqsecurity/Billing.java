package com.ubiqsecurity;

import com.google.common.util.concurrent.AbstractScheduledService;
import java.util.Date;
import java.time.Instant;
import java.util.concurrent.TimeUnit;
import java.util.HashMap;
import com.google.common.util.concurrent.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;



/**
 * Has Billing Events (usage) summed by unique key (dataset, API Key, dataset group, encrypt / decrypt)
 * These are then serialized into an array and sent to the server at an interval or when there are a 
 * predetermied quantity
 */
class BillingEvents {
    private static boolean verbose= false;
    private static HashMap<String, BillingEvent> billing_events;
    private static Lock lock;
    private static UbiqConfiguration ubiqConfiguration;

    static {
      lock = new ReentrantLock();;
      billing_events = new HashMap<String, BillingEvent>();
    }

    public enum BillingAction {
      ENCRYPT ("encrypt"), 
      DECRYPT ("decrypt");
    
      private final String value;
      
      BillingAction(String value) {
        this.value = value;
      }
    
      String to_s() {
        return value;
      }
    
    }

    public enum DatasetType {
      STRUCTURED ("structured"), 
      UNSTRUCTURED ("unstructured");
    
      private final String value;
      
      DatasetType(String value) {
        this.value = value;
      }
    
      String to_s() {
        return value;
      }
    
    }


    /**
     * Constructs a new list of bills and manage sending to the server when needed
     *
     */
    public BillingEvents (UbiqConfiguration ubiqConfiguration) {
      this.ubiqConfiguration = ubiqConfiguration;
    }

    /**
     * Send billing events to the server.  
     * @param ubiqWebServices   the UbiqWebServices object
     * @param events            the tracking event payload to send to the server
     * @return the HTTP status code of the request
     */

    /**
     * Has to be thread safe so payload has to be passed in.  Any reseting of the 
     * billing_events element has to be done outside of this function.
     * 
     */

    public static Integer processBillingEvents(UbiqWebServices ubiqWebServices, String events) {
      String csu = "processBillingEvents";

      try {
      // String payload = "{ \"usage\" : [" + serialize_events(events) + "]}";
        FPEBillingResponse fpeBillingResponse;

        if (verbose) System.out.printf("%s : events: %s\n", csu, events);
        
        fpeBillingResponse= ubiqWebServices.sendTrackingEvents(events);
        // Just need to report response to caller - Let them figure out how to handle success // failure
      
        if (verbose) System.out.printf("%s: %d \n", csu, fpeBillingResponse.status);
        return fpeBillingResponse.status;
      } catch (Exception e) {
        // If trapping exceptions, return success - else re-throw exception
        if (ubiqConfiguration.getEventReportingTrapExceptions()) {
          return 200;
        } else {
          throw e;
        }
      }
    }


    /**
     * Gets the serialized events and sends to a function that will invoke the Rest Endpoint Asynchronously.  The return
     * value is an object with the FUTURE Rest response, the serialized list of events and the number of times this payload
     * has been submitted.
     *
     * @param ubiqWebServices   the UbiqWebServices object
     * @return the object that contains the future object to track the Rest call, the payload, and the 
     * number of times the request has been submitted
     *
     */
    public RestCallFuture processBillingEventsAsync(UbiqWebServices ubiqWebServices) {
      String csu = "processBillingEventsAsync";

        String events = this.getAndResetSerializedData();
        if (verbose) System.out.printf("%s  events: %s\n", csu, events);

        return submitBillingEventsAsync(ubiqWebServices, events, 1);
    }

    /**
     * Submit this string of events to the web service.
     * @param ubiqWebServices   the UbiqWebServices object
     * @param events            the JSON formatted string with the {"usage" : [{events}]
     * @param submitCount       Number of times this payload has been submitted.
     */
    public RestCallFuture submitBillingEventsAsync(UbiqWebServices ubiqWebServices, String events, Integer submitCount) {
      String csu = "submitBillingEventsAsync";
      if (verbose) System.out.printf("%s   submitCount: %d   events: %s\n", csu, submitCount, events);
      ExecutorService execService = Executors.newSingleThreadExecutor();
      ListeningExecutorService lExecService = MoreExecutors.listeningDecorator(execService);

      Future<Integer> future = execService.submit(new Callable<Integer>(){
        public Integer call() throws Exception {
            return BillingEvents.processBillingEvents(ubiqWebServices, events);
        }
      });

      return new RestCallFuture(future, events, submitCount);
    }

    /**
     * Get the list of billing events AND reset the billing events structure
     * so we can capture next set of events and 
     * only send an event once.
     */
    public String getAndResetSerializedData() {
      HashMap<String, BillingEvent> events = new HashMap<String, BillingEvent>();
      try {
        this.lock.lock();
        events = this.billing_events;
        this.billing_events = new HashMap<String, BillingEvent>();
      } finally {
        this.lock.unlock();
      }
        return BillingEvents.serialize_events(events);
    }


    /**
     * Call this whenever a new billable item is created. It adds the transaction
     * to the bills ArrayList
     *
     * @param api_key   the public portion of an api_key
     * @param dataset_name   the name of the dataset being used
     * @param dataset_group   the name of the dataset group being used
     * @param action    either "encrypt" or "decrypt"
     * @param dataset_type    either "structured" or "unstructured"
     * @param key_number  the key number of the structured dataset
     * @param count the number of encrypt / decrypt events for this combination of values.
     *
     */
    public void addBillingEvent(
      String  api_key,
      String  dataset_name,
      String  dataset_group_name,
      BillingEvents.BillingAction  billing_action,
      BillingEvents.DatasetType    dataset_type,
      int     key_number,
      long    count)
    {
      try {
        String csu = "addBillingEvent";
        if (verbose) System.out.printf("%s   dataset: '%s' \n", csu, dataset_name);

        String key = BillingEvent.getKey(api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number);

        if (verbose) System.out.printf("%s   key: '%s' \n", csu, key);

        // If one exists, update it, else create a new one.

        try {
          this.lock.lock();
    
          BillingEvent b = billing_events.get(key);
          if (b == null) {
            b = new BillingEvent(api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number, count);
          }
          else {
            b.update_count(count);
          }
          billing_events.put(key, b);
        } finally {
          this.lock.unlock();
        }
      } catch (Exception e) {
        // If not trapping exceptions - then re-throw exception
        if (!ubiqConfiguration.getEventReportingTrapExceptions()) {
          throw e;
        }
      }
    }

    public static String serialize_events(HashMap<String, BillingEvent> events)
    {
      String str = "";
      String s = "";

      for (HashMap.Entry<String, BillingEvent> pair : events.entrySet()) {
        str += s + pair.getValue().serialize();
        s = ",";
      }

      return "{ \"usage\" : [" + str + "]}";
    }

    public long getEventCount() {
      long size = 0;
      try {
        this.lock.lock();
        size = billing_events.size();
      } finally {
        this.lock.unlock();
      }
      return size;
  }
}


/**
 * Representation of the JSON record that is sent to the server for each action
 */
class BillingEvent {
  String  api_key;
  String  dataset_name;
  String  dataset_group_name;
  BillingEvents.BillingAction  billing_action;
  BillingEvents.DatasetType    dataset_type;
  int     key_number;
  long    count;
  Instant last_call_timestamp; // GMT time of most recent call
  Instant first_call_timestamp;

  // Used to store the libray version
  private static final String version;

    /**
     * Constructs a new billing event record.
     *
     * @param api_key   the public portion of an api_key
     * @param dataset_name   the name of the dataset being used
     * @param dataset_group_name   the name of the dataset group being used
     * @param billing_action    either "encrypt" or "decrypt"
     * @param dataset_type    either "structured" or "unstructured"
     * @param key_number  the key number of the structured dataset
     * @param count the number of encrypt / decrypt events for this combination of values.
     */
  public BillingEvent(
    String  api_key,
    String  dataset_name,
    String  dataset_group_name,
    BillingEvents.BillingAction  billing_action,
    BillingEvents.DatasetType    dataset_type,
    int     key_number,
    long    count)
      {
        this.api_key = api_key;
        this.dataset_name = dataset_name;
        this.dataset_group_name = dataset_group_name;
        this.billing_action = billing_action;
        this.dataset_type = dataset_type;
        this.count = count;
        this.key_number = key_number;
        this.first_call_timestamp = Instant.now();
        this.last_call_timestamp = this.first_call_timestamp;

        // TODO - Add metadata for the first call and most recent call.
        // These are needed since a billing event can span a long time period and it would be good to know when the first and last 
        // call are made
    }

    // Only needs to be run once when package is class is loaded.
    static
    {
        Package pkg = BillingEvent.class.getPackage();
        version = pkg.getImplementationVersion();
    }
    
    public static String getKey(
      String  api_key,
      String  dataset_name,
      String  dataset_group_name,
      BillingEvents.BillingAction  billing_action,
      BillingEvents.DatasetType    dataset_type,
      int     key_number)
      {
        return String.format("api_key='%s' datasets='%s' billing_action='%s' dataset_groups='%s' key_number='%s' dataset_type='%s'",
          api_key, dataset_name, billing_action.to_s(), dataset_group_name, key_number, dataset_type.to_s());
      }


    /**
     * Setters and Getters
     */

    public String getKey() {
      return BillingEvent.getKey(api_key, dataset_name, dataset_group_name, billing_action, dataset_type, key_number);
    }

    public void update_count(long count) {
      this.count += count;
      this.last_call_timestamp = Instant.now();
    }

    public String serialize() {
        // TODO - Consider String.format("updateDecryptionKeyUsage exception: %s", "value")
        return "{\"datasets\":\"" + dataset_name + "\", \"dataset_groups\":\"" + dataset_group_name + 
        "\", \"dataset_type\":\"" + dataset_type.to_s() +
        "\", \"api_key\":\"" + api_key + "\", \"count\":" + count + 
      ",  \"key_number\":" + key_number + ",  \"action\":\"" + billing_action.to_s() + 
      "\", \"product\":\"" + "ubiq-java" + "\", \"product_version\":\"" + version + "\", \"user-agent\":\"" + "ubiq-java/" + version + "\", \"api_version\":\"" + "V3" + 
      "\", \"last_call_timestamp\":\"" + last_call_timestamp + 
      "\", \"first_call_timestamp\":\"" + first_call_timestamp + "\"}";

    }

}

