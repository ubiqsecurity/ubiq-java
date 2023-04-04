package com.ubiqsecurity;

import com.google.common.util.concurrent.AbstractScheduledService;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;
import java.time.Instant;
import java.util.Iterator;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Runs the scheduler used to send billing data to the server periodically
 */ 
class BillingEventsProcessor extends AbstractScheduledService
{
    private boolean verbose= false;
    private Instant nextFlushTime; // What time should the next flush of the billing events occur, regardless of count
    private static Lock lock;
    UbiqWebServices ubiqWebServices;
    BillingEvents billing_events;
    UbiqConfiguration ubiqConfiguration;

    ArrayList<RestCallFuture> trackingCalls;

  static {
    lock = new ReentrantLock();
  }

    /**
     * BillingEventsProcessor constructor
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param billing_events              the list of bills to process
     * @param ubiqConfiguration  Configuration object that can adjust the behavior of the library
     *
     */    
    public BillingEventsProcessor (UbiqWebServices ubiqWebServices, BillingEvents billing_events, 
      UbiqConfiguration ubiqConfiguration) {
        this.ubiqWebServices= ubiqWebServices;
        this.billing_events= billing_events;
        this.ubiqConfiguration = ubiqConfiguration;

        this.nextFlushTime = Instant.now().plusSeconds(ubiqConfiguration.getEventReportingFlushInterval());
        this.trackingCalls = new ArrayList<RestCallFuture>();
      }


    /**
     * Called during the startup phase.
     *
     */        
    @Override
    protected void startUp() {
        if (verbose) System.out.println("--Job started at: " + new java.util.Date());
    }

    /**
     * Called periodically to process the specified task, e.g. executor.startAsync();
     *
     */         
    @Override
    protected void runOneIteration() throws Exception {
      String csu = "runOneIteration";
      try {
        // perform periodic list processing here
        if (verbose) System.out.printf("%s   : %s  events(%d)\n", csu,new java.util.Date(), billing_events.getEventCount());
        
        // Wakes up periodically and if the flush time is reached 
        // OR the number of billing events is above the threshold, send them

        if ((nextFlushTime.compareTo(Instant.now()) < 0) || (billing_events.getEventCount() >= ubiqConfiguration.getEventReportingMinimumCount())) { 

          if (billing_events.getEventCount() > 0) {
            try {
              lock.lock();
              trackingCalls.add(billing_events.processBillingEventsAsync(ubiqWebServices));
              } finally {
                lock.unlock();
              }
            // billing_events.processBillingEventsAsync(ubiqWebServices, billing_events);
          }
          if (verbose) System.out.println("--    Sent processBillingEventsAsync");
        //   // Since billing events were sent, reset the flush time.
          this.nextFlushTime = Instant.now().plusSeconds(ubiqConfiguration.getEventReportingFlushInterval());
        } else {
          ArrayList<RestCallFuture> existingCalls;
          if (verbose) System.out.printf("%s   : Else\n", csu);
          try {
            lock.lock();
            existingCalls = trackingCalls; 
            trackingCalls = new ArrayList<RestCallFuture>();
          } finally {
            lock.unlock();
          }
          Iterator<RestCallFuture> iter = existingCalls.iterator();
          while (iter.hasNext()) {
            RestCallFuture restResults = (RestCallFuture)iter.next();
            if (restResults.future.isDone()) {
              Integer status = (Integer) restResults.future.get();
              if (verbose) System.out.printf("%s future status %d\n", csu, status);
              if (status == 200) {
                if (verbose) System.out.printf("%s remove \n", csu);
              } else {
                if (verbose) System.out.printf("%s Resubmit (%d) %s \n", csu,  restResults.processingCount, restResults.payload);
                // Resubmit and remove the old results, incrementing count to keep track of how many times it was submitted.
                try {
                  lock.lock();
                  trackingCalls.add(billing_events.submitBillingEventsAsync(ubiqWebServices, restResults.payload, restResults.processingCount + 1));
                } finally {
                  lock.unlock();
                }
              }
            }
          }
        }
      }
      catch (Exception e) {
        System.out.printf("%s   : %s   Exception %s  messasge: %s\n", csu,new java.util.Date(),  e.getClass().getName(), e.getMessage());
        // If not trapping exceptions - then re-throw exception
        if (!ubiqConfiguration.getEventReportingTrapExceptions()) {
          throw e;
        }
      }
        
    }

    /**
     * Called when a new change is made to the processing schedule
     *
     */          
    @Override
    protected Scheduler scheduler() {
        if (verbose) System.out.println("-- Running newFixedRateSchedule: " + new java.util.Date());
    
        // execute every period
        return Scheduler.newFixedRateSchedule(0, ubiqConfiguration.getEventReportingWakeInterval(), TimeUnit.SECONDS);
    }

    /**
     * Called when the scheduler is destroyed. e.g. executor.stopAsync();
     *
     */          
    @Override
    protected void shutDown() {
      String csu = "shutDown";
      try {
        if (verbose) System.out.printf("%s -- shutDown: started \n",csu);

        if (verbose) System.out.printf("%s -- shutDown:  trackingCalls.size() %d \n", csu,trackingCalls.size());

      // Submit unbilled items.
      if (billing_events.getEventCount() > 0) {
        if (verbose) System.out.printf("%s -- eventCount(%d)\n", csu, billing_events.getEventCount());
        trackingCalls.add(billing_events.processBillingEventsAsync(ubiqWebServices));
      }
      if (verbose) System.out.printf("%s -- shutDown: B", csu);
      Iterator<RestCallFuture> iter = trackingCalls.iterator();
      if (verbose) System.out.printf("%s -- shutDown: C", csu);
      while (iter.hasNext()) {
        if (verbose) System.out.printf("%s -- shutDown: finishing task\n", csu);
        RestCallFuture restResults = iter.next();
        // Wait until the events have been processed
        try {
          Integer res = (Integer) restResults.future.get();
          if (verbose) System.out.printf("%s -- shutDown: res (%d)\n", csu, res);

        } catch (InterruptedException | ExecutionException e) {
          if (verbose) System.out.printf("%s -- InterruptedException: %s\n", csu, e.getMessage());

        }
      }
      // perform final list processing here
      if (verbose) System.out.printf("%s-- Job terminated at: %s\n", csu, new java.util.Date());
    }  catch (Exception e) {
      System.out.printf("%s   : %s   Exception %s  messasge: %s\n", csu,new java.util.Date(),  e.getClass().getName(), e.getMessage());
    }
    if (verbose) System.out.printf("%s -- shutDown: D\n", csu);

    }
    
}












