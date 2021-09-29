package com.ubiqsecurity;

import com.google.common.util.concurrent.AbstractScheduledService;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;


/**
 * Runs the scheduler used to send billing data to the server periodically
 */ 
class FPEProcessor extends AbstractScheduledService
{
    private boolean verbose= false;
    private int secondsToProcess= 1;  // set the how often the list of bills are sent to the server
    private int billCountThresholdBeforeDoingAsync= 50;   // set to the minimum number of bills before sending to server
    UbiqWebServices ubiqWebServices;
    FPETransactions bill;

    /**
     * FPEProcessor constructor
     *
     * @param ubiqWebServices   used to specify the webservice object
     * @param bill              the list of bills to process
     * @param secondsToProcess  how often to schedule processing of the bills
     *
     */    
    public FPEProcessor (UbiqWebServices ubiqWebServices, FPETransactions bill, int secondsToProcess) {
        this.ubiqWebServices= ubiqWebServices;
        this.bill= bill;
        this.secondsToProcess= secondsToProcess;
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
        // perform periodic list processing here
        if (verbose) System.out.println("-- Running: " + new java.util.Date());
        
        if (bill.billCount() >= billCountThresholdBeforeDoingAsync) { 
            bill.processCurrentBillsAsync(ubiqWebServices, bill);
            if (verbose) System.out.println("--    Sent processCurrentBillsAsync");
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
        return Scheduler.newFixedRateSchedule(0, secondsToProcess, TimeUnit.SECONDS);
    }

    /**
     * Called when the scheduler is destroyed. e.g. executor.stopAsync();
     *
     */          
    @Override
    protected void shutDown() {
        // perform final list processing here
        if (verbose) System.out.println("-- Job terminated at: " + new java.util.Date());
        
    }
}










