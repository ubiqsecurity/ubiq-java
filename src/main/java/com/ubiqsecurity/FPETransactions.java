package com.ubiqsecurity;

import com.google.common.util.concurrent.AbstractScheduledService;
import com.google.gson.Gson; 
import java.util.Date;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;
import java.util.Iterator; 
import com.google.common.util.concurrent.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;



/**
 * Processes encrypt decrypt billing transactions based on the JSON format stored in an ArrayList:
 * [{"id": GUID, "action": encrypt|decrypt, "ffs_name": name, "timestamp": ISO8601, "count" : number}, ...]
 * For example:
 * [{"id":"305fcb40-ebac-4d99-b98b-52473da23410","action":"encrypt","ffs_name":"ALPHANUM_SSN","timestamp":"2021-09-13T16:20:35.671644Z","count":1}, ...]
 */
class FPETransactions {
    private boolean verbose= false;
    private String jsonStr;    
    private Gson gson;
    private ArrayList<FPETransactionsRecord> Bills;
    private String oldestUnprocessedItemID= "";


    /**
     * Constructs a new list of bills
     *
     */    
    public FPETransactions () {
        Bills = new ArrayList<FPETransactionsRecord>();
    }
    
    
    
    /**
     * Runs the bill processor by reading the bills ArrayList and sending it
     * as a JSON to the server.
     * 
     * If the server returns 201, then all the items in the list that were
     * processed are deleted. (Newly added items are not deleted as determined
     * by lastItemIDToProcess.
     *
     * If the server has a problem with the list, only the partial list of
     * items (if any) are deleted from the ArrayList. The record that 
     * the server had a problem with is moved to the end of the list to 
     * prevent blocking the processing of the remaining items next time around.
     *
     * @param ubiqWebServices   the UbiqWebServices object
     *
     */
    public void processCurrentBills(UbiqWebServices ubiqWebServices) {
        FPETransactions bill= this;
        
        String payload= bill.getTransactionAsJSON();
        if (verbose) System.out.println("1) payload=" + payload);
        String lastItemIDToProcess= bill.getLastItemInList();
        
        FPEBillingResponse fpeBillingResponse;
        fpeBillingResponse= ubiqWebServices.sendBilling(payload);
        if (fpeBillingResponse.status == 201) {
            // all submitted records have been processed by backend so OK to clear the local list
            if (verbose) System.out.println("Payload successfully received and processed by backend.");
            bill.deleteBillableItems(lastItemIDToProcess);
        } else if (fpeBillingResponse.status == 400) {
            if (verbose) System.out.println("WARNING: Backend stopped processing after UUID:"  + fpeBillingResponse.last_valid.id);
            
            // delete our local list up to and including the last record processed by the backend
            String newTopRecord= bill.deleteBillableItems(fpeBillingResponse.last_valid.id);
            
            if (verbose) {
                payload= bill.getTransactionAsJSON();
                System.out.println("2) payload=" + payload); 
            }
            
            // move the bad record to the end of the list so it won't block the next billing cycle (in case it was a bad record)
            if (newTopRecord.equals("") == false) {
                bill.deprioritizeBadBillingItem(newTopRecord);
                
                if (verbose) {
                    payload= bill.getTransactionAsJSON();
                    System.out.println("3) payload=" + payload); 
                }
            }
        } else {
            if (verbose) System.out.println("Cannot process bills, server returning error code: "  + fpeBillingResponse.status);
        }

    }
    
    
    /**
     * Runs the bill processor asynchronously by calling processCurrentBills() in
     * a separate thread.
     * 
     * @param ubiqWebServices   the UbiqWebServices object
     * @param bill              the FPETransactions context
     *
     */    
    public void processCurrentBillsAsync(UbiqWebServices ubiqWebServices, FPETransactions bill) {
        ExecutorService execService = Executors.newSingleThreadExecutor();
        ListeningExecutorService lExecService = MoreExecutors.listeningDecorator(execService);

        ListenableFuture<Integer> asyncTask = lExecService.submit(() -> {
            bill.processCurrentBills(ubiqWebServices);
            return 0;
        });    
    }
      
    
    /**
     * Call this whenever a new billable item is created. It adds the transaction
     * to the bills ArrayList
     * 
     * @param id        a unique GUID String
     * @param action    either "encrypt" or "decrypt"
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     * @param timestamp the timestamp String in ISO8601 format
     * @param count     the number of transactions of this type
     *
     */        
    public void createBillableItem(
        String  id,
        String  action,
        String  ffs_name,
        String  timestamp,
        int     count) 
    {
        FPETransactionsRecord transaction = new FPETransactionsRecord(id, action, ffs_name, timestamp, count); // Creating a new object
        Bills.add(transaction); // Adding it to the list
        
        // Since part of the list may be in process of being deleted, identify the last unprocessed item
        if (oldestUnprocessedItemID.equals("") == true) {
            oldestUnprocessedItemID= id;
            if (verbose) System.out.println("       SET unprocessed record: " + id);
        }
    }  
    
    
    
    /**
     * Converts the current list of billable transactions into JSON
     * This JSON is a "snapshot" of the actively building ArrayList so anything
     * added to the ArrayList afterwards is identified by the oldestUnprocessedItemID.
     *
     * @return the JSON
     */            
    public String getTransactionAsJSON() {
        // create the JSON from the list
        String json = new Gson().toJson(Bills);
        return json;
    }
    
    
    /**
     * Returns the last bill in the ArrayList. This is useful to get
     * a current "snapshot" if the billable items that are about to be
     * sent to the server for processing. If other bills are added to the
     * list after this point, we'll know to process those on the next
     * trip to the server.
     *
     * @return    the UUID of the last item
     */                
    public String getLastItemInList() {
        String id= "";
        if (Bills.size() > 0) {
            FPETransactionsRecord tr = Bills.get(Bills.size()-1);
            id= tr.id;
        }
        return id;
    }
    
    
    /**
     * if the server cannot process a record, move it to the end of the 
     * local list array so that it doesn't block other transactions.
     *
     * @param id        a GUID of the item to move
     *
     */                
    public void deprioritizeBadBillingItem(String id) {
        String  moved_id="";
        String  action="";
        String  ffs_name="";
        String  timestamp="";
        int     count=0;
        
        if ((id == null) || (Bills.size()==1)) {
            // don't bother changing priority if only one item in list
            return;
        }    
        
        // locate the item to deprioritize
        Iterator<FPETransactionsRecord> itr = Bills.iterator();
        boolean idExists = false;
        while (itr.hasNext()) {
            FPETransactionsRecord t = itr.next();
             
            if (id.equals(t.id) == true) {
                idExists= true;
                if (verbose) System.out.println("Found: " + t.id);
                moved_id= t.id;
                action= t.action;
                ffs_name= t.ffs_name;
                timestamp= t.timestamp;
                count= t.count;
                
                // delete the record
                itr.remove();
                break;
            }
        }
        
        // add the deleted record to the end of the list
        if (idExists == true) {   
            createBillableItem(moved_id, action, ffs_name, timestamp, count);
            
            // reset the unprocessed item to the beginning of the list
            FPETransactionsRecord tr = Bills.get(0);
            oldestUnprocessedItemID= tr.id;
            if (verbose) System.out.println("       RESET unprocessed record: " + oldestUnprocessedItemID);
        }
        
    }
    
    
    
    /**
     * Deletes all id's UP TO AND INCLUDING the specified id 
     * Call this with an id when the backend failed to delete the billable items up that id.
     * Otherwise call with empty id to delete all items in list.
     *
     * @param id        a GUID of the item to delete
     *
     * @return      the id of the top item of the bills ArrayList (if any)
     */                
    public String deleteBillableItems(String id) {
        String newTopRecord= "";
        Iterator<FPETransactionsRecord> itr = Bills.iterator();
        
        // if id is blank, then attempt to delete all items in list
        if (id == "") {
            if (verbose) System.out.println("Deleting all items");
             // delete each record up to the oldestUnprocessedItemID
            itr = Bills.iterator();
            while (itr.hasNext())
            {
                FPETransactionsRecord t = itr.next();
            
                // if this record was identified as unprocessed, stop deleting
                if (oldestUnprocessedItemID.equals(t.id)) {
                    if (verbose) System.out.println("       STOPPED deleting at unprocessed record: " + t.id);
                    break;
                } 

                if (verbose) System.out.println("   Deleting t.id: " + t.id);
                // delete the record
                itr.remove();

            }
        
            if (Bills.size()==1) {
                // if everything in the list was deleted, reset the oldestUnprocessedItemID
                oldestUnprocessedItemID= "";
            }
            newTopRecord = "";
        }
        else {
            if (verbose) System.out.println("Deleting all items up to and including...  " + id);
       
            //make sure that the current list has the id present before we start deleting records
            boolean idExists = false;
            while (itr.hasNext()) {
                FPETransactionsRecord t = itr.next();
            
                if (id.equals(t.id) == true) {
                    idExists= true;
                    if (verbose) System.out.println("Found: " + t.id);
                    break;
                }
            }
            if (idExists == false) {
                return "";
            }
        
            // delete each record up to and including the id
            itr = Bills.iterator();
            while (itr.hasNext())
            {
                FPETransactionsRecord t = itr.next();
                if (verbose) System.out.println("   Deleting t.id: " + t.id);
            
                // delete the record
                itr.remove();
            
                // if this record was identified as unprocessed, clear it now
                if (oldestUnprocessedItemID.equals(t.id)) {
                    oldestUnprocessedItemID= "";
                    if (verbose) System.out.println("       CLEARED unprocessed record: " + t.id);
                } 
            
                // if this is the id of the record the user specified then its the last to be deleted
                if (id.equals(t.id) == true) {
                    if (verbose) System.out.println("       Deleted all records up to and including: " + t.id);
                
                    // determine if there is another record after this one and return it's id
                    if (verbose) System.out.println("   Bills.size(): " + Bills.size());
                    if (Bills.size() > 0) {
                        FPETransactionsRecord tr = Bills.get(0);
                        newTopRecord= tr.id;
                        if (verbose) System.out.println("   There is a new top record: " + t.id);
                    } 
                    break;
                }
            }
        }    
        return newTopRecord;
    }  
}



/**
 * Representation of the JSON record that is sent to the server for each action
 */
class FPETransactionsRecord {
    String  id;
    String  action;
    String  ffs_name;
    String  timestamp;
    int     count;
    
    /**
     * Constructs a new transaction record.
     *
     * @param id        a unique GUID String
     * @param action    either "encrypt" or "decrypt"
     * @param ffs_name  the name of the FFS model, for example "ALPHANUM_SSN"
     * @param timestamp the timestamp String in ISO8601 format
     * @param count     the number of transactions of this type
     */    
    public FPETransactionsRecord(String id, String action, String ffs_name, String timestamp, int count) 
    {
        this.id = id;
        this.action = action;
        this.ffs_name = ffs_name;
        this.timestamp = timestamp;
        this.count = count;
    }
    

    /**
     * Setters and Getters
     */
	public String getid() {
		return id;
	}
	public void setid(String id) {
		this.id = id;
	}    
	public String getaction() {
		return action;
	}
	public void setaction(String action) {
		this.action = action;
	}    
	public String getffs_name() {
		return ffs_name;
	}
	public void setffs_name(String ffs_name) {
		this.ffs_name = ffs_name;
	}    
	public String gettimestamp() {
		return timestamp;
	}
	public void settimestamp(String timestamp) {
		this.timestamp = timestamp;
	}    
	public int getcount() {
		return count;
	}
	public void setcount(int count) {
		this.count = count;
	}    
	
} 






