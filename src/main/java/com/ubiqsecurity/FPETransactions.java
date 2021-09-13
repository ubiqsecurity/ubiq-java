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



/*
JSON format os a billing transaction
[{“id”: “<GUID>”, "action": "encrypt", "ffs_name": <name>, "timestamp": ISO8601, "count" : number},
*/
 
public class FPETransactions {
    private boolean verbose= true;
    private String jsonStr;    
    private Gson gson;
    private ArrayList<FPETransactionsRecord> Bills;
    private String oldestUnprocessedItemID= "";


    public FPETransactions () {
        Bills = new ArrayList<FPETransactionsRecord>();
    }
    
    
    
    // runs the bill processor and server access at the end before the
    // UbiqFPEEncryptDecrypt object is terminated
    public void processCurrentBills(UbiqWebServices ubiqWebServices) {
        FPETransactions bill= this;
        
        if (verbose) System.out.println("   IN processCurrentBills");
        
        
        String payload= bill.getTransactionAsJSON();
        System.out.println("1) payload=" + payload);
        String lastItemIDToProcess= bill.getLastItemInList();
        
        FPEBillingResponse fpeBillingResponse;
        fpeBillingResponse= ubiqWebServices.sendBilling(payload);
        if (fpeBillingResponse.status == 201) {
            // all submitted records have been processed by backend so OK to clear the local list
            System.out.println("Payload successfully received and processed by backend.");
            bill.deleteBillableItems(lastItemIDToProcess);
        } else {
            System.out.println("WARNING: Backend stopped processing after UUID:"  + fpeBillingResponse.last_valid.id);
            
            // delete our local list up to and including the last record processed by the backend
            String newTopRecord= bill.deleteBillableItems(fpeBillingResponse.last_valid.id);
            payload= bill.getTransactionAsJSON();
            System.out.println("2) payload=" + payload); 
            
            // move the bad record to the end of the list so it won't block the next billing cycle (in case it was a bad record)
            if (newTopRecord.equals("") == false) {
                bill.deprioritizeBadBillingItem(newTopRecord);
                
                payload= bill.getTransactionAsJSON();
                System.out.println("3) payload=" + payload); 
            }
        }

    }
    
    
    // runs the bill processor and server access in the background. To be called periodically by FPEProcessor
    public void processCurrentBillsAsync(UbiqWebServices ubiqWebServices, FPETransactions bill) {
        ExecutorService execService = Executors.newSingleThreadExecutor();
        ListeningExecutorService lExecService = MoreExecutors.listeningDecorator(execService);

        ListenableFuture<Integer> asyncTask = lExecService.submit(() -> {
            //TimeUnit.MILLISECONDS.sleep(500); // long running task
            bill.processCurrentBills(ubiqWebServices);
            
            return 0;
        });    
    }
      
    
    
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
        if (verbose) System.out.println("       oldestUnprocessedItemID: " + oldestUnprocessedItemID);
        if (oldestUnprocessedItemID.equals("") == true) {
            oldestUnprocessedItemID= id;
            if (verbose) System.out.println("       SET unprocessed record: " + id);
        }
        
    }  
    
    
    // converts the current list of billable transactions into JSON
    // This JSON is a "snapshot" of the actively building ArrayList<FPETransactionsRecord> so anything
    // added to the ArrayList afterwards is identified by the oldestUnprocessedItemID
    public String getTransactionAsJSON() {
        // create the JSON from the list
        String json = new Gson().toJson(Bills);
        return json;
    }
    
    
    public String getLastItemInList() {
        String id= "";
        if (Bills.size() > 0) {
            FPETransactionsRecord tr = Bills.get(Bills.size()-1);
            id= tr.id;
        }
        return id;
    }
    
    
    // if the server cannot process a record, move it to the end of the local list array so that it doesn't block other transactions
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
    
    
    
    // Deletes all id's UP TO AND INCLUDING the specified id  
    // Call this when the backend failed to delete the billable items up to id 
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

                //if (verbose) System.out.println("   Deleting t.id: " + t.id);
            
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
            
                //if (verbose) System.out.println("   Deleting t.id: " + t.id);
            
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



class FPETransactionsRecord {

    String  id;
    String  action;
    String  ffs_name;
    String  timestamp;
    int     count;
    
    
    public FPETransactionsRecord(
        String  id,
        String  action,
        String  ffs_name,
        String  timestamp,
        int     count) 
    {
        this.id = id;
        this.action = action;
        this.ffs_name = ffs_name;
        this.timestamp = timestamp;
        this.count = count;
    }
    
    
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
	
	
	
	@Override
    public String toString() {
        return "FPETransactionsRecord [id=" + id + ", action=" + action + ", ffs_name=" + ffs_name + ", timestamp=" + timestamp + ", count=" + count + "]";
    }
    
	
	// ArrayList<FPETransactionsRecord> items;
	
} 






