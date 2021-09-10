package com.ubiqsecurity;

import com.google.common.util.concurrent.AbstractScheduledService;
import com.google.gson.Gson; 
import java.util.Date;
import java.util.concurrent.TimeUnit;

import java.util.ArrayList;
import java.util.Iterator; 



/*

[{“id”: “<GUID>”, "action": "encrypt", "ffs_name": <name>, "timestamp": ISO8601, "count" : number},

{“id”: “<GUID>”, "action": "decrypt", "ffs_name": <name>, "timestamp": ISO8601, "count": number }]

*/
 
public class FPETransactions {
    private boolean verbose= true;
    private String jsonStr;    
    private Gson gson;
    //private FPETransactionsRecord[] billingArray;
    private ArrayList<FPETransactionsRecord> Bills;
    private String oldestUnprocessedItemID= "";


    public FPETransactions () {
        Bills = new ArrayList<FPETransactionsRecord>();
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
        if (oldestUnprocessedItemID.equals("")) {
            oldestUnprocessedItemID= id;
            if (verbose) System.out.println("       SET unprocessed record: " + id);
        }
        
    }  
    
    
    // converts the current list of billable transactions into JSON
    // This JSON is a "snapshot" of the actively building ArrayList<FPETransactionsRecord> so anything
    // added to the ArrayList afterwards is identified by the oldestUnprocessedItemID
    public void getTransactionAsJSON() {
        // clear the oldestUnprocessedItemID since it will be part of the JSON
        oldestUnprocessedItemID= "";
        
        // create the JSON from the list
        String json = new Gson().toJson(Bills);
        
        if (verbose) System.out.println("json=" + json);
        
        
    }
    
    
    
    
    
    // Deletes all id's up to and including the specified id  
    // Call this when the backend failed to delete the billable items up to id 
    public boolean deleteBillableItems(String  id) {
        if (verbose) System.out.println("Deleting all items up to... deleteBillableItems: " + id);
        if (id == null) {
            return false;
        }
        
        Iterator<FPETransactionsRecord> itr = Bills.iterator();
        
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
            return false;
        }
        
        
        // delete each record up to and including the id
        itr = Bills.iterator();
        while (itr.hasNext())
        {
            FPETransactionsRecord t = itr.next();
            
            if (verbose) System.out.println("t.id: " + t.id);
            
            // delete the record
            itr.remove();
            
            // if this record was identified as unprocessed, clear it now
            if (oldestUnprocessedItemID.equals(t.id)) {
                oldestUnprocessedItemID= "";
                if (verbose) System.out.println("       CLEARED unprocessed record: " + t.id);
            } 
            
            // if this is the id of the record the user specified then its the last to be deleted
            if (id.equals(t.id) == true) {
                if (verbose) System.out.println("       Deleted all records up to: " + t.id);
                break;
            }

        }
            
            
        return true;
    }  
     


    // Deletes all id's up to the unprocessed ones    
    // Call this when the backend successfully deleted all of the billable items
    public boolean deleteBillableItems() {
        if (verbose) System.out.println("Deleting all items... deleteBillableItems");
        
        Iterator<FPETransactionsRecord> itr = Bills.iterator();
        
        
        
        // delete each record up to the oldestUnprocessedItemID
        itr = Bills.iterator();
        while (itr.hasNext())
        {
            FPETransactionsRecord t = itr.next();
            
            if (verbose) System.out.println("t.id: " + t.id);

            // if this record was identified as unprocessed, stop deleting
            if (oldestUnprocessedItemID.equals(t.id)) {
                if (verbose) System.out.println("       STOPPED deleting at unprocessed record: " + t.id);
                break;
            } 
            
            // delete the record
            itr.remove();

        }
            
            
        return true;
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






