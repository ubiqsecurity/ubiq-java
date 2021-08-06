package com.ubiqsecurity;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;







public class FPEMask  {
    private String encryptable;  
    private String original;
    String regex;
    String redactedString;

    
    public FPEMask(String original, String regex) {
        this.original = original;
        this.regex = regex;
        this.redactedString = original;
    }
    
    
    
    /**
     * Inserts a String at a position in a String.
     *
     * Convenience function returns String with inserted char 
     * at an index position.
     *
     * @param originalString the original String
     * @param stringToBeInserted the String to insert
     * @param index the index position where to insert
     *
     * @return    the new String 
     */ 
    public String insertString(String originalString, String stringToBeInserted, int index) {
        if (index < 0) {
            throw new IllegalArgumentException("invalid argument, index cannot be less than 0.");
        }
        if ((originalString.isEmpty() == true) || (stringToBeInserted.isEmpty() == true)) {
            throw new IllegalArgumentException("invalid argument, input strings cannot be empty.");
        }
            
        // Create a new StringBuffer
        StringBuffer newString = new StringBuffer(originalString);
            
        System.out.println("  BEFORE delete: " + newString.toString() + "  index: " + index + "  stringToBeInserted.length(): " + stringToBeInserted.length() );    
        newString.delete(index, index + stringToBeInserted.length());
        System.out.println("  AFTER delete: " + newString.toString() );
  
        // Insert the string to be inserted
        newString.insert(index, stringToBeInserted);
        
        // create the redacted version
        String redactionGroup= "";
        StringBuffer newRedactedString  = new StringBuffer(redactedString);
        newRedactedString.delete(index, index + stringToBeInserted.length());
        for (int i = 1; i <= stringToBeInserted.length(); i++) {
            redactionGroup= redactionGroup + "X";
        }
        System.out.println("  redactionGroup: " + redactionGroup);
        newRedactedString.insert(index, redactionGroup);
        redactedString= newRedactedString.toString();
        
  
        // return the modified String
        return newString.toString();
    }
    



    
    /**
     * Returns only the encrypt-able portion of a concatenated String.
     * For example, if the original String is "123-45-6789" and the
     * regex is "(\\d{3})-(\\d{2})-\\d{4}". Then the portion "123-45" 
     * is the portion to be encrypted. The regex will return the digits
     * and this function will concatenate them as "12345".
     *
     * Use the function insertEncryptedPart() to reinsert the String
     * back into the appropriate original positions.
     *
     * @return    the encrypt-able/decrypt-able String
     */         
    public String getEncryptablePart() {
        String encryptable= "";

        // Create a Pattern object
        Pattern r = Pattern.compile(this.regex);

        // Now create matcher object.
        Matcher m = r.matcher(this.original);

        System.out.println("m.groupCount: " + m.groupCount() );

        if (m.find( )) {
            for (int i = 1; i <= m.groupCount(); i++) {
                 System.out.println("Found value: " + m.group(i) + "    m.start(): " + m.start(i) + "    m.end(): " + m.end(i));
                 encryptable = encryptable +  m.group(i);
            }
        } else {
         System.out.println("NO MATCH");
        }
        
        this.encryptable = encryptable;
        
        return encryptable;
    }


    /**
     * Inserts the encrypt-able portion of a concatenated String back
     * into the correct locations of the original String.
     * For example, if the original String is "123-45-6789" and the
     * regex is "(\\d{3})-(\\d{2})-\\d{4}" and the insertion String is "99988" 
     * then the result returned will be "999-88-6789".
     *
     * Use the function getEncryptablePart() identify the string to be encrypted/decrypted
     * and then use this function to insert the encrypted/decrypted text
     * back into the correct location.
     *
     * @param insertion the String to insert
     *
     * @return    the new String after the insertion
     */         
    public String insertEncryptedPart(String insertion) {
        String withInsertion= this.original;  // start with the original including all special characters
        //String insertable= insertion;
        String grouptext= "";
        int groupindex;
         
        // Create a Pattern object
        Pattern r = Pattern.compile(this.regex);

        // Now create matcher object.
        Matcher m = r.matcher(this.original);

        System.out.println("\nm.groupCount: " + m.groupCount() + "    insertion: " + insertion );

        if (m.find( )) {
            for (int i = 1; i <= m.groupCount(); i++) {
                 System.out.println("Found value: " + m.group(i) + "    m.start(): " + m.start(i) + "    m.end(): " + m.end(i));
                 
                 System.out.println("insertion = " + insertion.substring( 0, m.end(i) - m.start(i) ));
                 
                 
                 grouptext = insertion.substring( 0, m.end(i) - m.start(i) );
                 
                 
                 // insert this group into the proper location
                 System.out.println("BEFORE withInsertion = " + withInsertion + "      grouptext= " + grouptext);
                 withInsertion = insertString(withInsertion, grouptext, m.start(i) );
                 System.out.println("AFTER withInsertion = " + withInsertion);
                 
                 
                 
                 if (i != m.groupCount()) {
                     insertion= insertion.substring( m.end(i) - m.start(i) );  // move on to the next group
                     System.out.println("next insertion = " + insertion);
                 }
            }
        } else {
         System.out.println("NO MATCH");
        }
        
               
        return withInsertion;
    }
 
 
    /**
     * Returns the redacted string suitable for display on a UI.
     * The redacted portion will be displayed as "X". For example,
     * If the original String was "123-45-6789" and the regex is 
     * "(\\d{3})-(\\d{2})-\\d{4}", this will return "XXX-XX-6789". 
     *
     * Call this after insertEncryptedPart() to ensure that the
     * final redacted String has been created.
     *
     * @return    the new String with the encrypted portion redacted
     */          
    public String getRedacted() {
        return redactedString;    
    }
    
    
    
 
    
    
}    


