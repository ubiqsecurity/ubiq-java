package com.ubiqsecurity;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;



/**
 * Algorithms to pattern-match encryptable portions of a string
 * and apply masking based on an accompanied regex.
 */
class FPEMask  {
    private String encryptable;  
    private String original;
    String regex;
    String redactedString;
    String redactionSymbol;

    
    /**
     * Constructor allows caller to set redaction Symbol
     *
     * @param original the original String
     * @param regex the regex pattern to use
     * @param redactionSymbol the custom redaction Symbol
     */ 
    public FPEMask(String original, String regex, String redactionSymbol) {
        this.redactionSymbol = redactionSymbol;
        this.original = original;
        this.regex = regex;
        this.redactedString = original;
    }
    

    /**
     * Constructor assumes default redaction Symbol
     *
     * @param original the original String
     * @param regex the regex pattern to use
     */ 
    public FPEMask(String original, String regex) {
        this(original, regex, "*");
    }

    
    /**
     * Inserts a String at a position in a String by
     * replacing the same number of characters as its length.
     *
     *
     * @param originalString the original String
     * @param stringToBeInserted the String to insert
     * @param index the index position where to insert
     *
     * @return the new String 
     */ 
    public String insertString(String originalString, String stringToBeInserted, int index) {
        if (index < 0) {
            throw new IllegalArgumentException("invalid argument, index cannot be less than 0.");
        }
        if ((originalString.isEmpty() == true) || (stringToBeInserted.isEmpty() == true)) {
            throw new IllegalArgumentException("invalid argument, input strings cannot be empty.");
        }
            
        // Create a new StringBuffer with replaced string
        StringBuffer newString = new StringBuffer(originalString);
        newString.delete(index, index + stringToBeInserted.length());
        newString.insert(index, stringToBeInserted);
        
        // create the redacted version
        String redactionGroup= "";
        StringBuffer newRedactedString  = new StringBuffer(this.redactedString);
        newRedactedString.delete(index, index + stringToBeInserted.length());
        for (int i = 1; i <= stringToBeInserted.length(); i++) {
            redactionGroup= redactionGroup + redactionSymbol;
        }
        newRedactedString.insert(index, redactionGroup);
        this.redactedString= newRedactedString.toString();
        
        // return the modified String
        return newString.toString();
    }
    
    
    /**
     * Returns only the encrypt-able portion of a concatenated String.
     * For example, if the original String is "123-45-6789" and the
     * regex is "(\\d{3})-(\\d{2})-\\d{4}". Then the portion "123-45" 
     * is the portion to be encrypted. The regex will return the digits
     * and this function will concatenate them as "12345".
     * Normally call this function first and then insertEncryptedPart().
     *
     * Use the function insertEncryptedPart() to reinsert the String
     * back into the appropriate original positions.
     *
     * @return the encrypt-able/decrypt-able String
     */         
    public String getEncryptablePart() {
        this.encryptable= "";

        // Create a Pattern object
        Pattern r = Pattern.compile(this.regex);

        // Now create matcher object.
        Matcher m = r.matcher(this.original);

        // pattern search each group and concat them together
        if (m.find( )) {
            for (int i = 1; i <= m.groupCount(); i++) {
                 encryptable = encryptable +  m.group(i);
            }
        } else {
            throw new RuntimeException("Regex pattern " + this.regex + " not correct for given data.");
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
     * Normally call this function after getEncryptablePart().
     *
     * Use the function getEncryptablePart() identify the string to be encrypted/decrypted
     * and then use this function to insert the encrypted/decrypted text
     * back into the correct location.
     *
     * @param insertion the String to insert
     *
     * @return the new String after the insertion
     */         
    public String insertEncryptedPart(String insertion) {
        String withInsertion= this.original;  // start with the original including all special characters
        String grouptext= "";
        int groupindex;
        
        if (insertion.isEmpty() == true) {
            throw new IllegalArgumentException("Invalid argument, insertion string is empty.");
        }

        // Create a Pattern object
        Pattern r = Pattern.compile(this.regex);

        // Now create matcher object.
        Matcher m = r.matcher(this.original);

        // apply an insertion for each pattern-matched group
        if (m.find( )) {
            for (int i = 1; i <= m.groupCount(); i++) {
                 grouptext = insertion.substring( 0, m.end(i) - m.start(i) );
                 
                 // insert this group into the proper location
                 withInsertion = insertString(withInsertion, grouptext, m.start(i) );
                 
                 if (i != m.groupCount()) {
                     // move on to the next group
                     insertion= insertion.substring( m.end(i) - m.start(i) );  
                 }
            }
        } else {
            throw new RuntimeException("Regex pattern " + this.regex + " not correct for given data.");
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
     * @return the new String with the encrypted portion redacted
     */          
    public String getRedacted() {
        return redactedString;    
    }
    
    
    
 
    
    
}    


