package com.ubiqsecurity;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

 

/**
 * Algorithms to parse and build strings based on a given set
 * of input characters and passthrough characters
 */
class Parsing implements AutoCloseable  {
    private boolean verbose= false;
    private String trimmed_characters;  // Preallocated and filled with char[0] from input characterset.  Should be same length as input string
    private String empty_formatted_output; // Preallocated and filled with char[0] from OUTPUT characterset, Should be same length as input string

 
    /**
     * Constructor assumes default redaction Symbol
     *
     * @param trimmed_characters filled with char[0] from input characterset
     * @param empty_formatted_output filled with char[0] from OUTPUT characterset
     */ 
    public Parsing(String trimmed_characters, String empty_formatted_output) {
        this.trimmed_characters = trimmed_characters;
        this.empty_formatted_output = empty_formatted_output;
    }
    
    
    /**
     * Returns the current trimmed_characters value 
     *
     * @return    the trimmed_characters 
     */        
    public String get_trimmed_characters() {
        return this.trimmed_characters;
    }


    /**
     * Returns the current empty_formatted_output value 
     *
     * @return    the empty_formatted_output 
     */        
    public String get_empty_formatted_output() {
        return this.empty_formatted_output;
    }


    /**
     * Performs any wrapup when object is destroyed 
     *
     */        
    public void close() {

    }


    /**
     * Append a character at end of a String.
     *
     *
     * @param str the original String
     * @param ch the character to append
     *
     * @return    the new String containing the inserted ch 
     */    
    public static String appendChar(String str, char ch) {
        StringBuilder sb = new StringBuilder(str);
        sb.append(ch);
        return sb.toString();
    }
    

    
    /**
     * Replaces a character at a position in a String.
     *
     * Convenience function returns String with replaced char 
     * at an index position.
     *
     * @param str the original String
     * @param ch the character to replace
     * @param position the index position where to insert the ch
     *
     * @return    the new String containing the inserted ch 
     */    
    public static String replaceChar(String str, char ch, int position) {
        StringBuilder sb = new StringBuilder(str);
        sb.setCharAt(position, ch);
        return sb.toString();
    }
    
    
    /**
     * Creates a String of a specified size filled with a desired character string.
     *
     * @param stringLength the desired String length
     * @param strCharacter the desired character of type String
     *
     * @return    the new String  
     */    
    public static String createString(int stringLength, String strCharacter){
        StringBuilder sbString = new StringBuilder(stringLength);
        
        for(int i=0; i < stringLength; i++){
            sbString.append(strCharacter);
        }
        return sbString.toString();
    }
    
    
        

    /**
     * Performs parsing of a string based on an input character set and
     * applies the passthrough characters
     *
     * @param input_string the String to parse
     * @param input_character_set the set of characters for the input radix
     * @param passthrough_character_set the characters that should be allowed to passthrough
     *
     * @return    -1 if error encountered  
     */    
    public int ubiq_platform_efpe_parsing_parse_input(
        final String input_string, 
        final String input_character_set, 
        final String passthrough_character_set 
      )
      {
        int i = 0;
        int err = 0;
        char ch = '0';
        int trimmedSize = 0;

        while ((i < input_string.length()) && (err ==0)) {
            ch = input_string.charAt(i);
    
            // If the input string matches a passthrough character, copy to empty formatted output string
            if ( (passthrough_character_set!= null) && (passthrough_character_set.indexOf(ch) != -1) ) {
                this.empty_formatted_output = replaceChar(this.empty_formatted_output, ch, i);
            }
            // If the string is in the input character set, copy to trimmed characters
            else if (input_character_set.indexOf(ch) != -1) {
                this.trimmed_characters = replaceChar(this.trimmed_characters, ch, trimmedSize);
                trimmedSize++;
            }
            else {
                if (verbose) System.out.println("        input_string:  " + input_string);
                if (verbose) System.out.println("        input_character_set:  " + input_character_set);
                if (verbose) System.out.println("        passthrough_character_set:  " + passthrough_character_set);
                err = -1;
                
                throw new IllegalArgumentException("Input string has invalid character:  '" + ch + "'");
            }
            i++;
        }

        // Trimmed may be shorter than input so make sure to resize
        this.trimmed_characters = this.trimmed_characters.substring(0, trimmedSize);

        return err;
      }
 
    
    
}    


