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
    private StringBuilder input_string;
    private StringBuilder trimmed_characters;  // Characters that will be encrypted
    private StringBuilder formatted_output; // Formatted output including passthrough characters for the encrypted section of text
    private boolean passthrough_processed = false;
    private StringBuilder prefix_string; // May be input characters or may also include passthrough characters depending on passthrough priority
    private StringBuilder suffix_string; // May be input characters or may also include passthrough characters depending on passthrough priority

    private char dest_zeroth_char;
    private String source_character_set;
    private String passthrough_character_set;


    /**
     * Constructor assumes default redaction Symbol
     *
     * @param source_string the original string to parse
     * @param source_character_set the character set from the source strings
     * @param passthrough_character_set the passthrough characters
     * @param dest_zeroth_char the zeroth character in the destination characterset
     */ 


    public Parsing(
      String source_string, 
      String source_character_set, 
      String passthrough_character_set,
      char dest_zeroth_char) 
    {
      this.source_character_set = source_character_set;
      this.passthrough_character_set = passthrough_character_set;
      this.dest_zeroth_char = dest_zeroth_char;
      this.input_string = new StringBuilder(source_string);
      this.trimmed_characters = new StringBuilder(source_string.length());
      this.formatted_output = new StringBuilder(source_string.length());//source_string);
      this.passthrough_processed = false;
      this.prefix_string = new StringBuilder();
      this.suffix_string = new StringBuilder();

      // Make sure the input characters are valid
      for (int idx = 0; idx < input_string.length(); idx++) {
        char c = source_string.charAt(idx);
        if (passthrough_character_set.indexOf(c) == -1 &&
          source_character_set.indexOf(c) == -1) {
            throw new IllegalArgumentException("Input string has invalid character:  '" + c + "'");
          }
      }
    }

    /**
     * Returns the current trimmed_characters value 
     *
     * @return    the trimmed_characters 
     */        
    public String get_trimmed_characters() 
    {
      if (verbose) System.out.println("before trimmed (" + passthrough_processed + "): " +  this.trimmed_characters.toString());
      if (!passthrough_processed) {
        ubiq_platform_efpe_parsing_parse_input();
      }
      if (verbose) System.out.println("after trimmed: " +  this.trimmed_characters.toString());
      return this.trimmed_characters.toString();
    }


    /**
     * Returns the current formatted_output value 
     *
     * @return    the formatted_output 
     */        
    public String get_formatted_output() 
    {
      if (verbose) System.out.println("before formatted_output (" + passthrough_processed + "): " +  this.formatted_output.toString());
      if (!passthrough_processed) {
        ubiq_platform_efpe_parsing_parse_input();
      }
      if (verbose) System.out.println("after formatted_output: " +  this.formatted_output.toString());
      return this.formatted_output.toString();
    }

    public String get_prefix_string() 
    {
      if (verbose) System.out.println("prefix_string: " +  this.prefix_string.toString());
      return this.prefix_string.toString();
    }

    public String get_suffix_string() 
    {
      if (verbose) System.out.println("suffix_string: " +  this.suffix_string.toString());
      return this.suffix_string.toString();
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
    public static String appendChar(String str, char ch) 
    {
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
    public static String replaceChar(String str, char ch, int position) 
    {
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
    public static String createString(int stringLength, String strCharacter)
    {
        StringBuilder sbString = new StringBuilder(stringLength);
        
        for(int i=0; i < stringLength; i++){
            sbString.append(strCharacter);
        }
        return sbString.toString();
    }
    
    
        

    /**
     * Performs parsing of a string based on an input character set and
     * applies the passthrough characters.  This takes into account prefix or 
     * suffix lengths that may have already been applied
     *
     * @return    -1 if error encountered  
     */    
    public int ubiq_platform_efpe_parsing_parse_input()
    {
        int err = 0;
        for (int idx = 0; idx < input_string.length(); idx++) {
          char c = input_string.charAt(idx);
          if (passthrough_character_set.indexOf(c) != -1) {
            // Valid passthrough character, copy the character to Formatted output
            formatted_output.append(c);//setCharAt(idx, c);
          } else if (source_character_set.indexOf(c) != -1) {
            // If input characterset character, add to trimmed and set the formatted to zeroth char.
            trimmed_characters.append(c);
            formatted_output.append(dest_zeroth_char);
          } 
        }
        passthrough_processed = true;

        return err;
      }
 
    public int process_prefix(final Integer prefix_length) 
    {
        if (!passthrough_processed) {
          prefix_string = new StringBuilder(input_string.substring(0, prefix_length));
          input_string.delete(0, prefix_length);
          if (verbose) System.out.println("prefix_string: " + prefix_string);
          if (verbose) System.out.println("input_string: " + input_string);
        } else {
          // This is after passthrough has been processed
          // Check formatted character to see if it is a passthrough or not.
          // If passthrough, move the character and loop
          // If not passthrough, move the trimmed.  In both cases, re,ove the formatted character.  It will be added later

          int i = 0;
          while (i < prefix_length) {
            if (passthrough_character_set.indexOf(formatted_output.charAt(0)) != -1) {
              prefix_string.append(formatted_output.charAt(0));
            } else {
              prefix_string.append(trimmed_characters.charAt(0));
              trimmed_characters.deleteCharAt(0);
              i++;
            }
            formatted_output.deleteCharAt(0);
          }
        }
        if (verbose) System.out.println("prefix_string: " + prefix_string);
        if (verbose) System.out.println("trimmed_characters: " + trimmed_characters);
        if (verbose) System.out.println("formatted_output: " + formatted_output);

      return 0;
    }

    public int process_suffix(final Integer suffix_length) 
    {
      if (!passthrough_processed) {
        suffix_string = new StringBuilder(input_string.substring(input_string.length() - suffix_length));
        input_string.delete(input_string.length() - suffix_length, input_string.length());
      } else {
        // This is after passthrough has been processed
        // Check formatted character to see if it is a passthrough or not.
        // If passthrough, move the character and loop
        // If not passthrough, move the trimmed.  In both cases, re,ove the formatted character.  It will be added later

        int i = 0;
        while (i < suffix_length) {
          char ch = formatted_output.charAt(formatted_output.length() - 1);
          if (passthrough_character_set.indexOf(ch) != -1) {
            suffix_string.insert(0, ch);
          } else {
            suffix_string.insert(0, trimmed_characters.charAt(trimmed_characters.length() - 1));
            trimmed_characters.deleteCharAt(trimmed_characters.length() - 1);
            i++;
          }
          formatted_output.deleteCharAt(formatted_output.length() - 1);
        }
      }
      
      return 0;
    }
}    


