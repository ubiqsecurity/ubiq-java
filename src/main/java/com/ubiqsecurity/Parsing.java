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
    private StringBuilder trimmed_characters;  // Preallocated and filled with char[0] from input characterset.  Should be same length as input string
    private StringBuilder formatted_output; // Preallocated and filled with char[0] from OUTPUT characterset, Should be same length as input string
    // private Integer first_empty_idx; // Location of first cell in formatted output that is considered available.
    private boolean passthrough_processed = false;
    private StringBuilder prefix_string;
    private StringBuilder suffix_string;

    private char dest_zeroth_char;
    private String source_character_set;
    private String passthrough_character_set;


    /*
     * Constructor assumes default redaction Symbol
     *
    //  * @param trimmed_characters filled with char[0] from input characterset
    //  * @param formatted_output filled with char[0] from OUTPUT characterset
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
      // this.first_empty_idx = 0;

      // Make sure the input characters are valid
      for (int idx = 0; idx < input_string.length(); idx++) {
        char c = source_string.charAt(idx);
        if (passthrough_character_set.indexOf(c) == -1 &&
          source_character_set.indexOf(c) == -1) {
            throw new IllegalArgumentException("Input string has invalid character:  '" + c + "'");
          }
        // {
        //   // Valid passthrough character, move the character to Formatted
        //   formatted_output.setCharAt(idx, c);
        // } else if (source_character_set.indexOf(c) != -1) {
        //   // If input characterset, add to trimmed and set the formatted to zeroth char.
        //   trimmed_characters.append(c);
        //   formatted_output.setCharAt(idx, dest_zeroth_char);
        // } else {
        //   // System.out.println("Invalid character");
        //   throw new IllegalArgumentException("Input string has invalid character:  '" + c + "'");
        // }
      }
    }

    // public Parsing(String trimmed_characters, String formatted_output) {
    //     this.trimmed_characters = new StringBuilder(trimmed_characters);
    //     this.formatted_output = new StringBuilder(formatted_output);
    //     this.first_empty_idx = 0;
    // }
    
    
    /**
     * Returns the current trimmed_characters value 
     *
     * @return    the trimmed_characters 
     */        
    public String get_trimmed_characters() {
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
    public String get_formatted_output() {
      if (verbose) System.out.println("before formatted_output (" + passthrough_processed + "): " +  this.formatted_output.toString());
      if (!passthrough_processed) {
        ubiq_platform_efpe_parsing_parse_input();
      }
      if (verbose) System.out.println("after formatted_output: " +  this.formatted_output.toString());
      return this.formatted_output.toString();
    }

    public String get_prefix_string() {
      if (verbose) System.out.println("prefix_string: " +  this.prefix_string.toString());
      return this.prefix_string.toString();
    }

    public String get_suffix_string() {
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
        // final String input_string, 
        // final String input_character_set, 
        // final String passthrough_character_set 
      )
      {
        int err = 0;
        for (int idx = 0; idx < input_string.length(); idx++) {
          char c = input_string.charAt(idx);
          if (passthrough_character_set.indexOf(c) != -1) {
            // Valid passthrough character, move the character to Formatted
            formatted_output.append(c);//setCharAt(idx, c);
          } else if (source_character_set.indexOf(c) != -1) {
            // If input characterset, add to trimmed and set the formatted to zeroth char.
            trimmed_characters.append(c);
            formatted_output.append(dest_zeroth_char);
            // formatted_output.setCharAt(idx, dest_zeroth_char);
          } 
        }


        // int err = 0;
        // // Find first not passthrough character
        // while (first_empty_idx < formatted_output.length()) {
        //   System.out.println( "Passthrough\tfirst_empty_idx: " + first_empty_idx );
        //   if (passthrough_character_set.indexOf(formatted_output.charAt(first_empty_idx)) == -1) {
        //     break;
        //   }
        //   first_empty_idx++;
        // }
        passthrough_processed = true;
        // int d = first_empty_idx;
        // for (int i = 0; i < input_string.length(); i++) {
        //   if (passthrough_character_set.indexOf(input_string.charAt(i)) != -1) {
        //     formatted_output.setCharAt(first_empty_idx + i, input_string.charAt(i));
        //   }
        // }

        // int i = 0;
        // int err = 0;
        // char ch = '0';
        // int trimmedSize = 0;
        // passthrough_processed = true;

        // while ((i < input_string.length()) && (err ==0)) {
        //     // ch = input_string.charAt(i);
    
        //     // If the input string matches a passthrough character, copy to empty formatted output string
        //     if ( (passthrough_character_set!= null) && (passthrough_character_set.indexOf(ch) != -1) ) {
        //         this.formatted_output = replaceChar(this.formatted_output, ch, i);
        //     }
        //     // If the string is in the input character set, copy to trimmed characters
        //     else if (input_character_set.indexOf(ch) != -1) {
        //         this.trimmed_characters = replaceChar(this.trimmed_characters, ch, trimmedSize);
        //         trimmedSize++;
        //         if (first_empty_idx == null) {
        //           // Save the location of the first non passthrough character in the formatted output
        //           first_empty_idx = i;
        //         }
        //     }
        //     else {
        //         if (verbose) System.out.println("        input_string:  " + input_string);
        //         if (verbose) System.out.println("        input_character_set:  " + input_character_set);
        //         if (verbose) System.out.println("        passthrough_character_set:  " + passthrough_character_set);
        //         err = -1;
                
        //         throw new IllegalArgumentException("Input string has invalid character:  '" + ch + "'");
        //     }
        //     i++;
        // }

        // // Trimmed may be shorter than input so make sure to resize
        // this.trimmed_characters = this.trimmed_characters.substring(0, trimmedSize);

        return err;
      }
 
      public int process_prefix(
        final Integer prefix_length) {

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


        // Move prefix characters from trimmed to formatted.

        // If the passthrough has already been processed, skip over formatted output that
        // contains passthrough characters.

        // int i = 0;
        // // int dest_idx = 0;
        // while (i < prefix_length) {
        //   System.out.println("Prefix \tfirst_empty_idx: " + first_empty_idx + "\ti: " + i);
        //   if (passthrough_processed) {
        //     // first_empty_idx should be correct.  Simply need to move input trimmed characters to formatted but skip over passthrough in dest.
        //     while (passthrough_character_set.indexOf(formatted_output.charAt(first_empty_idx)) != -1 && first_empty_idx < formatted_output.length()) {
        //       // dest_idx++;
        //       first_empty_idx++;
        //     }

        //     if (first_empty_idx >= formatted_output.length()) {
        //       System.out.println("Throw Exception");
        //     }

        //     formatted_output.setCharAt(first_empty_idx, trimmed_characters.charAt(0));
        //     trimmed_characters.deleteCharAt(0);
        //     first_empty_idx++;
        //     // dest_idx++;

        //     // if (formatted_output.indexOf(trimmed_characters.charAt(i)))
        //     //   formatted_output.setCharAt(first_empty_idx, trimmed_characters.charAt(0));
        //     //   trimmed_characters.deleteCharAt(0);
        //     //   first_empty_idx++;
        //     // }
        //   } else {
        //     // Move trimmed characters to formatted as long as formmatted is not a passthrough character
        //     // first_empty_idx is not yet set
        //     // for (int idx = 0; idx < prefix_length; idx++) {
        //       if (passthrough_character_set.indexOf(formatted_output.charAt(i)) == -1) {
        //         formatted_output.setCharAt(i, trimmed_characters.charAt(0));
        //         trimmed_characters.deleteCharAt(0);
                
        //       } else {
        //         // Simply treat this is that character has been moved since it basically was but was passthrough character.
        //       }
        //       first_empty_idx++;
        //     // }
        //   }
        //   i++;



            // Skip over passthrough characters in destination
          //   while (passthrough_character_set.indexOf(this.formatted_output.charAt(dest_idx)) != -1) {
          //     dest_idx++;
          //     first_empty_idx++;
          //   }
          //   formatted_output.setCharAt(dest_idx, trimmed_characters.charAt(0));
          //   dest_idx++;
          //   trimmed_characters.deleteCharAt(0);
          //   // trimmed_characters = trimmed_characters.substring(1);
          // } else {

          //   // Passthrough has not been processed but only copy over a source character 
          //   // if the dest is not a passthrough.  Otherwise count the move and go to next dest
          //   if (passthrough_character_set.indexOf(trimmed_characters.charAt(0)) == -1) {
          //     // formatted_output = replaceChar(formatted_output, trimmed_characters.charAt(0), dest_idx);
          //     formatted_output.setCharAt(dest_idx, trimmed_characters.charAt(0));
          //     //              trimmed_characters = trimmed_characters.substring(1);
          //     trimmed_characters.deleteCharAt(0);
          //   }
          //   dest_idx++;
          // }
          // first_empty_idx++;
          // i++;
        // }
        return 0;
      }

      public int process_suffix(final Integer suffix_length) {


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
        

        // Move prefix characters from trimmed to formatted.

        // If the passthrough has already been processed, skip over formatted output that
        // contains passthrough characters.

//         int i = 0;
//         int dest_idx = formatted_output.length() - 1;
//         int src_idx = trimmed_characters.length() - 1;
//         while (i < suffix_length) {
//           System.out.println("suffix \ti: " + i + "\tdest_idx: " + dest_idx + "\tsrc_idx: " + src_idx +
//           "\tformatted_output: " + formatted_output + "\ttrimmed_characters: "+trimmed_characters);
//           if (passthrough_processed) {
//             // Skip over passthrough characters in destination
//             if (passthrough_character_set != null)  {
//               while (passthrough_character_set.indexOf(formatted_output.charAt(dest_idx)) != -1 && dest_idx >= 0) {
//                 dest_idx--;
//               }
//             }
//             if (dest_idx < 0) {

//             }
//             formatted_output.setCharAt(dest_idx, trimmed_characters.charAt(src_idx)); // = replaceChar(formatted_output, trimmed_characters.charAt(src_idx), dest_idx);
//             dest_idx--;
//             trimmed_characters.deleteCharAt(trimmed_characters.length() - 1);// = trimmed_characters.substring(0, trimmed_characters.length() - 1);
//             System.out.println("\tsuffix \ti: " + i + "\tdest_idx: " + dest_idx + "\tsrc_idx: " + src_idx +
//               "\tformatted_output: " + formatted_output + "\ttrimmed_characters: "+trimmed_characters);
//             } else {
//             // Passthrough has not been processed but only copy ofver a source character 
//             // if the dest is not a passthrough.  Otherwise count the move and go to next dest
//             if ( passthrough_character_set != null) {
//               formatted_output.setCharAt(dest_idx, trimmed_characters.charAt(src_idx)); // = replaceChar(formatted_output, trimmed_characters.charAt(src_idx), dest_idx);
//               // formatted_output = replaceChar(formatted_output, trimmed_characters.charAt(src_idx), dest_idx);
// //              trimmed_characters = trimmed_characters.substring(0, trimmed_characters.length() - 1);
//               trimmed_characters.deleteCharAt(trimmed_characters.length() - 1);// = trimmed_characters.substring(0, trimmed_characters.length() - 1);
//             }
//             dest_idx--;
//             System.out.println("\tsuffix \ti: " + i + "\tdest_idx: " + dest_idx + "\tsrc_idx: " + src_idx +
//               "\tformatted_output: " + formatted_output + "\ttrimmed_characters: "+trimmed_characters);
//           }
//           src_idx--;
//           i++;
//         }
        return 0;
      }

      Integer getFormattedFirstEmptyIdx() {
        return 0;// first_empty_idx;
      }

}    


