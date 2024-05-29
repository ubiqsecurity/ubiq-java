package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;
import java.math.BigInteger;


import java.util.Arrays;
import ubiqsecurity.fpe.FF1;
import ubiqsecurity.fpe.FF3_1;
import com.ubiqsecurity.UbiqFactory;

import java.util.concurrent.ExecutionException;


import java.util.*;
import org.junit.rules.ExpectedException;



public class ParsingTest
{
    @Test
    public void simple() {
        String pt = "123-45-6789";
        String input_character_set = "0123456789";
        String passthrough_character_set = "-";
        
        try (Parsing parsing = new Parsing(
          pt, input_character_set, passthrough_character_set, 'A')) {

            int status = parsing.ubiq_platform_efpe_parsing_parse_input(); 
            
            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), "123456789"); 
            assertEquals(parsing.get_formatted_output(), "AAA-AA-AAAA");  
                
         }
    }

    @Test
    public void prefix() {
        String pt = "123-45-6789";
        String input_character_set = "0123456789";
        String passthrough_character_set = "-";
        
        try (Parsing parsing = new Parsing(
          pt, input_character_set, passthrough_character_set, 'A')) {

            int status = parsing.ubiq_platform_efpe_parsing_parse_input(); 
            
            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), "123456789"); 
            assertEquals(parsing.get_formatted_output(), "AAA-AA-AAAA");  

            status = parsing.process_prefix(4);

            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), "56789"); 
            assertEquals(parsing.get_formatted_output(), "A-AAAA");  
            assertEquals(parsing.get_prefix_string(), "123-4");  


         }
    }

    @Test
    public void prefix_first() {
        String pt = "123-45-6789";
        String input_character_set = "0123456789";
        String passthrough_character_set = "-";
        
        try (Parsing parsing = new Parsing(
          pt, input_character_set, passthrough_character_set, 'A')) {

            int status = parsing.process_prefix(4);

            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), "456789"); 
            assertEquals(parsing.get_formatted_output(), "AA-AAAA");  
            assertEquals(parsing.get_prefix_string(), "123-");  


         }
    }

    @Test
    public void suffix() {
        String pt = "123-45-6789";
        String input_character_set = "0123456789";
        String passthrough_character_set = "-";
        
        try (Parsing parsing = new Parsing(
          pt, input_character_set, passthrough_character_set, 'A')) {

            int status = parsing.ubiq_platform_efpe_parsing_parse_input(); 
            
            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), "123456789"); 
            assertEquals(parsing.get_formatted_output(), "AAA-AA-AAAA");  

            status = parsing.process_suffix(5);

            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), "1234"); 
            assertEquals(parsing.get_formatted_output(), "AAA-A");  
            assertEquals(parsing.get_suffix_string(), "5-6789");  


         }
    }

    @Test
    public void suffix_first() {
        String pt = "123-45-6789";
        String input_character_set = "0123456789";
        String passthrough_character_set = "-";
        
        try (Parsing parsing = new Parsing(
          pt, input_character_set, passthrough_character_set, 'A')) {

            int status = parsing.process_suffix(5);

            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), "12345"); 
            assertEquals(parsing.get_formatted_output(), "AAA-AA");  
            assertEquals(parsing.get_suffix_string(), "-6789");  


         }
    }


    @Test
    public void suffix_prefix() {
        String pt = "--123-45-6789--";
        String input_character_set = "0123456789";
        String passthrough_character_set = "-";
        
        try (Parsing parsing = new Parsing(
          pt, input_character_set, passthrough_character_set, 'A')) {

            int status = parsing.process_suffix(6);
            assertEquals(status, 0);  
            status = parsing.process_prefix(5);

            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), "45"); 
            assertEquals(parsing.get_formatted_output(), "-AA-");  
            assertEquals(parsing.get_suffix_string(), "6789--");  
            assertEquals(parsing.get_prefix_string(), "--123");  
         }
    }

    @Test
    public void passthrough_suffix_prefix() {
        String pt = "--0123-4--0--5-67890--";
        String input_character_set = "0123456789";
        String passthrough_character_set = "-";
        
        try (Parsing parsing = new Parsing(
          pt, input_character_set, passthrough_character_set, 'A')) {

            int status = parsing.ubiq_platform_efpe_parsing_parse_input(); 
            assertEquals(status, 0);  
            status = parsing.process_suffix(6);
            assertEquals(status, 0);  
            status = parsing.process_prefix(5);

            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), "0"); 
            assertEquals(parsing.get_formatted_output(), "--A--");  
            assertEquals(parsing.get_suffix_string(), "5-67890--");  
            assertEquals(parsing.get_prefix_string(), "--0123-4");  
         }
    }
}
