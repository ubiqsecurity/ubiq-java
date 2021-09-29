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




public class ParsingTest
{




    @Test
    public void simple() {
        String pt = "123-45-6789";
        String input_character_set = "0123456789";
        String passthrough_character_set = "-";
        
        String empty_formatted_output = Parsing.createString(pt.length(), "A");  
        String trimmed_output = Parsing.createString(pt.length(), "B");

     
        try (Parsing parsing = new Parsing(trimmed_output, empty_formatted_output)) {

            int status = parsing.ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set); 
            
            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), "123456789"); 
            assertEquals(parsing.get_empty_formatted_output(), "AAA-AA-AAAA");  
                
         }
    }





    @Test
    public void no_passthrough() {
        String pt = "123-45-6789";
        String input_character_set = "0123456789-";
        String passthrough_character_set = "";
        
        String empty_formatted_output = Parsing.createString(pt.length(), "A");  
        String trimmed_output = Parsing.createString(pt.length(), "B");

     
        try (Parsing parsing = new Parsing(trimmed_output, empty_formatted_output)) {

            int status = parsing.ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set); 
            
            assertEquals(status, 0);  
            assertEquals(parsing.get_trimmed_characters(), pt); 
                
         }
    }







    @Test
    public void invalid_data() {
        String pt = "123-45-6789";
        String input_character_set = "0123456789";
        String passthrough_character_set = "";
        
        String empty_formatted_output = Parsing.createString(pt.length(), "A");  
        String trimmed_output = Parsing.createString(pt.length(), "B");

     
        try (Parsing parsing = new Parsing(trimmed_output, empty_formatted_output)) {

            int status = parsing.ubiq_platform_efpe_parsing_parse_input(pt, input_character_set, passthrough_character_set); 
            
            assertEquals(status, -1);  
                
         }
    }








 

 





}
