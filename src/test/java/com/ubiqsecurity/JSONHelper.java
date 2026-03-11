package com.ubiqsecurity;

import java.io.FileReader;
import java.io.IOException;

import com.google.gson.JsonArray;
import com.google.gson.JsonParser;

public class JSONHelper {

  public static JsonArray parseDataArrayFile(String infilePath) throws IOException {

    JsonArray jsonArray = null;

    try (FileReader reader = new FileReader(infilePath)) {
        //Read JSON file
        Object obj = JsonParser.parseReader(reader);

        jsonArray = (JsonArray) obj;
    }
    return jsonArray;
}


}
