package com.ubiqsecurity;

import com.ubiqsecurity.structured.FF1;
import java.math.BigInteger;

import java.util.HashSet;
import java.util.Set;
import java.util.Arrays;

public class StringUtils {

  private static boolean verbose = false;

  public static String padLeft(Character c, long length, String s) {
    if (verbose) System.out.println("Character: '" + c + "'");
    if (verbose) System.out.println("length: '" + length + "'");
    if (verbose) System.out.println("s: '" + s + "'");
    String ret = s;
    if (s.length() < length) {
        ret = new String(new char[(int)length - s.length()]).replace('\0', c) + s;
    }
    return ret;
  }

  public static String convertRadix(String originalValue, String inputCharacters, String outputCharacters, final Boolean skipLengthCheck, Boolean leftPad) {
    final String csu = "convertRadix";

    if (verbose) System.out.printf("%s   : %s  originalValue: '%s'  inputCharacters: '%s' outputCharacters: '%s'\n",csu, new java.util.Date(), originalValue, inputCharacters, outputCharacters);

    // convert a given string to a numerical location based on a given Input_character_set
    BigInteger r1 = FF1.number(originalValue, inputCharacters);

    // Convert to output string - making sure to pad to original length
    String output = FF1.str(originalValue.length(), outputCharacters, r1, skipLengthCheck, leftPad);

    if (verbose) System.out.printf("%s   : %s  output: '%s'\n",csu, new java.util.Date(), output);
    return output;

  }

  public static String encodeKeyNumber(String str, String alphabet, long msbEncodingBits, int keyNumber) {

    char charBuf = str.charAt(0);

    int ct_value = alphabet.indexOf(charBuf);
    if (verbose) System.out.println("ct_value: " + ct_value);

    ct_value =  ct_value + (keyNumber << msbEncodingBits);

    char ch = alphabet.charAt(ct_value);
    str = Parsing.replaceChar(str, ch, 0);

    return str;
  }

  // Using an array for KeyNumber as simple In / Out parameter.  Other options were possible but this helps make it clear
  public static String decodeKeyNumber(String str, String alphabet, long msbEncodingBits, Integer[] keyNumber) {
    int key_num = 0;

        char charBuf = str.charAt(0);
        int encoded_value = alphabet.indexOf(charBuf);

        key_num =  encoded_value >> msbEncodingBits;

        char ch = alphabet.charAt(encoded_value - (key_num << msbEncodingBits));
        str = Parsing.replaceChar(str, ch, 0);

        keyNumber[0] = key_num;

    return str;
  }
  public static String trimStart(String str, int len) {
    return str.substring(0, str.length() - len);
  }
  public static String trimEnd(String str, int len) {
    return str.substring(len);
  }
  public static String trimLeftPad(String str, Character trimChar) {
    String ret = null;
    int idx = -1;
    if (str.charAt(0) == trimChar) {
      idx = 1;
      while (idx < str.length() && str.charAt(idx) == trimChar) {
        idx++;
      }
    }
    if (idx >= 0) {
      ret = str.substring(idx);
    } else {
      ret = str;
    }
    return ret;
  }

  public static String formatToTemplate(String  input, String template, String passthroughCharacters) {
    char[] templateCharacters = template.toCharArray();
    int j = 0;
    Set<Character> passthroughCharacterSet = new HashSet<>();
    for (char c : passthroughCharacters.toCharArray()) {
        passthroughCharacterSet.add(c);
    }

    for (int i = 0; i < templateCharacters.length; i++)
    {
        char ch = templateCharacters[i];
        if (passthroughCharacterSet.contains(ch))
        {
            continue;
        }

        if (j >= input.length()) {
            throw new IllegalArgumentException("Input length does not match template");
        }

        templateCharacters[i] = input.charAt(j);
        j += 1;
    }

    if (j != input.length()) {
            throw new IllegalArgumentException("Input length does not match template");
    }

    return new String(templateCharacters);
  }

  public static Boolean isNullOrEmpty(String str) {
    return (str == null || str.trim().isEmpty());
  }
  public static Boolean isNullOrEmpty(Character ch) {
    return (ch == null);
  }
}
