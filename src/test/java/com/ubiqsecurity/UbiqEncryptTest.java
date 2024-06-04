package com.ubiqsecurity;

import org.junit.Test;
import static org.junit.Assert.*;
import com.ubiqsecurity.UbiqFactory;
import java.util.concurrent.ExecutionException;
import java.util.*;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import java.io.IOException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import com.google.common.primitives.Bytes;


public class UbiqEncryptTest
{

    static void testSimpleRt(byte[] plainText,UbiqCredentials ubiqCredentials)
      throws InvalidCipherTextException {

      byte[] cipherBytes = UbiqEncrypt.encrypt(ubiqCredentials, plainText);

      byte[] plainBytes = UbiqDecrypt.decrypt(ubiqCredentials, cipherBytes);

      assertEquals(plainBytes.length, plainText.length);
      for (int i = 0;i < plainBytes.length; i++) {
        assertEquals(plainBytes[i], plainText[i]);
      }


    }

    static void testPiecewiseRt(byte[] plainText,UbiqCredentials ubiqCredentials) 
    throws InvalidCipherTextException {

      UbiqEncrypt ubiqEncrypt = new UbiqEncrypt(ubiqCredentials, 1);
      UbiqDecrypt ubiqDecrypt = new UbiqDecrypt(ubiqCredentials);

      List<Byte> cipherBytes = new ArrayList<Byte>();

      byte [] x  = ubiqEncrypt.begin();
      for (byte y : x) {
        cipherBytes.add(y);
      }

      x = ubiqEncrypt.update(plainText, 0, plainText.length);
      for (byte y : x) {
        cipherBytes.add(y);
      }

      x = ubiqEncrypt.end();
      for (byte y : x) {
        cipherBytes.add(y);
      }

      byte[] cipherData = Bytes.toArray(cipherBytes);

      List<Byte> plainBytes = new ArrayList<Byte>();

      x  = ubiqDecrypt.begin();
      for (byte y : x) {
        plainBytes.add(y);
      }

      x = ubiqDecrypt.update(cipherData, 0, cipherData.length);
      for (byte y : x) {
        plainBytes.add(y);
      }

      x = ubiqDecrypt.end();
      for (byte y : x) {
        plainBytes.add(y);
      }

      byte[] plainData = Bytes.toArray(plainBytes);

      assertEquals(plainData.length, plainText.length);
      for (int i = 0;i < plainData.length; i++) {
        assertEquals(plainData[i], plainText[i]);
      }

      ubiqEncrypt.close();
      ubiqDecrypt.close();

    }

    static void testRt(byte[] plainText) {
      UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);

      try {

        testSimpleRt(plainText, ubiqCredentials);
        testPiecewiseRt(plainText, ubiqCredentials);
      } catch (Exception ex) {
        System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
        ex.printStackTrace();
        fail(ex.toString());
      }

    }



    @Test
    public void encrypt_simple() {
        testRt("ABC".getBytes());
    }

    @Test
    public void encrypt_aes_block_size() {
        testRt("ABCDEFGHIJKLMNOP".getBytes());
    }

    @Test
    public void encrypt_aes_block_size_2xm1() {
        testRt("ABCDEFGHIJKLMNOPQRSTUVWXYZ01234".getBytes());
    }

    @Test
    public void encrypt_aes_block_size_2x() {
        testRt("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345".getBytes());
    }

    @Test
    public void encrypt_aes_block_size_2xp1() {
        testRt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456".getBytes());
    }

    @Test
    public void addReportingUserDefinedMetadataTest(){
      UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
      UbiqEncrypt ubiqEncrypt = new UbiqEncrypt(ubiqCredentials, 1);
      UbiqDecrypt ubiqDecrypt = new UbiqDecrypt(ubiqCredentials);

      Throwable exception = assertThrows(IllegalArgumentException.class, () -> ubiqEncrypt.addReportingUserDefinedMetadata(""));
      exception = assertThrows(IllegalArgumentException.class, () -> ubiqEncrypt.addReportingUserDefinedMetadata(null));
      exception = assertThrows(IllegalArgumentException.class, () -> ubiqEncrypt.addReportingUserDefinedMetadata("null"));
      ubiqEncrypt.addReportingUserDefinedMetadata("{\"long\" : \"" + String.format("%-5s", "a") + "\"}"); // To prove short format works
      exception = assertThrows(IllegalArgumentException.class, () -> ubiqEncrypt.addReportingUserDefinedMetadata("{\"long\" : \"" + String.format("%-1025s", "a") + "\"}"));

      exception = assertThrows(IllegalArgumentException.class, () -> ubiqDecrypt.addReportingUserDefinedMetadata(""));
      exception = assertThrows(IllegalArgumentException.class, () -> ubiqDecrypt.addReportingUserDefinedMetadata(null));
      exception = assertThrows(IllegalArgumentException.class, () -> ubiqDecrypt.addReportingUserDefinedMetadata("null"));
      ubiqDecrypt.addReportingUserDefinedMetadata("{\"long\" : \"" + String.format("%-5s", "a") + "\"}"); // To prove short format works
      exception = assertThrows(IllegalArgumentException.class, () -> ubiqDecrypt.addReportingUserDefinedMetadata("{\"long\" : \"" + String.format("%-1025s", "a") + "\"}"));

      ubiqEncrypt.close();
      ubiqDecrypt.close();

    }

    static byte[] encrypt(UbiqEncrypt ubiqEncrypt, byte[] pt) throws InvalidCipherTextException {
      List<Byte> cipherBytes = new ArrayList<Byte>();

      byte [] x  = ubiqEncrypt.begin();
      for (byte y : x) {
        cipherBytes.add(y);
      }

      x = ubiqEncrypt.update(pt, 0, pt.length);
      for (byte y : x) {
        cipherBytes.add(y);
      }

      x = ubiqEncrypt.end();
      for (byte y : x) {
        cipherBytes.add(y);
      }

      return Bytes.toArray(cipherBytes);
    }

    static byte[] decrypt(UbiqDecrypt ubiqDecrypt, byte[] ct) throws InvalidCipherTextException {
      List<Byte> ptBytes = new ArrayList<Byte>();

      byte [] x  = ubiqDecrypt.begin();
      for (byte y : x) {
        ptBytes.add(y);
      }

      x = ubiqDecrypt.update(ct, 0, ct.length);
      for (byte y : x) {
        ptBytes.add(y);
      }

      x = ubiqDecrypt.end();
      for (byte y : x) {
        ptBytes.add(y);
      }

      return Bytes.toArray(ptBytes);
    }


    @Test
    public void unstructuredUsageGrouping(){
      try {
      byte[] pt = "ABC".getBytes();

      UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
      // Make sure usage doesn't get flushed too soon so get copy of usage will include
      // results to two calls.
      UbiqConfiguration ubiqConfiguration = UbiqFactory.createConfiguration(90,90,90,false);
      UbiqEncrypt ubiqEncrypt = new UbiqEncrypt(ubiqCredentials, 1, ubiqConfiguration);
      UbiqDecrypt ubiqDecrypt = new UbiqDecrypt(ubiqCredentials, ubiqConfiguration);

      // Two encrypts should be same length and have a record that says "count":2
      byte[] cipherData = encrypt(ubiqEncrypt, pt);
      String usage = ubiqEncrypt.getCopyOfUsage();

      cipherData = encrypt(ubiqEncrypt, pt);
      String usage2 = ubiqEncrypt.getCopyOfUsage();

      System.out.println("usage: " + usage + "\tusage2: " + usage);

      assertEquals(usage.length(), usage2.length());
      assertEquals(usage2.contains("\"count\":2"), true);

      // Two decrypts should be same length and have a record that says "count":2
      byte[] ptData = decrypt(ubiqDecrypt, cipherData);
      usage = ubiqDecrypt.getCopyOfUsage();

      ptData = decrypt(ubiqDecrypt, cipherData);
      usage2 = ubiqDecrypt.getCopyOfUsage();

      assertEquals(usage.length(), usage2.length());
      assertEquals(usage2.contains("\"count\":2"), true);

      ubiqEncrypt.close();
      ubiqDecrypt.close();
      } catch (Exception ex) {
        System.out.println(String.format("****************** Exception: %s", ex.getMessage()));
        ex.printStackTrace();
        fail(ex.toString());
      }

    }

  }
