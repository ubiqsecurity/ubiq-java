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

  }
