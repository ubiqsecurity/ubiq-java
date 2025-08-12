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
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.Iterator;
import java.lang.Thread;


  class UnstructuredMultithreading implements Runnable {
      UbiqEncrypt encrypt;
      UbiqDecrypt decrypt;
      SecureRandom random;
      UbiqUnstructuredEncryptSession encryptSession = null;
      UbiqUnstructuredDecryptSession decryptSession = null;
      Integer size = 0;
      Integer count = 0;
      public Long average = 0L;

      UnstructuredMultithreading(UbiqEncrypt encrypt, UbiqDecrypt decrypt, SecureRandom random, Integer size, Integer count) {
        this.encrypt = encrypt;
        this.decrypt = decrypt;
        this.random = random;
        this.encryptSession = encrypt.initSession();
        this.decryptSession = decrypt.initSession();
        this.size = size;
        this.count = count;

      }

        public void run()
        {
          Boolean verbose = false;
          Instant s = Instant.now();
            try {
              for (int i = 1; i <= count; i++) {
                byte pt[] = new byte[size];
                random.nextBytes(pt);
                if (verbose) System.out.println(Thread.currentThread().getName() + ": before encrypt.begin");
                List<Byte> ctBytes = new ArrayList<Byte>();
                byte [] x  = this.encrypt.begin(encryptSession);
                ctBytes.addAll(Bytes.asList(x));

                if (verbose) System.out.println(Thread.currentThread().getName() + ": before encrypt.update");
                x = this.encrypt.update(encryptSession, pt, 0, pt.length);
                ctBytes.addAll(Bytes.asList(x));

                if (verbose) System.out.println(Thread.currentThread().getName() + ": before encrypt.end");
                x = this.encrypt.end(encryptSession);
                ctBytes.addAll(Bytes.asList(x));

                byte [] ct = Bytes.toArray(ctBytes);
                if (verbose) System.out.println(Thread.currentThread().getName() + " pt.length: " + pt.length);
                if (verbose) System.out.println(Thread.currentThread().getName() + " ct.length: " + ct.length);

                List<Byte> ptBytes = new ArrayList<Byte>();

                if (verbose) System.out.println(Thread.currentThread().getName() + ": before decrypt.begin");
                  byte [] y  = this.decrypt.begin(decryptSession);
                  ptBytes.addAll(Bytes.asList(y));

                if (verbose) System.out.println(Thread.currentThread().getName() + ": before decrypt.update");
                  y = this.decrypt.update(decryptSession, ct, 0, ct.length);
                  ptBytes.addAll(Bytes.asList(y));

                if (verbose) System.out.println(Thread.currentThread().getName() + ": before decrypt.end");
                  y = this.decrypt.end(decryptSession);
                  ptBytes.addAll(Bytes.asList(y));

                assertEquals(Arrays.equals(pt, Bytes.toArray(ptBytes)), true);
              }
            }
            catch (Exception e) {
                // Throwing an exception
                System.out.println(Thread.currentThread().getName() + " Exception is caught " + e.getMessage());
                e.printStackTrace();
                // System.out.println( e.getStackTrace());
                assertEquals(false, true);
            }
          Instant e = Instant.now();
          Long d = Duration.between(s, e).toNanos();
          if (verbose) System.out.println(Thread.currentThread().getName() + " Count: " + count);
          if (verbose) System.out.println(Thread.currentThread().getName() + " size: " + size);
          if (verbose) System.out.println(Thread.currentThread().getName() + " Thread: " + Thread.currentThread().getName() + ": \t  Average (uS): " + d / 1000 / count + ", Total(uS): " + d / 1000);
          average = (Long) (d / 1000 / count);
   
        }
    }

public class UbiqUnstructuredMultithreadTest
{

    @Test
    public void multithread() {
    UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(null,null,null,null);
    UbiqConfiguration cfg = UbiqFactory.defaultConfiguration();
    UbiqEncrypt encrypt = new UbiqEncrypt(ubiqCredentials,1, cfg);
    UbiqDecrypt decrypt = new UbiqDecrypt(ubiqCredentials, cfg);
    SecureRandom random = new SecureRandom();

    Collection<Thread> syncCollection = Collections.synchronizedCollection(new ArrayList<>());
    Collection<UnstructuredMultithreading> classCollection = Collections.synchronizedCollection(new ArrayList<>());

    Integer size = 5000;
    Integer count = 50000;
    
    int n = 25; // Number of threads
    for (int i = 0; i < n; i++) {
        UnstructuredMultithreading z = new UnstructuredMultithreading(encrypt, decrypt, random, size, count);
        classCollection.add(z);
        Thread object = new Thread(z);
        object.start();
        syncCollection.add(object);
    }
    try {
      Thread.sleep(1);
      Iterator<Thread> iterator = syncCollection.iterator();
      while (iterator.hasNext()) {
        iterator.next().join();
      // Use the element
      }
    } catch (InterruptedException e) {

    }
    Long average = 0L;
    Iterator<UnstructuredMultithreading> iterator = classCollection.iterator();
    while (iterator.hasNext()) {
      UnstructuredMultithreading x = iterator.next();
      average += x.average;
    }

    syncCollection.clear();
    classCollection.clear();

    System.out.println("Total Cycles: " + count * n + " \t in " + n + " threads with " + size + " bytes per cycle \t Average Time: (uS): " + average / n);

    encrypt.close();
    decrypt.close();

  }
}
