package com.ubiqsecurity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.crypto.InvalidCipherTextException;
import java.util.concurrent.TimeUnit;

public class UbiqDecrypt implements AutoCloseable {
    private boolean verbose= false;
    private UbiqWebServices ubiqWebServices; // null on close

    private DecryptionKeyResponse decryptionKey;
    private BillingEvents billing_events;
    private BillingEventsProcessor executor;
    private UbiqCredentials ubiqCredentials;
    private UbiqConfiguration ubiqConfiguration;
    private UnstructuredKeyCache unstructuredKeyCache;
    private UbiqUnstructuredDecryptSession session; // For compatibility of non-threadsafe methods

    public UbiqDecrypt(UbiqCredentials ubiqCredentials) {
      this(ubiqCredentials, UbiqFactory.defaultConfiguration());
    }

    public UbiqDecrypt(UbiqCredentials ubiqCredentials, UbiqConfiguration ubiqConfiguration) {
      this.ubiqCredentials = ubiqCredentials;
      this.ubiqConfiguration = ubiqConfiguration;
      this.ubiqWebServices = new UbiqWebServices(ubiqCredentials, this.ubiqConfiguration);
      this.unstructuredKeyCache = new UnstructuredKeyCache(this.ubiqWebServices,this.ubiqConfiguration);

      billing_events = new BillingEvents(this.ubiqConfiguration);
      executor = new BillingEventsProcessor(this.ubiqWebServices, this.billing_events, this.ubiqConfiguration);
      executor.startAsync();

      this.session = null;

    }

    public UbiqUnstructuredDecryptSession initSession() {
      if (this.ubiqWebServices == null) {
          throw new IllegalStateException("object closed");
      } 
      return new UbiqUnstructuredDecryptSession();
    }

    public void close() {
      String csu = "close";
      if (verbose) System.out.println(csu);
      if (this.ubiqWebServices != null) {

            // this stops any remaining background billing processing
            try {
              if (executor != null) {
                executor.stopAsync().awaitTerminated(5, TimeUnit.SECONDS);
              }
            } catch (Exception e) {
               System.out.printf("%s   : %s Exception %s  messasge: %s\n", csu,new java.util.Date(),  e.getClass().getName(), e.getMessage());
            }            

            reset();

            this.ubiqWebServices = null;
        }
    }

    /**
     * Begin the decryption process and return decrypted bytes
     * @return - decrypted bytes
     * 
     * @throws IllegalStateException if the object have not been initialized correctly
     * @deprecated use instance method begin(UbiqUnstructuredDecryptSession session) instead.  
     */
    @Deprecated
    public byte[] begin() throws IllegalStateException {
       if (this.session != null && this.session.inUse()) {
          throw new IllegalStateException("encryption in progress");
      }
      this.session = initSession();
      return begin(this.session);
    }

    /**
     * Begin the decryption process and return decrypted bytes
     * @param session Session object to manage state between begin, update, and end calls
     * @return - decrypted bytes
     * 
     * @throws IllegalStateException if the object have not been initialized correctly
     */
    public byte[] begin(UbiqUnstructuredDecryptSession session) throws IllegalStateException {

        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        } else if (session.inUse()) {
          throw new IllegalStateException("Session is already in use");
        }

        // note: cached 'decryptionKey' may be present from a previous decryption run

        return new byte[0];
    }

    /**
     * Continue the decryption process with the additional cipher text bytes passed in

     * @param cipherBytes Source data to decrypt
     * @param offset Offset into the source data
     * @param count Number of bytes to use
     * @return - decrypted bytes
     * @deprecated use instance method update(UbiqUnstructuredDecryptSession session, ...) instead.  
     */
    @Deprecated
    public byte[] update(byte[] cipherBytes, int offset, int count) {
      return update(this.session, cipherBytes, offset, count);
    }

    /**
     * Continue the decryption process with the additional cipher text bytes passed in

     * @param session Session object to manage state between begin, update, and end calls
     * @param cipherBytes Source data to decrypt
     * @param offset Offset into the source data
     * @param count Number of bytes to use
     * @return - decrypted bytes
     */

    // Each encryption has a header on it that identifies the algorithm
    // used and an encryption of the data key that was used to encrypt
    // the original plain text. There is no guarantee how much of that
    // data will be passed to this function or how many times this
    // function will be called to process all of the data. to that end,
    // this function buffers data internally, when it is unable to
    // process it.

    // The function buffers data internally until the entire header is
    // received. Once the header has been received, the encrypted data
    // key is sent to the server for decryption. After the header has
    // been successfully handled, this function always decrypts all of
    // the data in its internal buffer.
    public byte[] update(UbiqUnstructuredDecryptSession session, byte[] cipherBytes, int offset, int count) {
        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        } else if (session == null) { // Cannot check cipher because it cannot be built until data is seen
            throw new RuntimeException("session not initialized");
        }

        byte[] plainBytes = new byte[0]; // returned

        // make sure new data is appended to end
        session.getByteQueue().enqueue(cipherBytes, offset, count);

        if (session.getCipherHeader() == null) {
            // see if we've got enough data for the header record
            try (ByteArrayInputStream byteStream = new ByteArrayInputStream(session.getByteQueue().peek())) {
                session.setCipherHeader(CipherHeader.deserialize(byteStream));
            } catch (IOException ex) {
                System.out.println("stream exception");
                // keep going anyway...
            }

            if (session.getCipherHeader() != null) {
                // success: prune cipher header bytes from the buffer
               session.getByteQueue().dequeue(session.getCipherHeader().calcLength());

                try {
                // JIT: request encryption key from server.  Will return from cache
                this.decryptionKey = this.unstructuredKeyCache.unstructuredCache.get(Base64.getEncoder().encodeToString(session.getCipherHeader().encryptedDataKeyBytes));

                // Cache may or may not have unwrapped key.  Will not be set if 
                // configuration wants cache encrypted.
                byte[] unwrappedDataKey = this.decryptionKey.UnwrappedDataKey;
                if (unwrappedDataKey.length == 0) {
                  unwrappedDataKey = ubiqWebServices.getUnwrappedKey(this.decryptionKey.EncryptedPrivateKey, this.decryptionKey.WrappedDataKey);
                }

                if (this.decryptionKey != null) {
                    AlgorithmInfo algorithmInfo = new AlgorithmInfo(session.getCipherHeader().algorithmId);

                    // create decryptor from header-specified algorithm + server-supplied decryption key
                    AesGcmBlockCipher aesGcmBlockCipher = new AesGcmBlockCipher(false, algorithmInfo,
                            unwrappedDataKey, session.getCipherHeader().initVectorBytes,
                            ((session.getCipherHeader().flags & CipherHeader.FLAGS_AAD_ENABLED) != 0)
                                ? session.getCipherHeader().serialize()
                                : null);
                    session.setCipher(aesGcmBlockCipher);
                    billing_events.addBillingEvent(ubiqCredentials.getAccessKeyId(), "", "", BillingEvents.BillingAction.DECRYPT, BillingEvents.DatasetType.UNSTRUCTURED, 0,1);
                }
              } catch (ExecutionException e) {
                e.printStackTrace();
              }

            } else {
                // holding pattern... need more header bytes
                return plainBytes;
            }
        }

        // If we get this far, assume we have a valid header record.
        assert session.getCipherHeader() != null;

        if ((this.decryptionKey != null) && session.inUse()) {
            // pass all available buffered bytes to the decryptor
            if (session.getByteQueue().getLength() > 0) {
                byte[] bufferedBytes = session.getByteQueue().dequeue(session.getByteQueue().getLength());
                plainBytes = session.getCipher().update(bufferedBytes, 0, bufferedBytes.length);
            }
        }

        return plainBytes;
    }

    /**
     * End the decryption process and return any remaining decrypted data
     * @return - decrypted bytes
     * 
     * @throws IllegalStateException if the object have not been initialized correctly
     * @throws InvalidCipherTextException if an exception was encountered while decrypting the data
     * @deprecated use instance method end(UbiqUnstructuredDecryptSession session instead.  
     */
    @Deprecated
    public byte[] end() throws IllegalStateException, InvalidCipherTextException {
          return end(this.session);
    }

    /**
     * End the decryption process and return any remaining decrypted data
     * @param session Session object to manage state between begin, update, and end calls
     * @return - decrypted bytes
     * 
     * @throws IllegalStateException if the object have not been initialized correctly
     * @throws InvalidCipherTextException if an exception was encountered while decrypting the data
     */
    public byte[] end(UbiqUnstructuredDecryptSession session) throws IllegalStateException, InvalidCipherTextException {
        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        } else if ((session == null) || (!session.inUse())) {
            throw new RuntimeException("session not initialized");
        }

        byte[] finalPlainBytes = session.getCipher().doFinal();
        session.close();
        return finalPlainBytes;
    }

    
    public static byte[] decrypt(UbiqCredentials ubiqCredentials, byte[] data)
            throws IllegalStateException, InvalidCipherTextException {
        return decrypt(ubiqCredentials, data, UbiqFactory.defaultConfiguration());
    }

    public static byte[] decrypt(UbiqCredentials ubiqCredentials, byte[] data, UbiqConfiguration ubiqConfiguration)
            throws IllegalStateException, InvalidCipherTextException {
        try (UbiqDecrypt ubiqDecrypt = new UbiqDecrypt(ubiqCredentials, ubiqConfiguration)) {
            try (ByteArrayOutputStream plainStream = new ByteArrayOutputStream()) {

                UbiqUnstructuredDecryptSession session = ubiqDecrypt.initSession();

                plainStream.write(ubiqDecrypt.begin(session));
                plainStream.write(ubiqDecrypt.update(session, data, 0, data.length));
                plainStream.write(ubiqDecrypt.end(session));

                return plainStream.toByteArray();
            } catch (IOException ex) {
                System.out.println("stream exception");
                return null;
            }
        }
    }

    // Reset the internal state of the decryption object.
    // This function can be called at any time to abort an existing
    // decryption operation.  It is also called by internal functions
    // when a new decryption requires a different key than the one
    // used by the previous decryption.
    private void reset() {
        assert this.ubiqWebServices != null;

        if (decryptionKey != null) {
            this.decryptionKey = null;
        }

        this.session = null;
    }

    public void addReportingUserDefinedMetadata(String jsonString) {
      billing_events.addUserDefinedMetadata(jsonString);
    }

    public String getCopyOfUsage() {
      return billing_events.getSerializedData();
    }
 
}
