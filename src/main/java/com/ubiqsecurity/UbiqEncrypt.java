package com.ubiqsecurity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.InvalidCipherTextException;

public class UbiqEncrypt implements AutoCloseable {
    private boolean verbose= false;
    private int usesRequested;

    private UbiqWebServices ubiqWebServices; // null when closed
    private EncryptionKeyResponse encryptionKey;
    private BillingEvents billing_events;
    private BillingEventsProcessor executor;
    private UbiqCredentials ubiqCredentials;
    private UbiqConfiguration ubiqConfiguration;
    private UbiqUnstructuredEncryptSession session; // For compatibility of non-threadsafe methods

    public UbiqEncrypt(UbiqCredentials ubiqCredentials, int usesRequested) {
      this(ubiqCredentials, usesRequested, UbiqFactory.defaultConfiguration());
    }
   

    public UbiqEncrypt(UbiqCredentials ubiqCredentials, int usesRequested, UbiqConfiguration ubiqConfiguration) {
        this.usesRequested = usesRequested;
        this.ubiqCredentials = ubiqCredentials;
        this.ubiqConfiguration = ubiqConfiguration;

        this.ubiqWebServices = new UbiqWebServices(ubiqCredentials, this.ubiqConfiguration);

        billing_events = new BillingEvents(this.ubiqConfiguration);
        executor = new BillingEventsProcessor(this.ubiqWebServices, this.billing_events, this.ubiqConfiguration);
        executor.startAsync();

        if (this.encryptionKey == null) {
          // Get key at start to improve caching later.  Warm up can be done once and 
          // key reused later
          this.encryptionKey = this.ubiqWebServices.getEncryptionKey(this.usesRequested);
        }
        this.session = null;

    }

    public UbiqUnstructuredEncryptSession initSession() {
      if (this.ubiqWebServices == null) {
          throw new IllegalStateException("object closed");
      } 
      return new UbiqUnstructuredEncryptSession();
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

          this.ubiqWebServices = null;
      }
    }

    
    /**
     * Begin the encryption process and return encrypted bytes
     * @return - encrypted bytes
     * 
     * @deprecated use instance method begin(UbiqUnstructuredEncryptSession session) instead.  
     */
    @Deprecated
    public byte[] begin() {
      if (this.session != null && this.session.inUse()) {
          throw new IllegalStateException("encryption in progress");
      }

      this.session = initSession();
      return begin(this.session);

    }

    
    /**
     * Begin the encryption process and return encrypted bytes
     * @param session Session object to manage state between begin, update, and end calls
     * @return - encrypted bytes
     * 
     */
    public byte[] begin(UbiqUnstructuredEncryptSession session) {

        if (session == null) {
            throw new IllegalStateException("Session was not created");
        } else if (session.inUse()) {
          throw new IllegalStateException("Session is already in use");
        }

        billing_events.addBillingEvent(ubiqCredentials.getAccessKeyId(), "", "", BillingEvents.BillingAction.ENCRYPT, BillingEvents.DatasetType.UNSTRUCTURED, 0,1);

        AlgorithmInfo algorithmInfo = new AlgorithmInfo(this.encryptionKey.SecurityModel.Algorithm);

        // generate random IV for encryption
        byte[] initVector = new byte[algorithmInfo.getInitVectorLength()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(initVector);

        CipherHeader cipherHeader = new CipherHeader();
        cipherHeader.version = 0;
        cipherHeader.flags = CipherHeader.FLAGS_AAD_ENABLED;
        cipherHeader.algorithmId = algorithmInfo.getId();
        cipherHeader.initVectorLength = (byte) (initVector.length);
        cipherHeader.encryptedDataKeyLength = (short) (this.encryptionKey.EncryptedDataKeyBytes.length);
        cipherHeader.initVectorBytes = initVector;
        cipherHeader.encryptedDataKeyBytes = this.encryptionKey.EncryptedDataKeyBytes;

        byte[] cipherHeaderBytes = cipherHeader.serialize();

        // note: include cipher header bytes in AES calc!
         AesGcmBlockCipher aesGcmBlockCipher = new AesGcmBlockCipher(true, algorithmInfo, this.encryptionKey.UnwrappedDataKey,
                initVector, cipherHeaderBytes);

        session.setCipher(aesGcmBlockCipher);
        return cipherHeaderBytes;
    }

    /**
     * Continue the encryption process with the additional plaintext bytes passed in
     * @param plainBytes Source data to encrypt
     * @param offset Offset into the source data
     * @param count Number of bytes to use
     * @return - encrypted bytes
     * 
     * @deprecated use instance method update(UbiqUnstructuredEncryptSession session, ...) instead.  
     */
    @Deprecated
    public byte[] update(byte[] plainBytes, int offset, int count) {
      return update(this.session, plainBytes, offset, count);
    }

    /**
     * Continue the encryption process with the additional plaintext bytes passed in

     * @param session Session object to manage state between begin, update, and end calls
     * @param plainBytes Source data to encrypt
     * @param offset Offset into the source data
     * @param count Number of bytes to use
     * @return - encrypted bytes
     */

    public byte[] update(UbiqUnstructuredEncryptSession session, byte[] plainBytes, int offset, int count) {
        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        } else if ((session == null) || (!session.inUse())) {
            throw new RuntimeException("session not initialized");
        }

        byte[] cipherBytes = session.getCipher().update(plainBytes, offset, count);
        return cipherBytes;
    }

    /**
     * End the encryption process and return any remaining encrypted data
     * @return - encrypted bytes
     * 
     * @throws IllegalStateException if the object have not been initialized correctly
     * @throws InvalidCipherTextException if an exception was encountered while encrypting the data
     * @deprecated use instance method end(UbiqUnstructuredEncryptSession session instead.  
     */
    @Deprecated
    public byte[] end() throws IllegalStateException, InvalidCipherTextException {
        return end(this.session);
    }

    /**
     * End the encryption process and return any remaining encrypted data
     * @param session Session object to manage state between begin, update, and end calls
     * @return - encrypted bytes
     *
     * @throws IllegalStateException if the object have not been initialized correctly
     * @throws InvalidCipherTextException if an exception was encountered while encrypting the data
     */
    public byte[] end(UbiqUnstructuredEncryptSession session) throws IllegalStateException, InvalidCipherTextException {
        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        } else if ((session == null) || (!session.inUse())) {
            throw new RuntimeException("session not initialized");
        }

        byte[] finalBytes = session.getCipher().doFinal();
        session.close();
        return finalBytes;
    }

    public static byte[] encrypt(UbiqCredentials ubiqCredentials, byte[] data, UbiqConfiguration ubiqConfiguration)
            throws IllegalStateException, InvalidCipherTextException {
        try (UbiqEncrypt ubiqEncrypt = new UbiqEncrypt(ubiqCredentials, 1, ubiqConfiguration);
             ByteArrayOutputStream cipherStream = new ByteArrayOutputStream()) {

            UbiqUnstructuredEncryptSession session = ubiqEncrypt.initSession();

            cipherStream.write(ubiqEncrypt.begin(session));
            cipherStream.write(ubiqEncrypt.update(session,data, 0, data.length));
            cipherStream.write(ubiqEncrypt.end(session));

            return cipherStream.toByteArray();
        } catch (IOException ex) {
            System.out.println("stream exception");
            return null;
        }
    }

    public static byte[] encrypt(UbiqCredentials ubiqCredentials, byte[] data)
            throws IllegalStateException, InvalidCipherTextException {
        return encrypt(ubiqCredentials, data, UbiqFactory.defaultConfiguration());
    }

    public void addReportingUserDefinedMetadata(String jsonString) {
      billing_events.addUserDefinedMetadata(jsonString);
    }

    public String getCopyOfUsage() {
      return billing_events.getSerializedData();
    }
 
}
