package com.ubiqsecurity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;

public class UbiqEncrypt implements AutoCloseable {
    private boolean verbose= false;
    private int usesRequested;

    private UbiqWebServices ubiqWebServices; // null when closed
    private EncryptionKeyResponse encryptionKey;
    private AesGcmBlockCipher aesGcmBlockCipher;
    private BillingEvents billing_events;
    private BillingEventsProcessor executor;
    private UbiqCredentials ubiqCredentials;
    private UbiqConfiguration ubiqConfiguration;

    public UbiqEncrypt(UbiqCredentials ubiqCredentials, int usesRequested) {
      this(ubiqCredentials, usesRequested, UbiqFactory.defaultConfiguration());
    }
   

    public UbiqEncrypt(UbiqCredentials ubiqCredentials, int usesRequested, UbiqConfiguration ubiqConfiguration) {
        this.usesRequested = usesRequested;
        this.ubiqCredentials = ubiqCredentials;
        this.ubiqConfiguration = ubiqConfiguration;

        this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);

        billing_events = new BillingEvents(this.ubiqConfiguration);
        executor = new BillingEventsProcessor(this.ubiqWebServices, this.billing_events, this.ubiqConfiguration);
        executor.startAsync();

    }

    public void close() {
      if (verbose) System.out.println("Close");

        if (this.ubiqWebServices != null) {

            // this stops any remaining background billing processing since we'll make an explicit final call now
            // executor.stopAsync();
            executor.shutDown();

            this.ubiqWebServices = null;
        }
    }

    public byte[] begin() {
        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        } else if (this.aesGcmBlockCipher != null) {
            throw new IllegalStateException("encryption in progress");
        }

        if (this.encryptionKey == null) {
            // JIT: request encryption key from server
            this.encryptionKey = this.ubiqWebServices.getEncryptionKey(this.usesRequested);
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
        this.aesGcmBlockCipher = new AesGcmBlockCipher(true, algorithmInfo, this.encryptionKey.UnwrappedDataKey,
                initVector, cipherHeaderBytes);

        return cipherHeaderBytes;
    }

    public byte[] update(byte[] plainBytes, int offset, int count) {
        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        } else if ((this.encryptionKey == null) || (this.aesGcmBlockCipher == null)) {
            throw new RuntimeException("encryptor not initialized");
        }

        byte[] cipherBytes = this.aesGcmBlockCipher.update(plainBytes, offset, count);
        return cipherBytes;
    }

    public byte[] end() throws IllegalStateException, InvalidCipherTextException {
        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        }

        var finalBytes = this.aesGcmBlockCipher.doFinal();
        this.aesGcmBlockCipher = null;
        return finalBytes;
    }

    public static byte[] encrypt(UbiqCredentials ubiqCredentials, byte[] data)
            throws IllegalStateException, InvalidCipherTextException {

        try (UbiqEncrypt ubiqEncrypt = new UbiqEncrypt(ubiqCredentials, 1)) {
            try (ByteArrayOutputStream cipherStream = new ByteArrayOutputStream()) {
                cipherStream.write(ubiqEncrypt.begin());
                cipherStream.write(ubiqEncrypt.update(data, 0, data.length));
                cipherStream.write(ubiqEncrypt.end());

                return cipherStream.toByteArray();
            } catch (IOException ex) {
                System.out.println("stream exception");
                return null;
            }
        }
    }
}
