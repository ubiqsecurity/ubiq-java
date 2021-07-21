package com.ubiqsecurity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.InvalidCipherTextException;

public class UbiqFPEEncrypt implements AutoCloseable {
    private int usesRequested;

    private UbiqWebServices ubiqWebServices; // null when closed
    private int useCount;
    private EncryptionKeyResponse encryptionKey;
    private AesGcmBlockCipher aesGcmBlockCipher;

    public UbiqFPEEncrypt(UbiqCredentials ubiqCredentials, int usesRequested) {
        this.usesRequested = usesRequested;
        this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);
    }

    public void close() {
        if (this.ubiqWebServices != null) {
            if (this.encryptionKey != null) {
                // if key was used less times than requested, notify the server.
                if (this.useCount < this.usesRequested) {
                    System.out.println(String.format("UbiqFPEEncrypt.close: reporting key usage: %d of %d", this.useCount,
                            this.usesRequested));
                    this.ubiqWebServices.updateEncryptionKeyUsage(this.useCount, this.usesRequested,
                            this.encryptionKey.KeyFingerprint, this.encryptionKey.EncryptionSession);
                }
            }

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

        // check key 'usage count' against server-specified limit
        if (this.useCount > this.encryptionKey.MaxUses) {
            throw new RuntimeException("maximum key uses exceeded");
        }

        this.useCount++;

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

        try (UbiqFPEEncrypt ubiqEncrypt = new UbiqFPEEncrypt(ubiqCredentials, 1)) {
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
