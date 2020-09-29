package com.ubiqsecurity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.bouncycastle.crypto.InvalidCipherTextException;

public class UbiqDecrypt implements AutoCloseable {
    private UbiqWebServices ubiqWebServices; // null on close

    private CipherHeader cipherHeader; // extracted from beginning of ciphertext
    private ByteQueue byteQueue;
    private DecryptionKeyResponse decryptionKey;
    private AesGcmBlockCipher aesGcmBlockCipher;

    public UbiqDecrypt(UbiqCredentials ubiqCredentials) {
        this.ubiqWebServices = new UbiqWebServices(ubiqCredentials);
    }

    public void close() {
        if (this.ubiqWebServices != null) {
            // reports decryption key usage to server, if applicable
            reset();

            // this.ubiqWebServices.close();
            this.ubiqWebServices = null;
        }
    }

    public byte[] begin() {
        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        } else if (this.aesGcmBlockCipher != null) {
            throw new IllegalStateException("decryption in progress");
        }

        // prepare to receive initial header bytes
        this.cipherHeader = null;
        this.byteQueue = null;

        // note: cached 'decryptionKey' may be present from a previous decryption run

        return new byte[0];
    }

    // each encryption has a header on it that identifies the algorithm
    // used and an encryption of the data key that was used to encrypt
    // the original plain text. there is no guarantee how much of that
    // data will be passed to this function or how many times this
    // function will be called to process all of the data. to that end,
    // this function buffers data internally, when it is unable to
    // process it.

    // the function buffers data internally until the entire header is
    // received. once the header has been received, the encrypted data
    // key is sent to the server for decryption. after the header has
    // been successfully handled, this function always decrypts all of
    // the data in its internal buffer
    public byte[] update(byte[] cipherBytes, int offset, int count) {
        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        }

        byte[] plainBytes = new byte[0]; // returned

        if (this.byteQueue == null) {
            this.byteQueue = new ByteQueue(null);
        }

        // make sure new data is appended to end
        this.byteQueue.enqueue(cipherBytes, offset, count);

        if (this.cipherHeader == null) {
            // see if we've got enough data for the header record
            try (ByteArrayInputStream byteStream = new ByteArrayInputStream(this.byteQueue.peek())) {
                this.cipherHeader = CipherHeader.deserialize(byteStream);
            } catch (IOException ex) {
                System.out.println("stream exception");
                // keep going anyway...
            }

            if (this.cipherHeader != null) {
                // success: prune cipher header bytes from the buffer
                this.byteQueue.dequeue(this.cipherHeader.calcLength());

                if (this.decryptionKey != null) {
                    // See if we can reuse the key from a previous decryption, meaning
                    // the new data was encrypted with the same key as the old data - i.e.
                    // both cipher headers have the same key.
                    //
                    // If not, clear the previous decryption key.
                    if (!Arrays.equals(this.cipherHeader.encryptedDataKeyBytes,
                            this.decryptionKey.LastCipherHeaderEncryptedDataKeyBytes)) {
                        reset();
                        assert this.decryptionKey == null;
                    }
                }

                // If needed, use the header info to fetch the decryption key.
                if (this.decryptionKey == null) {
                    // JIT: request encryption key from server
                    this.decryptionKey = this.ubiqWebServices.getDecryptionKey(this.cipherHeader.encryptedDataKeyBytes);
                }

                if (this.decryptionKey != null) {
                    AlgorithmInfo algorithmInfo = new AlgorithmInfo(this.cipherHeader.algorithmId);

                    // save key extracted from header to detect future key changes
                    this.decryptionKey.LastCipherHeaderEncryptedDataKeyBytes = this.cipherHeader.encryptedDataKeyBytes;

                    // create decryptor from header-specified algorithm + server-supplied decryption key
                    this.aesGcmBlockCipher = new AesGcmBlockCipher(false, algorithmInfo,
                            this.decryptionKey.UnwrappedDataKey, this.cipherHeader.initVectorBytes,
                            ((this.cipherHeader.flags & CipherHeader.FLAGS_AAD_ENABLED) != 0)
                                ? this.cipherHeader.serialize()
                                : null);

                    this.decryptionKey.KeyUseCount++;
                }
            } else {
                // holding pattern... need more header bytes
                return plainBytes;
            }
        }

        // If we get this far, assume we have a valid header record.
        assert this.cipherHeader != null;

        if ((this.decryptionKey != null) && (this.aesGcmBlockCipher != null)) {
            // pass all available buffered bytes to the decryptor
            if (this.byteQueue.getLength() > 0) {
                byte[] bufferedBytes = this.byteQueue.dequeue(this.byteQueue.getLength());
                plainBytes = this.aesGcmBlockCipher.update(bufferedBytes, 0, bufferedBytes.length);
            }
        }

        return plainBytes;
    }

    public byte[] end() throws IllegalStateException, InvalidCipherTextException {
        if (this.ubiqWebServices == null) {
            throw new IllegalStateException("object closed");
        }

        byte[] finalPlainBytes = this.aesGcmBlockCipher.doFinal();
        this.aesGcmBlockCipher = null;
        this.byteQueue = null;
        return finalPlainBytes;
    }

    public static byte[] decrypt(UbiqCredentials ubiqCredentials, byte[] data)
            throws IllegalStateException, InvalidCipherTextException {
        try (UbiqDecrypt ubiqDecrypt = new UbiqDecrypt(ubiqCredentials)) {
            try (ByteArrayOutputStream plainStream = new ByteArrayOutputStream()) {
                plainStream.write(ubiqDecrypt.begin());
                plainStream.write(ubiqDecrypt.update(data, 0, data.length));
                plainStream.write(ubiqDecrypt.end());

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
            if (decryptionKey.KeyUseCount > 0) {
                // report key usage to server
                System.out.println(
                        String.format("UbiqDecrypt.reset: reporting key count: %d", this.decryptionKey.KeyUseCount));

                this.ubiqWebServices.updateDecryptionKeyUsage(this.decryptionKey.KeyUseCount,
                        this.decryptionKey.KeyFingerprint, this.decryptionKey.EncryptionSession);
            }

            this.decryptionKey = null;
        }

        this.aesGcmBlockCipher = null;
    }
}
