package com.ubiqsecurity;

public class UbiqUnstructuredDecryptSession implements AutoCloseable {
    private AesGcmBlockCipher aesGcmBlockCipher = null;
    private ByteQueue byteQueue = null;
    private CipherHeader cipherHeader = null; // extracted from beginning of ciphertext

    UbiqUnstructuredDecryptSession() {
      byteQueue = new ByteQueue(null);
    }

    public void setCipher(AesGcmBlockCipher aesGcmBlockCipher) {
      this.aesGcmBlockCipher = aesGcmBlockCipher;
    }

    public boolean inUse() {
      return this.aesGcmBlockCipher != null;
    }

    public AesGcmBlockCipher getCipher() {
      if (this.aesGcmBlockCipher == null) {
            throw new RuntimeException("Session not initialized");
      }
      return this.aesGcmBlockCipher;
    }

    public ByteQueue getByteQueue() {
      return this.byteQueue;
    }

    public CipherHeader getCipherHeader() {
      return this.cipherHeader;
    }

    public void setCipherHeader(CipherHeader cipherHeader) {
      this.cipherHeader = cipherHeader;
    }

    public void close() {
      if (this.aesGcmBlockCipher == null) {
            throw new RuntimeException("Session not initialized");
      }
      this.aesGcmBlockCipher = null;
      this.byteQueue = new ByteQueue(null);
      this.cipherHeader = null;
    }
    

}
