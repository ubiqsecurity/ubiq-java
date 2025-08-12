package com.ubiqsecurity;

public class UbiqUnstructuredEncryptSession implements AutoCloseable {
    private AesGcmBlockCipher aesGcmBlockCipher = null;

    UbiqUnstructuredEncryptSession() {
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

      public void close() {
      if (this.aesGcmBlockCipher == null) {
            throw new RuntimeException("Session not initialized");
      }
      this.aesGcmBlockCipher = null;
    }

}
