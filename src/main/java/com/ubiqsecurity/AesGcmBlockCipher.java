package com.ubiqsecurity;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

class AesGcmBlockCipher {
    private GCMBlockCipher gcmBlockCipher;

    // 'additionalBytes' can be null
    AesGcmBlockCipher(boolean forEncryption, AlgorithmInfo algorithmInfo, byte[] key, byte[] initVector,
            byte[] additionalBytes) {
        if (key.length != algorithmInfo.getKeyLength()) {
            throw new IllegalArgumentException("key length mismatch");
        } else if (initVector.length != algorithmInfo.getInitVectorLength()) {
            throw new IllegalArgumentException("init vector length mismatch");
        }

        // get Cipher Instance
        this.gcmBlockCipher = new GCMBlockCipher(new AESEngine());

        AEADParameters aeadParameters = new AEADParameters(new KeyParameter(key), algorithmInfo.getMacLength() * 8,
                initVector, additionalBytes);

        this.gcmBlockCipher.init(forEncryption, aeadParameters);
    }

    byte[] update(byte[] inBytes, int inOffset, int inCount) {
        byte[] outBytes = new byte[this.gcmBlockCipher.getOutputSize(inBytes.length)];
        int length = this.gcmBlockCipher.processBytes(inBytes, inOffset, inCount, outBytes, 0);
        if (length < outBytes.length) {
            byte[] shortenedOutBytes = new byte[length];
            System.arraycopy(outBytes, 0, shortenedOutBytes, 0, shortenedOutBytes.length);
            return shortenedOutBytes;
        } else {
            return outBytes;
        }
    }

    byte[] doFinal() throws IllegalStateException, InvalidCipherTextException {
        var finalBytes = new byte[32]; // large enough for MAC result
        int retLen = this.gcmBlockCipher.doFinal(finalBytes, 0);
        if (retLen < finalBytes.length) {
            byte[] shortenedFinalBytes = new byte[retLen];
            System.arraycopy(finalBytes, 0, shortenedFinalBytes, 0, shortenedFinalBytes.length);
            return shortenedFinalBytes;
        } else {
            return finalBytes;
        }
    }
}
