package com.ubiqsecurity;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;

// Binary header for Ubiq ciphertext.
// The first six bytes form a fixed-length record, which indicates the length
// of two variable-length fields that follow

// TODO: what is the naming convention for Java member vars without getter/setter?
class CipherHeader {
    // Definitions for the 'flags' bit field.
    static final byte FLAGS_AAD_ENABLED = (byte)0x01;
    static final byte FLAGS_RESERVED_1 =  (byte)0x02;
    static final byte FLAGS_RESERVED_2 =  (byte)0x04;
    static final byte FLAGS_RESERVED_3 =  (byte)0x08;
    static final byte FLAGS_RESERVED_4 =  (byte)0x10;
    static final byte FLAGS_RESERVED_5 =  (byte)0x20;
    static final byte FLAGS_RESERVED_6 =  (byte)0x40;
    static final byte FLAGS_RESERVED_7 =  (byte)0x80;

    byte version;
    byte flags;
    byte algorithmId;
    // Length of Initialization Vector, in bytes.
    byte initVectorLength;
    short encryptedDataKeyLength;

    // Variable-length buffer of size 'InitVectorLength'
    byte[] initVectorBytes;

    // Variable-length buffer of size <see cref="EncryptedDataKeyLength"/>
    byte[] encryptedDataKeyBytes;

    int calcLength() {
        // start with fixed-length parts
        int length = 6;

        // add variable-length parts
        if (initVectorBytes != null) {
            length += initVectorBytes.length;
        }

        if (encryptedDataKeyBytes != null) {
            length += encryptedDataKeyBytes.length;
        }

        return length;
    }

    static CipherHeader deserialize(ByteArrayInputStream stream) {
        byte[] fixedBytes = new byte[6];

        if (stream.read(fixedBytes, 0, fixedBytes.length) < fixedBytes.length) {
            // not enough bytes for fixed-length part
            return null;
        }

        // decode the fixed-length part:
        // 4 x 1-byte
        // 1 x 2-byte
        CipherHeader cipherHeader = new CipherHeader();
        cipherHeader.version = fixedBytes[0];
        cipherHeader.flags = fixedBytes[1];
        cipherHeader.algorithmId = fixedBytes[2];
        cipherHeader.initVectorLength = fixedBytes[3];

        if (cipherHeader.version != 0) {
            throw new IllegalArgumentException("invalid encryption header version");
        }

        // assume two-byte big-endian value
        ByteBuffer shortBytes = ByteBuffer.allocate(2);
        shortBytes.put(fixedBytes[4]);
        shortBytes.put(fixedBytes[5]);
        cipherHeader.encryptedDataKeyLength = shortBytes.getShort(0);

        // at this point, the fixed-length header can tell us the size of
        // the remaining variable-length fields
        byte[] variableBytes = new byte[cipherHeader.initVectorLength + cipherHeader.encryptedDataKeyLength];
        if (stream.read(variableBytes, 0, variableBytes.length) < variableBytes.length) {
            // not enough bytes for variable-length part
            return null;
        }

        // good to go... populate remainder of header
        cipherHeader.initVectorBytes = new byte[cipherHeader.initVectorLength];
        System.arraycopy(variableBytes, 0, cipherHeader.initVectorBytes, 0, cipherHeader.initVectorBytes.length);

        cipherHeader.encryptedDataKeyBytes = new byte[cipherHeader.encryptedDataKeyLength];
        System.arraycopy(variableBytes, cipherHeader.initVectorLength, cipherHeader.encryptedDataKeyBytes, 0,
                cipherHeader.encryptedDataKeyBytes.length);

        return cipherHeader;
    }

    byte[] serialize() {
        ByteBuffer headerBytes = ByteBuffer.allocate(calcLength());
        headerBytes.put(version);
        headerBytes.put(flags);
        headerBytes.put(algorithmId);
        headerBytes.put(initVectorLength);
        // tricky: write two-byte value in big-endian order
        headerBytes.putShort(encryptedDataKeyLength);

        // write randomly-generated init vector
        headerBytes.put(initVectorBytes);

        // write server-provided EncryptedDataKey
        headerBytes.put(encryptedDataKeyBytes);
        return headerBytes.array();
    }
}
