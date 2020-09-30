/*
 * Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains the property
 * of Ubiq Security, Inc. The intellectual and technical concepts contained
 * herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
 * covered by U.S. and Foreign Patents, patents in process, and are
 * protected by trade secret or copyright law. Dissemination of this
 * information or reproduction of this material is strictly forbidden
 * unless prior written permission is obtained from Ubiq Security, Inc.
 *
 * Your use of the software is expressly conditioned upon the terms
 * and conditions available at:
 *
 *     https://ubiqsecurity.com/legal
 *
 */

package com.ubiqsecurity;

import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

class EncryptionKeyResponse {
    @SerializedName("encrypted_private_key")
    String EncryptedPrivateKey;

    @SerializedName("encryption_session")
    String EncryptionSession;

    @SerializedName("key_fingerprint")
    String KeyFingerprint;

    @SerializedName("security_model")
    SecurityModel SecurityModel;

    @SerializedName("max_uses")
    int MaxUses;

    @SerializedName("wrapped_data_key")
    String WrappedDataKey;

    @SerializedName("encrypted_data_key")
    String EncryptedDataKey;

    // not serialized - used only at runtime
    @Expose(serialize = false, deserialize = false)
    int Uses;

    // not serialized - used only at runtime
    @Expose(serialize = false, deserialize = false)
    byte[] UnwrappedDataKey;

    // not serialized - used only at runtime
    @Expose(serialize = false, deserialize = false)
    byte[] EncryptedDataKeyBytes;

    // reference:
    // https://stackoverflow.com/questions/22920131/read-an-encrypted-private-key-with-bouncycastle-spongycastle
    void postProcess(String secretCryptoAccessKey)
            throws IOException, OperatorCreationException, PKCSException, InvalidCipherTextException {

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        //System.out.println("EncryptionKeyResponse.postProcess: calling PEMParser...");
        try (PEMParser pemParser = new PEMParser(new StringReader(EncryptedPrivateKey))) {
            Object object = pemParser.readObject();
            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                JceOpenSSLPKCS8DecryptorProviderBuilder builder = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC");

                // Decrypt the private key using our secret key
                InputDecryptorProvider decryptProvider  = builder.build(secretCryptoAccessKey.toCharArray());

                PKCS8EncryptedPrivateKeyInfo keyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
                PrivateKeyInfo privateKeyInfo = keyInfo.decryptPrivateKeyInfo(decryptProvider);

                JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider("BC");
                PrivateKey privateKey = keyConverter.getPrivateKey(privateKeyInfo);
                if (privateKey instanceof BCRSAPrivateCrtKey) {
                    // now that we've decrypted the server-provided empheral key, we can 
                    // decrypt the key to be used for local encryption
                    //System.out.println("EncryptionKeyResponse.postProcess: decrypting WrappedDataKey...");

                    // TODO: is there a better way?
                    BCRSAPrivateCrtKey rsaPrivateKey = (BCRSAPrivateCrtKey)privateKey;
                    RSAPrivateCrtKeyParameters cipherParams = new RSAPrivateCrtKeyParameters(
                        rsaPrivateKey.getModulus(),
                        rsaPrivateKey.getPublicExponent(),
                        rsaPrivateKey.getPrivateExponent(),
                        rsaPrivateKey.getPrimeP(),
                        rsaPrivateKey.getPrimeQ(),
                        rsaPrivateKey.getPrimeExponentP(),
                        rsaPrivateKey.getPrimeExponentQ(),
                        rsaPrivateKey.getCrtCoefficient());

                    OAEPEncoding rsaEngine = new OAEPEncoding(
                        new RSAEngine(),
                        new SHA1Digest(),
                        new SHA1Digest(),
                        null);
                    
                    rsaEngine.init(false, cipherParams);

                    // 'UnwrappedDataKey' is used for local encryptions
                    byte[] wrappedDataKeyBytes = Base64.getDecoder().decode(WrappedDataKey);
                    UnwrappedDataKey = rsaEngine.processBlock(wrappedDataKeyBytes, 0, wrappedDataKeyBytes.length);
                }
            }
        }

        // convert server-provided Base64 to byte[]
        EncryptedDataKeyBytes = Base64.getDecoder().decode(EncryptedDataKey);
    }
}
