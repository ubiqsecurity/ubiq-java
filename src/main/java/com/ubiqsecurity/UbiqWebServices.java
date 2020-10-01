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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.Builder;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
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
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import java.security.PrivateKey;
import java.security.Security;
import java.util.Base64;
import java.io.IOException;
import java.io.StringReader;

class UbiqWebServices {
    private final String applicationJson = "application/json";
    private final String restApiRoot = "api/v0";

    private UbiqCredentials ubiqCredentials;
    private String baseUrl;
    private static final String version;

    UbiqWebServices(UbiqCredentials ubiqCredentials) {
        this.ubiqCredentials = ubiqCredentials;

        if (!this.ubiqCredentials.getHost().startsWith("http")) {
            this.baseUrl = String.format("https://%s", this.ubiqCredentials.getHost());
        } else {
            this.baseUrl = this.ubiqCredentials.getHost();
        }
    }

    // Only needs to be run once when package is class is loaded.
    static 
    {
        Package pkg = UbiqWebServices.class.getPackage();
        version = pkg.getImplementationVersion();
    }

    EncryptionKeyResponse getEncryptionKey(int uses) {
        String urlString = String.format("%s/%s/encryption/key", this.baseUrl, this.restApiRoot);

        String jsonRequest = String.format("{\"uses\": %s}", uses);

        try {
            HttpRequest signedHttpRequest = buildSignedHttpRequest("POST", urlString, jsonRequest,
                this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());


            // submit HTTP request + expect HTTP response w/ status 'Created' (201)
            String jsonResponse = submitHttpRequest(signedHttpRequest, 201);
            //System.out.println(jsonResponse);

            // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            EncryptionKeyResponse encryptionKeyResponse = gson.fromJson(jsonResponse, EncryptionKeyResponse.class);

            // decrypt the server-provided encryption key
            encryptionKeyResponse.UnwrappedDataKey = unwrapKey(
            		encryptionKeyResponse.EncryptedPrivateKey,
            		encryptionKeyResponse.WrappedDataKey,
            		this.ubiqCredentials.getSecretCryptoAccessKey());
            
//            encryptionKeyResponse.postProcess(this.ubiqCredentials.getSecretCryptoAccessKey());
            
            encryptionKeyResponse.EncryptedDataKeyBytes = Base64.getDecoder().decode(encryptionKeyResponse.EncryptedDataKey);
            
            return encryptionKeyResponse;
        } catch (Exception ex) {
            System.out.println(String.format("getEncryptionKey exception: %s", ex.getMessage()));
            return null;
        }
    }

    void updateEncryptionKeyUsage(int actual, int requested, String keyFingerprint, String encryptionSession) {
        String urlString = String.format("%s/%s/encryption/key/%s/%s", this.baseUrl, this.restApiRoot, keyFingerprint,
                encryptionSession);

        String jsonRequest = String.format("{\"requested\": %d, \"actual\": %d}", requested, actual);

        try {
            HttpRequest signedHttpRequest = buildSignedHttpRequest("PATCH", urlString, jsonRequest,
                    this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP status 'NoContent' (204)
            String jsonResponse = submitHttpRequest(signedHttpRequest, 204);

            // expect empty response
        } catch (Exception ex) {
            System.out.println(String.format("updateEncryptionKeyUsage exception: %s", ex.getMessage()));
        }
    }

    DecryptionKeyResponse getDecryptionKey(byte[] encryptedDataKey) {
        String urlString = String.format("%s/%s/decryption/key", this.baseUrl, this.restApiRoot);

        // convert binary key bytes to Base64
        String base64DataKey = Base64.getEncoder().encodeToString(encryptedDataKey);
        String jsonRequest = String.format("{\"encrypted_data_key\": \"%s\"}", base64DataKey);

        try {
            HttpRequest signedHttpRequest =  buildSignedHttpRequest("POST", urlString, jsonRequest,
                this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'OK' (200)
            String jsonResponse = submitHttpRequest(signedHttpRequest, 200);

            // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            DecryptionKeyResponse decryptionKeyResponse = gson.fromJson(jsonResponse, DecryptionKeyResponse.class);

            // decrypt the server-provided encryption key
            decryptionKeyResponse.UnwrappedDataKey = unwrapKey(
            		decryptionKeyResponse.EncryptedPrivateKey,
            		decryptionKeyResponse.WrappedDataKey,
            		this.ubiqCredentials.getSecretCryptoAccessKey());
            		
//            decryptionKeyResponse.postProcess(this.ubiqCredentials.getSecretCryptoAccessKey());
            
//            decryptionKeyResponse.WrappedDataKey = null;
            
            return decryptionKeyResponse;
        } catch (Exception ex) {
            System.out.println(String.format("getDecryptionKey exception: %s", ex.getMessage()));
            return null;
        }
    }

    void updateDecryptionKeyUsage(int uses, String keyFingerprint, String encryptionSession) {
        String urlString = String.format("%s/%s/decryption/key/%s/%s", this.baseUrl, this.restApiRoot, keyFingerprint,
                encryptionSession);

        String jsonRequest = String.format("{\"uses\": %d}", uses);

        try {
            HttpRequest signedHttpRequest = buildSignedHttpRequest("PATCH", urlString, jsonRequest,
                    this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'NoContent' (204)
            String jsonResponse = submitHttpRequest(signedHttpRequest, 204);

            // expect empty response
        } catch (Exception ex) {
            System.out.println(String.format("updateDecryptionKeyUsage exception: %s", ex.getMessage()));
        }
    }

    private HttpRequest buildSignedHttpRequest(String httpMethod, String urlString, String jsonRequest,
            String publicAccessKey, String secretSigningKey) throws NoSuchAlgorithmException, InvalidKeyException,
            IOException {

        URL url = new URL(urlString);

        BodyPublisher bodyPublisher = HttpRequest.BodyPublishers.ofString(jsonRequest);
        Builder builder = HttpRequest.newBuilder();
        builder.uri(URI.create(urlString));
        builder.method(httpMethod, bodyPublisher);

        Map<String, String> headerFields = new HashMap<String, String>();

        headerFields.put("Content-Length", String.valueOf(bodyPublisher.contentLength()));
        headerFields.put("Content-Type", this.applicationJson);
        headerFields.put("Accept", this.applicationJson);
        headerFields.put("User-Agent", "ubiq-java/" + version);
        String host = url.getHost();
        // If port is specified, it needs to be included
        if (url.getPort() != -1) {
        	host += ":" + url.getPort();
        }
        headerFields.put("Host", host);
        headerFields.put("Digest", buildDigestValue(jsonRequest.getBytes(StandardCharsets.UTF_8)));

        String unixTimeString = unixTimeAsString();
        String requestTarget = buildRequestTarget(httpMethod, url);
        String signature = buildSignature(headerFields, unixTimeString, requestTarget, publicAccessKey,
                secretSigningKey);
        headerFields.put("Signature", signature);

        // JDK 11 doesn't allow override of certain automatically-added request headers, so ditch them.
        headerFields.remove("Content-Length");
        headerFields.remove("Host");

        for (String fieldName : headerFields.keySet()) {
            builder.header(fieldName, headerFields.get(fieldName));
        }

        HttpRequest httpRequest = builder.build();
        return httpRequest;
    }
    
    // reference:
    // https://stackoverflow.com/questions/22920131/read-an-encrypted-private-key-with-bouncycastle-spongycastle
    byte[] unwrapKey(String encryptedPrivateKey, 
    		String wrappedDataKey, String secretCryptoAccessKey)
            throws IOException, OperatorCreationException, PKCSException, InvalidCipherTextException {

    	byte[] unwrappedDataKey = null;
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        //System.out.println("EncryptionKeyResponse.postProcess: calling PEMParser...");
        try (PEMParser pemParser = new PEMParser(new StringReader(encryptedPrivateKey))) {
        	
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
                	BCRSAPrivateKey rsaPrivateKey = (BCRSAPrivateKey)privateKey;
                	
                    // now that we've decrypted the server-provided empheral key, we can 
                    // decrypt the key to be used for local encryption

                	RSAKeyParameters cipherParams = new RSAKeyParameters(
                			true, 
                			rsaPrivateKey.getModulus(),
                			rsaPrivateKey.getPrivateExponent());
                	
                    OAEPEncoding rsaEngine = new OAEPEncoding(
                        new RSAEngine(),
                        new SHA1Digest(),
                        new SHA1Digest(),
                        null);
                    
                    rsaEngine.init(false, cipherParams);

                    // 'UnwrappedDataKey' is used for local encryptions
                    byte[] wrappedDataKeyBytes = Base64.getDecoder().decode(wrappedDataKey);
                    unwrappedDataKey = rsaEngine.processBlock(wrappedDataKeyBytes, 0, wrappedDataKeyBytes.length);
                }
            }
        }

        return unwrappedDataKey;
    }


    private static String submitHttpRequest(HttpRequest httpRequest, int successCode)
            throws IOException, InterruptedException {
        HttpClient httpClient = HttpClient.newBuilder().build();
        HttpResponse<String> httpResponse = httpClient.send(httpRequest, BodyHandlers.ofString());

        String responseString = httpResponse.body();

        if (httpResponse.statusCode() != successCode) {
            throw new IOException(String.format("Ubiq API request failed: %s", responseString));
        }

        return responseString;
    }

    private static String buildDateValue() {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'");
        return formatter.format(Instant.now().atZone(ZoneOffset.UTC));
    }

    private static String unixTimeAsString() {
        long unixTime = System.currentTimeMillis() / 1000L;
        return String.valueOf(unixTime);
    }

    private static String buildRequestTarget(String httpMethod, URL url) {
        String requestTarget = httpMethod.toLowerCase() + " " + url.getPath();
        return requestTarget;
    }

    private static String buildDigestValue(byte[] jsonRequestBytes) throws NoSuchAlgorithmException {

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
        byte[] hashBytes = messageDigest.digest(jsonRequestBytes);
        return "SHA-512=" + Base64.getEncoder().encodeToString(hashBytes);
    }

    private static String buildSignature(Map<String, String> headerFields, String unixTimeString, String requestTarget,
            String publicAccessKey, String secretSigningKey) throws IOException, NoSuchAlgorithmException, InvalidKeyException {

        try (ByteArrayOutputStream hashStream = new ByteArrayOutputStream()) {
            writeHashableBytes(hashStream, "(created)", unixTimeString);
            writeHashableBytes(hashStream, "(request-target)", requestTarget);
            writeHashableBytes(hashStream, "Content-Type", headerFields.get("Content-Type"));
            writeHashableBytes(hashStream, "Digest", headerFields.get("Digest"));
            writeHashableBytes(hashStream, "Host", headerFields.get("Host"));

            final String HMAC_SHA512 = "HmacSHA512";

            byte[] secretSigningKeyBytes = secretSigningKey.getBytes(StandardCharsets.UTF_8);
            SecretKeySpec keySpec = new SecretKeySpec(secretSigningKeyBytes, HMAC_SHA512);

            Mac hmacSha512 = Mac.getInstance(HMAC_SHA512);
            hmacSha512.init(keySpec);

            // Compute the hash of the input data
            byte[] hashBytes = hmacSha512.doFinal(hashStream.toByteArray());

            // assemble final signature string
            StringBuilder signature = new StringBuilder();
            signature.append(String.format("keyId=\"%s\"", publicAccessKey));
            signature.append(", algorithm=\"hmac-sha512\"");
            signature.append(String.format(", created=%s", unixTimeString));
            signature.append(", headers=\"(created) (request-target) content-type digest host\"");
            signature.append(String.format(", signature=\"%s\"", Base64.getEncoder().encodeToString(hashBytes)));

            return signature.toString();
        }
    }

    private static void writeHashableBytes(ByteArrayOutputStream hashStream, String name, String value) {
        // build hashable string
        String hashableString = name.toLowerCase() + ": " + value + "\n";

        // convert to UTF-8 byte array
        byte[] hashableBytes = hashableString.getBytes(StandardCharsets.UTF_8);

        // write bytes to caller-provided Stream
        hashStream.write(hashableBytes, 0, hashableBytes.length);
    }
}
