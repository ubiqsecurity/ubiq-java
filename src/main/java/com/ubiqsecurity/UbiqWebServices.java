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


import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;


import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;



class UbiqWebServices {
    private boolean verbose= false;
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


    public static String encode(String url)
      {
            try {
                 String encodeURL=URLEncoder.encode( url, StandardCharsets.UTF_8.toString() );
                 return encodeURL.replaceAll("\\+", "%20");
            } catch (UnsupportedEncodingException e) {
                 return "Issue while encoding: " +e.getMessage();
            }
      }


    byte[] getUnwrappedKey(String EncryptedPrivateKey, String WrappedDataKey) {
        byte[] UnwrappedDataKey = {(byte)0x00};
        try {
            // decrypt the provided encryption key
            UnwrappedDataKey = unwrapKey(
                        EncryptedPrivateKey,
                        WrappedDataKey,
                        this.ubiqCredentials.getSecretCryptoAccessKey());

            return UnwrappedDataKey;
        } catch (Exception ex) {
            System.out.println(String.format("getUnwrappedKey exception: %s", ex.getMessage()));
            return UnwrappedDataKey;
        }
    }




    FPEBillingResponse sendBilling(String payload) {
        String urlString = String.format("%s/%s/fpe/billing/%s", this.baseUrl, this.restApiRoot, encode(this.ubiqCredentials.getAccessKeyId()));
        if (verbose) System.out.println("\n    sendBilling urlString: " + urlString);

        String jsonRequest = payload;

        try {
          HttpRequest signedHttpRequest = buildSignedHttpRequest("POST", urlString, "", jsonRequest,
              this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());


          // submit HTTP request + expect HTTP response w/ status 'Created' (201)
          String jsonResponse = submitHttpRequest(signedHttpRequest, 201);
          if (verbose) System.out.println("    sendBilling jsonResponse: " + jsonResponse);

          // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            FPEBillingResponse fpeBillingResponse = gson.fromJson(jsonResponse, FPEBillingResponse.class);

            if (verbose) System.out.println("    status: " + fpeBillingResponse.status + ", message: " + fpeBillingResponse.message + ", last_valid: " + fpeBillingResponse.last_valid);

            return fpeBillingResponse;
        } catch (Exception ex) {
            String jsonResponse = ex.getMessage();

            if (verbose) System.out.println("Server unable to process billing transactions after: " + jsonResponse);
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            FPEBillingResponse fpeBillingResponse =
                    gson.fromJson(jsonResponse, FPEBillingResponse.class);

            return fpeBillingResponse;
        }
    }









    FFSRecordResponse getFFSDefinition(String ffs_name) {
        //String urlString = String.format("%s/%s/ffs/%s", this.baseUrl, this.restApiRoot, this.ubiqCredentials.getAccessKeyId());
        String jsonRequest="";
        String params = String.format("ffs_name=%s&papi=%s", encode(ffs_name), encode(this.ubiqCredentials.getAccessKeyId()));
        String urlString = String.format("%s/%s/ffs?%s", this.baseUrl, this.restApiRoot, params);

        if (verbose) System.out.println("\n    urlString: " + urlString + "\n");
        if (verbose) System.out.println("\n    params: " + params + "\n");

        try {
            HttpRequest signedHttpRequest = buildSignedHttpRequest("GET", urlString, params, jsonRequest,
                this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'Created' (201)
            String jsonResponse = submitHttpRequest(signedHttpRequest, 200);

            if (verbose) System.out.println("\n    getFFSDefinition: " + jsonResponse + "\n");

            // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            FFSRecordResponse ffsRecordResponse =
                    gson.fromJson(jsonResponse, FFSRecordResponse.class);

            return ffsRecordResponse;
        } catch (Exception ex) {
            System.out.println(String.format("getFFSDefinition exception: %s", ex.getMessage()));
            return null;
        }
    }





    FPEKeyResponse getFPEEncryptionKey(String ffs_name) {
        String jsonRequest="";
        String params = String.format("ffs_name=%s&papi=%s", encode(ffs_name), encode(this.ubiqCredentials.getAccessKeyId()));
        String urlString = String.format("%s/%s/fpe/key?%s", this.baseUrl, this.restApiRoot, params);

        try {
            HttpRequest signedHttpRequest = buildSignedHttpRequest("GET", urlString, params, jsonRequest,
                this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'Created' (201)
            String jsonResponse = submitHttpRequest(signedHttpRequest, 200);

            //if (verbose) System.out.println("\n    getFPEEncryptionKey: " + jsonResponse + "\n");

            // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            FPEKeyResponse encryptionKeyResponse =
                    gson.fromJson(jsonResponse, FPEKeyResponse.class);

            return encryptionKeyResponse;
        } catch (Exception ex) {
            System.out.println(String.format("getFPEEncryptionKey exception: %s", ex.getMessage()));
            return null;
        }
    }



    FPEKeyResponse getFPEDecryptionKey(String ffs_name, int key_number) {
        String jsonRequest="";
        String params = String.format("ffs_name=%s&papi=%s&key_number=%d", encode(ffs_name), encode(this.ubiqCredentials.getAccessKeyId()), key_number);
        String urlString = String.format("%s/%s/fpe/key?%s", this.baseUrl, this.restApiRoot, params);
        if (verbose) System.out.println("getFPEDecryptionKey  params: " + params);
        try {
            HttpRequest signedHttpRequest =  buildSignedHttpRequest("GET", urlString, params, jsonRequest,
                this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'OK' (200)
            String jsonResponse = submitHttpRequest(signedHttpRequest, 200);
            //if (verbose) System.out.println("\n    getFPEDecryptionKey: " + jsonResponse + "\n");

            // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            FPEKeyResponse decryptionKeyResponse = gson.fromJson(jsonResponse, FPEKeyResponse.class);

            return decryptionKeyResponse;
        } catch (Exception ex) {
            System.out.println(String.format("getFPEDecryptionKey exception: %s", ex.getMessage()));
            return null;
        }
    }




    EncryptionKeyResponse getEncryptionKey(int uses) {
        String urlString = String.format("%s/%s/encryption/key", this.baseUrl, this.restApiRoot);

        String jsonRequest = String.format("{\"uses\": %s}", uses);

        try {
            HttpRequest signedHttpRequest = buildSignedHttpRequest("POST", urlString, "", jsonRequest,
                this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());


            // submit HTTP request + expect HTTP response w/ status 'Created' (201)
            String jsonResponse = submitHttpRequest(signedHttpRequest, 201);
            //System.out.println(jsonResponse);

            // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            EncryptionKeyResponse encryptionKeyResponse =
                    gson.fromJson(jsonResponse, EncryptionKeyResponse.class);

            // decrypt the server-provided encryption key
            encryptionKeyResponse.UnwrappedDataKey = unwrapKey(
                        encryptionKeyResponse.EncryptedPrivateKey,
                        encryptionKeyResponse.WrappedDataKey,
                        this.ubiqCredentials.getSecretCryptoAccessKey());

            encryptionKeyResponse.EncryptedDataKeyBytes =
                    Base64.getDecoder().decode(encryptionKeyResponse.EncryptedDataKey);

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
            HttpRequest signedHttpRequest = buildSignedHttpRequest("PATCH", urlString, "", jsonRequest,
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
            HttpRequest signedHttpRequest =  buildSignedHttpRequest("POST", urlString, "", jsonRequest,
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
            HttpRequest signedHttpRequest = buildSignedHttpRequest("PATCH", urlString, "", jsonRequest,
                    this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'NoContent' (204)
            String jsonResponse = submitHttpRequest(signedHttpRequest, 204);

            // expect empty response
        } catch (Exception ex) {
            System.out.println(String.format("updateDecryptionKeyUsage exception: %s", ex.getMessage()));
        }
    }

    private HttpRequest buildSignedHttpRequest(String httpMethod, String urlString, String params, String jsonRequest,
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
        String requestTarget;
        if (params != "" ) {
            requestTarget = buildRequestTarget(httpMethod, url) + "?" + params;
        } else {
            requestTarget = buildRequestTarget(httpMethod, url);
        }
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
    private byte[] unwrapKey(String encryptedPrivateKey,
                String wrappedDataKey, String secretCryptoAccessKey)
            throws IOException, OperatorCreationException, PKCSException, InvalidCipherTextException {

        byte[] unwrappedDataKey = null;
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        try (PEMParser pemParser = new PEMParser(new StringReader(encryptedPrivateKey))) {

            Object object = pemParser.readObject();
            if (!(object instanceof PKCS8EncryptedPrivateKeyInfo)) {
                throw new RuntimeException("Unrecognized Encrypted Private Key format");
            }

            JceOpenSSLPKCS8DecryptorProviderBuilder builder = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider("BC");

            // Decrypt the private key using our secret key
            InputDecryptorProvider decryptProvider  = builder.build(secretCryptoAccessKey.toCharArray());

            PKCS8EncryptedPrivateKeyInfo keyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
            PrivateKeyInfo privateKeyInfo = keyInfo.decryptPrivateKeyInfo(decryptProvider);

            JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider("BC");
            PrivateKey privateKey = keyConverter.getPrivateKey(privateKeyInfo);

            if (!(privateKey instanceof BCRSAPrivateCrtKey)) {
                throw new RuntimeException("Unrecognized Private Key format");
            }
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

        return unwrappedDataKey;
    }


    private static String submitHttpRequest(HttpRequest httpRequest, int successCode)
            throws IOException, InterruptedException {
        HttpClient httpClient = HttpClient.newBuilder().build();

        HttpResponse<String> httpResponse = httpClient.send(httpRequest, BodyHandlers.ofString());

        String responseString = httpResponse.body();

        if (httpResponse.statusCode() != successCode) {
            // Making string match the FPEBillingResponse with status and message
            throw new IOException("{\"status\" : " + httpResponse.statusCode() + ", \"message\" : \"" + String.format(responseString) + "\"}");
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
