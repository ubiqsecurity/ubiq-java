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

class UbiqWebServices {
    private final String applicationJson = "application/json";
    private final String restApiRoot = "api/v0";

    private UbiqCredentials ubiqCredentials;
    private String baseUrl;

    UbiqWebServices(UbiqCredentials ubiqCredentials) {
        this.ubiqCredentials = ubiqCredentials;

        if (!this.ubiqCredentials.getHost().startsWith("http")) {
            this.baseUrl = String.format("https://%s", this.ubiqCredentials.getHost());
        } else {
            this.baseUrl = this.ubiqCredentials.getHost();
        }
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
            encryptionKeyResponse.postProcess(this.ubiqCredentials.getSecretCryptoAccessKey());
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
            //System.out.println(jsonResponse);

            // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            DecryptionKeyResponse decryptionKeyResponse = gson.fromJson(jsonResponse, DecryptionKeyResponse.class);

            // decrypt the server-provided encryption key
            decryptionKeyResponse.postProcess(this.ubiqCredentials.getSecretCryptoAccessKey());
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
        headerFields.put("User-Agent", "ubiq-java/0.0.0"); // TODO: replace with actual package version
//        headerFields.put("Date", buildDateValue());
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
            //System.out.println("header[" + fieldName + "] = " + headerFields.get(fieldName));
            builder.header(fieldName, headerFields.get(fieldName));
        }

        HttpRequest httpRequest = builder.build();
        return httpRequest;
    }

    private static String submitHttpRequest(HttpRequest httpRequest, int successCode)
            throws IOException, InterruptedException {
        HttpClient httpClient = HttpClient.newBuilder().build();
        HttpResponse<String> httpResponse = httpClient.send(httpRequest, BodyHandlers.ofString());

//        System.out.println("httpResponse.statusCode() = " + httpResponse.statusCode());

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
//            writeHashableBytes(hashStream, "Content-Length", headerFields.get("Content-Length"));
            writeHashableBytes(hashStream, "Content-Type", headerFields.get("Content-Type"));
//            writeHashableBytes(hashStream, "Date", headerFields.get("Date"));
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

        // System.out.println("hashableString: " + hashableString);

        // convert to UTF-8 byte array
        byte[] hashableBytes = hashableString.getBytes(StandardCharsets.UTF_8);

        // write bytes to caller-provided Stream
        hashStream.write(hashableBytes, 0, hashableBytes.length);
    }
}
