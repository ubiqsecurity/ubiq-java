package com.ubiqsecurity;


import java.math.BigInteger;
import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import org.apache.http.client.methods.RequestBuilder;

import java.net.URI;
import java.net.URL;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.*;
import org.apache.http.Header;

import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.CloseableHttpClient;

import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.entity.ContentType;

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
import java.security.interfaces.RSAPrivateKey;
import com.google.gson.*;

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
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import java.security.PrivateKey;
import java.security.Security;
import java.io.IOException;
import java.io.StringReader;


import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;


import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import java.io.PrintWriter;
import java.io.StringWriter;


class UbiqWebServices {
    private boolean verbose= false;
    private final String applicationJson = "application/json";
    private final String restApiRoot = "api/v0";
    private final String restApiV3Root = "api/v3";

    private UbiqCredentials ubiqCredentials;
    private String baseUrl;

    private static String print(byte[] bytes) {
      StringBuilder sb = new StringBuilder();
      sb.append("[ ");
      for (byte b : bytes) {
          sb.append(String.format("0x%02X ", b));
      }
      sb.append("]");
      return sb.toString();
   }
  
    UbiqWebServices(UbiqCredentials ubiqCredentials) {
        this.ubiqCredentials = ubiqCredentials;

        if (!this.ubiqCredentials.getHost().startsWith("http")) {
            this.baseUrl = String.format("https://%s", this.ubiqCredentials.getHost());
        } else {
            this.baseUrl = this.ubiqCredentials.getHost();
        }
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




    FPEBillingResponse sendTrackingEvents(String payload) {
      String csu = "sendTrackingEvents";
      String urlString = String.format("%s/%s/tracking/events", this.baseUrl, this.restApiV3Root);
        if (verbose) System.out.printf("%s  urlString: %s\n", csu, urlString);

        String jsonRequest = payload;
        FPEBillingResponse fpeBillingResponse = new FPEBillingResponse(200, "");
        try {

          HttpRequestBase request = buildSignedHttpRequest("POST", urlString, "", jsonRequest, this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

          String jsonResponse = submitHttpRequest(request, 200);

          if (verbose) System.out.println("    sendBilling jsonResponse: " + jsonResponse);
          if (jsonResponse != null && !jsonResponse.isEmpty()) {

            if (verbose) System.out.println("    jsonResponse is NOT NULL");

            // We know success is 200, so just add the json response
            fpeBillingResponse = new FPEBillingResponse(200, jsonResponse);

            if (verbose) System.out.println("  RETURN  status: " + fpeBillingResponse.status + ", message: " + fpeBillingResponse.message );
          }
          return fpeBillingResponse;
        } catch (Exception ex) {

            return new FPEBillingResponse(400, "Server Error: " + ex.getMessage());

        }
    }


    // Get the search keys using the fpe/def_keys endpoint
    JsonObject getFpeDefKeys(String ffs_name) {

      boolean verbose = false;
      String jsonRequest="";
      String params = String.format("ffs_name=%s&papi=%s", encode(ffs_name), encode(this.ubiqCredentials.getAccessKeyId()));
      String urlString = String.format("%s/%s/fpe/def_keys?%s", this.baseUrl, this.restApiRoot, params);

      if (verbose) System.out.println("\n    urlString: " + urlString + "\n");
      if (verbose) System.out.println("\n    params: " + params + "\n");

      try {

        HttpRequestBase request = buildSignedHttpRequest("GET", urlString, params, jsonRequest, this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

        // submit HTTP request + expect HTTP response w/ status 'Created' (200)
        String jsonResponse = submitHttpRequest(request, 200);

        if (verbose) System.out.println("\n    getFpeDefKeys: " + jsonResponse + "\n");

        JsonParser parser = new JsonParser();

        // deserialize the JSON response to POJO
        JsonObject results = parser.parse(jsonResponse).getAsJsonObject();

        return results;
      } catch (Exception ex) {
          System.out.println(String.format("getFpeDefKeys exception: %s", ex.getMessage()));
          return null;
      }

    }

    FFS_Record getFFSDefinition(String ffs_name) {
        //String urlString = String.format("%s/%s/ffs/%s", this.baseUrl, this.restApiRoot, this.ubiqCredentials.getAccessKeyId());
        String jsonRequest="";
        String params = String.format("ffs_name=%s&papi=%s", encode(ffs_name), encode(this.ubiqCredentials.getAccessKeyId()));
        String urlString = String.format("%s/%s/ffs?%s", this.baseUrl, this.restApiRoot, params);

        if (verbose) System.out.println("\n    urlString: " + urlString + "\n");
        if (verbose) System.out.println("\n    params: " + params + "\n");

        try {

            HttpRequestBase request = buildSignedHttpRequest("GET", urlString, params, jsonRequest, this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'Created' (200)
            String jsonResponse = submitHttpRequest(request, 200);

            if (verbose) System.out.println("\n    getFFSDefinition: " + jsonResponse + "\n");

            // deserialize the JSON response to POJO
            FFS_Record ffsRecord = FFS_Record.parse(jsonResponse);
            if (verbose) System.out.println("\n    getFFSDefinition(ffsRecord): " + jsonResponse + "\n");

            return ffsRecord;
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


            HttpRequestBase request = buildSignedHttpRequest("GET", urlString, params, jsonRequest, this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'Created' (200)
            String jsonResponse = submitHttpRequest(request, 200);

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

            HttpRequestBase request = buildSignedHttpRequest("GET", urlString, params, jsonRequest, this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'OK' (200)
            String jsonResponse = submitHttpRequest(request, 200);
            if (verbose) System.out.println("\n    getFPEDecryptionKey: " + jsonResponse + "\n");

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
            HttpRequestBase request = buildSignedHttpRequest("POST", urlString, "", jsonRequest, this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'Created' (201)
            String jsonResponse = submitHttpRequest(request, 201);
            if (verbose) System.out.println(jsonResponse);

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

    DecryptionKeyResponse getDecryptionKey(byte[] encryptedDataKey) {
        String urlString = String.format("%s/%s/decryption/key", this.baseUrl, this.restApiRoot);

        // convert binary key bytes to Base64
        String base64DataKey = Base64.getEncoder().encodeToString(encryptedDataKey);
        String jsonRequest = String.format("{\"encrypted_data_key\": \"%s\"}", base64DataKey);

        try {
            HttpRequestBase request = buildSignedHttpRequest("POST", urlString, "", jsonRequest, this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'OK' (200)
            String jsonResponse = submitHttpRequest(request, 200);

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

    private HttpRequestBase buildSignedHttpRequest
      (String httpMethod, String urlString, String params, String jsonRequest,
    String publicAccessKey, String secretSigningKey) throws URISyntaxException, NoSuchAlgorithmException, InvalidKeyException,
    IOException {

      HttpRequestBase request = null;
      URI uri = new URI(urlString);

      // Only available on patch, post, put
      HttpEntity stringEntity = new StringEntity(jsonRequest,ContentType.APPLICATION_JSON);
      Map<String, String> headerFields = new HashMap<String, String>();
      String unixTimeString = unixTimeAsString();
      headerFields.put("Content-Type", ContentType.APPLICATION_JSON.toString());

      switch (httpMethod) {
        case "POST":
          request = new HttpPost(uri);
          ((HttpEntityEnclosingRequestBase)request).setEntity(stringEntity);
          headerFields.put("Content-Length", String.valueOf(stringEntity.getContentLength()));
        break;

        case "GET":
          request = new HttpGet(uri);
        break;

        case "PATCH":
          request = new HttpPatch(uri);
          ((HttpEntityEnclosingRequestBase)request).setEntity(stringEntity);
          headerFields.put("Content-Length", String.valueOf(stringEntity.getContentLength()));
        break;

        case "DELETE":
          request = new HttpDelete(uri);
        break;

        case "PUT":
          request = new HttpPut(uri);
          ((HttpEntityEnclosingRequestBase)request).setEntity(stringEntity);
          headerFields.put("Content-Length", String.valueOf(stringEntity.getContentLength()));
        break;

      }

      headerFields.put("Accept", ContentType.APPLICATION_JSON.toString());
      headerFields.put("User-Agent", "ubiq-java/" + Version.VERSION);


      // Some JDK don't allow override of certain automatically-added request headers, so ditch them.

      String host = uri.getHost();
      // If port is specified, it needs to be included
      if (uri.getPort() != -1) {
              host += ":" + uri.getPort();
      }
      headerFields.put("Host", host);
      headerFields.put("Digest", buildDigestValue(jsonRequest.getBytes(StandardCharsets.UTF_8)));

      String requestTarget;
      if (params != null && params != "" ) {
          requestTarget = buildRequestTarget(httpMethod, uri) + "?" + params;
      } else {
          requestTarget = buildRequestTarget(httpMethod, uri);
      }

      String signature = buildSignature(headerFields, unixTimeString, requestTarget, publicAccessKey, secretSigningKey);
      headerFields.put("Signature", signature);

      // Content length and host are supplied automatically.  Need to include for signature calculation
      // but not when setting the request headers.
      headerFields.remove("Content-Length");
      headerFields.remove("Host");

      for (String fieldName : headerFields.keySet()) {
        request.addHeader(fieldName, headerFields.get(fieldName));
      }

      return request;
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

            JceOpenSSLPKCS8DecryptorProviderBuilder builder = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(new BouncyCastleProvider());

            // Decrypt the private key using our secret key
            InputDecryptorProvider decryptProvider  = builder.build(secretCryptoAccessKey.toCharArray());

            PKCS8EncryptedPrivateKeyInfo keyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
            PrivateKeyInfo privateKeyInfo = keyInfo.decryptPrivateKeyInfo(decryptProvider);

            JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider(new BouncyCastleProvider());
            PrivateKey privateKey = keyConverter.getPrivateKey(privateKeyInfo);


            if (!(privateKey instanceof BCRSAPrivateCrtKey)) {
                throw new RuntimeException("Unrecognized Private Key format: " + privateKey.getClass().getName() + " " );
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

    private static String submitHttpRequest(HttpRequestBase httpRequest, int successCode)
            throws IOException, InterruptedException {

        HttpClient httpclient = HttpClients.createDefault();
        HttpResponse response = httpclient.execute(httpRequest);
      
        BufferedReader reader = new BufferedReader(new InputStreamReader(
          response.getEntity().getContent()));
  
        String inputLine;
        StringBuffer r = new StringBuffer();
      
          while ((inputLine = reader.readLine()) != null) {
            r.append(inputLine);
          }
          reader.close();
      
          String responseString = r.toString();

        if (response.getStatusLine().getStatusCode() != successCode) {
        // Making string match the FPEBillingResponse with status and message
          throw new IOException("{\"status\" : " + response.getStatusLine().getStatusCode() + ", \"message\" : \"" + String.format(responseString) + "\"}");
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

    private static String buildRequestTarget(String httpMethod, URI uri) {
        String requestTarget = httpMethod.toLowerCase() + " " + uri.getPath();
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
