package com.ubiqsecurity;


import com.google.gson.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import java.math.BigInteger;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;

import java.nio.charset.StandardCharsets;

import java.security.interfaces.RSAPrivateKey;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;

import java.text.SimpleDateFormat;

import java.time.format.DateTimeFormatter;
import java.time.Instant;
import java.time.ZoneOffset;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.*;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.config.RequestConfig.Builder;
import org.apache.http.client.config.RequestConfig;

import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.http.client.config.CookieSpecs;


import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateCrtKey;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;



class UbiqWebServices {
    private boolean verbose= false;
    private final String applicationJson = "application/json";
    private final String restApiRoot = "api/v0";
    private final String restApiV3Root = "api/v3";

    private UbiqCredentials ubiqCredentials;
    private UbiqConfiguration ubiqConfiguration;
    private String baseUrl;

    private BouncyCastleProvider bcProvider;

    private static String print(byte[] bytes) {
      StringBuilder sb = new StringBuilder();
      sb.append("[ ");
      for (byte b : bytes) {
          sb.append(String.format("0x%02X ", b));
      }
      sb.append("]");
      return sb.toString();
   }
  
    UbiqWebServices(UbiqCredentials ubiqCredentials, UbiqConfiguration ubiqConfiguration) {
        this.bcProvider = new BouncyCastleProvider();
        this.ubiqCredentials = ubiqCredentials;
        this.ubiqConfiguration = ubiqConfiguration;

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
        if (verbose) System.out.println("Unwrapping key");
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

      String jsonRequest="";
      String params = String.format("ffs_name=%s&papi=%s", encode(ffs_name), encode(this.ubiqCredentials.getAccessKeyId()));
      if (this.ubiqCredentials.isIdp()) {
          // Need to check cert before it is used
        this.ubiqCredentials.renewIdpCert();
        params += String.format("&payload_cert=%s", this.ubiqCredentials.getApiCertBase64());
      }
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
 
        if (ubiqCredentials.isIdp()) {
          results.getAsJsonObject(ffs_name).addProperty("encrypted_private_key", this.ubiqCredentials.getEncryptedPrivateKey());
          if (verbose) {
            System.out.println(String.format("getFpeDefKeys results: %s", results.toString()));

          }
        }

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
        if (this.ubiqCredentials.isIdp()) {
            // Need to check cert before it is used
          this.ubiqCredentials.renewIdpCert();
          params += String.format("&payload_cert=%s", this.ubiqCredentials.getApiCertBase64());
        }
        String urlString = String.format("%s/%s/fpe/key?%s", this.baseUrl, this.restApiRoot, params);
        if (verbose) System.out.println("params :" + params);
        if (verbose) System.out.println("accessKeyId :" + this.ubiqCredentials.getAccessKeyId());
        if (verbose) System.out.println("secretSigningKey :" + this.ubiqCredentials.getSecretSigningKey());

        try {
            HttpRequestBase request = buildSignedHttpRequest("GET", urlString, params, jsonRequest, this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'Created' (200)
            String jsonResponse = submitHttpRequest(request, 200);

            if (verbose) System.out.println("jsonResponse :" + jsonResponse);

            // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            FPEKeyResponse encryptionKeyResponse =
                    gson.fromJson(jsonResponse, FPEKeyResponse.class);
            if (this.ubiqCredentials.isIdp()) {
              encryptionKeyResponse.EncryptedPrivateKey = this.ubiqCredentials.getEncryptedPrivateKey();
            }

            return encryptionKeyResponse;
        } catch (Exception ex) {
            System.out.println(String.format("getFPEEncryptionKey exception: %s", ex.getMessage()));
            return null;
        }
    }



    FPEKeyResponse getFPEDecryptionKey(String ffs_name, int key_number) {
        String jsonRequest="";
        String params = String.format("ffs_name=%s&papi=%s&key_number=%d", encode(ffs_name), encode(this.ubiqCredentials.getAccessKeyId()), key_number);
        if (this.ubiqCredentials.isIdp()) {
            // Need to check cert before it is used
          this.ubiqCredentials.renewIdpCert();
          params += String.format("&payload_cert=%s", this.ubiqCredentials.getApiCertBase64());
        }
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
            if (this.ubiqCredentials.isIdp()) {
              decryptionKeyResponse.EncryptedPrivateKey = this.ubiqCredentials.getEncryptedPrivateKey();
            }

            return decryptionKeyResponse;
        } catch (Exception ex) {
            System.out.println(String.format("getFPEDecryptionKey exception: %s", ex.getMessage()));
            return null;
        }
    }




    EncryptionKeyResponse getEncryptionKey(int uses) {
        String urlString = String.format("%s/%s/encryption/key", this.baseUrl, this.restApiRoot);

        JsonObject data = new JsonObject();
        data.addProperty("uses", uses);

        if (this.ubiqCredentials.isIdp()) {
          // Need to check cert before it is used
          this.ubiqCredentials.renewIdpCert();
          data.addProperty("payload_cert", this.ubiqCredentials.getApiCertBase64());
        }

        if (verbose) System.out.println("json: " + data.toString());

        try {
            HttpRequestBase request = buildSignedHttpRequest("POST", urlString, "", data.toString(), this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'Created' (201)
            String jsonResponse = submitHttpRequest(request, 201);
            if (verbose) System.out.println(jsonResponse);

            // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            EncryptionKeyResponse encryptionKeyResponse =
                    gson.fromJson(jsonResponse, EncryptionKeyResponse.class);

            if (this.ubiqCredentials.isIdp()) {
              encryptionKeyResponse.EncryptedPrivateKey = this.ubiqCredentials.getEncryptedPrivateKey();
            }

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

        JsonObject data = new JsonObject();
        data.addProperty("encrypted_data_key", base64DataKey);
        if (this.ubiqCredentials.isIdp()) {
          // Need to check cert before it is used
          this.ubiqCredentials.renewIdpCert();
          data.addProperty("payload_cert", this.ubiqCredentials.getApiCertBase64());
        }

        try {
            HttpRequestBase request = buildSignedHttpRequest("POST", urlString, "", data.toString(), this.ubiqCredentials.getAccessKeyId(), this.ubiqCredentials.getSecretSigningKey());

            // submit HTTP request + expect HTTP response w/ status 'OK' (200)
            String jsonResponse = submitHttpRequest(request, 200);

            // deserialize the JSON response to POJO
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            DecryptionKeyResponse decryptionKeyResponse = gson.fromJson(jsonResponse, DecryptionKeyResponse.class);

            if (this.ubiqCredentials.isIdp()) {
              decryptionKeyResponse.EncryptedPrivateKey = this.ubiqCredentials.getEncryptedPrivateKey();
            }

            // To make sure it isn't null and length will be 0.
            decryptionKeyResponse.UnwrappedDataKey = new byte[0];

            return decryptionKeyResponse;
        } catch (Exception ex) {
            System.out.println(String.format("getDecryptionKey exception: %s", ex.getMessage()));
            return null;
        }
    }
  
    String GetOAuthToken() {
      HttpResponse response = null;
      
      try (CloseableHttpClient client = HttpClients.custom()
          .setDefaultRequestConfig(RequestConfig.custom()
          .setCookieSpec(CookieSpecs.STANDARD)
          .build()).build()) {
        HttpPost post = new HttpPost(new URI(this.ubiqConfiguration.getIdpTokenEndpointUrl()));

        post.setHeader("Accept", ContentType.APPLICATION_JSON.toString());
        post.setHeader("Cache-Control", "no-cache");
        post.setHeader("Content-Type", ContentType.APPLICATION_FORM_URLENCODED.toString());
        
        Map<String, String> params = new HashMap<>();
        params.put("client_id", this.ubiqConfiguration.getIdpTenantId());
        params.put("client_secret", this.ubiqConfiguration.getIdpClientSecret());
        params.put("username", this.ubiqCredentials.getIdpUsername());
        params.put("password", this.ubiqCredentials.getIdpPassword());
        params.put("grant_type", "password");
        params.put("scope", "okta.users.read okta.groups.manage");
  
        if (this.ubiqConfiguration.getIdpType().equals("okta")) {
          params.put("scope", "openid offline_access okta.users.read okta.groups.read");
  
        } else if (this.ubiqConfiguration.getIdpType().equals("entra")) {
          params.put("scope", "api://" + this.ubiqConfiguration.getIdpTenantId() + "/.default");
        }

        StringBuilder sb = new StringBuilder();

        for (Map.Entry<String, String> entry : params.entrySet()) {
          if (sb.length() > 0) {
              sb.append("&");
          }
          try {
            sb.append(entry.getKey())
                      .append("=")
                      .append(URLEncoder.encode(entry.getValue()));
          } catch (Exception e) {
            System.out.println("    GetOAuthToken exception sb : " + e.getMessage());
            throw new RuntimeException(e);
          }
        }

        post.setEntity(new StringEntity(sb.toString()));
        response = client.execute(post);
        String responseString = EntityUtils.toString(response.getEntity(), "UTF-8");

        if (verbose) System.out.println("Response Code: " + response.getStatusLine().getStatusCode());
        if (verbose) System.out.println("Response: " + responseString);
        return responseString;
      } catch (Exception e) {
        throw new RuntimeException("{\"status\" : " + 400 + ", \"message\" : \"" + e.getMessage() + "\"}");
      }
    }    

String getSso(String access_token, String csr) {
  HttpResponse response = null;
      
  String responseString = null;
      try (CloseableHttpClient client = HttpClients.custom()
            .setDefaultRequestConfig(RequestConfig.custom()
            .setCookieSpec(CookieSpecs.STANDARD)
            .build()).build()) {
        HttpPost post = new HttpPost(new URI(String.format("%s/%s/%s/scim/sso", this.baseUrl, this.ubiqConfiguration.getIdpCustomerId(), this.restApiV3Root)));

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("csr", csr);

        post.setHeader("Accept", ContentType.APPLICATION_JSON.toString());
        post.setHeader("Authorization", String.format("Bearer %s", access_token));
        post.setHeader("Cache-Control", "no-cache");
        post.setHeader("Content-Type", ContentType.APPLICATION_JSON.toString());
        
        post.setEntity(new StringEntity(jsonObject.toString()));
        response = client.execute(post);
        responseString = EntityUtils.toString(response.getEntity(), "UTF-8");

        if (response.getStatusLine().getStatusCode() != 200) {
          throw new IOException("{\"status\" : " + response.getStatusLine().getStatusCode() + ", \"message\" : \"" + String.format(responseString) + "\"}");
        }

        if (verbose) System.out.println("Response Code: " + response.getStatusLine().getStatusCode());
        if (verbose) System.out.println("Response: " + responseString);
      } catch (Exception e) {
        throw new RuntimeException("{\"status\" : " + 400 + ", \"message\" : \"" + e.getMessage() + "\"}");
      }
      return responseString;
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
            Security.addProvider(this.bcProvider);
        } 

        try (PEMParser pemParser = new PEMParser(new StringReader(encryptedPrivateKey))) {

            Object object = pemParser.readObject();
            if (!(object instanceof PKCS8EncryptedPrivateKeyInfo)) {
                throw new RuntimeException("Unrecognized Encrypted Private Key format");
            }

            JceOpenSSLPKCS8DecryptorProviderBuilder builder = new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(this.bcProvider);

            // Decrypt the private key using our secret key
            InputDecryptorProvider decryptProvider  = builder.build(secretCryptoAccessKey.toCharArray());

            PKCS8EncryptedPrivateKeyInfo keyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
            PrivateKeyInfo privateKeyInfo = keyInfo.decryptPrivateKeyInfo(decryptProvider);

            JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter().setProvider(this.bcProvider);
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
