package com.ubiqsecurity;

import com.google.gson.*;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;

import java.time.ZonedDateTime;
import java.time.ZoneOffset;

import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.jcajce.*;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class UbiqCredentials {

  class Sso {
    @SerializedName("public_value")
    String public_value;

    @SerializedName("signing_value")
    String signing_value;

    @SerializedName("enabled")
    Boolean enabled = false;

    @SerializedName("api_cert")
    String api_cert;
  }

  class OAuth2 {
    @SerializedName("access_token")
    String access_token;

    @SerializedName("expires_in")
    Integer expires_in;
  }

    private static boolean verbose= false;


    // Environment variable names
    private final String UBIQ_ACCESS_KEY_ID = "UBIQ_ACCESS_KEY_ID";
    private final String UBIQ_SECRET_SIGNING_KEY = "UBIQ_SECRET_SIGNING_KEY";
    private final String UBIQ_SECRET_CRYPTO_ACCESS_KEY = "UBIQ_SECRET_CRYPTO_ACCESS_KEY";
    private final String UBIQ_SERVER = "UBIQ_SERVER";
    private static final String DEFAULT_UBIQ_HOST = "api.ubiqsecurity.com";
    private final String UBIQ_IDP_USERNAME = "UBIQ_IDP_USERNAME";
    private final String UBIQ_IDP_PASSWORD = "UBIQ_IDP_PASSWORD";

    // Property values
    private String accessKeyId;
    private String secretSigningKey;
    private String secretCryptoAccessKey;
    private String host;
    private String idp_username;
    private String idp_password;
    private String api_cert_base64;
    private Boolean initialized = false;
    private UbiqConfiguration config = null;
    private UbiqWebServices ubiqWebServices = null;
    private String csr;
    private OAuth2 OauthResults = null;
    // private String token;
    // private String sso;
    private Sso SsoResults = null;
    private ZonedDateTime cert_expires = ZonedDateTime.now(ZoneOffset.UTC);
    private String encryptedPrivateKeyPem;



    UbiqCredentials(String accessKeyId, String secretSigningKey, String secretCryptoAccessKey, String host,
                    String idp_username, String idp_password) {
        if (accessKeyId == null) {
            accessKeyId = System.getenv(UBIQ_ACCESS_KEY_ID);
        }
        this.accessKeyId = accessKeyId;

        if (secretSigningKey == null) {
            secretSigningKey = System.getenv(UBIQ_SECRET_SIGNING_KEY);
        }
        this.secretSigningKey = secretSigningKey;

        if (secretCryptoAccessKey == null) {
            secretCryptoAccessKey = System.getenv(UBIQ_SECRET_CRYPTO_ACCESS_KEY);
        }
        this.secretCryptoAccessKey = secretCryptoAccessKey;

        if (host == null) {
          host = System.getenv(UBIQ_SERVER);
        }
        if (host == null) {
          host = DEFAULT_UBIQ_HOST;
        }
        this.host = host;

        if (idp_username == null) {
          idp_username= System.getenv(UBIQ_IDP_USERNAME);
        }
        this.idp_username = idp_username;

        if (idp_password == null) {
          idp_password= System.getenv(UBIQ_IDP_PASSWORD);
        }
        this.idp_password = idp_password;

        if ((this.secretCryptoAccessKey != null) || ((this.idp_username != null) && (this.idp_password != null))) {
          // NOP
        }
        else {
          throw new IllegalArgumentException("Credentials data is incomplete");
        }
    }

    UbiqCredentials(String pathname, String profile) throws IOException {
        final String DEFAULT_SECTION = "default";
        final String ACCESS_KEY_ID = "access_key_id";
        final String SECRET_SIGNING_KEY = "secret_signing_key";
        final String SECRET_CRYPTO_ACCESS_KEY = "secret_crypto_access_key";
        final String SERVER_KEY = "server";
        final String IDP_USERNAME = "idp_username";
        final String IDP_PASSWORD = "idp_password";

        if ((pathname == null) || pathname.isEmpty()) {
            // credentials file not specified, so look for ~/.ubiq/credentials
            pathname = String.format("%s/.ubiq/credentials", System.getProperty("user.home"));
        }

        ConfigParser configParser = new ConfigParser(pathname);
        this.accessKeyId = configParser.fetchValue(profile, ACCESS_KEY_ID);
        if (this.accessKeyId == null) {
            this.accessKeyId = configParser.fetchValue(DEFAULT_SECTION, ACCESS_KEY_ID);
        }

        this.secretSigningKey = configParser.fetchValue(profile, SECRET_SIGNING_KEY);
        if (this.secretSigningKey == null) {
            this.secretSigningKey = configParser.fetchValue(DEFAULT_SECTION, SECRET_SIGNING_KEY);
        }

        this.secretCryptoAccessKey = configParser.fetchValue(profile, SECRET_CRYPTO_ACCESS_KEY);
        if (this.secretCryptoAccessKey == null) {
            this.secretCryptoAccessKey = configParser.fetchValue(DEFAULT_SECTION, SECRET_CRYPTO_ACCESS_KEY);
        }

        this.host = configParser.fetchValue(profile, SERVER_KEY);
        if (this.host == null) {
            this.host = configParser.fetchValue(DEFAULT_SECTION, SERVER_KEY);
        }
        if (this.host == null) {
            this.host = DEFAULT_UBIQ_HOST;
        }

        this.idp_username = configParser.fetchValue(profile, IDP_USERNAME);
        if (this.idp_username == null) {
            this.idp_username = configParser.fetchValue(DEFAULT_SECTION, IDP_USERNAME);
        }

        this.idp_password = configParser.fetchValue(profile, IDP_PASSWORD);
        if (this.idp_password == null) {
            this.idp_password = configParser.fetchValue(DEFAULT_SECTION, IDP_PASSWORD);
        }
    }

    public Boolean init(UbiqConfiguration config){
      try {
        if (this.idp_username != null) {

          // This is a little chicken and egg but need Webservice to
          // validate SSO using the IDP parameters
          this.ubiqWebServices = new UbiqWebServices(this, config);

          // Create a secretCryptoAccessKey which will be used to decrypt a private RSA keys
          byte[] key = new byte[33];
          SecureRandom random = new SecureRandom();
          random.nextBytes(key);
          this.secretCryptoAccessKey = new String(Base64.getEncoder().encode(key));
          if (verbose) System.out.println("'" + this.secretCryptoAccessKey + "'");

          // Create the RSA Key Pair
          KeyPair keypair = RSAKeys.generateKeyPair("RSA", 4096);

          // Generate a CSR that will be signed by the server
          this.csr = RSAKeys.generateCsr(keypair);
          if (verbose) System.out.println(String.format("CSR: %s", csr));

          // Get OAuth token and SSO token
          getIdpTokenAndCert();

          // Encrypt the private RSA key with the secretCryptoAccessKey
          PrivateKey privateKeyParameter = keypair.getPrivate();
          PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKeyParameter.getEncoded());

          PKCS8EncryptedPrivateKeyInfoBuilder builder = new PKCS8EncryptedPrivateKeyInfoBuilder(pkInfo);

          PKCS8EncryptedPrivateKeyInfo encInfo = builder.build(
            new JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                .setPRF(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))
                .setProvider(new BouncyCastleProvider())
                .build(this.secretCryptoAccessKey.toCharArray()));

          EncryptedPrivateKeyInfo encPkInfo = EncryptedPrivateKeyInfo.getInstance(encInfo.getEncoded());

          // Get the encrypted key bytes
          byte[] encryptedKeyBytes = encPkInfo.getEncoded();

          if (verbose) System.out.println(String.format("encryptedKeyBytes %s", encryptedKeyBytes.toString()));

          // Create PEM formatted encrypted private key (optional)
          StringWriter stringWriter = new StringWriter();
          JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
          PemObject pemObject = new PemObject("ENCRYPTED PRIVATE KEY", encryptedKeyBytes);
          pemWriter.writeObject(pemObject);
          pemWriter.close();

          this.encryptedPrivateKeyPem = stringWriter.toString();
          if (verbose) System.out.println("encryptedPrivateKeyPem: " + this.encryptedPrivateKeyPem);
        }
        this.initialized = true;
      } catch (Exception e) {
        System.out.println(String.format("Credentials init exception: %s", e.getMessage()));
      }

      return this.initialized;
    }

    public void renewIdpCert() {
      if (this.isIdp()) {
        ZonedDateTime currentDate = ZonedDateTime.now(ZoneOffset.UTC);
        if (currentDate.isAfter(this.cert_expires)) {
          getIdpTokenAndCert();
        }
      }
    }

    private void getIdpTokenAndCert() {
      try {
        String tokenRsp = this.ubiqWebServices.GetOAuthToken();
        if (verbose) System.out.println(String.format("GetOAuthToken: %s", tokenRsp));

        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        this.OauthResults = gson.fromJson(JsonParser.parseString(tokenRsp), UbiqCredentials.OAuth2.class);

        if (verbose) System.out.println("Expires in " + this.OauthResults.expires_in.toString());

        String token = this.OauthResults.access_token;
        // (new JsonParser()).parse(tokenRsp).getAsJsonObject().get("access_token").getAsString();
        if (verbose) System.out.println(String.format("GetOAuthToken: this.token %s", token ));

        String ssoRsp = this.ubiqWebServices.getSso(token, this.csr);
        if (verbose) System.out.println(String.format("getSso: %s", ssoRsp.toString()));

        this.SsoResults = gson.fromJson(JsonParser.parseString(ssoRsp), UbiqCredentials.Sso.class);

        if (this.SsoResults.enabled) {
          this.accessKeyId = this.SsoResults.public_value;
          this.secretSigningKey = this.SsoResults.signing_value;
          this.api_cert_base64 =  Base64.getEncoder().encodeToString(this.SsoResults.api_cert.getBytes());
        
          byte[] certBytes = this.SsoResults.api_cert.getBytes("UTF-8");
          CertificateFactory factory = CertificateFactory.getInstance("X.509");
          X509Certificate x509Certificate = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));

          // Get certificate expiration date and subtract 1 minute (60000 milliseconds)
          Date certExpires = x509Certificate.getNotAfter();
          this.cert_expires = ZonedDateTime.ofInstant((new Date(certExpires.getTime() - 60000)).toInstant(), ZoneOffset.UTC);
        }
      } catch (Exception e) {
        System.out.println(String.format("Idp Error: %s", e.getMessage()));
        throw new RuntimeException(String.format("Idp Error: %s", e.getMessage()));
      }
    }

    public String getAccessKeyId() {
        return accessKeyId;
    }

    public String getSecretSigningKey() {
        return secretSigningKey;
    }

    public String getSecretCryptoAccessKey() {
        return secretCryptoAccessKey;
    }

    public String getHost() {
        return host;
    }

    public String getEncryptedPrivateKey() {
      return this.encryptedPrivateKeyPem;
    }

    public Boolean isIdp() {
      // Only need to check for Idp if credentials have IDP Parameters
      // Otherwise the initialized flag can be ignored.
      Boolean ret = (this.idp_username != null && this.idp_username.length() > 0);

      if (ret && !this.initialized) {
        throw new IllegalArgumentException("Credentials.init(configuration) has not been called or failed but is required when using IDP authentication");
      }

      return ret;
    }

    public String getIdpUsername() {
      return idp_username;
    }

    public String getIdpPassword() {
      return idp_password;
    }
    public String getApiCertBase64() {
      return api_cert_base64;
    }
}
