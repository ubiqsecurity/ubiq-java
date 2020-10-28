package com.ubiqsecurity;

import java.io.IOException;

public class UbiqCredentials {
    // Environment variable names
    private final String UBIQ_ACCESS_KEY_ID = "UBIQ_ACCESS_KEY_ID";
    private final String UBIQ_SECRET_SIGNING_KEY = "UBIQ_SECRET_SIGNING_KEY";
    private final String UBIQ_SECRET_CRYPTO_ACCESS_KEY = "UBIQ_SECRET_CRYPTO_ACCESS_KEY";

    // Property values
    private String accessKeyId;
    private String secretSigningKey;
    private String secretCryptoAccessKey;
    private String host;

    UbiqCredentials(String accessKeyId, String secretSigningKey, String secretCryptoAccessKey, String host) {
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

        this.host = host;
    }

    UbiqCredentials(String pathname, String profile, String host) throws IOException {
        final String DEFAULT_SECTION = "default";
        final String ACCESS_KEY_ID = "access_key_id";
        final String SECRET_SIGNING_KEY = "secret_signing_key";
        final String SECRET_CRYPTO_ACCESS_KEY = "secret_crypto_access_key";
        final String SERVER_KEY = "server";

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
            this.host = host;
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
}
