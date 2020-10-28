package com.ubiqsecurity;

import java.io.IOException;

public abstract class UbiqFactory {
    private static final String DEFAULT_UBIQ_HOST = "api.ubiqsecurity.com";

    public static UbiqCredentials createCredentials(String accessKeyId, String secretSigningKey,
            String secretCryptoAccessKey, String host) {
        if ((host == null) || host.isEmpty()) {
            host = DEFAULT_UBIQ_HOST;
        }
        return new UbiqCredentials(accessKeyId, secretSigningKey, secretCryptoAccessKey, host);
    }

    public static UbiqCredentials readCredentialsFromFile(String pathname, String profile) throws IOException {
        return new UbiqCredentials(pathname, profile, DEFAULT_UBIQ_HOST);
    }
}
