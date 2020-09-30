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
