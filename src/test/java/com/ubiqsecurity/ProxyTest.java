package com.ubiqsecurity;

import org.apache.http.client.config.RequestConfig;
import org.junit.Test;

import static org.junit.Assert.*;


public class ProxyTest {
    @Test
    public void testBuildRequestConfigSetsProxy() {
        UbiqCredentials ubiqCredentials = UbiqFactory.createCredentials(
                "accessKeyId", "secretSigningKey", "secretCryptoKey", "keyFingerprint"
        );
        UbiqConfiguration ubiqConfiguration = UbiqFactory.createConfiguration(
                null, null, null, null, null, null, null, null, null,
                "proxy.example.com", 8080);

        UbiqWebServices svc = new UbiqWebServices(ubiqCredentials, ubiqConfiguration);
        RequestConfig config = svc.buildRequestConfig();

        assertNotNull(config.getProxy());
        assertEquals("proxy.example.com", config.getProxy().getHostName());
        assertEquals(8080, config.getProxy().getPort());
    }
}
