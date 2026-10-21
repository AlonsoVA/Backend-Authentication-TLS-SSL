package com.trabajo1.security;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.Test;

class DevKeystoreTest {

    @Test
    void pkcs12ContainsLocalhostCertificate() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream input = getClass().getResourceAsStream("/keystore/dev-keystore.p12")) {
            assertNotNull(input, "El keystore de desarrollo debe estar en el classpath");
            keyStore.load(input, "dev-local-changeit".toCharArray());
        }

        Certificate certificate = keyStore.getCertificate("backend-tls");
        assertNotNull(certificate);
        X509Certificate x509 = (X509Certificate) certificate;
        assertTrue(x509.getSubjectX500Principal().getName().contains("CN=localhost"));

        Collection<List<?>> alternativeNames = x509.getSubjectAlternativeNames();
        assertNotNull(alternativeNames);
        assertTrue(alternativeNames.stream().anyMatch(name -> "localhost".equals(String.valueOf(name.get(1)))));
    }
}
