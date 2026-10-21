package com.trabajo1.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;

@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT, properties = {
        "server.port=18443",
        "app.http.port=18080"
})
class TlsHandshakeTest {

    @Test
    void plainHttpIsRejectedWithCustomMessage() throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:18080/api/public/health"))
                .GET()
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());

        assertEquals(426, response.statusCode());
        assertTrue(response.body().contains("TLS 1.2"));
        assertTrue(response.body().contains("TLS 1.3"));
    }

    @Test
    void httpsHealthUsesTls12() throws Exception {
        assertEquals("TLSv1.2", negotiatedProtocol(new String[]{"TLSv1.2"}));
    }

    @Test
    void httpsHealthUsesTls13() throws Exception {
        assertEquals("TLSv1.3", negotiatedProtocol(new String[]{"TLSv1.3"}));
    }

    @Test
    void legacyTls11IsRejected() throws Exception {
        String previous = Security.getProperty("jdk.tls.disabledAlgorithms");
        try {
            Security.setProperty("jdk.tls.disabledAlgorithms", "");
            SSLContext context = trustDevKeystore();
            try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket("127.0.0.1", 18443)) {
                try {
                    socket.setEnabledProtocols(new String[]{"TLSv1.1"});
                } catch (IllegalArgumentException ex) {
                    Assumptions.abort("El JDK cliente no ofrece TLS 1.1: " + ex.getMessage());
                }
                assertThrows(SSLException.class, socket::startHandshake);
            }
        } finally {
            Security.setProperty("jdk.tls.disabledAlgorithms", previous);
        }
    }

    @Test
    void protectedEndpointOverHttpsRequiresBearerToken() throws Exception {
        HttpClient client = HttpClient.newBuilder().sslContext(trustDevKeystore()).build();

        HttpResponse<String> unauthorized = client.send(
                HttpRequest.newBuilder(URI.create("https://localhost:18443/api/secure/profile")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(401, unauthorized.statusCode());
        assertTrue(unauthorized.body().contains("token de autenticación"));

        String userToken = accessToken(client, "user", "User123!");
        HttpResponse<String> forbidden = client.send(
                HttpRequest.newBuilder(URI.create("https://localhost:18443/api/admin/reports"))
                        .header("Authorization", "Bearer " + userToken)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(403, forbidden.statusCode());

        String adminToken = accessToken(client, "admin", "Admin123!");
        HttpResponse<String> reports = client.send(
                HttpRequest.newBuilder(URI.create("https://localhost:18443/api/admin/reports"))
                        .header("Authorization", "Bearer " + adminToken)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, reports.statusCode());
        assertTrue(reports.body().contains("acceso de administrador concedido"));
    }

    private String accessToken(HttpClient client, String username, String password) throws Exception {
        HttpRequest login = HttpRequest.newBuilder(URI.create("https://localhost:18443/api/auth/login"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .build();
        HttpResponse<String> tokenResponse = client.send(login, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, tokenResponse.statusCode(), tokenResponse.body());
        return tokenResponse.body().split("\"accessToken\":\"")[1].split("\"")[0];
    }

    private String negotiatedProtocol(String[] protocols) throws Exception {
        SSLContext context = trustDevKeystore();
        try (SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket("localhost", 18443)) {
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setProtocols(protocols);
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);
            socket.startHandshake();
            Certificate[] chain = socket.getSession().getPeerCertificates();
            assertTrue(chain[0] instanceof X509Certificate);
            return socket.getSession().getProtocol();
        }
    }

    private SSLContext trustDevKeystore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (var input = getClass().getResourceAsStream("/keystore/dev-keystore.p12")) {
            keyStore.load(input, "dev-local-changeit".toCharArray());
        }
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustManagerFactory.getTrustManagers(), new SecureRandom());
        return context;
    }
}
