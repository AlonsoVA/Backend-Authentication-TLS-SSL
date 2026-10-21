package com.trabajo1.security.config;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

public final class TlsProtocolPolicy {

    private static final Set<String> ALLOWED = Set.of("TLSv1.2", "TLSv1.3");

    private TlsProtocolPolicy() {
    }

    public static List<String> parse(String configured) {
        if (configured == null || configured.isBlank()) {
            throw new IllegalStateException("server.ssl.enabled-protocols debe declarar TLSv1.2 y TLSv1.3");
        }
        List<String> protocols = Arrays.stream(configured.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .toList();
        if (protocols.isEmpty() || !ALLOWED.containsAll(protocols)) {
            throw new IllegalStateException(
                    "Solo se permiten TLSv1.2 y TLSv1.3. Configuración recibida: " + configured);
        }
        if (!protocols.contains("TLSv1.2") || !protocols.contains("TLSv1.3")) {
            throw new IllegalStateException("Deben estar habilitados tanto TLSv1.2 como TLSv1.3");
        }
        return List.copyOf(protocols);
    }
}
