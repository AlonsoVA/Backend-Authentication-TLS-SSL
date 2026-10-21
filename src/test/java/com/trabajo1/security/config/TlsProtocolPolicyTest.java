package com.trabajo1.security.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;

class TlsProtocolPolicyTest {

    @Test
    void acceptsTls12AndTls13() {
        assertEquals(List.of("TLSv1.2", "TLSv1.3"), TlsProtocolPolicy.parse("TLSv1.2,TLSv1.3"));
    }

    @Test
    void rejectsLegacyProtocols() {
        assertThrows(IllegalStateException.class, () -> TlsProtocolPolicy.parse("TLSv1.2,TLSv1.1"));
        assertThrows(IllegalStateException.class, () -> TlsProtocolPolicy.parse("TLSv1,TLSv1.2,TLSv1.3"));
        assertThrows(IllegalStateException.class, () -> TlsProtocolPolicy.parse("SSLv3"));
    }

    @Test
    void requiresBothModernProtocols() {
        assertThrows(IllegalStateException.class, () -> TlsProtocolPolicy.parse("TLSv1.2"));
        assertThrows(IllegalStateException.class, () -> TlsProtocolPolicy.parse(" "));
    }
}
