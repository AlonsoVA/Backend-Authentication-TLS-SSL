package com.trabajo1.security.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class SecurityAuditLogger {

    private static final Logger AUDIT = LoggerFactory.getLogger("SECURITY.AUDIT");

    public void loginSuccess(String username) {
        AUDIT.info("Autenticación exitosa para el usuario {}", username);
    }

    public void loginFailure(String username) {
        AUDIT.warn("Autenticación rechazada para el usuario {}", username);
    }

    public void unauthorized(String path, String message) {
        AUDIT.warn("401 Unauthorized en {}: {}", path, message);
    }

    public void forbidden(String path, String username) {
        AUDIT.warn("403 Forbidden en {} para {}", path, username);
    }
}
