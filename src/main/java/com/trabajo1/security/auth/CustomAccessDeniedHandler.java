package com.trabajo1.security.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    static final String MESSAGE = "No cuenta con permisos suficientes para acceder a este recurso";

    private final ApiErrorWriter apiErrorWriter;
    private final SecurityAuditLogger auditLogger;

    public CustomAccessDeniedHandler(ApiErrorWriter apiErrorWriter, SecurityAuditLogger auditLogger) {
        this.apiErrorWriter = apiErrorWriter;
        this.auditLogger = auditLogger;
    }

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication == null ? "anónimo" : authentication.getName();
        auditLogger.forbidden(request.getRequestURI(), username);
        apiErrorWriter.write(response, HttpServletResponse.SC_FORBIDDEN, "Forbidden", MESSAGE, request.getRequestURI());
    }
}
