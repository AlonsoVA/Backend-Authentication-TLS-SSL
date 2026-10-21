package com.trabajo1.security.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ApiErrorWriter apiErrorWriter;
    private final SecurityAuditLogger auditLogger;

    public CustomAuthenticationEntryPoint(ApiErrorWriter apiErrorWriter, SecurityAuditLogger auditLogger) {
        this.apiErrorWriter = apiErrorWriter;
        this.auditLogger = auditLogger;
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        Object customMessage = request.getAttribute(JwtAuthenticationFilter.AUTH_ERROR);
        String message = customMessage instanceof String text && !text.isBlank()
                ? text
                : "No se proporcionó un token de autenticación válido";
        auditLogger.unauthorized(request.getRequestURI(), message);
        apiErrorWriter.write(response, HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized", message, request.getRequestURI());
    }
}
