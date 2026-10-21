package com.trabajo1.security.tls;

import jakarta.servlet.ServletException;
import java.io.IOException;
import java.time.Instant;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PlainHttpRejectionValve extends ValveBase {

    public static final String MESSAGE =
            "Las comunicaciones HTTP sin cifrar fueron rechazadas. Use HTTPS con TLS 1.2 o TLS 1.3.";

    private static final Logger TLS_LOG = LoggerFactory.getLogger("SECURITY.TLS");

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        if (!request.isSecure()) {
            String path = request.getRequestURI() == null ? "" : request.getRequestURI();
            TLS_LOG.warn(
                    "Petición HTTP no cifrada rechazada desde {} {} {}",
                    request.getRemoteAddr(),
                    request.getMethod(),
                    path);
            response.setStatus(426);
            response.setContentType("application/json;charset=UTF-8");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(body(path));
            response.getWriter().flush();
            return;
        }
        getNext().invoke(request, response);
    }

    private String body(String path) {
        return "{"
                + "\"timestamp\":\"" + Instant.now() + "\","
                + "\"status\":426,"
                + "\"error\":\"Upgrade Required\","
                + "\"message\":\"" + MESSAGE + "\","
                + "\"path\":\"" + escape(path) + "\""
                + "}";
    }

    private String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
