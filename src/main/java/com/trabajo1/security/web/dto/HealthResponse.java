package com.trabajo1.security.web.dto;

import java.util.List;

public record HealthResponse(
        String status,
        String transport,
        List<String> enabledProtocols
) {
}
