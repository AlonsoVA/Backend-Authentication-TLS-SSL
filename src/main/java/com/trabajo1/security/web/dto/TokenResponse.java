package com.trabajo1.security.web.dto;

public record TokenResponse(
        String tokenType,
        String accessToken,
        long expiresInSeconds
) {
}
