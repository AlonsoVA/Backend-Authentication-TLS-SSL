package com.trabajo1.security.web.dto;

import java.util.List;

public record ProfileResponse(
        String username,
        List<String> roles
) {
}
