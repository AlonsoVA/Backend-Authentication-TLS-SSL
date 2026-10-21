package com.trabajo1.security.web.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "El nombre de usuario es obligatorio") String username,
        @NotBlank(message = "La contraseña es obligatoria") String password
) {
}
