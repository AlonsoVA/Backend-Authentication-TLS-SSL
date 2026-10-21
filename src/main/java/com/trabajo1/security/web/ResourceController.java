package com.trabajo1.security.web;

import com.trabajo1.security.web.dto.HealthResponse;
import com.trabajo1.security.web.dto.ProfileResponse;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

    @GetMapping("/api/public/health")
    public HealthResponse health() {
        return new HealthResponse("UP", "HTTPS", List.of("TLSv1.2", "TLSv1.3"));
    }

    @GetMapping("/api/secure/profile")
    public ProfileResponse profile(Authentication authentication) {
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        return new ProfileResponse(authentication.getName(), roles);
    }

    @GetMapping("/api/admin/reports")
    public Map<String, String> reports() {
        return Map.of(
                "report", "acceso de administrador concedido",
                "classification", "interno");
    }
}
