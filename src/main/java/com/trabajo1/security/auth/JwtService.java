package com.trabajo1.security.auth;

import com.trabajo1.security.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    private final JwtProperties properties;
    private final SecretKey key;

    public JwtService(JwtProperties properties) {
        byte[] secret = properties.getSecret().getBytes(StandardCharsets.UTF_8);
        if (secret.length < 32) {
            throw new IllegalStateException("app.jwt.secret debe tener al menos 32 bytes para HS256");
        }
        this.properties = properties;
        this.key = Keys.hmacShaKeyFor(secret);
    }

    public String generateToken(UserDetails user) {
        Instant issuedAt = Instant.now();
        return generateToken(user.getUsername(), authorities(user), issuedAt, issuedAt.plus(properties.getExpiration()));
    }

    public String generateToken(String username, List<String> roles, Instant issuedAt, Instant expiresAt) {
        return Jwts.builder()
                .issuer(properties.getIssuer())
                .subject(username)
                .claim("roles", roles)
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiresAt))
                .signWith(key)
                .compact();
    }

    public Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .requireIssuer(properties.getIssuer())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public long expiresInSeconds() {
        return properties.getExpiration().toSeconds();
    }

    private List<String> authorities(UserDetails user) {
        return user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
    }
}
