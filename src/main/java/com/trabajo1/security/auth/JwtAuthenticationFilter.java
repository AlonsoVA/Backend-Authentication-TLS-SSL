package com.trabajo1.security.auth;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public static final String AUTH_ERROR = "AUTH_ERROR_MESSAGE";

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7).trim();
            if (!token.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
                authenticate(request, token);
            }
        }
        filterChain.doFilter(request, response);
    }

    private void authenticate(HttpServletRequest request, String token) {
        try {
            Claims claims = jwtService.parse(token);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    claims.getSubject(),
                    null,
                    roles(claims).stream().map(SimpleGrantedAuthority::new).toList());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (ExpiredJwtException ex) {
            SecurityContextHolder.clearContext();
            request.setAttribute(AUTH_ERROR, "El token JWT ha expirado");
        } catch (JwtException | IllegalArgumentException ex) {
            SecurityContextHolder.clearContext();
            request.setAttribute(AUTH_ERROR, "El token JWT es inválido");
        }
    }

    private List<String> roles(Claims claims) {
        Object rawRoles = claims.get("roles");
        List<String> roles = new ArrayList<>();
        if (rawRoles instanceof List<?> values) {
            for (Object value : values) {
                roles.add(String.valueOf(value));
            }
        }
        return roles;
    }
}
