package com.trabajo1.security.auth;

import com.trabajo1.security.web.dto.LoginRequest;
import com.trabajo1.security.web.dto.TokenResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final SecurityAuditLogger auditLogger;

    public AuthService(
            AuthenticationManager authenticationManager,
            JwtService jwtService,
            SecurityAuditLogger auditLogger) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.auditLogger = auditLogger;
    }

    public TokenResponse login(LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password()));
            UserDetails user = (UserDetails) authentication.getPrincipal();
            auditLogger.loginSuccess(user.getUsername());
            return new TokenResponse("Bearer", jwtService.generateToken(user), jwtService.expiresInSeconds());
        } catch (AuthenticationException ex) {
            auditLogger.loginFailure(request.username());
            throw new BadCredentialsException("Credenciales inválidas");
        }
    }
}
