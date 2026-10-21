package com.trabajo1.security.auth;

import com.trabajo1.security.config.AppUserProperties;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class DevUserDetailsService implements UserDetailsService {

    private final Map<String, UserDetails> users;

    public DevUserDetailsService(AppUserProperties properties, PasswordEncoder passwordEncoder) {
        if (properties.getUsers() == null || properties.getUsers().isEmpty()) {
            throw new IllegalStateException("Debe configurar al menos un usuario en app.users");
        }
        Map<String, UserDetails> loaded = new HashMap<>();
        for (AppUserProperties.Account account : properties.getUsers()) {
            if (account.getUsername() == null || account.getUsername().isBlank()
                    || account.getPassword() == null || account.getPassword().isBlank()
                    || account.getRoles() == null || account.getRoles().isEmpty()) {
                throw new IllegalStateException("Cada usuario requiere username, password y roles");
            }
            UserDetails user = User.withUsername(account.getUsername())
                    .password(passwordEncoder.encode(account.getPassword()))
                    .roles(account.getRoles().toArray(String[]::new))
                    .build();
            loaded.put(user.getUsername(), user);
        }
        this.users = Map.copyOf(loaded);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("Credenciales inválidas");
        }
        return user;
    }
}
