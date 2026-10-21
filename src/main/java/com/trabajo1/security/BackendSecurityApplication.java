package com.trabajo1.security;

import com.trabajo1.security.config.AppUserProperties;
import com.trabajo1.security.config.CorsProperties;
import com.trabajo1.security.config.HttpListenerProperties;
import com.trabajo1.security.config.JwtProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({
        JwtProperties.class,
        HttpListenerProperties.class,
        CorsProperties.class,
        AppUserProperties.class
})
public class BackendSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(BackendSecurityApplication.class, args);
    }
}
