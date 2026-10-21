package com.trabajo1.security.config;

import com.trabajo1.security.tls.PlainHttpRejectionValve;
import java.util.List;
import org.apache.catalina.connector.Connector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnProperty(prefix = "server.ssl", name = "enabled", havingValue = "true", matchIfMissing = true)
public class TlsServerConfig {

    private static final Logger TLS_LOG = LoggerFactory.getLogger("SECURITY.TLS");

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> httpRejectionCustomizer(
            HttpListenerProperties httpListenerProperties) {
        return factory -> {
            factory.addAdditionalTomcatConnectors(plainHttpConnector(httpListenerProperties.getPort()));
            factory.addContextCustomizers(context -> context.getPipeline().addValve(new PlainHttpRejectionValve()));
        };
    }

    @Bean
    ApplicationRunner tlsPolicyLogger(
            @Value("${server.ssl.enabled-protocols}") String enabledProtocols,
            @Value("${server.port}") int httpsPort,
            HttpListenerProperties httpListenerProperties) {
        return args -> {
            List<String> protocols = TlsProtocolPolicy.parse(enabledProtocols);
            TLS_LOG.info(
                    "HTTPS activo en el puerto {} con protocolos {}. El puerto HTTP {} rechaza tráfico sin cifrar.",
                    httpsPort,
                    protocols,
                    httpListenerProperties.getPort());
        };
    }

    private Connector plainHttpConnector(int port) {
        Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
        connector.setScheme("http");
        connector.setPort(port);
        connector.setSecure(false);
        return connector;
    }
}
