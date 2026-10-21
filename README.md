# Implementación de Autenticación y Cifrado TLS/SSL en el API Backend

**Historia de usuario:** HU-SEC-001  
**Épica:** Seguridad e Infraestructura Backend  
**Stack:** Java 21, Spring Boot, Spring Security, JWT, TLS 1.2 y TLS 1.3

API backend que solo acepta HTTPS con TLS 1.2 o TLS 1.3 y protege las rutas con tokens Bearer (JWT). Las peticiones HTTP sin cifrar se rechazan. Los fallos de autenticación y de autorización responden con JSON y los códigos 401 y 403.

## Requisitos

- JDK 21
- Maven 3.9 o superior

## Arranque

```bash
mvn spring-boot:run
```

| Canal | Dirección | Comportamiento |
| --- | --- | --- |
| HTTPS | `https://localhost:8443` | TLS 1.2 y TLS 1.3 |
| HTTP | `http://localhost:8080` | Respuesta `426` con mensaje de uso obligatorio de HTTPS |

El certificado es autofirmado y solo sirve para desarrollo local. El navegador y `curl` mostrarán una advertencia; en `curl` se usa `-k`.

Para regenerar el keystore PKCS12:

```bash
FORCE=1 ./scripts/generate-keystore.sh
```

## Usuarios de desarrollo

| Usuario | Contraseña | Rol |
| --- | --- | --- |
| `user` | `User123!` | `USER` |
| `admin` | `Admin123!` | `ADMIN` |

La contraseña del keystore local es `dev-local-changeit`. El secreto JWT de desarrollo está en `application.yml` y puede sustituirse con la variable `JWT_SECRET`. Estos valores no deben usarse fuera del entorno local.

## Rutas

| Método y ruta | Acceso |
| --- | --- |
| `GET /api/public/health` | Público |
| `POST /api/auth/login` | Público |
| `GET /api/secure/profile` | Token Bearer válido |
| `GET /api/admin/reports` | Token con rol `ADMIN` |

CORS permite el origen de Angular `http://localhost:4200`.

## Verificación

Con la aplicación en ejecución:

```bash
chmod +x scripts/verify-tls.sh
./scripts/verify-tls.sh
```

Ejemplos manuales:

```bash
curl -sv http://127.0.0.1:8080/api/public/health

curl -sk --tlsv1.2 --tls-max 1.2 https://localhost:8443/api/public/health
curl -sk --tlsv1.3 --tls-max 1.3 https://localhost:8443/api/public/health

curl -sk -X POST https://localhost:8443/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"user","password":"User123!"}'

curl -sk https://localhost:8443/api/secure/profile \
  -H "Authorization: Bearer <accessToken>"
```

Un token ausente, inválido o expirado responde `401`. Un usuario autenticado sin el rol exigido responde `403`. El fallo de handshake con TLS 1.0 o TLS 1.1 queda registrado por Tomcat (`org.apache.tomcat.util.net.SecureNioChannel`); en esa fase todavía no existe una respuesta HTTP que personalizar.

## Pruebas

```bash
mvn test
```

## Criterios de aceptación

- Keystore PKCS12 en `src/main/resources/keystore/dev-keystore.p12`, con alias `backend-tls` y SAN `localhost`.
- `server.ssl.enabled-protocols` limitado a `TLSv1.2,TLSv1.3` en el puerto `8443`.
- El puerto `8080` rechaza HTTP en claro con un JSON propio.
- `SecurityFilterChain` publica `/api/auth/**` y `/api/public/**`, exige autenticación en el resto y reserva `/api/admin/**` al rol `ADMIN`.
- Los endpoints protegidos exigen `Authorization: Bearer`.
- `401` y `403` se devuelven como JSON y quedan en el logger `SECURITY.AUDIT`.
