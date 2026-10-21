package com.trabajo1.security.web;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiErrorController implements ErrorController {

    @RequestMapping("/error")
    public ResponseEntity<ApiError> error(HttpServletRequest request) {
        int status = status(request);
        HttpStatus httpStatus = HttpStatus.resolve(status);
        String error = httpStatus == null ? "Error" : httpStatus.getReasonPhrase();
        String message = message(request, status);
        ApiError body = new ApiError(Instant.now(), status, error, message, path(request));
        return ResponseEntity.status(status).body(body);
    }

    private int status(HttpServletRequest request) {
        Object value = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        if (value instanceof Integer code) {
            return code;
        }
        return HttpStatus.INTERNAL_SERVER_ERROR.value();
    }

    private String message(HttpServletRequest request, int status) {
        Object value = request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
        if (value instanceof String text && !text.isBlank()) {
            return text;
        }
        if (status == HttpStatus.NOT_FOUND.value()) {
            return "El recurso solicitado no existe";
        }
        return "No fue posible completar la petición";
    }

    private String path(HttpServletRequest request) {
        Object value = request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI);
        if (value instanceof String text && !text.isBlank()) {
            return text;
        }
        return request.getRequestURI();
    }
}
