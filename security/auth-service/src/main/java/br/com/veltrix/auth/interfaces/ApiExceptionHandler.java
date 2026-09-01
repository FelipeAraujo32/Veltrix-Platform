package br.com.veltrix.auth.interfaces;

import br.com.veltrix.auth.domain.BusinessException;
import java.util.stream.Collectors;
import org.slf4j.MDC;
import org.springframework.http.*;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(AuthController.UnauthorizedException.class)
    ResponseEntity<ApiError> unauthorized(){return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ApiError("UNAUTHORIZED","Credenciais inválidas",MDC.get("correlationId")));}
    @ExceptionHandler(AuthController.LockedException.class)
    ResponseEntity<ApiError> locked(AuthController.LockedException exception){return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).header(HttpHeaders.RETRY_AFTER,String.valueOf(Math.max(1,exception.retryAfterSeconds))).body(new ApiError("TOO_MANY_REQUESTS","Muitas tentativas de login. Tente novamente mais tarde.",MDC.get("correlationId")));}
    @ExceptionHandler(BusinessException.class)
    ResponseEntity<ApiError> business(BusinessException exception){
        HttpStatus status=switch(exception.getCode()){
            case "USER_NOT_FOUND","ROLE_NOT_FOUND","PERMISSION_NOT_FOUND"->HttpStatus.NOT_FOUND;
            case "EMAIL_IN_USE","ROLE_NAME_IN_USE"->HttpStatus.CONFLICT;
            case "VALIDATION_ERROR"->HttpStatus.BAD_REQUEST;
            default->HttpStatus.UNPROCESSABLE_ENTITY;
        };
        return ResponseEntity.status(status).body(new ApiError(exception.getCode(),exception.getMessage(),MDC.get("correlationId")));
    }
    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ApiError> validation(MethodArgumentNotValidException exception){
        String message=exception.getBindingResult().getFieldErrors().stream().map(error->error.getField()+": "+error.getDefaultMessage()).collect(Collectors.joining(", "));
        return ResponseEntity.badRequest().body(new ApiError("VALIDATION_ERROR",message,MDC.get("correlationId")));
    }
    public record ApiError(String error,String message,String correlationId){}
}
