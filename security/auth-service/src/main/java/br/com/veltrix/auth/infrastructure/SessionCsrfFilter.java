package br.com.veltrix.auth.infrastructure;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

public class SessionCsrfFilter extends OncePerRequestFilter {
    public static final String COOKIE="veltrix_csrf",HEADER="X-CSRF-Token";
    private final Set<String> allowedOrigins;
    public SessionCsrfFilter(String origins){this.allowedOrigins=new HashSet<>(Arrays.stream(origins.split(",")).map(String::trim).filter(v->!v.isBlank()).toList());}
    @Override protected boolean shouldNotFilter(HttpServletRequest request){String path=request.getRequestURI();return !"POST".equals(request.getMethod())||!(path.equals("/api/v1/auth/login")||path.equals("/api/v1/auth/refresh")||path.equals("/api/v1/auth/logout"));}
    @Override protected void doFilterInternal(HttpServletRequest request,HttpServletResponse response,FilterChain chain)throws ServletException,IOException{
        String origin=request.getHeader("Origin");
        if(origin!=null&&!allowedOrigins.contains(origin)){response.sendError(HttpStatus.FORBIDDEN.value(),"Origin not allowed");return;}
        String cookie=Arrays.stream(Optional.ofNullable(request.getCookies()).orElse(new Cookie[0])).filter(c->COOKIE.equals(c.getName())).map(Cookie::getValue).findFirst().orElse(null);
        String header=request.getHeader(HEADER);
        if(cookie==null||header==null||!MessageDigest.isEqual(cookie.getBytes(StandardCharsets.UTF_8),header.getBytes(StandardCharsets.UTF_8))){response.sendError(HttpStatus.FORBIDDEN.value(),"CSRF validation failed");return;}
        chain.doFilter(request,response);
    }
}
