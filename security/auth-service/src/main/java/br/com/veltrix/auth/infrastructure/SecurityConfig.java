package br.com.veltrix.auth.infrastructure;

import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import java.util.Collection;
import java.util.ArrayList;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;

@Configuration @EnableWebSecurity @EnableMethodSecurity
public class SecurityConfig {
    private static final Logger LOG = LoggerFactory.getLogger(SecurityConfig.class);
    @Bean PasswordEncoder passwordEncoder(){return new BCryptPasswordEncoder();}
    @Bean SessionCsrfFilter sessionCsrfFilter(@Value("${security.allowed-origins:http://localhost:4200,http://localhost:4201}")String origins){return new SessionCsrfFilter(origins);}
    @Bean org.springframework.boot.web.servlet.FilterRegistrationBean<SessionCsrfFilter> disableContainerRegistration(SessionCsrfFilter filter){var registration=new org.springframework.boot.web.servlet.FilterRegistrationBean<>(filter);registration.setEnabled(false);return registration;}
    @Bean SecurityFilterChain securityFilterChain(HttpSecurity http,SessionCsrfFilter sessionCsrfFilter) throws Exception {
        return http.csrf(csrf->csrf.disable()).sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(sessionCsrfFilter,BearerTokenAuthenticationFilter.class)
                .httpBasic(b->b.disable()).formLogin(f->f.disable()).exceptionHandling(e->e.authenticationEntryPoint((request,response,exception)->{
                    LOG.warn("Autenticação rejeitada: method={}, path={}, tipo={}, motivo={}", request.getMethod(), request.getRequestURI(), exception.getClass().getSimpleName(), exception.getMessage());
                    response.sendError(401);
                })).oauth2ResourceServer(o->o
                        .authenticationEntryPoint((request,response,exception)->{
                            LOG.warn("Bearer JWT rejeitado: method={}, path={}, tipo={}, motivo={}", request.getMethod(), request.getRequestURI(), exception.getClass().getSimpleName(), exception.getMessage());
                            response.sendError(401);
                        })
                        .jwt(jwt->jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
                .authorizeHttpRequests(a->a.requestMatchers("/api/v1/auth/**","/.well-known/jwks.json","/actuator/health","/actuator/info","/error").permitAll().anyRequest().authenticated()).build();
    }
    private JwtAuthenticationConverter jwtAuthenticationConverter(){
        JwtAuthenticationConverter converter=new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt->{
            Collection<GrantedAuthority> authorities=new ArrayList<>();
            Collection<String> permissions=jwt.getClaimAsStringList("permissions");
            Collection<String> roles=jwt.getClaimAsStringList("roles");
            if(permissions!=null)permissions.forEach(value->authorities.add(new SimpleGrantedAuthority(value)));
            if(roles!=null)roles.forEach(value->authorities.add(new SimpleGrantedAuthority("ROLE_"+value)));
            return authorities;
        });
        return converter;
    }
}
