package br.com.veltrix.security;

import java.util.Optional;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;

@Aspect
public class EntitlementAuthorizationAspect {
    private final EntitlementVerifier verifier;

    public EntitlementAuthorizationAspect(EntitlementVerifier verifier) { this.verifier = verifier; }

    @Around("@within(br.com.veltrix.security.RequiresEntitlement) || @annotation(br.com.veltrix.security.RequiresEntitlement)")
    public Object authorize(ProceedingJoinPoint joinPoint) throws Throwable {
        RequiresEntitlement annotation = ((MethodSignature) joinPoint.getSignature()).getMethod()
                .getAnnotation(RequiresEntitlement.class);
        if (annotation == null) annotation = joinPoint.getTarget().getClass().getAnnotation(RequiresEntitlement.class);
        AccessContext context = AccessContextResolver.resolve(SecurityContextHolder.getContext().getAuthentication())
                .orElseThrow(() -> new AccessDeniedException("Authenticated access context is required"));
        EntitlementDecision decision = verifier.verify(context, annotation.value());
        if (!decision.allowed()) throw new AccessDeniedException("Active entitlement is required");
        return joinPoint.proceed();
    }
}
