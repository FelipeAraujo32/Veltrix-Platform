package com.gateway.gateway.Filter;

import java.util.List;
import org.springframework.util.AntPathMatcher;

/**
 * Matches request paths against the configured public Ant patterns ({@code veltrix.gateway.public-paths}).
 * A new module declares its own public endpoints in configuration; the filters stay module-agnostic.
 */
public class PublicPathMatcher {
    private final List<String> patterns;
    private final AntPathMatcher matcher = new AntPathMatcher();

    public PublicPathMatcher(List<String> patterns) {
        this.patterns = List.copyOf(patterns);
    }

    public boolean isPublic(String path) {
        for (String pattern : patterns) {
            if (matcher.match(pattern, path)) return true;
        }
        return false;
    }
}
