package no.fintlabs.oidc;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
public class CodeVerifierCache {

    private final Cache<String, String> cache;

    public CodeVerifierCache() {
        this.cache = Caffeine.newBuilder()
                .expireAfterWrite(10, TimeUnit.MINUTES)
                .maximumSize(10_000)
                .build();
    }

    public void storeCodeVerifier(String sessionId, String codeVerifier) {
        cache.put(sessionId, codeVerifier);
    }

    public String getCodeVerifier(String sessionId) {
        return cache.getIfPresent(sessionId);
    }

    public void removeCodeVerifier(String sessionId) {
        cache.invalidate(sessionId);
    }
}