package com.example.oidcdemo.api;

import io.quarkus.security.Authenticated;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/api/me")
@Produces(MediaType.APPLICATION_JSON)
public class IdentityResource {
    private final JsonWebToken token;

    public IdentityResource(JsonWebToken token) {
        this.token = token;
    }

    @GET
    @Authenticated
    public Map<String, Object> me() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("subject", token.getSubject());
        payload.put("name", token.getClaim("name"));
        payload.put("preferredUsername", token.getClaim("preferred_username"));
        payload.put("email", token.getClaim("email"));
        payload.put("issuer", token.getIssuer());
        payload.put("audience", asList(token.getClaim("aud")));
        payload.put("scopes", splitScopes(token.getClaim("scope")));
        payload.put("groups", token.getGroups());
        payload.put("claims", allClaims());
        return payload;
    }

    private Map<String, Object> allClaims() {
        Map<String, Object> claims = new TreeMap<>();
        for (String name : token.getClaimNames()) {
            claims.put(name, token.getClaim(name));
        }
        return claims;
    }

    private List<String> splitScopes(Object value) {
        if (value instanceof String scopeValue && !scopeValue.isBlank()) {
            return List.of(scopeValue.trim().split("\\s+"));
        }
        if (value instanceof Collection<?> collection) {
            return collection.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    private List<String> asList(Object value) {
        if (value instanceof Collection<?> collection) {
            return collection.stream().map(String::valueOf).toList();
        }
        if (value == null) {
            return List.of();
        }
        return List.of(String.valueOf(value));
    }
}
