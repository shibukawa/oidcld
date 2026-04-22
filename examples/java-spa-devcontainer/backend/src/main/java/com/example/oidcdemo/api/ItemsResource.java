package com.example.oidcdemo.api;

import com.example.oidcdemo.model.Item;
import com.example.oidcdemo.model.ItemUpsertRequest;
import com.example.oidcdemo.service.ItemStore;
import io.quarkus.security.Authenticated;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/api/items")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ItemsResource {
    private final ItemStore store;
    private final JsonWebToken token;

    public ItemsResource(ItemStore store, JsonWebToken token) {
        this.store = store;
        this.token = token;
    }

    @GET
    @Authenticated
    public List<Item> list() {
        requireScope("items.read");
        return store.list();
    }

    @POST
    @Authenticated
    public Item create(ItemUpsertRequest request) {
        requireScope("items.write");
        return store.create(request);
    }

    @PUT
    @Path("/{id}")
    @Authenticated
    public Item update(@PathParam("id") long id, ItemUpsertRequest request) {
        requireScope("items.write");
        return store.update(id, request);
    }

    @DELETE
    @Path("/{id}")
    @Authenticated
    public void delete(@PathParam("id") long id) {
        requireScope("items.write");
        store.delete(id);
    }

    private void requireScope(String requiredScope) {
        if (!scopes().contains(requiredScope)) {
            throw new ForbiddenException("Missing required scope: " + requiredScope);
        }
    }

    private Set<String> scopes() {
        Object scopeClaim = token.getClaim("scope");
        if (scopeClaim instanceof String value && !value.isBlank()) {
            return Set.of(value.trim().split("\\s+"));
        }
        if (scopeClaim instanceof Collection<?> collection) {
            Set<String> scopes = new TreeSet<>();
            for (Object entry : collection) {
                scopes.add(String.valueOf(entry));
            }
            return scopes;
        }
        return Set.of();
    }
}
