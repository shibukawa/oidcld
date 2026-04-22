package com.example.oidcdemo.service;

import com.example.oidcdemo.model.Item;
import com.example.oidcdemo.model.ItemUpsertRequest;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.NotFoundException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

@ApplicationScoped
public class ItemStore {
    private final AtomicLong ids = new AtomicLong(2);
    private final Map<Long, Item> items = new LinkedHashMap<>();

    public ItemStore() {
        items.put(1L, new Item(1L, "Wire Quarkus API", "editor", "todo", "Verify token claims and health check."));
        items.put(2L, new Item(2L, "Build Vue screen", "reviewer", "in-progress", "Hook up login state and CRUD controls."));
    }

    public synchronized List<Item> list() {
        return items.values()
            .stream()
            .sorted(Comparator.comparingLong(Item::id))
            .toList();
    }

    public synchronized Item create(ItemUpsertRequest request) {
        long id = ids.incrementAndGet();
        Item item = new Item(id, normalize(request.title()), normalize(request.owner()), normalizeStatus(request.status()),
            normalize(request.notes()));
        items.put(id, item);
        return item;
    }

    public synchronized Item update(long id, ItemUpsertRequest request) {
        if (!items.containsKey(id)) {
            throw new NotFoundException("Item " + id + " was not found");
        }
        Item item = new Item(id, normalize(request.title()), normalize(request.owner()), normalizeStatus(request.status()),
            normalize(request.notes()));
        items.put(id, item);
        return item;
    }

    public synchronized void delete(long id) {
        if (items.remove(id) == null) {
            throw new NotFoundException("Item " + id + " was not found");
        }
    }

    private String normalize(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.trim();
    }

    private String normalizeStatus(String value) {
        String status = normalize(value);
        return status.isEmpty() ? "todo" : status;
    }
}

