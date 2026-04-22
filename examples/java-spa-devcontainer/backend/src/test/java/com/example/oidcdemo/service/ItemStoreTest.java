package com.example.oidcdemo.service;

import com.example.oidcdemo.model.Item;
import com.example.oidcdemo.model.ItemUpsertRequest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class ItemStoreTest {
    @Test
    void createUpdateAndDeleteRoundTrip() {
        ItemStore store = new ItemStore();

        Item created = store.create(new ItemUpsertRequest("New item", "editor", "todo", "note"));
        Assertions.assertTrue(store.list().stream().anyMatch(item -> item.id() == created.id()));

        Item updated = store.update(created.id(), new ItemUpsertRequest("Updated", "reviewer", "done", "changed"));
        Assertions.assertEquals("Updated", updated.title());
        Assertions.assertEquals("done", updated.status());

        store.delete(created.id());
        Assertions.assertFalse(store.list().stream().anyMatch(item -> item.id() == created.id()));
    }
}

