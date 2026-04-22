<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { getAccessToken, getUser, handleCallback, login, logout } from "./auth";

type MeResponse = {
  subject: string;
  preferredUsername: string | null;
  email: string | null;
  issuer: string;
  audience: string[];
  scopes: string[];
  claims: Record<string, unknown>;
};

type Item = {
  id: number;
  title: string;
  owner: string;
  status: string;
  notes: string;
};

const currentUser = ref<{ profile?: Record<string, unknown> } | null>(null);
const me = ref<MeResponse | null>(null);
const items = ref<Item[]>([]);
const pending = ref(true);
const syncing = ref(false);
const error = ref("");
const editingId = ref<number | null>(null);

const form = reactive({
  title: "",
  owner: "",
  status: "todo",
  notes: ""
});

const isAuthenticated = computed(() => !!currentUser.value);
const userLabel = computed(
  () =>
    String(
      currentUser.value?.profile?.preferred_username ||
        currentUser.value?.profile?.name ||
        currentUser.value?.profile?.sub ||
        ""
    ) || "anonymous"
);

onMounted(async () => {
  try {
    if (window.location.pathname === "/callback") {
      await handleCallback();
      window.history.replaceState({}, "", "/");
    }

    currentUser.value = await getUser();
    if (currentUser.value) {
      await refreshAll();
    }
  } catch (cause) {
    error.value = asMessage(cause);
  } finally {
    pending.value = false;
  }
});

async function refreshAll() {
  syncing.value = true;
  error.value = "";
  try {
    const [meResponse, itemResponse] = await Promise.all([apiFetch<MeResponse>("/api/me"), apiFetch<Item[]>("/api/items")]);
    me.value = meResponse;
    items.value = itemResponse;
  } catch (cause) {
    error.value = asMessage(cause);
  } finally {
    syncing.value = false;
  }
}

async function saveItem() {
  syncing.value = true;
  error.value = "";
  try {
    const payload = {
      title: form.title,
      owner: form.owner,
      status: form.status,
      notes: form.notes
    };

    if (editingId.value === null) {
      await apiFetch<Item>("/api/items", { method: "POST", body: JSON.stringify(payload) });
    } else {
      await apiFetch<Item>(`/api/items/${editingId.value}`, { method: "PUT", body: JSON.stringify(payload) });
    }

    resetForm();
    await refreshAll();
  } catch (cause) {
    error.value = asMessage(cause);
  } finally {
    syncing.value = false;
  }
}

async function removeItem(id: number) {
  syncing.value = true;
  error.value = "";
  try {
    await apiFetch<void>(`/api/items/${id}`, { method: "DELETE" });
    if (editingId.value === id) {
      resetForm();
    }
    await refreshAll();
  } catch (cause) {
    error.value = asMessage(cause);
  } finally {
    syncing.value = false;
  }
}

function startEdit(item: Item) {
  editingId.value = item.id;
  form.title = item.title;
  form.owner = item.owner;
  form.status = item.status;
  form.notes = item.notes;
}

function resetForm() {
  editingId.value = null;
  form.title = "";
  form.owner = "";
  form.status = "todo";
  form.notes = "";
}

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const accessToken = await getAccessToken();
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken ?? ""}`,
      ...(init.headers ?? {})
    }
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `Request failed with status ${response.status}`);
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return (await response.json()) as T;
}

function asMessage(cause: unknown) {
  if (cause instanceof Error) {
    return cause.message;
  }
  return String(cause);
}
</script>

<template>
  <main class="page-shell">
    <section class="hero-card">
      <div class="hero-copy">
        <p class="eyebrow">Dev Container Example</p>
        <h1>Quarkus + Vue on top of oidcld</h1>
        <p class="summary">
          The browser talks only to <code>https://app.localhost:8443</code>. oidcld terminates TLS,
          handles login, and reverse-proxies Vue and Quarkus running inside the dev container.
        </p>
      </div>
      <div class="hero-actions">
        <button v-if="!isAuthenticated" class="primary-button" @click="login">Sign In</button>
        <button v-else class="secondary-button" @click="logout">Sign Out</button>
        <button v-if="isAuthenticated" class="ghost-button" @click="refreshAll" :disabled="syncing">
          Refresh Data
        </button>
      </div>
    </section>

    <section class="grid-layout">
      <article class="panel">
        <div class="panel-header">
          <div>
            <p class="panel-label">Session</p>
            <h2>{{ isAuthenticated ? userLabel : "Not signed in" }}</h2>
          </div>
          <span class="pill" :class="isAuthenticated ? 'ok' : 'idle'">
            {{ isAuthenticated ? "authenticated" : "anonymous" }}
          </span>
        </div>

        <p v-if="pending" class="muted">Checking login state...</p>
        <p v-else-if="!isAuthenticated" class="muted">
          Sign in with <code>editor</code> for read/write or <code>reviewer</code> for read-only access.
        </p>
        <div v-else class="claims-list">
          <div class="claim-row">
            <span>Issuer</span>
            <code>{{ me?.issuer }}</code>
          </div>
          <div class="claim-row">
            <span>Email</span>
            <code>{{ me?.email }}</code>
          </div>
          <div class="claim-row">
            <span>Audience</span>
            <code>{{ me?.audience.join(", ") }}</code>
          </div>
          <div class="claim-row">
            <span>Scopes</span>
            <code>{{ me?.scopes.join(" ") }}</code>
          </div>
        </div>
      </article>

      <article class="panel">
        <div class="panel-header">
          <div>
            <p class="panel-label">CRUD</p>
            <h2>{{ editingId === null ? "Create item" : `Edit item #${editingId}` }}</h2>
          </div>
          <span class="pill idle">in-memory</span>
        </div>

        <form class="item-form" @submit.prevent="saveItem">
          <label>
            <span>Title</span>
            <input v-model="form.title" required />
          </label>
          <label>
            <span>Owner</span>
            <input v-model="form.owner" placeholder="editor" />
          </label>
          <label>
            <span>Status</span>
            <select v-model="form.status">
              <option value="todo">todo</option>
              <option value="in-progress">in-progress</option>
              <option value="done">done</option>
            </select>
          </label>
          <label>
            <span>Notes</span>
            <textarea v-model="form.notes" rows="4" />
          </label>
          <div class="form-actions">
            <button class="primary-button" :disabled="!isAuthenticated || syncing">Save</button>
            <button class="ghost-button" type="button" @click="resetForm" :disabled="syncing">Clear</button>
          </div>
        </form>
      </article>
    </section>

    <section class="panel full-width">
      <div class="panel-header">
        <div>
          <p class="panel-label">Items</p>
          <h2>Seeded records reset when Quarkus restarts</h2>
        </div>
        <span class="pill" :class="syncing ? 'idle' : 'ok'">{{ syncing ? "syncing" : "ready" }}</span>
      </div>

      <p v-if="error" class="error-banner">{{ error }}</p>
      <p v-if="!isAuthenticated" class="muted">Sign in to load the API response.</p>

      <div v-else class="item-grid">
        <article v-for="item in items" :key="item.id" class="item-card">
          <div class="item-heading">
            <h3>{{ item.title }}</h3>
            <span class="status-chip">{{ item.status }}</span>
          </div>
          <p class="item-owner">Owner: {{ item.owner || "unassigned" }}</p>
          <p class="item-notes">{{ item.notes || "No notes" }}</p>
          <div class="item-actions">
            <button class="ghost-button" @click="startEdit(item)">Edit</button>
            <button class="ghost-danger" @click="removeItem(item.id)">Delete</button>
          </div>
        </article>
      </div>
    </section>
  </main>
</template>

