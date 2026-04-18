<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

type LogEntry = {
  timestamp: string
  host: string
  method: string
  path: string
  statusCode: number
  durationMs: number
  bytes: number
  routeType: string
  routeHost: string
  routePath: string
  target: string
  remoteAddr: string
}

type LogsPayload = {
  entries: LogEntry[]
}

const payload = ref<LogsPayload | null>(null)
const loading = ref(true)

const entries = computed(() => payload.value?.entries ?? [])

function formatTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString()
}

async function loadPage() {
  try {
    const response = await fetch('/console/api/reverse-proxy/logs')
    payload.value = (await response.json()) as LogsPayload
  } finally {
    loading.value = false
  }
}

function typeLabel(value: string) {
  if (value === 'oidc') {
    return 'OIDC'
  }
  if (value === 'proxy') {
    return 'Proxy'
  }
  if (value === 'static') {
    return 'Static'
  }
  return value
}

onMounted(() => {
  void loadPage()
})
</script>

<template>
  <section class="page">
    <div v-if="loading" class="section-card loading-card">
      <p class="list-copy">Loading traffic logs...</p>
    </div>

    <article v-else class="section-card panel-sheen">
      <div class="section-heading">
        <div>
          <h3>Access Logs</h3>
        </div>
        <span class="status-pill" :class="{ 'status-pill-muted': entries.length === 0 }">
          {{ entries.length === 0 ? 'No traffic yet' : `${entries.length} entries` }}
        </span>
      </div>

      <div v-if="entries.length === 0" class="proxy-log-empty">
        <p class="table-value">No traffic has been recorded yet.</p>
        <p class="table-helper">OIDC requests and configured reverse proxy traffic appear here after the first request.</p>
      </div>

      <div v-else class="proxy-log-list">
        <article v-for="entry in entries" :key="`${entry.timestamp}-${entry.host}-${entry.path}`" class="proxy-log-row">
          <div class="proxy-log-topline">
            <p class="table-value">{{ entry.method }} {{ entry.path }}</p>
            <span class="status-pill" :class="{ 'status-pill-muted': entry.statusCode >= 400 }">
              {{ entry.statusCode }}
            </span>
          </div>

          <div class="proxy-log-grid">
            <p class="table-helper">When: {{ formatTime(entry.timestamp) }}</p>
            <p class="table-helper">Host: {{ entry.host }}</p>
            <p class="table-helper">Route: {{ entry.routeHost }} {{ entry.routePath }}</p>
            <p class="table-helper">Type: {{ typeLabel(entry.routeType) }}</p>
            <p class="table-helper">Target: {{ entry.target }}</p>
            <p class="table-helper">Latency: {{ entry.durationMs }} ms / {{ entry.bytes }} bytes</p>
            <p class="table-helper">Remote: {{ entry.remoteAddr }}</p>
          </div>
        </article>
      </div>
    </article>
  </section>
</template>

<style scoped>
.proxy-log-list {
  display: flex;
  flex-direction: column;
  gap: 0.9rem;
}

.proxy-log-row {
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: rgba(255, 255, 255, 0.05);
  border-radius: 1rem;
  padding: 1rem;
}

.proxy-log-topline {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 0.7rem;
}

.proxy-log-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.45rem 1rem;
}

.proxy-log-empty {
  display: flex;
  flex-direction: column;
  gap: 0.45rem;
}

@media (max-width: 960px) {
  .proxy-log-grid {
    grid-template-columns: 1fr;
  }

  .proxy-log-topline {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
