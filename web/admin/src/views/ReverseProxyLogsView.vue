<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

type LogEntry = {
  id: number
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

const { t, locale } = useI18n()
const logEntries = ref<LogEntry[]>([])
const loading = ref(true)
const syncComplete = ref(false)
const scrollContainer = ref<HTMLElement | null>(null)

const seenEntryIds = new Set<number>()
let eventSource: EventSource | null = null

const entries = computed(() => logEntries.value)

function formatTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString(locale.value)
}

function typeLabel(value: string) {
  if (value === 'oidc') {
    return t('common.oidc')
  }
  if (value === 'proxy') {
    return t('common.proxy')
  }
  if (value === 'static') {
    return t('common.static')
  }
  return value
}

function isNearBottom(element: HTMLElement | null) {
  if (!element) {
    return true
  }
  return element.scrollHeight - (element.scrollTop + element.clientHeight) <= 24
}

async function appendEntry(entry: LogEntry) {
  if (seenEntryIds.has(entry.id)) {
    return
  }

  const shouldStickToBottom = isNearBottom(scrollContainer.value)
  seenEntryIds.add(entry.id)
  logEntries.value = [...logEntries.value, entry]

  if (shouldStickToBottom) {
    await nextTick()
    if (scrollContainer.value) {
      scrollContainer.value.scrollTop = scrollContainer.value.scrollHeight
    }
  }
}

function connectStream() {
  eventSource = new EventSource('/console/api/reverse-proxy/logs/stream')

  eventSource.onmessage = (event) => {
    const entry = JSON.parse(event.data) as LogEntry
    void appendEntry(entry)
  }

  eventSource.addEventListener('sync', () => {
    syncComplete.value = true
    loading.value = false
    void nextTick(() => {
      if (scrollContainer.value) {
        scrollContainer.value.scrollTop = scrollContainer.value.scrollHeight
      }
    })
  })

  eventSource.onerror = () => {
    if (syncComplete.value) {
      loading.value = false
    }
  }
}

onMounted(() => {
  connectStream()
})

onBeforeUnmount(() => {
  eventSource?.close()
  eventSource = null
})
</script>

<template>
  <section ref="scrollContainer" class="oidc-page">
    <div v-if="loading" class="oidc-loading">
      <p>{{ t('accessLogs.loading') }}</p>
    </div>

    <article v-else class="oidc-panel">
      <div class="panel-header">
        <div>
          <h2>{{ t('accessLogs.title') }}</h2>
        </div>
        <span class="status-pill" :class="{ 'status-pill-muted': entries.length === 0 }">
          {{ entries.length === 0 ? t('accessLogs.noTrafficYet') : t('accessLogs.entriesCount', { count: entries.length }) }}
        </span>
      </div>

      <div v-if="entries.length === 0" class="empty-state">
        <p class="table-value">{{ t('accessLogs.emptyTitle') }}</p>
        <p class="table-helper">{{ t('accessLogs.emptyCopy') }}</p>
      </div>

      <div v-else class="proxy-log-list">
        <article v-for="entry in entries" :key="entry.id" class="proxy-log-row">
          <div class="proxy-log-topline">
            <p class="table-value">{{ entry.method }} {{ entry.path }}</p>
            <span class="status-pill" :class="entry.statusCode >= 400 ? 'status-pill-danger' : ''">
              {{ entry.statusCode }}
            </span>
          </div>

          <div class="meta-grid">
            <p class="meta-row"><span class="meta-label">{{ t('accessLogs.when') }}:</span> {{ formatTime(entry.timestamp) }}</p>
            <p class="meta-row"><span class="meta-label">{{ t('accessLogs.host') }}:</span> {{ entry.host }}</p>
            <p class="meta-row"><span class="meta-label">{{ t('accessLogs.route') }}:</span> {{ entry.routeHost }} {{ entry.routePath }}</p>
            <p class="meta-row"><span class="meta-label">{{ t('accessLogs.type') }}:</span> {{ typeLabel(entry.routeType) }}</p>
            <p class="meta-row"><span class="meta-label">{{ t('accessLogs.target') }}:</span> {{ entry.target }}</p>
            <p class="meta-row"><span class="meta-label">{{ t('accessLogs.latency') }}:</span> {{ t('accessLogs.latencyValue', { duration: entry.durationMs, bytes: entry.bytes }) }}</p>
            <p class="meta-row"><span class="meta-label">{{ t('accessLogs.remote') }}:</span> {{ entry.remoteAddr }}</p>
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
}

.proxy-log-row {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  padding: 1rem 0;
  border-top: 1px solid rgba(255, 255, 255, 0.12);
}

.proxy-log-row:first-child {
  padding-top: 0;
  border-top: 0;
}

.proxy-log-row:last-child {
  padding-bottom: 0;
}

.proxy-log-topline {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}

@media (max-width: 960px) {
  .proxy-log-topline {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
