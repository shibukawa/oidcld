<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const allMethodOptions = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT', 'OPTIONS']

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
  routeLabel: string
  target: string
  remoteAddr: string
}

const { t, locale } = useI18n()
const logEntries = ref<LogEntry[]>([])
const loading = ref(true)
const syncComplete = ref(false)
const scrollContainer = ref<HTMLElement | null>(null)
const selectedRouteLabel = ref('')
const selectedMethods = ref<string[]>([])
const pathFilter = ref('')
const selectedStatusGroups = ref([2, 3, 4, 5])
const methodDropdownOpen = ref(false)
const methodDropdownRef = ref<HTMLElement | null>(null)
const statusDropdownOpen = ref(false)
const statusDropdownRef = ref<HTMLElement | null>(null)

const seenEntryIds = new Set<number>()
let eventSource: EventSource | null = null

const entries = computed(() => logEntries.value)
const routeLabelOptions = computed(() =>
  [...new Set(entries.value.map((entry) => entry.routeLabel).filter((value) => value.trim() !== ''))].sort((left, right) =>
    left.localeCompare(right),
  ),
)
const methodOptions = computed(() => [...allMethodOptions])
const filteredEntries = computed(() => {
  const normalizedPathFilter = pathFilter.value.trim().toLowerCase()

  return entries.value.filter((entry) => {
    if (selectedRouteLabel.value !== '' && entry.routeLabel !== selectedRouteLabel.value) {
      return false
    }
    if (selectedMethods.value.length > 0 && !selectedMethods.value.includes(entry.method)) {
      return false
    }
    if (normalizedPathFilter !== '' && !entry.path.toLowerCase().includes(normalizedPathFilter)) {
      return false
    }
    return selectedStatusGroups.value.includes(Math.floor(entry.statusCode / 100))
  })
})
const methodFilterSummary = computed(() => {
  if (methodOptions.value.length === 0) {
    return t('accessLogs.allMethods')
  }
  if (selectedMethods.value.length === methodOptions.value.length) {
    return t('accessLogs.allMethods')
  }
  if (selectedMethods.value.length === 1) {
    return selectedMethods.value[0] ?? t('accessLogs.allMethods')
  }
  return t('accessLogs.selectedMethodsCount', { count: selectedMethods.value.length })
})
const statusFilterSummary = computed(() => {
  if (selectedStatusGroups.value.length === 4) {
    return t('accessLogs.allStatusCodes')
  }
  if (selectedStatusGroups.value.length === 0) {
    return t('accessLogs.noStatusCodes')
  }
  return selectedStatusGroups.value.map((group) => `${group}xx`).join(', ')
})

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

function formatRoute(entry: LogEntry) {
  if (entry.routeLabel.trim() === '') {
    return `${entry.routeHost} ${entry.routePath}`
  }
  return `${entry.routeLabel} (${entry.routeHost} ${entry.routePath})`
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

function resetFilters() {
  selectedRouteLabel.value = ''
  selectedMethods.value = [...methodOptions.value]
  pathFilter.value = ''
  selectedStatusGroups.value = [2, 3, 4, 5]
  methodDropdownOpen.value = false
  statusDropdownOpen.value = false
}

function toggleMethod(method: string) {
  if (selectedMethods.value.includes(method)) {
    if (selectedMethods.value.length === 1) {
      return
    }
    selectedMethods.value = selectedMethods.value.filter((value) => value !== method)
    return
  }
  selectedMethods.value = [...selectedMethods.value, method].sort((left, right) => left.localeCompare(right))
}

function toggleMethodDropdown() {
  methodDropdownOpen.value = !methodDropdownOpen.value
}

function closeMethodDropdown() {
  methodDropdownOpen.value = false
}

function toggleStatusGroup(group: number) {
  if (selectedStatusGroups.value.includes(group)) {
    if (selectedStatusGroups.value.length === 1) {
      return
    }
    selectedStatusGroups.value = selectedStatusGroups.value.filter((value) => value !== group)
    return
  }
  selectedStatusGroups.value = [...selectedStatusGroups.value, group].sort((left, right) => left - right)
}

function toggleStatusDropdown() {
  statusDropdownOpen.value = !statusDropdownOpen.value
}

function closeStatusDropdown() {
  statusDropdownOpen.value = false
}

function handleDocumentClick(event: MouseEvent) {
  if (!(event.target instanceof Node)) {
    return
  }
  if (methodDropdownOpen.value && !methodDropdownRef.value?.contains(event.target)) {
    closeMethodDropdown()
  }
  if (statusDropdownOpen.value && !statusDropdownRef.value?.contains(event.target)) {
    closeStatusDropdown()
  }
}

onMounted(() => {
  document.addEventListener('click', handleDocumentClick)
  connectStream()
})

onBeforeUnmount(() => {
  document.removeEventListener('click', handleDocumentClick)
  eventSource?.close()
  eventSource = null
})

watch(
  methodOptions,
  (options) => {
    const nextSelected = selectedMethods.value.filter((method) => options.includes(method))
    const missing = options.filter((method) => !nextSelected.includes(method))

    if (nextSelected.length === 0) {
      selectedMethods.value = [...options]
      return
    }
    if (missing.length > 0) {
      selectedMethods.value = [...nextSelected, ...missing].sort((left, right) => left.localeCompare(right))
      return
    }
    if (nextSelected.length !== selectedMethods.value.length) {
      selectedMethods.value = nextSelected
    }
  },
  { immediate: true },
)
</script>

<template>
  <section class="oidc-page proxy-log-page">
    <div v-if="loading" class="oidc-loading">
      <p>{{ t('accessLogs.loading') }}</p>
    </div>

    <template v-else>
      <article v-if="entries.length > 0" class="oidc-panel proxy-log-filter-panel">
        <div class="panel-header proxy-log-panel-header">
          <div>
            <h2>{{ t('accessLogs.title') }}</h2>
          </div>
          <button class="proxy-log-reset" type="button" @click="resetFilters">{{ t('accessLogs.resetFilters') }}</button>
        </div>

        <div class="proxy-log-filters">
          <label class="proxy-log-filter">
            <span class="table-helper">{{ t('accessLogs.filterRouteLabel') }}</span>
            <select v-model="selectedRouteLabel" class="proxy-log-select">
              <option value="">{{ t('accessLogs.allLabels') }}</option>
              <option v-for="label in routeLabelOptions" :key="label" :value="label">
                {{ label }}
              </option>
            </select>
          </label>

          <div ref="methodDropdownRef" class="proxy-log-filter proxy-log-method-dropdown">
            <span class="table-helper">{{ t('accessLogs.filterMethod') }}</span>
            <button
              class="proxy-log-dropdown-button"
              type="button"
              :aria-expanded="methodDropdownOpen"
              @click="toggleMethodDropdown"
            >
              <span>{{ methodFilterSummary }}</span>
              <span class="proxy-log-dropdown-caret">{{ methodDropdownOpen ? '▴' : '▾' }}</span>
            </button>
            <div v-if="methodDropdownOpen" class="proxy-log-dropdown-menu">
              <label v-for="method in methodOptions" :key="method" class="proxy-log-checkbox">
                <input :checked="selectedMethods.includes(method)" type="checkbox" @change="toggleMethod(method)" />
                <span>{{ method }}</span>
              </label>
            </div>
          </div>

          <label class="proxy-log-filter proxy-log-filter-wide">
            <span class="table-helper">{{ t('accessLogs.filterApi') }}</span>
            <input
              v-model="pathFilter"
              class="proxy-log-input"
              type="text"
              :placeholder="t('accessLogs.apiPlaceholder')"
              autocomplete="off"
            />
          </label>

          <div ref="statusDropdownRef" class="proxy-log-filter proxy-log-status-dropdown">
            <span class="table-helper">{{ t('accessLogs.filterStatusCode') }}</span>
            <button
              class="proxy-log-dropdown-button"
              type="button"
              :aria-expanded="statusDropdownOpen"
              @click="toggleStatusDropdown"
            >
              <span>{{ statusFilterSummary }}</span>
              <span class="proxy-log-dropdown-caret">{{ statusDropdownOpen ? '▴' : '▾' }}</span>
            </button>
            <div v-if="statusDropdownOpen" class="proxy-log-dropdown-menu">
              <label v-for="group in [2, 3, 4, 5]" :key="group" class="proxy-log-checkbox">
                <input :checked="selectedStatusGroups.includes(group)" type="checkbox" @change="toggleStatusGroup(group)" />
                <span>{{ group }}xx</span>
              </label>
            </div>
          </div>
        </div>
      </article>

      <article class="oidc-panel proxy-log-results-panel">
        <div ref="scrollContainer" class="proxy-log-results-body">
          <div v-if="entries.length === 0" class="empty-state">
            <p class="table-value">{{ t('accessLogs.emptyTitle') }}</p>
            <p class="table-helper">{{ t('accessLogs.emptyCopy') }}</p>
          </div>

          <div v-else-if="filteredEntries.length === 0" class="empty-state">
            <p class="table-value">{{ t('accessLogs.filteredEmptyTitle') }}</p>
            <p class="table-helper">{{ t('accessLogs.filteredEmptyCopy') }}</p>
          </div>

          <div v-else class="proxy-log-list">
            <article v-for="entry in filteredEntries" :key="entry.id" class="proxy-log-row">
              <div class="proxy-log-topline">
                <p class="table-value">{{ entry.method }} {{ entry.path }}</p>
                <span class="status-pill" :class="entry.statusCode >= 400 ? 'status-pill-danger' : ''">
                  {{ entry.statusCode }}
                </span>
              </div>

              <div class="meta-grid">
                <p class="meta-row"><span class="meta-label">{{ t('accessLogs.when') }}:</span> {{ formatTime(entry.timestamp) }}</p>
                <p class="meta-row"><span class="meta-label">{{ t('accessLogs.host') }}:</span> {{ entry.host }}</p>
                <p class="meta-row"><span class="meta-label">{{ t('accessLogs.route') }}:</span> {{ formatRoute(entry) }}</p>
                <p class="meta-row"><span class="meta-label">{{ t('accessLogs.type') }}:</span> {{ typeLabel(entry.routeType) }}</p>
                <p class="meta-row"><span class="meta-label">{{ t('accessLogs.target') }}:</span> {{ entry.target }}</p>
                <p class="meta-row"><span class="meta-label">{{ t('accessLogs.latency') }}:</span> {{ t('accessLogs.latencyValue', { duration: entry.durationMs, bytes: entry.bytes }) }}</p>
                <p class="meta-row"><span class="meta-label">{{ t('accessLogs.remote') }}:</span> {{ entry.remoteAddr }}</p>
              </div>
            </article>
          </div>
        </div>
      </article>
    </template>
  </section>
</template>

<style scoped>
.proxy-log-page {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  height: 100%;
  overflow: hidden;
}

.proxy-log-filter-panel,
.proxy-log-results-panel {
  min-height: 0;
}

.proxy-log-filter-panel {
  flex: 0 0 auto;
  overflow: visible;
}

.proxy-log-results-panel {
  display: flex;
  flex-direction: column;
  flex: 1 1 auto;
  overflow: hidden;
}

.proxy-log-panel-header {
  margin-bottom: 0;
}

.proxy-log-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 0.9rem 1rem;
  align-items: end;
  margin-top: 0.9rem;
}

.proxy-log-filter,
.proxy-log-status-dropdown {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  min-width: 10rem;
}

.proxy-log-filter-wide {
  flex: 1 1 16rem;
}

.proxy-log-select,
.proxy-log-input {
  width: 100%;
  min-height: 2.7rem;
  border-radius: 0.85rem;
  border: 1px solid rgba(255, 255, 255, 0.16);
  background: rgba(10, 16, 26, 0.76);
  color: #f6f9ff;
  padding: 0.7rem 0.85rem;
}

.proxy-log-select:focus,
.proxy-log-input:focus {
  outline: 2px solid rgba(121, 192, 255, 0.35);
  outline-offset: 1px;
}

.proxy-log-input::placeholder {
  color: rgba(224, 234, 250, 0.45);
}

.proxy-log-status-dropdown {
  position: relative;
  min-width: 14rem;
}

.proxy-log-method-dropdown {
  position: relative;
  min-width: 12rem;
}

.proxy-log-checkbox {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  color: rgba(224, 234, 250, 0.88);
  padding: 0.2rem 0;
}

.proxy-log-dropdown-button {
  width: 100%;
  min-height: 2.7rem;
  border-radius: 0.85rem;
  border: 1px solid rgba(255, 255, 255, 0.16);
  background: rgba(10, 16, 26, 0.76);
  color: #f6f9ff;
  padding: 0.7rem 0.85rem;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  text-align: left;
}

.proxy-log-dropdown-button:hover {
  background: rgba(16, 24, 38, 0.9);
}

.proxy-log-dropdown-button:focus {
  outline: 2px solid rgba(121, 192, 255, 0.35);
  outline-offset: 1px;
}

.proxy-log-dropdown-caret {
  color: rgba(224, 234, 250, 0.7);
  flex-shrink: 0;
}

.proxy-log-dropdown-menu {
  position: absolute;
  top: calc(100% + 0.45rem);
  left: 0;
  z-index: 10;
  min-width: 100%;
  padding: 0.75rem 0.85rem;
  border-radius: 0.9rem;
  border: 1px solid rgba(255, 255, 255, 0.16);
  background: rgba(10, 16, 26, 0.98);
  box-shadow: 0 14px 34px rgba(0, 0, 0, 0.35);
}

.proxy-log-reset {
  min-height: 2.7rem;
  border-radius: 0.85rem;
  border: 1px solid rgba(255, 255, 255, 0.16);
  background: rgba(255, 255, 255, 0.08);
  color: #f6f9ff;
  padding: 0.7rem 1rem;
  cursor: pointer;
}

.proxy-log-reset:hover {
  background: rgba(255, 255, 255, 0.12);
}

.proxy-log-results-body {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
  padding-right: 0.25rem;
}

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
  .proxy-log-filters {
    flex-direction: column;
    align-items: stretch;
  }

  .proxy-log-topline {
    align-items: flex-start;
    flex-direction: column;
  }

  .proxy-log-status-dropdown {
    min-width: 0;
  }

  .proxy-log-method-dropdown {
    min-width: 0;
  }
}
</style>
