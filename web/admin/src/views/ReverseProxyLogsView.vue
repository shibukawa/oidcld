<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const allMethodOptions = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'CONNECT', 'OPTIONS']
const contentTypeOptions = ['All', 'HTML', 'JS', 'CSS', 'JSON', 'Other'] as const
const savedRequestSetsStorageKey = 'oidcld-admin-saved-request-sets'

type LogSummary = {
  id: number
  timestamp: string
  host: string
  method: string
  path: string
  statusCode: number
  contentTypeLabel: string
  durationMs: number
  bytes: number
  routeType: string
  routeHost: string
  routePath: string
  routeLabel: string
}

type CapturedBody = {
  kind: string
  contentType?: string
  text?: string
  truncated?: boolean
  omittedReason?: string
}

type CapturedRequest = {
  scheme: string
  host: string
  method: string
  path: string
  query?: string
  headers: Record<string, string[]>
  body: CapturedBody
}

type CapturedResponse = {
  statusCode: number
  headers: Record<string, string[]>
  contentType?: string
  bytes: number
  body: CapturedBody
}

type LogDetail = {
  id: number
  summary: LogSummary
  target: string
  rewritePathPrefix?: string
  remoteAddr: string
  request: CapturedRequest
  response: CapturedResponse
}

type ReplayRequest = {
  name?: string
  scheme: string
  host: string
  method: string
  path: string
  query?: string
  headers?: Record<string, string[]>
  body: CapturedBody
}

type SavedRequestSet = {
  version: 1
  name: string
  createdAt: string
  requests: ReplayRequest[]
}

const { t, locale } = useI18n()
const logEntries = ref<LogSummary[]>([])
const loading = ref(true)
const syncComplete = ref(false)
const scrollContainer = ref<HTMLElement | null>(null)
const selectedRouteLabel = ref('')
const selectedMethods = ref<string[]>([])
const selectedContentType = ref<(typeof contentTypeOptions)[number]>('All')
const pathFilter = ref('')
const selectedStatusGroups = ref([2, 3, 4, 5])
const methodDropdownOpen = ref(false)
const methodDropdownRef = ref<HTMLElement | null>(null)
const statusDropdownOpen = ref(false)
const statusDropdownRef = ref<HTMLElement | null>(null)
const savedSetsFloatingRef = ref<HTMLElement | null>(null)
const expandedIds = ref<number[]>([])
const selectedIds = ref<number[]>([])
const detailById = ref<Record<number, LogDetail>>({})
const detailErrors = ref<Record<number, string>>({})
const detailLoadingIds = ref<number[]>([])
const copiedKey = ref<string | null>(null)
const savedRequestSets = ref<SavedRequestSet[]>([])
const saveSetName = ref('')
const savedSetsOpen = ref(false)

const seenEntryIds = new Set<number>()
let eventSource: EventSource | null = null
let copiedTimer: number | undefined

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
    if (!matchesContentTypeFilter(entry.contentTypeLabel, selectedContentType.value)) {
      return false
    }
    return selectedStatusGroups.value.includes(Math.floor(entry.statusCode / 100))
  })
})
const methodFilterSummary = computed(() => {
  if (methodOptions.value.length === 0 || selectedMethods.value.length === methodOptions.value.length) {
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
const selectedEntries = computed(() => filteredEntries.value.filter((entry) => selectedIds.value.includes(entry.id)))
const selectedDetails = computed(() =>
  selectedEntries.value
    .map((entry) => detailById.value[entry.id])
    .filter((detail): detail is LogDetail => Boolean(detail)),
)

function formatTime(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  const now = new Date()
  const sameDay =
    date.getFullYear() === now.getFullYear() &&
    date.getMonth() === now.getMonth() &&
    date.getDate() === now.getDate()

  if (sameDay) {
    return date.toLocaleTimeString(locale.value, {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  return date.toLocaleDateString(locale.value, {
    month: '2-digit',
    day: '2-digit',
  })
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

function formatRoute(entry: LogSummary) {
  if (entry.routeLabel.trim() === '') {
    return `${entry.routeHost} ${entry.routePath}`
  }
  return `${entry.routeLabel}`
}

function matchesContentTypeFilter(label: string, selected: (typeof contentTypeOptions)[number]) {
  if (selected === 'All') {
    return true
  }
  if (selected === 'Other') {
    return !contentTypeOptions.slice(1, -1).includes(label as never) || label === '-'
  }
  return label === selected
}

function formatBytes(value: number) {
  if (value < 1024) {
    return `${value} B`
  }
  if (value < 1024 * 1024) {
    return `${(value / 1024).toFixed(1)} KB`
  }
  return `${(value / (1024 * 1024)).toFixed(1)} MB`
}

function bodyPreview(body?: CapturedBody) {
  if (!body) {
    return t('common.unavailable')
  }
  if (body.omittedReason === 'unsupported') {
    return t('accessLogs.bodyUnsupported')
  }
  if (body.omittedReason === 'too_large') {
    return t('accessLogs.bodyTooLarge')
  }
  if (body.omittedReason === 'read_error') {
    return t('accessLogs.bodyReadError')
  }
  if (!body.text) {
    return t('accessLogs.bodyEmpty')
  }
  return body.text
}

function formatHeaderValue(values?: string[]) {
  return values?.join(', ') ?? ''
}

function sortedHeaderEntries(headers: Record<string, string[]>) {
  return Object.entries(headers).sort(([left], [right]) => left.localeCompare(right))
}

function copyStateKey(prefix: string, value: string) {
  return `${prefix}:${value}`
}

function clearCopyFeedback() {
  if (copiedTimer !== undefined) {
    window.clearTimeout(copiedTimer)
    copiedTimer = undefined
  }
}

async function copyToClipboard(key: string, value: string) {
  if (!navigator.clipboard) {
    return
  }
  await navigator.clipboard.writeText(value)
  copiedKey.value = key
  clearCopyFeedback()
  copiedTimer = window.setTimeout(() => {
    copiedKey.value = null
    copiedTimer = undefined
  }, 1800)
}

function isCopied(key: string) {
  return copiedKey.value === key
}

function isNearBottom(element: HTMLElement | null) {
  if (!element) {
    return true
  }
  return element.scrollHeight - (element.scrollTop + element.clientHeight) <= 24
}

async function appendEntry(entry: LogSummary) {
  if (seenEntryIds.has(entry.id)) {
    return
  }

  const shouldStickToBottom = isNearBottom(scrollContainer.value)
  seenEntryIds.add(entry.id)
  logEntries.value = [entry, ...logEntries.value]

  if (shouldStickToBottom) {
    await nextTick()
    if (scrollContainer.value) {
      scrollContainer.value.scrollTop = 0
    }
  }
}

function connectStream() {
  eventSource = new EventSource('/console/api/reverse-proxy/logs/stream')

  eventSource.onmessage = (event) => {
    const entry = JSON.parse(event.data) as LogSummary
    void appendEntry(entry)
  }

  eventSource.addEventListener('sync', () => {
    syncComplete.value = true
    loading.value = false
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
  selectedContentType.value = 'All'
  pathFilter.value = ''
  selectedStatusGroups.value = [2, 3, 4, 5]
  saveSetName.value = ''
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
  if (savedSetsOpen.value && !savedSetsFloatingRef.value?.contains(event.target)) {
    savedSetsOpen.value = false
  }
}

async function loadDetail(id: number) {
  if (detailById.value[id] || detailLoadingIds.value.includes(id)) {
    return
  }
  detailLoadingIds.value = [...detailLoadingIds.value, id]
  detailErrors.value = { ...detailErrors.value, [id]: '' }
  try {
    const response = await fetch(`/console/api/reverse-proxy/logs/${id}`)
    if (!response.ok) {
      throw new Error(await response.text())
    }
    const detail = (await response.json()) as LogDetail
    detailById.value = { ...detailById.value, [id]: detail }
  } catch (error) {
    detailErrors.value = { ...detailErrors.value, [id]: error instanceof Error ? error.message : t('accessLogs.detailLoadFailed') }
  } finally {
    detailLoadingIds.value = detailLoadingIds.value.filter((value) => value !== id)
  }
}

function toggleExpanded(id: number) {
  if (expandedIds.value.includes(id)) {
    expandedIds.value = expandedIds.value.filter((value) => value !== id)
    return
  }
  expandedIds.value = [...expandedIds.value, id]
  void loadDetail(id)
}

function isExpanded(id: number) {
  return expandedIds.value.includes(id)
}

function detailOrThrow(id: number) {
  const detail = detailById.value[id]
  if (!detail) {
    throw new Error(`detail ${id} is not loaded`)
  }
  return detail
}

function toggleSelected(id: number) {
  if (selectedIds.value.includes(id)) {
    selectedIds.value = selectedIds.value.filter((value) => value !== id)
    return
  }
  selectedIds.value = [...selectedIds.value, id]
  void loadDetail(id)
}

function handleRowClick(id: number) {
  toggleExpanded(id)
}

function replayRequestFromDetail(detail: LogDetail): ReplayRequest {
  return {
    scheme: detail.request.scheme,
    host: detail.request.host,
    method: detail.request.method,
    path: detail.request.path,
    query: detail.request.query,
    headers: detail.request.headers,
    body: detail.request.body,
  }
}

function requestUrl(request: ReplayRequest | CapturedRequest) {
  const querySuffix = request.query ? `?${request.query}` : ''
  return `${request.scheme}://${request.host}${request.path}${querySuffix}`
}

function shellSingleQuote(value: string) {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`
}

function curlCommand(detail: LogDetail) {
  const request = replayRequestFromDetail(detail)
  const parts = [`curl -X ${request.method}`, shellSingleQuote(requestUrl(request))]
  const headerEntries = Object.entries(request.headers ?? {}).sort(([left], [right]) => left.localeCompare(right))
  for (const [key, values] of headerEntries) {
    const canonical = key.toLowerCase()
    if (canonical === 'host' || canonical === 'content-length' || canonical === 'cookie') {
      continue
    }
    for (const value of values) {
      parts.push(`-H ${shellSingleQuote(`${key}: ${value}`)}`)
    }
  }
  if (request.body.text && !request.body.omittedReason) {
    parts.push(`--data-raw ${shellSingleQuote(request.body.text)}`)
  }
  return parts.join(' ')
}

async function replayRequests(items: ReplayRequest[]) {
  const response = await fetch('/console/api/reverse-proxy/logs/replay', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(items),
  })
  if (!response.ok) {
    throw new Error(await response.text())
  }
}

async function replaySelected() {
  const requests = selectedDetails.value.map((detail) => replayRequestFromDetail(detail))
  if (requests.length === 0) {
    return
  }
  await replayRequests(requests)
}

function loadSavedRequestSets() {
  if (typeof window === 'undefined') {
    return
  }
  try {
    const raw = window.localStorage.getItem(savedRequestSetsStorageKey)
    if (!raw) {
      savedRequestSets.value = []
      return
    }
    const parsed = JSON.parse(raw) as SavedRequestSet[]
    savedRequestSets.value = Array.isArray(parsed) ? parsed : []
  } catch {
    savedRequestSets.value = []
  }
}

function persistSavedRequestSets() {
  if (typeof window === 'undefined') {
    return
  }
  window.localStorage.setItem(savedRequestSetsStorageKey, JSON.stringify(savedRequestSets.value))
}

function saveSelectedRequestSet() {
  const requests = selectedDetails.value.map((detail) => replayRequestFromDetail(detail))
  const name = saveSetName.value.trim()
  if (requests.length === 0 || name === '' || typeof window === 'undefined') {
    return
  }
  savedRequestSets.value = [
    {
      version: 1,
      name,
      createdAt: new Date().toISOString(),
      requests,
    },
    ...savedRequestSets.value,
  ]
  saveSetName.value = ''
  persistSavedRequestSets()
}

async function replaySavedSet(item: SavedRequestSet) {
  await replayRequests(item.requests)
  savedSetsOpen.value = false
}

function deleteSavedSet(name: string, createdAt: string) {
  savedRequestSets.value = savedRequestSets.value.filter((item) => !(item.name === name && item.createdAt === createdAt))
  persistSavedRequestSets()
  if (savedRequestSets.value.length === 0) {
    savedSetsOpen.value = false
  }
}

function toggleSavedSets() {
  savedSetsOpen.value = !savedSetsOpen.value
}

function shouldShowRequestBody(detail: LogDetail) {
  if (['GET', 'HEAD', 'OPTIONS', 'DELETE'].includes(detail.request.method.toUpperCase())) {
    return false
  }
  return detail.request.body.kind === 'json' || detail.request.body.kind === 'form'
}

function shouldShowResponseBody(detail: LogDetail) {
  return detail.summary.contentTypeLabel === 'JSON' && detail.response.body.kind === 'json'
}

function detailFlowLine(detail: LogDetail) {
  const remote = `${t('accessLogs.remote')}: ${detail.remoteAddr}`
  const host = `${t('accessLogs.host')}: ${detail.request.host}`
  if (detail.summary.routeType === 'oidc') {
    return `${remote} → ${host} → OIDC`
  }
  return `${remote} → ${host} → ${t('accessLogs.proxyLabel')}: ${detail.target}`
}

onMounted(() => {
  loadSavedRequestSets()
  document.addEventListener('click', handleDocumentClick)
  connectStream()
})

onBeforeUnmount(() => {
  document.removeEventListener('click', handleDocumentClick)
  clearCopyFeedback()
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
            </button>
            <div v-if="statusDropdownOpen" class="proxy-log-dropdown-menu">
              <label v-for="group in [2, 3, 4, 5]" :key="group" class="proxy-log-checkbox">
                <input :checked="selectedStatusGroups.includes(group)" type="checkbox" @change="toggleStatusGroup(group)" />
                <span>{{ group }}xx</span>
              </label>
            </div>
          </div>

          <label class="proxy-log-filter">
            <span class="table-helper">{{ t('accessLogs.filterContentType') }}</span>
            <select v-model="selectedContentType" class="proxy-log-select">
              <option v-for="option in contentTypeOptions" :key="option" :value="option">
                {{ option }}
              </option>
            </select>
          </label>

          <button
            class="proxy-log-reset-icon"
            type="button"
            :aria-label="t('accessLogs.resetFilters')"
            @click="resetFilters"
          >
            <span aria-hidden="true">🗑</span>
          </button>
        </div>
      </article>

      <article class="oidc-panel proxy-log-results-panel" :class="{ 'proxy-log-results-panel-with-selection': selectedEntries.length > 0 }">
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
            <article
              v-for="entry in filteredEntries"
              :key="entry.id"
              class="proxy-log-row inline-list-row"
              :class="{ 'proxy-log-row-expanded': isExpanded(entry.id) }"
              @click="handleRowClick(entry.id)"
            >
              <div class="proxy-log-summary-row">
                <span class="proxy-log-time">{{ formatTime(entry.timestamp) }}</span>
                <span class="proxy-log-method">{{ entry.method }}</span>
                <span class="proxy-log-path">{{ entry.path }}</span>
                <span class="proxy-log-route-pill">{{ formatRoute(entry) }}</span>
                <span class="status-pill" :class="entry.statusCode >= 400 ? 'status-pill-danger' : ''">
                  {{ entry.statusCode }}
                </span>
                <span class="proxy-log-type-pill">{{ entry.contentTypeLabel || '-' }}</span>
                <span class="proxy-log-metric">{{ entry.durationMs }} ms</span>
                <span class="proxy-log-metric">{{ formatBytes(entry.bytes) }}</span>
                <label class="proxy-log-select-cell" @click.stop>
                  <input
                    :checked="selectedIds.includes(entry.id)"
                    class="proxy-log-row-checkbox"
                    type="checkbox"
                    @change="toggleSelected(entry.id)"
                  />
                </label>
              </div>

              <div v-if="isExpanded(entry.id)" class="proxy-log-detail" @click.stop>
                <div v-if="detailLoadingIds.includes(entry.id)" class="table-helper">{{ t('accessLogs.loadingDetail') }}</div>
                <div v-else-if="detailErrors[entry.id]" class="table-helper proxy-log-error">{{ detailErrors[entry.id] }}</div>
                <template v-else-if="detailById[entry.id]">
                  <p class="proxy-log-detail-line">
                    <span class="proxy-log-detail-type">{{ typeLabel(entry.routeType) }}</span>
                    <span>{{ detailFlowLine(detailOrThrow(entry.id)) }}</span>
                  </p>

                  <div class="proxy-log-detail-grid">
                    <section v-if="shouldShowRequestBody(detailOrThrow(entry.id))" class="proxy-log-detail-card">
                      <p class="table-label">{{ t('accessLogs.requestSection') }}</p>
                      <p class="table-helper">{{ detailOrThrow(entry.id).request.method }} {{ requestUrl(detailOrThrow(entry.id).request) }}</p>
                      <pre class="code-surface">{{ bodyPreview(detailOrThrow(entry.id).request.body) }}</pre>
                    </section>

                    <section v-if="shouldShowResponseBody(detailOrThrow(entry.id))" class="proxy-log-detail-card">
                      <p class="table-label">{{ t('accessLogs.responseSection') }}</p>
                      <p class="table-helper">{{ detailOrThrow(entry.id).response.statusCode }} · {{ detailOrThrow(entry.id).response.contentType || '-' }}</p>
                      <pre class="code-surface">{{ bodyPreview(detailOrThrow(entry.id).response.body) }}</pre>
                    </section>

                    <section class="proxy-log-detail-card">
                      <p class="table-label">{{ t('accessLogs.requestHeaders') }}</p>
                      <div v-if="sortedHeaderEntries(detailOrThrow(entry.id).request.headers).length === 0" class="table-helper">{{ t('accessLogs.noHeaders') }}</div>
                      <div v-else class="header-list">
                        <div v-for="[key, values] in sortedHeaderEntries(detailOrThrow(entry.id).request.headers)" :key="`request-${key}`" class="header-row">
                          <span class="meta-label">{{ key }}</span>
                          <code>{{ formatHeaderValue(values) }}</code>
                        </div>
                      </div>
                    </section>

                    <section class="proxy-log-detail-card">
                      <p class="table-label">{{ t('accessLogs.responseHeaders') }}</p>
                      <div v-if="sortedHeaderEntries(detailOrThrow(entry.id).response.headers).length === 0" class="table-helper">{{ t('accessLogs.noHeaders') }}</div>
                      <div v-else class="header-list">
                        <div v-for="[key, values] in sortedHeaderEntries(detailOrThrow(entry.id).response.headers)" :key="`response-${key}`" class="header-row">
                          <span class="meta-label">{{ key }}</span>
                          <code>{{ formatHeaderValue(values) }}</code>
                        </div>
                      </div>
                    </section>

                    <section class="proxy-log-detail-card proxy-log-detail-card-wide">
                      <div class="proxy-log-curl-row">
                        <span class="proxy-log-curl-label">{{ t('accessLogs.curlLabel') }}</span>
                        <code class="proxy-log-curl-command">{{ curlCommand(detailOrThrow(entry.id)) }}</code>
                        <button
                          type="button"
                          class="copy-button"
                          @click.stop="copyToClipboard(copyStateKey('curl', curlCommand(detailOrThrow(entry.id))), curlCommand(detailOrThrow(entry.id)))"
                        >
                          {{ isCopied(copyStateKey('curl', curlCommand(detailOrThrow(entry.id)))) ? t('common.copied') : t('accessLogs.copyCurl') }}
                        </button>
                      </div>
                    </section>
                  </div>
                </template>
              </div>
            </article>
          </div>
        </div>

        <div v-if="selectedEntries.length > 0" class="proxy-log-selection-bar">
          <p class="table-helper">{{ t('accessLogs.selectedEntriesCount', { count: selectedEntries.length }) }}</p>
          <input
            v-model="saveSetName"
            class="proxy-log-save-name"
            type="text"
            :placeholder="t('accessLogs.saveNamePlaceholder')"
            @click.stop
          />
          <div class="proxy-log-selection-actions">
            <button type="button" class="copy-button" @click="replaySelected">{{ t('accessLogs.replaySelected') }}</button>
            <button type="button" class="copy-button" :disabled="saveSetName.trim() === ''" @click="saveSelectedRequestSet">
              {{ t('accessLogs.saveSelected') }}
            </button>
          </div>
        </div>

        <div v-if="savedRequestSets.length > 0" ref="savedSetsFloatingRef" class="proxy-log-saved-floating">
          <button
            type="button"
            class="proxy-log-saved-fab"
            :aria-expanded="savedSetsOpen"
            :aria-label="t('accessLogs.savedSetsTitle')"
            @click.stop="toggleSavedSets"
          >
            <span aria-hidden="true">☰</span>
          </button>

          <div v-if="savedSetsOpen" class="proxy-log-saved-popover" @click.stop>
            <div class="proxy-log-saved-popover-header">
              <p class="table-label">{{ t('accessLogs.savedSetsTitle') }}</p>
            </div>
            <div class="proxy-log-saved-list">
              <article v-for="item in savedRequestSets" :key="`${item.name}-${item.createdAt}`" class="proxy-log-saved-item">
                <div>
                  <p class="table-value">{{ item.name }}</p>
                  <p class="table-helper">{{ t('accessLogs.savedSetMeta', { count: item.requests.length, createdAt: formatTime(item.createdAt) }) }}</p>
                </div>
                <div class="proxy-log-saved-item-actions">
                  <button type="button" class="copy-button" @click="replaySavedSet(item)">{{ t('accessLogs.replaySaved') }}</button>
                  <button type="button" class="copy-button" @click="deleteSavedSet(item.name, item.createdAt)">{{ t('accessLogs.deleteSaved') }}</button>
                </div>
              </article>
            </div>
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
  min-height: 0;
  overflow: hidden;
}

.proxy-log-filter-panel,
.proxy-log-results-panel {
  min-height: 0;
}

.proxy-log-filter-panel {
  display: flex;
  flex-direction: column;
  gap: 0.9rem;
  flex: 0 0 auto;
  position: relative;
  z-index: 4;
  overflow: visible;
}

.proxy-log-panel-header {
  margin-bottom: 0;
}

.proxy-log-results-panel {
  display: flex;
  flex-direction: column;
  flex: 1 1 auto;
  min-height: 0;
  overflow: hidden;
  position: relative;
  z-index: 1;
}

.proxy-log-results-panel-with-selection .proxy-log-results-body {
  padding-bottom: 5.6rem;
}

.proxy-log-filters {
  display: flex;
  flex-wrap: wrap;
  gap: 0.9rem 1rem;
  align-items: end;
  margin-top: 0;
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

.proxy-log-select {
  appearance: none;
  -webkit-appearance: none;
  -moz-appearance: none;
  padding-right: 2.75rem;
  background-image:
    linear-gradient(45deg, transparent 50%, rgba(225, 236, 255, 0.86) 50%),
    linear-gradient(135deg, rgba(225, 236, 255, 0.86) 50%, transparent 50%);
  background-position:
    calc(100% - 1.1rem) calc(50% - 0.12rem),
    calc(100% - 0.78rem) calc(50% - 0.12rem);
  background-size: 0.42rem 0.42rem, 0.42rem 0.42rem;
  background-repeat: no-repeat;
}

.proxy-log-method-dropdown,
.proxy-log-status-dropdown {
  position: relative;
}

.proxy-log-dropdown-button,
.copy-button {
  min-height: 2.5rem;
  border-radius: 0.85rem;
  border: 1px solid rgba(255, 255, 255, 0.16);
  background: rgba(255, 255, 255, 0.08);
  color: #f6f9ff;
  padding: 0.65rem 0.9rem;
  cursor: pointer;
}

.proxy-log-dropdown-button {
  width: 100%;
  display: flex;
  align-items: center;
  justify-content: flex-start;
}

.proxy-log-reset-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 2.7rem;
  min-width: 2.7rem;
  min-height: 2.7rem;
  border: 1px solid rgba(255, 168, 168, 0.26);
  border-radius: 0.95rem;
  background:
    linear-gradient(180deg, rgba(255, 214, 214, 0.12), rgba(255, 104, 104, 0.16)),
    rgba(106, 19, 19, 0.58);
  color: #ffd7d7;
  cursor: pointer;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.14);
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

.proxy-log-checkbox {
  display: flex;
  align-items: center;
  gap: 0.45rem;
  color: rgba(224, 234, 250, 0.88);
  padding: 0.2rem 0;
}

.proxy-log-summary-row,
.proxy-log-selection-actions {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.proxy-log-results-body {
  flex: 1 1 auto;
  min-height: 0;
  overflow-y: auto;
  overflow-x: hidden;
}

.proxy-log-list {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.proxy-log-row {
  display: block;
  padding: 0;
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  overflow: visible;
  cursor: pointer;
  transition: background 140ms ease;
}

.proxy-log-row:first-child {
  border-top: 0;
}

.proxy-log-row:hover {
  background: rgba(255, 255, 255, 0.05);
}

.proxy-log-row-expanded {
  background: rgba(85, 188, 224, 0.1);
}

.proxy-log-summary-row {
  display: grid;
  grid-template-columns: 7rem 5rem minmax(18rem, 2.2fr) minmax(8rem, 1fr) 5rem 5.5rem 6rem 6rem 2.6rem;
  gap: 0.7rem;
  align-items: center;
  padding: 1rem 0;
}

.proxy-log-select-cell {
  display: flex;
  align-items: center;
  justify-content: center;
}

.proxy-log-row-checkbox {
  width: 1.05rem;
  height: 1.05rem;
}

.proxy-log-time,
.proxy-log-method,
.proxy-log-path,
.proxy-log-metric {
  font-size: 0.88rem;
}

.proxy-log-method,
.proxy-log-type-pill,
.proxy-log-route-pill {
  font-weight: 700;
}

.proxy-log-path {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.proxy-log-type-pill,
.proxy-log-route-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 2rem;
  padding: 0.28rem 0.65rem;
  border-radius: 999px;
  background: rgba(89, 199, 255, 0.12);
  color: #bfeeff;
}

.proxy-log-route-pill {
  justify-content: flex-start;
  max-width: 100%;
}

.proxy-log-detail {
  border-top: 1px solid rgba(255, 255, 255, 0.08);
  padding: 1rem 0 1.1rem;
}

.proxy-log-detail-line {
  margin: 0 0 0.9rem;
  color: rgba(224, 234, 250, 0.82);
  overflow-wrap: anywhere;
}

.proxy-log-detail-type {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-right: 0.6rem;
  padding: 0.18rem 0.55rem;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.08);
  font-weight: 700;
  color: #f6f9ff;
}

.proxy-log-detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.9rem;
  margin-top: 1rem;
}

.proxy-log-detail-card {
  padding: 0.9rem 0;
  border-radius: 0;
  border: 0;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
  background: transparent;
}

.proxy-log-detail-card:nth-child(-n + 2) {
  border-top: 0;
}

.proxy-log-detail-card-wide {
  grid-column: 1 / -1;
}

.proxy-log-selection-bar {
  position: absolute;
  right: 1.25rem;
  bottom: 1.25rem;
  width: min(66%, calc(100% - 7rem));
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 0.9rem;
  padding: 0.95rem 1rem;
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 1rem;
  background: rgba(7, 17, 31, 0.88);
  backdrop-filter: blur(18px);
  box-shadow: 0 16px 30px rgba(0, 0, 0, 0.28);
}

.proxy-log-saved-floating {
  position: absolute;
  left: 1.25rem;
  bottom: 1.25rem;
  z-index: 3;
}

.proxy-log-saved-fab {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 3.15rem;
  height: 3.15rem;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 999px;
  background: rgba(10, 16, 26, 0.9);
  color: #f6f9ff;
  box-shadow: 0 14px 26px rgba(0, 0, 0, 0.28);
  cursor: pointer;
  backdrop-filter: blur(18px);
}

.proxy-log-saved-popover {
  position: absolute;
  left: 0;
  bottom: calc(100% + 0.8rem);
  width: min(28rem, calc(100vw - 4rem));
  max-height: min(28rem, calc(100vh - 15rem));
  overflow: auto;
  padding: 0.95rem 1rem;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 1rem;
  background: rgba(7, 17, 31, 0.94);
  backdrop-filter: blur(18px);
  box-shadow: 0 18px 34px rgba(0, 0, 0, 0.3);
}

.proxy-log-saved-popover-header {
  padding-bottom: 0.75rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
}

.proxy-log-saved-list {
  display: flex;
  flex-direction: column;
}

.proxy-log-saved-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.9rem;
  padding: 0.85rem 0;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
}

.proxy-log-saved-item:first-child {
  border-top: 0;
}

.proxy-log-saved-item-actions {
  display: flex;
  align-items: center;
  gap: 0.7rem;
}

.proxy-log-save-name {
  flex: 1 1 14rem;
  min-width: 12rem;
  min-height: 2.6rem;
  border: 1px solid rgba(255, 255, 255, 0.16);
  border-radius: 0.85rem;
  padding: 0.7rem 0.85rem;
  background: rgba(10, 16, 26, 0.76);
  color: #f6f9ff;
}

.header-list {
  display: flex;
  flex-direction: column;
  gap: 0.45rem;
  margin-top: 0.5rem;
}

.header-row {
  display: grid;
  grid-template-columns: 12rem minmax(0, 1fr);
  gap: 0.8rem;
  align-items: start;
}

.header-row code {
  overflow-wrap: anywhere;
}

.meta-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.4rem 0.9rem;
}

.meta-row {
  margin: 0;
}

.meta-label {
  color: rgba(188, 226, 255, 0.9);
  font-weight: 700;
}

.proxy-log-error {
  color: #ffb9b9;
}

.proxy-log-curl-row {
  display: flex;
  align-items: center;
  gap: 0.8rem;
}

.proxy-log-curl-label {
  flex: 0 0 auto;
  color: rgba(188, 226, 255, 0.9);
  font-weight: 700;
}

.proxy-log-curl-command {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  padding: 0.7rem 0.85rem;
  border-radius: 0.85rem;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.04);
}

@media (max-width: 1280px) {
  .proxy-log-summary-row {
    grid-template-columns: 6.5rem 4.5rem minmax(14rem, 2fr) minmax(8rem, 1fr) 4.5rem 4.5rem 5.5rem 5.5rem 2.6rem;
  }
}

@media (max-width: 1080px) {
  .proxy-log-summary-row {
    grid-template-columns: 6.5rem 4.5rem minmax(12rem, 2fr) 5rem 5rem 5rem 2.6rem;
  }

  .proxy-log-route-pill,
  .proxy-log-type-pill,
  .proxy-log-metric:last-child {
    display: none;
  }

  .proxy-log-detail-grid,
  .meta-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 720px) {
  .proxy-log-summary-row {
    grid-template-columns: 1fr auto 2.6rem;
    gap: 0.5rem;
  }

  .proxy-log-time,
  .proxy-log-route-pill,
  .proxy-log-type-pill,
  .proxy-log-metric,
  .proxy-log-method {
    display: none;
  }

  .proxy-log-path {
    white-space: normal;
  }

  .header-row {
    grid-template-columns: 1fr;
  }

  .proxy-log-saved-item,
  .proxy-log-selection-bar {
    flex-direction: column;
    align-items: stretch;
  }

  .proxy-log-selection-bar {
    left: 1.25rem;
    width: auto;
  }

  .proxy-log-saved-item-actions {
    justify-content: stretch;
  }
}
</style>
