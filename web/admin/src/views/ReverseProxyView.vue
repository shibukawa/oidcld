<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

type ReverseProxyRoute = {
  path: string
  label: string
  routeType: string
  target: string
  spaFallback: boolean
  rewritePathPrefix?: string
  gatewayEnabled: boolean
  gatewayRequired?: Record<string, unknown>
  gatewayReplayAuthorization: boolean
  mockPreferExamples: boolean
  mockDefaultStatus?: string
}

type ReverseProxyHost = {
  host: string
  defaultVirtualHost: boolean
  tlsSource: string
  routes: ReverseProxyRoute[]
}

type ReverseProxyPayload = {
  logRetention: number
  hosts: ReverseProxyHost[]
}

const { t } = useI18n()
const payload = ref<ReverseProxyPayload | null>(null)
const loading = ref(true)

const hosts = computed(() => payload.value?.hosts ?? [])

function routeTypeLabel(value: string) {
  if (value === 'proxy') {
    return t('common.proxy')
  }
  if (value === 'static') {
    return t('common.static')
  }
  if (value === 'mock') {
    return t('common.mock')
  }
  return value
}

function formatGatewayRequired(required?: Record<string, unknown>) {
  if (!required) {
    return ''
  }
  return Object.entries(required)
    .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join(', ') : String(value)}`)
    .join(' / ')
}

async function loadPage() {
  try {
    const response = await fetch('/console/api/reverse-proxy')
    payload.value = (await response.json()) as ReverseProxyPayload
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadPage()
})
</script>

<template>
  <section class="oidc-page">
    <div v-if="loading" class="oidc-loading">
      <p>{{ t('reverseProxy.loading') }}</p>
    </div>

    <div v-else class="proxy-layout">
      <section class="oidc-panel proxy-panel">
        <div class="panel-header">
          <div>
            <h2>{{ t('reverseProxy.title') }}</h2>
          </div>
          <span class="status-pill" :class="{ 'status-pill-muted': hosts.length === 0 }">
            {{ hosts.length === 0 ? t('reverseProxy.disabled') : t('reverseProxy.active') }}
          </span>
        </div>

        <div v-if="hosts.length === 0" class="proxy-empty">
          <p class="detail-text">{{ t('reverseProxy.emptyTitle') }}</p>
          <p class="detail-value">{{ t('reverseProxy.emptyCopy') }}</p>
        </div>

        <div v-else class="proxy-hosts">
          <article v-for="host in hosts" :key="host.host" class="proxy-host-row">
            <div class="proxy-host-header">
              <div class="proxy-host-summary">
                <p class="table-value">{{ host.host }}</p>
                <p class="table-helper">
                  {{ t('reverseProxy.tls') }}: {{ host.tlsSource }} / {{ t('reverseProxy.routes') }}: {{ host.routes.length }}
                </p>
              </div>
            </div>

            <div class="proxy-route-list">
              <article v-for="route in host.routes" :key="`${host.host}-${route.path}-${route.target}`" class="proxy-route-row">
                <div class="proxy-route-copy">
                  <p class="proxy-route-path">{{ route.label }} · {{ route.path }}</p>
                  <p class="proxy-route-meta">
                    {{ routeTypeLabel(route.routeType) }}
                    <span v-if="route.spaFallback"> / {{ t('reverseProxy.spaFallback') }}</span>
                    <span v-if="route.rewritePathPrefix"> / {{ t('reverseProxy.rewriteTo', { prefix: route.rewritePathPrefix }) }}</span>
                    <span v-if="route.gatewayEnabled"> / {{ t('reverseProxy.gateway') }}</span>
                    <span v-if="route.mockPreferExamples"> / {{ t('reverseProxy.examplesPreferred') }}</span>
                    <span v-if="route.mockDefaultStatus"> / {{ t('reverseProxy.defaultStatus', { status: route.mockDefaultStatus }) }}</span>
                  </p>
                  <p v-if="route.gatewayRequired && Object.keys(route.gatewayRequired).length > 0" class="proxy-route-meta">
                    {{ t('reverseProxy.requiredClaims', { claims: formatGatewayRequired(route.gatewayRequired) }) }}
                  </p>
                  <p v-if="route.gatewayEnabled" class="proxy-route-meta">
                    {{ t('reverseProxy.replayAuthorization', { enabled: route.gatewayReplayAuthorization ? t('common.active') : t('common.disabled') }) }}
                  </p>
                </div>
                <code class="proxy-target">{{ route.target }}</code>
              </article>
            </div>
          </article>
        </div>
      </section>
    </div>
  </section>
</template>

<style scoped>
.proxy-layout {
  display: grid;
  gap: 1rem;
  grid-template-columns: minmax(0, 1fr);
}

.proxy-empty,
.proxy-hosts {
  display: flex;
  flex-direction: column;
}

.proxy-host-row {
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
  padding: 1rem 0;
  border-top: 1px solid rgba(255, 255, 255, 0.12);
}

.proxy-host-row:first-child {
  padding-top: 0;
  border-top: 0;
}

.proxy-host-row:last-child {
  padding-bottom: 0;
}

.proxy-host-header,
.proxy-host-summary {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.proxy-host-summary .table-value,
.proxy-host-summary .table-helper {
  margin: 0;
}

.proxy-route-list {
  display: flex;
  flex-direction: column;
}

.proxy-route-row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 1rem;
  padding: 0.9rem 0;
  border-top: 1px solid rgba(255, 255, 255, 0.12);
}

.proxy-route-row:first-child {
  padding-top: 0.2rem;
}

.proxy-route-copy {
  display: flex;
  flex-direction: column;
  gap: 0.18rem;
  min-width: 0;
}

.proxy-route-path,
.proxy-route-meta {
  margin: 0;
}

.proxy-route-path {
  color: #f6f9ff;
  font-weight: 700;
}

.proxy-route-meta {
  color: rgba(224, 234, 250, 0.78);
  font-size: 0.84rem;
}

.proxy-target {
  max-width: 52%;
  white-space: normal;
  word-break: break-word;
  color: #dff4ff;
}

@media (max-width: 640px) {
  .panel-header,
  .proxy-route-row {
    flex-direction: column;
    align-items: flex-start;
  }

  .proxy-target {
    max-width: 100%;
  }
}
</style>
