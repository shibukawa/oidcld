<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

type ReverseProxyRoute = {
  path: string
  routeType: string
  target: string
  spaFallback: boolean
  rewritePathPrefix?: string
}

type ReverseProxyHost = {
  host: string
  tlsSource: string
  routes: ReverseProxyRoute[]
}

type ReverseProxyPayload = {
  logRetention: number
  hosts: ReverseProxyHost[]
}

const payload = ref<ReverseProxyPayload | null>(null)
const loading = ref(true)

const hosts = computed(() => payload.value?.hosts ?? [])

function routeTypeLabel(value: string) {
  if (value === 'proxy') {
    return 'Proxy'
  }
  if (value === 'static') {
    return 'Static'
  }
  return value
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
      <p>Loading reverse proxy routes...</p>
    </div>

    <div v-else class="proxy-layout">
      <section class="oidc-panel proxy-panel">
        <div class="panel-header">
          <div>
            <h2>Reverse Proxy Configurations</h2>
          </div>
          <span class="status-pill" :class="{ 'status-pill-muted': hosts.length === 0 }">
            {{ hosts.length === 0 ? 'Disabled' : 'Active' }}
          </span>
        </div>

        <div v-if="hosts.length === 0" class="proxy-empty">
          <p class="detail-text">No reverse proxy hosts configured.</p>
          <p class="detail-value">Add a `reverse_proxy.hosts` section in the config file to expose dev servers or static sites.</p>
        </div>

        <div v-else class="proxy-hosts">
          <article v-for="host in hosts" :key="host.host" class="proxy-host-card">
            <div class="detail-grid">
              <div class="detail-row detail-row-span-2">
                <span class="detail-label">Host</span>
                <code class="detail-value">{{ host.host }}</code>
              </div>

              <div class="detail-row">
                <span class="detail-label">TLS</span>
                <code class="detail-value">{{ host.tlsSource }}</code>
              </div>

              <div class="detail-row">
                <span class="detail-label">Routes</span>
                <code class="detail-value">{{ host.routes.length }}</code>
              </div>
            </div>

            <div class="proxy-route-list">
              <article v-for="route in host.routes" :key="`${host.host}-${route.path}-${route.target}`" class="proxy-route-row">
                <div class="proxy-route-copy">
                  <p class="proxy-route-path">{{ route.path }}</p>
                  <p class="proxy-route-meta">
                    {{ routeTypeLabel(route.routeType) }}
                    <span v-if="route.spaFallback"> / SPA fallback</span>
                    <span v-if="route.rewritePathPrefix"> / rewrite to {{ route.rewritePathPrefix }}</span>
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

.proxy-empty {
  display: flex;
  flex-direction: column;
  gap: 0.45rem;
}

.proxy-hosts {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.proxy-host-card {
  display: flex;
  flex-direction: column;
  gap: 0.95rem;
  padding: 1rem;
  border-radius: 1rem;
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: rgba(255, 255, 255, 0.05);
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
  padding-top: 0;
  border-top: 0;
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
