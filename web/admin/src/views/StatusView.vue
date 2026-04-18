<script setup lang="ts">
import { onMounted, ref } from 'vue'

type StatusPayload = {
  issuer: string
  httpsExpected: boolean
  autocertEnabled: boolean
  usersCount: number
  validScopes: string[]
  staticAssetsResolved: boolean
  adminConsole?: {
    bindAddress: string
    port: string
  }
  selfSignedTls?: {
    enabled: boolean
    domains: string[]
    ready: boolean
    reason?: string
  }
}

const statusRows = ref<Array<{ title: string; copy: string; state: string }>>([])
const loading = ref(true)

async function loadStatus() {
  try {
    const response = await fetch('/console/api/status')
    const payload = (await response.json()) as StatusPayload
    statusRows.value = [
      {
        title: 'Developer Console listener',
        copy: `Configured bind: ${payload.adminConsole?.bindAddress ?? '127.0.0.1'}:${payload.adminConsole?.port ?? '18889'}`,
        state: payload.staticAssetsResolved ? 'Serving SPA assets' : 'Fallback response',
      },
      {
        title: 'OIDC HTTPS listener',
        copy: payload.selfSignedTls?.enabled
          ? payload.selfSignedTls.ready
            ? 'Managed self-signed leaf certificates are active.'
            : payload.selfSignedTls.reason ?? 'Managed self-signed TLS is configured.'
          : payload.httpsExpected
            ? 'HTTPS is expected from issuer or autocert configuration.'
            : 'HTTP-only configuration',
        state: payload.autocertEnabled ? 'Autocert' : payload.selfSignedTls?.enabled ? 'Self-signed managed' : 'Standard mode',
      },
      {
        title: 'OIDC runtime summary',
        copy: `Issuer ${payload.issuer} · ${payload.usersCount} users · scopes: ${payload.validScopes.join(', ')}`,
        state: 'Runtime snapshot',
      },
    ]
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadStatus()
})
</script>

<template>
  <section class="page">
    <header class="page-header">
      <p class="page-eyebrow">System Status</p>
      <h2>Local control surface</h2>
      <p class="page-copy">The Developer Console remains local-only and now carries the HTTP metadata companion alongside certificate and runtime status workflows.</p>
    </header>

    <div v-if="loading" class="page-panel">
      <p class="list-copy">Loading runtime snapshot...</p>
    </div>

    <div v-else class="list-stack">
      <article v-for="row in statusRows" :key="row.title" class="card">
        <p class="list-title">{{ row.title }}</p>
        <p class="list-copy">{{ row.copy }}</p>
        <p class="download-tag">{{ row.state }}</p>
      </article>
    </div>
  </section>
</template>

<style scoped>
.card {
  display: flex;
  flex-direction: column;
  gap: 0.55rem;
}
</style>
