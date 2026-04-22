<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

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

const { t } = useI18n()
const statusRows = ref<Array<{ title: string; copy: string; state: string }>>([])
const loading = ref(true)

async function loadStatus() {
  try {
    const response = await fetch('/console/api/status')
    const payload = (await response.json()) as StatusPayload
    statusRows.value = [
      {
        title: t('status.listenerTitle'),
        copy: t('status.configuredBind', {
          address: payload.adminConsole?.bindAddress ?? '127.0.0.1',
          port: payload.adminConsole?.port ?? '8888',
        }),
        state: payload.staticAssetsResolved ? t('status.servingSpaAssets') : t('status.fallbackResponse'),
      },
      {
        title: t('status.httpsTitle'),
        copy: payload.selfSignedTls?.enabled
          ? payload.selfSignedTls.ready
            ? t('status.managedActive')
            : payload.selfSignedTls.reason ?? t('status.managedConfigured')
          : payload.httpsExpected
            ? t('status.httpsExpected')
            : t('status.httpOnly'),
        state: payload.autocertEnabled ? t('status.autocert') : payload.selfSignedTls?.enabled ? t('status.managedMode') : t('status.standardMode'),
      },
      {
        title: t('status.runtimeTitle'),
        copy: t('status.runtimeCopy', {
          issuer: payload.issuer,
          users: payload.usersCount,
          scopes: payload.validScopes.join(', '),
        }),
        state: t('status.runtimeState'),
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
      <p class="page-eyebrow">{{ t('status.eyebrow') }}</p>
      <h2>{{ t('status.title') }}</h2>
      <p class="page-copy">{{ t('status.copy') }}</p>
    </header>

    <div v-if="loading" class="page-panel">
      <p class="list-copy">{{ t('status.loading') }}</p>
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
