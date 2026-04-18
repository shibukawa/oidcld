<script setup lang="ts">
import { onMounted, ref } from 'vue'

type CertificatePayload = {
  rootCA: {
    available: boolean
    reason?: string
    info?: {
      subject?: string
      serial?: string
      notAfter?: string
      certificate?: string
    }
  }
  leafCertificates: Array<{
    subject?: string
    serial?: string
    notAfter?: string
    dnsNames?: string[]
  }>
}

const rows = ref<Array<{ label: string; value: string; helper: string }>>([])
const loading = ref(true)

async function loadCertificates() {
  try {
    const response = await fetch('/console/api/certificates')
    const payload = (await response.json()) as CertificatePayload
    rows.value = [
      {
        label: 'Root CA',
        value: payload.rootCA.available ? payload.rootCA.info?.subject ?? 'Available' : 'Not created yet',
        helper: payload.rootCA.available
          ? `Expires ${payload.rootCA.info?.notAfter ?? 'unknown'} · ${payload.rootCA.info?.certificate ?? ''}`
          : payload.rootCA.reason ?? 'Managed root CA is not available yet.',
      },
      {
        label: 'OIDCLD leaf',
        value: payload.leafCertificates[0]?.subject ?? 'Not created yet',
        helper: payload.leafCertificates[0]
          ? `SANs: ${(payload.leafCertificates[0].dnsNames ?? []).join(', ')}`
          : 'The managed leaf certificate will appear here after self-signed TLS startup.',
      },
      {
        label: 'Wildcard scope',
        value: payload.leafCertificates[0]?.dnsNames?.find((name) => name.startsWith('*.')) ?? 'Configured by certificate_authority.domains',
        helper: 'Unknown hosts are allowed only inside the configured wildcard suffix.',
      },
    ]
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadCertificates()
})
</script>

<template>
  <section class="page">
    <header class="page-header">
      <p class="page-eyebrow">Certificates</p>
      <h2>Managed trust inventory</h2>
      <p class="page-copy">This module will surface the persisted root CA and the leaf certificates OIDCLD uses for HTTPS startup. The current scaffold defines the information shape before the backend handlers are wired in.</p>
    </header>

    <div v-if="loading" class="page-panel">
      <p class="list-copy">Loading managed certificate inventory...</p>
    </div>

    <div v-else class="table-stack">
      <article v-for="row in rows" :key="row.label" class="table-row">
        <div>
          <p class="table-label">{{ row.label }}</p>
          <p class="table-value">{{ row.value }}</p>
          <p class="table-helper">{{ row.helper }}</p>
        </div>
        <span class="status-pill">Managed</span>
      </article>
    </div>
  </section>
</template>
