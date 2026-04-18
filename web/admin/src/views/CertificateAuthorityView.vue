<script setup lang="ts">
import { onMounted, ref } from 'vue'

type StatusPayload = {
  selfSignedTls?: {
    caDir: string
    domains: string[]
    caCertTtl: string
    leafCertTtl: string
    enabled: boolean
    ready: boolean
    reason?: string
  }
}

type CertificatePayload = {
  rootCA: {
    available: boolean
    reason?: string
    info?: {
      subject?: string
      serial?: string
      notBefore?: string
      notAfter?: string
      certificate?: string
    }
  }
  leafCertificates: Array<{
    subject?: string
    organization?: string
    serial?: string
    notBefore?: string
    notAfter?: string
    domain?: string
    certFile?: string
    keyFile?: string
  }>
}

const status = ref<StatusPayload | null>(null)
const certificates = ref<CertificatePayload | null>(null)
const loading = ref(true)

const installerDownloadHref = '/console/api/downloads/certificate-installer.zip'

function joinValues(values?: string[], fallback = 'Not configured') {
  if (!values || values.length === 0) {
    return fallback
  }
  return values.join(', ')
}

function formatDate(value?: string) {
  if (!value) {
    return 'unknown'
  }
  return value.split('T')[0] ?? value
}

function formatValidity(from?: string, to?: string) {
  if (!from && !to) {
    return 'Unknown'
  }
  return `${formatDate(from)} to ${formatDate(to)}`
}

function formatIssued(from?: string) {
  if (!from) {
    return 'Issued unknown'
  }
  return `Issued ${formatDate(from)}`
}

function formatEnded(to?: string) {
  if (!to) {
    return 'Ends unknown'
  }
  return `Ends ${formatDate(to)}`
}

function issuedDomain(item: CertificatePayload['leafCertificates'][number]) {
  return item.domain ?? 'Unknown domain'
}

function issuedOrganization(item: CertificatePayload['leafCertificates'][number]) {
  return item.organization ?? 'Unknown organization'
}

async function loadPage() {
  try {
    const [statusResponse, certificateResponse] = await Promise.all([
      fetch('/console/api/status'),
      fetch('/console/api/certificates'),
    ])

    status.value = (await statusResponse.json()) as StatusPayload
    certificates.value = (await certificateResponse.json()) as CertificatePayload
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadPage()
})
</script>

<template>
  <section class="page page-certificates">
    <div v-if="loading" class="section-card loading-card">
      <p class="list-copy">Loading certificate authority details...</p>
    </div>

    <template v-else>
      <article class="section-card panel-sheen certificate-panel">
        <div class="section-heading">
          <div>
            <p class="page-eyebrow">Root certificate</p>
            <h3>Root certification installer</h3>
          </div>
          <span class="status-pill" :class="{ 'status-pill-muted': !certificates?.rootCA.available }">
            {{ certificates?.rootCA.available ? 'Available' : 'Pending' }}
          </span>
        </div>

        <div class="certificate-split">
          <div class="certificate-kv-grid">
            <div class="certificate-kv">
              <p class="table-label">SAN</p>
              <p class="table-value">{{ joinValues(status?.selfSignedTls?.domains) }}</p>
            </div>
            <div class="certificate-kv">
              <p class="table-label">OIDCLD</p>
              <p class="table-value">{{ certificates?.rootCA.info?.subject ?? 'Not created yet' }}</p>
            </div>
            <div class="certificate-kv">
              <p class="table-label">Validity</p>
              <p class="table-value">{{ formatValidity(certificates?.rootCA.info?.notBefore, certificates?.rootCA.info?.notAfter) }}</p>
            </div>
            <div class="certificate-kv">
              <p class="table-label">Domains</p>
              <p class="table-value">{{ joinValues(status?.selfSignedTls?.domains) }}</p>
            </div>
          </div>

          <div class="certificate-download-panel">
            <a class="download-action" :href="installerDownloadHref">Download Certificate Installer</a>
            <p class="table-helper">Unzip and run `install.sh` on macOS/Linux or `install.ps1` on Windows.</p>
          </div>
        </div>
      </article>

      <article class="section-card panel-sheen certificate-panel">
        <div class="section-heading">
          <div>
            <p class="page-eyebrow">Issued certificates</p>
            <h3>Issued certificate list</h3>
          </div>
        </div>

        <div v-if="(certificates?.leafCertificates.length ?? 0) === 0" class="certificate-empty">
          <p class="table-value">No certificates issued yet</p>
        </div>

        <div v-else class="certificate-list">
          <article v-for="item in certificates?.leafCertificates" :key="`${item.subject ?? 'certificate'}-${item.serial ?? 'unknown'}`" class="certificate-row-inline">
            <p class="table-value certificate-row-organization">{{ issuedOrganization(item) }}</p>
            <p class="table-helper certificate-row-domain">Domain: {{ issuedDomain(item) }}</p>
            <p class="table-helper certificate-row-date">Expires: {{ formatDate(item.notAfter) }}</p>
          </article>
        </div>
      </article>

      <article class="section-card panel-sheen certificate-panel">
        <div class="section-heading">
          <div>
            <p class="page-eyebrow">Issued certificates</p>
            <h3>Host-specific leaf issuance</h3>
          </div>
          <span class="status-pill status-pill-muted">Managed</span>
        </div>

        <div class="certificate-placeholder">
          <p class="placeholder-title">Managed self-signed issues single-host leaf certificates for each client.</p>
          <p class="table-helper">The configured CA domains define what can be issued. The issued certificate list shows only certificates created by this managed self-signed flow.</p>
        </div>
      </article>
    </template>
  </section>
</template>

<style scoped>
.page-certificates {
  gap: 1rem;
}

.certificate-panel {
  gap: 1.1rem;
  padding: 1.15rem 1.2rem;
}

.certificate-split {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(260px, 0.85fr);
  gap: 1.2rem;
  align-items: start;
}

.certificate-kv-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.9rem 1.1rem;
}

.certificate-kv {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
  min-width: 0;
}

.certificate-kv .table-value {
  word-break: break-word;
}

.certificate-download-panel {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  justify-content: center;
  gap: 0.75rem;
  min-height: 100%;
  padding-left: 1.2rem;
  border-left: 1px solid rgba(255, 255, 255, 0.1);
}

.certificate-list {
  display: flex;
  flex-direction: column;
  gap: 0;
  align-items: flex-start;
}

.certificate-row-inline {
  display: grid;
  grid-template-columns: max-content max-content max-content;
  gap: 0.8rem;
  align-items: center;
  justify-content: flex-start;
  padding: 1rem 0;
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  width: auto;
  max-width: 100%;
}

.certificate-row-organization,
.certificate-row-domain,
.certificate-row-date {
  margin: 0;
  min-width: 0;
}

.certificate-row-organization {
  word-break: break-word;
}

.certificate-row-domain {
  overflow-wrap: anywhere;
}

.certificate-row-date {
  white-space: nowrap;
}

.certificate-row-inline:first-child {
  border-top: 0;
  padding-top: 0;
}

.certificate-row-inline:last-child {
  padding-bottom: 0;
}

.certificate-empty,
.certificate-placeholder {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.certificate-empty,
.certificate-placeholder {
  padding: 0.2rem 0 0;
}

@media (max-width: 960px) {
  .certificate-split,
  .certificate-kv-grid {
    grid-template-columns: 1fr;
  }

  .certificate-row-inline {
    grid-template-columns: 1fr;
    gap: 0.45rem 0.8rem;
  }

  .certificate-download-panel {
    padding-left: 0;
    padding-top: 1rem;
    border-left: 0;
    border-top: 1px solid rgba(255, 255, 255, 0.1);
  }
}
</style>
