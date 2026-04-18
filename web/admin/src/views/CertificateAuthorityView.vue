<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'

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
const issueSubmitting = ref(false)
const issueError = ref('')
const copiedKey = ref<string | null>(null)
const issuanceOrganization = ref('')
const issuanceDomainLabel = ref('')
const issuanceTTL = ref('720h')
const issuanceStartLocal = ref(defaultStartDateTimeLocal())

const installerDownloadHref = '/console/api/downloads/certificate-installer.zip'

let copiedTimer: number | undefined

const wildcardDomain = computed(() => {
  return status.value?.selfSignedTls?.domains?.find((domain) => domain.startsWith('*.')) ?? ''
})

const wildcardSuffix = computed(() => wildcardDomain.value.replace(/^\*\./, ''))
const fullIssuedDomain = computed(() => {
  const label = issuanceDomainLabel.value.trim()
  return label && wildcardSuffix.value ? `${label}.${wildcardSuffix.value}` : ''
})
const startRFC3339 = computed(() => {
  if (!issuanceStartLocal.value) {
    return ''
  }
  const date = new Date(issuanceStartLocal.value)
  if (Number.isNaN(date.getTime())) {
    return ''
  }
  return date.toISOString()
})
const issuePayload = computed(() => ({
  organization: issuanceOrganization.value.trim(),
  domainLabel: issuanceDomainLabel.value.trim(),
  ttl: issuanceTTL.value.trim(),
  notBefore: startRFC3339.value,
}))
const curlPreview = computed(() => {
  const payload = JSON.stringify(issuePayload.value)
  const filename = `certificate-${fullIssuedDomain.value || 'host'}.zip`
  return `curl -X POST /console/api/certificates/issue -H 'Content-Type: application/json' --data-raw ${shellSingleQuote(payload)} --output ${shellSingleQuote(filename)}`
})
const hasRequiredInputs = computed(() => {
  return Boolean(
    wildcardDomain.value &&
    issuePayload.value.organization &&
    issuePayload.value.domainLabel &&
    issuePayload.value.ttl &&
    issuePayload.value.notBefore,
  )
})
const canSubmit = computed(() => hasRequiredInputs.value)

function defaultStartDateTimeLocal() {
  const now = new Date()
  now.setHours(0, 0, 0, 0)
  const year = now.getFullYear()
  const month = String(now.getMonth() + 1).padStart(2, '0')
  const day = String(now.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}T00:00`
}

function shellSingleQuote(value: string) {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`
}

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

function issuedDomain(item: CertificatePayload['leafCertificates'][number]) {
  return item.domain ?? 'Unknown domain'
}

function issuedOrganization(item: CertificatePayload['leafCertificates'][number]) {
  return item.organization ?? 'Unknown organization'
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

function parseDownloadFilename(headerValue: string | null, fallback: string) {
  if (!headerValue) {
    return fallback
  }
  const utf8Match = headerValue.match(/filename\*=UTF-8''([^;]+)/i)
  if (utf8Match?.[1]) {
    return decodeURIComponent(utf8Match[1])
  }
  const match = headerValue.match(/filename="?([^"]+)"?/i)
  return match?.[1] ?? fallback
}

async function issueCertificate() {
  if (!canSubmit.value || issueSubmitting.value) {
    return
  }

  issueSubmitting.value = true
  issueError.value = ''

  try {
    const response = await fetch('/console/api/certificates/issue', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(issuePayload.value),
    })

    if (!response.ok) {
      issueError.value = await response.text()
      return
    }

    const blob = await response.blob()
    const downloadUrl = window.URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = downloadUrl
    anchor.download = parseDownloadFilename(
      response.headers.get('Content-Disposition'),
      `certificate-${fullIssuedDomain.value || 'host'}.zip`,
    )
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    window.URL.revokeObjectURL(downloadUrl)
    await loadPage()
  } catch (error) {
    issueError.value = error instanceof Error ? error.message : 'Certificate issuance failed.'
  } finally {
    issueSubmitting.value = false
  }
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

onBeforeUnmount(() => {
  clearCopyFeedback()
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
            <h3>Local Root certificate Authority</h3>
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
            <h3>Certification Generator</h3>
          </div>
        </div>

        <div v-if="wildcardDomain" class="certificate-issuance">
          <p class="table-helper">Generate a leaf certificate inside {{ wildcardDomain }} and download the PEM bundle immediately.</p>

          <div class="issuance-grid">
            <label class="issuance-field">
              <span class="table-label">Organization (Name of Certificate)</span>
              <input v-model="issuanceOrganization" class="issuance-input" type="text" autocomplete="off">
            </label>

            <label class="issuance-field">
              <span class="table-label">Domain</span>
              <div class="issuance-domain-row">
                <input v-model="issuanceDomainLabel" class="issuance-input issuance-input-domain" type="text" autocomplete="off" placeholder="host">
                <span class="issuance-domain-suffix">.{{ wildcardSuffix }}</span>
              </div>
            </label>

            <div class="issuance-grid-spacer" aria-hidden="true"></div>

            <label class="issuance-field issuance-field-expiration">
              <span class="table-label">Expiration</span>
              <input v-model="issuanceTTL" class="issuance-input" type="text" autocomplete="off">
            </label>

            <label class="issuance-field">
              <span class="table-label">Start date/time</span>
              <input v-model="issuanceStartLocal" class="issuance-input" type="datetime-local">
            </label>

            <div class="issuance-field issuance-field-action">
              <button type="button" class="download-action issuance-submit" :disabled="!canSubmit || issueSubmitting" @click="issueCertificate">
                {{ issueSubmitting ? 'Preparing...' : 'Create' }}
              </button>
            </div>
          </div>

          <p v-if="fullIssuedDomain" class="table-helper">Issued host: {{ fullIssuedDomain }}</p>

          <p v-if="issueError" class="issuance-error">{{ issueError }}</p>

          <div v-if="hasRequiredInputs" class="curl-preview">
            <div class="curl-preview-header">
              <div>
                <p class="table-label">curl</p>
                <p class="table-helper">Use the same API from a terminal.</p>
              </div>
              <button
                type="button"
                class="copy-button"
                @click="copyToClipboard(copyStateKey('curl', curlPreview), curlPreview)"
              >
                {{ isCopied(copyStateKey('curl', curlPreview)) ? 'Copied' : 'Copy' }}
              </button>
            </div>
            <pre class="curl-command">{{ curlPreview }}</pre>
          </div>
        </div>

        <div v-else class="certificate-placeholder">
          <p class="placeholder-title">Managed self-signed issues single-host leaf certificates for each client.</p>
          <p class="table-helper">The configured CA domains define what can be issued. Add a wildcard domain to enable manual host issuance from this page.</p>
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
.certificate-placeholder,
.certificate-issuance {
  display: flex;
  flex-direction: column;
  gap: 0.65rem;
}

.certificate-empty,
.certificate-placeholder,
.certificate-issuance {
  padding: 0.2rem 0 0;
}

.issuance-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 0.9rem 1rem;
}

.issuance-field {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  min-width: 0;
}

.issuance-grid-spacer {
  min-height: 0;
}

.issuance-field-expiration {
  grid-column: 1;
}

.issuance-domain-row,
.curl-preview-header {
  display: flex;
  align-items: center;
  gap: 0.8rem;
}

.issuance-domain-row {
  flex-wrap: wrap;
}

.issuance-input {
  width: 100%;
  min-height: 2.6rem;
  border: 1px solid rgba(255, 255, 255, 0.16);
  border-radius: 0.85rem;
  padding: 0.7rem 0.85rem;
  background: rgba(7, 17, 31, 0.45);
  color: #f6f9ff;
  font: inherit;
}

.issuance-input::placeholder {
  color: rgba(224, 234, 250, 0.36);
}

.issuance-input:focus {
  outline: none;
  border-color: rgba(140, 212, 255, 0.45);
  box-shadow: 0 0 0 3px rgba(55, 200, 192, 0.14);
}

.issuance-input-domain {
  flex: 1 1 12rem;
}

.issuance-domain-suffix {
  color: rgba(224, 234, 250, 0.9);
  font-weight: 600;
  overflow-wrap: anywhere;
}

.issuance-submit {
  border: 0;
  width: auto;
  min-width: 7.5rem;
  min-height: 2.6rem;
  margin-top: auto;
}

.issuance-field-action {
  justify-self: end;
  align-self: end;
  width: auto;
}

.issuance-submit:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}

.issuance-error {
  margin: 0;
  color: #ffb9b9;
  font-size: 0.9rem;
}

.curl-preview {
  display: flex;
  flex-direction: column;
  gap: 0.8rem;
  padding: 1rem 1.05rem;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 1rem;
  background: rgba(7, 17, 31, 0.34);
}

.curl-preview-header {
  justify-content: space-between;
  align-items: flex-start;
}

.curl-command {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  color: #f6f9ff;
  font-size: 0.84rem;
  line-height: 1.55;
}

.copy-button {
  flex: 0 0 auto;
  border: 1px solid rgba(255, 255, 255, 0.16);
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.08);
  color: #eff7ff;
  font-size: 0.76rem;
  font-weight: 700;
  padding: 0.36rem 0.72rem;
  cursor: pointer;
  transition:
    background 140ms ease,
    transform 140ms ease,
    border-color 140ms ease;
}

.copy-button:hover {
  transform: translateY(-1px);
  background: rgba(43, 144, 220, 0.18);
  border-color: rgba(140, 212, 255, 0.32);
}

@media (max-width: 960px) {
  .certificate-split,
  .certificate-kv-grid,
  .issuance-grid {
    grid-template-columns: 1fr;
  }

  .issuance-field-expiration {
    grid-column: auto;
  }

  .issuance-field-action {
    justify-self: stretch;
    width: 100%;
  }

  .issuance-submit {
    width: 100%;
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

  .curl-preview-header,
  .issuance-domain-row {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
