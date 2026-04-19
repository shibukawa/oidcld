<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

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

const { t } = useI18n()
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
const rootDetails = computed(() => [
  { key: 'san', label: t('certificateAuthority.san'), value: joinValues(status.value?.selfSignedTls?.domains) },
  {
    key: 'subject',
    label: t('certificateAuthority.subject'),
    value: certificates.value?.rootCA.info?.subject ?? t('certificateAuthority.notCreatedYet'),
  },
  {
    key: 'validity',
    label: t('certificateAuthority.validity'),
    value: formatValidity(certificates.value?.rootCA.info?.notBefore, certificates.value?.rootCA.info?.notAfter),
  },
  { key: 'domains', label: t('certificateAuthority.domains'), value: joinValues(status.value?.selfSignedTls?.domains) },
])

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

function joinValues(values?: string[], fallback = t('common.notConfigured')) {
  if (!values || values.length === 0) {
    return fallback
  }
  return values.join(', ')
}

function formatDate(value?: string) {
  if (!value) {
    return t('common.unknown')
  }
  return value.split('T')[0] ?? value
}

function formatValidity(from?: string, to?: string) {
  if (!from && !to) {
    return t('common.unknown')
  }
  return t('certificateAuthority.validityRange', { from: formatDate(from), to: formatDate(to) })
}

function issuedDomain(item: CertificatePayload['leafCertificates'][number]) {
  return item.domain ?? t('certificateAuthority.unknownDomain')
}

function issuedOrganization(item: CertificatePayload['leafCertificates'][number]) {
  return item.organization ?? t('certificateAuthority.unknownOrganization')
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
    issueError.value = error instanceof Error ? error.message : t('certificateAuthority.issueFailed')
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
  <section class="oidc-page page-certificates">
    <div v-if="loading" class="oidc-loading">
      <p>{{ t('certificateAuthority.loading') }}</p>
    </div>

    <template v-else>
      <article class="oidc-panel certificate-panel">
        <div class="panel-header">
          <div>
            <h2>{{ t('certificateAuthority.title') }}</h2>
          </div>
          <span class="status-pill" :class="{ 'status-pill-muted': !certificates?.rootCA.available }">
            {{ certificates?.rootCA.available ? t('certificateAuthority.issuerStatusAvailable') : t('certificateAuthority.issuerStatusPending') }}
          </span>
        </div>

        <div class="certificate-split">
          <div class="detail-grid certificate-detail-grid">
            <div v-for="item in rootDetails" :key="item.key" class="detail-row detail-row-span-2">
              <span class="detail-label">{{ item.label }}</span>
              <code class="detail-value">{{ item.value }}</code>
            </div>
          </div>

          <div class="certificate-download-panel">
            <a class="download-action" :href="installerDownloadHref">{{ t('certificateAuthority.downloadInstaller') }}</a>
            <p class="table-helper">{{ t('certificateAuthority.downloadHelp') }}</p>
          </div>
        </div>
      </article>

      <article class="oidc-panel certificate-panel">
        <div class="panel-header">
          <div>
            <h3>{{ t('certificateAuthority.issuedListTitle') }}</h3>
          </div>
        </div>

        <div v-if="(certificates?.leafCertificates.length ?? 0) === 0" class="empty-state">
          <p class="table-value">{{ t('certificateAuthority.noIssuedCertificates') }}</p>
        </div>

        <div v-else class="inline-list">
          <article
            v-for="item in certificates?.leafCertificates"
            :key="`${item.subject ?? 'certificate'}-${item.serial ?? 'unknown'}`"
            class="inline-list-row"
          >
            <p class="table-value certificate-row-organization">{{ issuedOrganization(item) }}</p>
            <p class="table-helper certificate-row-domain">{{ t('certificateAuthority.issuedDomain', { domain: issuedDomain(item) }) }}</p>
            <p class="table-helper certificate-row-date">{{ t('certificateAuthority.issuedExpires', { date: formatDate(item.notAfter) }) }}</p>
          </article>
        </div>
      </article>

      <article class="oidc-panel certificate-panel">
        <div class="panel-header">
          <div>
            <h3>{{ t('certificateAuthority.generatorTitle') }}</h3>
          </div>
        </div>

        <div v-if="wildcardDomain" class="stack-panel">
          <p class="table-helper">{{ t('certificateAuthority.generatorHelp', { domain: wildcardDomain }) }}</p>

          <div class="issuance-grid">
            <label class="issuance-field">
              <span class="table-label">{{ t('certificateAuthority.fieldOrganization') }}</span>
              <input v-model="issuanceOrganization" class="form-input" type="text" autocomplete="off">
            </label>

            <label class="issuance-field">
              <span class="table-label">{{ t('certificateAuthority.fieldDomain') }}</span>
              <div class="issuance-domain-row">
                <input
                  v-model="issuanceDomainLabel"
                  class="form-input issuance-input-domain"
                  type="text"
                  autocomplete="off"
                  :placeholder="t('certificateAuthority.domainPlaceholder')"
                >
                <span class="issuance-domain-suffix">.{{ wildcardSuffix }}</span>
              </div>
            </label>

            <div class="issuance-grid-spacer" aria-hidden="true"></div>

            <label class="issuance-field issuance-field-expiration">
              <span class="table-label">{{ t('certificateAuthority.fieldExpiration') }}</span>
              <input v-model="issuanceTTL" class="form-input" type="text" autocomplete="off">
            </label>

            <label class="issuance-field">
              <span class="table-label">{{ t('certificateAuthority.fieldStartDateTime') }}</span>
              <input v-model="issuanceStartLocal" class="form-input" type="datetime-local">
            </label>

            <div class="issuance-field issuance-field-action">
              <button type="button" class="download-action issuance-submit" :disabled="!canSubmit || issueSubmitting" @click="issueCertificate">
                {{ issueSubmitting ? t('certificateAuthority.preparing') : t('certificateAuthority.create') }}
              </button>
            </div>
          </div>

          <p v-if="fullIssuedDomain" class="table-helper">{{ t('certificateAuthority.issuedHost', { domain: fullIssuedDomain }) }}</p>

          <p v-if="issueError" class="issuance-error">{{ issueError }}</p>

          <div v-if="hasRequiredInputs" class="stack-panel">
            <div class="panel-divider"></div>
            <div class="curl-preview-header">
              <div>
                <p class="table-label">{{ t('certificateAuthority.curlLabel') }}</p>
                <p class="table-helper">{{ t('certificateAuthority.curlHelp') }}</p>
              </div>
              <button
                type="button"
                class="copy-button"
                @click="copyToClipboard(copyStateKey('curl', curlPreview), curlPreview)"
              >
                {{ isCopied(copyStateKey('curl', curlPreview)) ? t('common.copied') : t('common.copy') }}
              </button>
            </div>
            <pre class="code-surface curl-command">{{ curlPreview }}</pre>
          </div>
        </div>

        <div v-else class="empty-state">
          <p class="placeholder-title">{{ t('certificateAuthority.placeholderTitle') }}</p>
          <p class="table-helper">{{ t('certificateAuthority.placeholderCopy') }}</p>
        </div>
      </article>
    </template>
  </section>
</template>

<style scoped>
.page-certificates {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.certificate-panel {
  gap: 1.1rem;
}

.certificate-split {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(260px, 0.85fr);
  gap: 1.2rem;
  align-items: start;
}

.certificate-detail-grid {
  gap: 0.9rem 1.1rem;
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

.curl-preview-header {
  justify-content: space-between;
  align-items: flex-start;
}

.curl-command {
  white-space: pre-wrap;
  word-break: break-word;
}

@media (max-width: 980px) {
  .certificate-split,
  .certificate-detail-grid,
  .issuance-grid {
    grid-template-columns: 1fr;
  }

  .certificate-download-panel {
    padding-left: 0;
    padding-top: 1rem;
    border-left: 0;
    border-top: 1px solid rgba(255, 255, 255, 0.1);
  }

  .issuance-field-action {
    justify-self: stretch;
  }
}

@media (max-width: 640px) {
  .curl-preview-header,
  .issuance-domain-row {
    align-items: flex-start;
    flex-direction: column;
  }

  .issuance-submit {
    width: 100%;
  }
}
</style>
