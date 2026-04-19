<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'

type StatusPayload = {
  issuer: string
  usersCount: number
  validScopes: string[]
  staticAssetsResolved: boolean
  adminConsole?: {
    bindAddress: string
    port: string
  }
  oidc?: {
    mode: string
    tlsSource: string
    accessFilter: string
    pkceRequired: boolean
    nonceRequired: boolean
    expiredIn: number
    audClaimFormat: string
    refreshTokenEnabled: boolean
    refreshTokenExpiry: number
    endSessionEnabled: boolean
    tenants?: string[]
    endpoints: {
      discovery: string
      authorize: string
      token: string
      userInfo: string
      deviceAuthorization: string
      jwks: string
      logout: string
      healthCheck: string
    }
  }
  selfSignedTls?: {
    enabled?: boolean
    ready: boolean
    reason?: string
  }
  autocertEnabled: boolean
  httpsExpected: boolean
}

type UserSummary = {
  id: string
  displayName: string
  extraClaims: Record<string, unknown>
  extraValidScopes?: string[]
}

type UsersPayload = {
  users: UserSummary[]
}

const { t } = useI18n()
const status = ref<StatusPayload | null>(null)
const users = ref<UserSummary[]>([])
const selectedUserId = ref<string | null>(null)
const loading = ref(true)
const copiedKey = ref<string | null>(null)
let copiedTimer: number | undefined

const selectedUser = computed(() => users.value.find((user) => user.id === selectedUserId.value) ?? null)
const selectedUserClaims = computed(() =>
  selectedUser.value ? JSON.stringify(selectedUser.value.extraClaims ?? {}, null, 2) : '',
)

const modeOptions = computed(() => {
  const currentMode = (status.value?.oidc?.mode ?? 'oidc').toLowerCase()
  return [
    { key: 'oidc', label: 'OIDC', selected: currentMode === 'oidc' },
    { key: 'entraid-v1', label: 'EntraIDv1', selected: currentMode === 'entraid v1' },
    { key: 'entraid-v2', label: 'EntraIDv2', selected: currentMode === 'entraid v2' },
  ]
})

const tlsOptions = computed(() => {
  const currentTLS = (status.value?.oidc?.tlsSource ?? 'none').toLowerCase()
  return [
    { key: 'none', label: t('common.none'), selected: currentTLS === 'none' },
    { key: 'manual', label: t('common.manual'), selected: currentTLS === 'manual' },
    { key: 'acme', label: t('common.acme'), selected: currentTLS === 'acme' },
    { key: 'self-signed', label: t('common.selfSigned'), selected: currentTLS === 'self-signed' },
  ]
})

const audienceOptions = computed(() => {
  const currentAudience = (status.value?.oidc?.audClaimFormat ?? 'string').toLowerCase()
  return [
    { key: 'string', label: t('common.string'), selected: currentAudience === 'string' },
    { key: 'array', label: t('common.array'), selected: currentAudience === 'array' },
  ]
})

const endpointRows = computed(() => [
  {
    key: 'https-discovery',
    label: t('openidConnect.httpsDiscovery'),
    value: 'https://localhost:18443/.well-known/openid-configuration',
  },
  {
    key: 'https-jwks',
    label: t('openidConnect.httpsJwks'),
    value: 'https://localhost:18443/keys',
  },
  {
    key: 'http-discovery',
    label: t('openidConnect.httpDiscovery'),
    value: 'http://localhost:18889/.well-known/openid-configuration',
  },
  {
    key: 'http-jwks',
    label: t('openidConnect.httpJwks'),
    value: 'http://localhost:18889/keys',
  },
])

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

async function loadPage() {
  try {
    const [statusResponse, usersResponse] = await Promise.all([
      fetch('/console/api/status'),
      fetch('/console/api/openid-connect/users'),
    ])

    status.value = (await statusResponse.json()) as StatusPayload
    const usersPayload = (await usersResponse.json()) as UsersPayload
    users.value = usersPayload.users ?? []
    selectedUserId.value = null
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
  <section class="oidc-page">
    <div v-if="loading" class="oidc-loading">
      <p>{{ t('openidConnect.loading') }}</p>
    </div>

    <div v-else class="oidc-layout">
      <section class="oidc-panel oidc-panel-top">
        <div class="panel-header">
          <div>
            <h2>{{ t('openidConnect.title') }}</h2>
          </div>
        </div>

        <div class="detail-grid">
          <div class="detail-row detail-row-span-4">
            <span class="detail-label">{{ t('openidConnect.issuer') }}</span>
            <div class="detail-value-group">
              <code class="detail-value">{{ status?.issuer ?? t('common.unavailable') }}</code>
              <button
                type="button"
                class="copy-button"
                @click="copyToClipboard(copyStateKey('issuer', status?.issuer ?? t('common.unavailable')), status?.issuer ?? t('common.unavailable'))"
              >
                {{ isCopied(copyStateKey('issuer', status?.issuer ?? t('common.unavailable'))) ? t('common.copied') : t('common.copy') }}
              </button>
            </div>
          </div>

          <div class="detail-row detail-row-span-4">
            <span class="detail-label">{{ t('openidConnect.validScopes') }}</span>
            <code class="detail-value">{{ status?.validScopes.join(', ') || t('openidConnect.noScopesConfigured') }}</code>
          </div>

          <div v-if="(status?.oidc?.tenants ?? []).length > 0" class="detail-row detail-row-span-4">
            <span class="detail-label">{{ t('openidConnect.tenantPaths') }}</span>
            <code class="detail-value">{{ status?.oidc?.tenants?.join(', ') }}</code>
          </div>

          <div class="detail-row detail-row-span-2">
            <span class="detail-label">{{ t('openidConnect.mode') }}</span>
            <div class="option-list">
              <span
                v-for="option in modeOptions"
                :key="option.key"
                class="option-chip"
                :class="{ 'option-chip-active': option.selected }"
              >
                {{ option.label }}
              </span>
            </div>
          </div>

          <div class="detail-row detail-row-span-2">
            <span class="detail-label">{{ t('openidConnect.tls') }}</span>
            <div class="option-list">
              <span
                v-for="option in tlsOptions"
                :key="option.key"
                class="option-chip"
                :class="{ 'option-chip-active': option.selected }"
              >
                {{ option.label }}
              </span>
            </div>
          </div>

          <div class="detail-row">
            <span class="detail-label">{{ t('openidConnect.pkce') }}</span>
            <code class="detail-value">{{ String(status?.oidc?.pkceRequired ?? false) }}</code>
          </div>

          <div class="detail-row">
            <span class="detail-label">{{ t('openidConnect.nonce') }}</span>
            <code class="detail-value">{{ String(status?.oidc?.nonceRequired ?? false) }}</code>
          </div>

          <div class="detail-row">
            <span class="detail-label">{{ t('openidConnect.expiredIn') }}</span>
            <code class="detail-value">{{ status?.oidc?.expiredIn ?? 0 }}</code>
          </div>

          <div class="detail-row">
            <span class="detail-label">{{ t('openidConnect.audience') }}</span>
            <div class="option-list">
              <span
                v-for="option in audienceOptions"
                :key="option.key"
                class="option-chip"
                :class="{ 'option-chip-active': option.selected }"
              >
                {{ option.label }}
              </span>
            </div>
          </div>

          <div class="detail-row">
            <span class="detail-label">{{ t('openidConnect.refreshToken') }}</span>
            <code class="detail-value">{{ String(status?.oidc?.refreshTokenEnabled ?? false) }}</code>
          </div>

          <div class="detail-row">
            <span class="detail-label">{{ t('openidConnect.refreshExpiry') }}</span>
            <code class="detail-value">{{ status?.oidc?.refreshTokenExpiry ?? 0 }}</code>
          </div>

          <div class="detail-row">
            <span class="detail-label">{{ t('openidConnect.endSession') }}</span>
            <code class="detail-value">{{ String(status?.oidc?.endSessionEnabled ?? false) }}</code>
          </div>

          <div class="detail-row detail-row-span-4">
            <span class="detail-label">{{ t('openidConnect.accessFilter') }}</span>
            <span class="detail-text">{{ status?.oidc?.accessFilter ?? t('openidConnect.accessFilterDisabled') }}</span>
          </div>
        </div>
      </section>

      <section class="oidc-panel oidc-panel-users">
        <div class="panel-header">
          <div>
            <h3>{{ t('openidConnect.usersTitle') }}</h3>
          </div>
        </div>

        <div class="users-content">
          <div class="user-list">
            <button
              v-for="user in users"
              :key="user.id"
              type="button"
              class="user-button"
              :class="{ 'user-button-active': user.id === selectedUserId }"
              @click="selectedUserId = user.id"
            >
              {{ user.displayName || user.id }}
            </button>
          </div>

          <div v-if="selectedUser" class="claims-panel">
            <div class="claims-header">
              <div>
                <p class="claims-name">{{ selectedUser.displayName || selectedUser.id }}</p>
                <p class="claims-id">{{ selectedUser.id }}</p>
              </div>
              <button
                type="button"
                class="copy-button"
                @click="copyToClipboard(copyStateKey('claims', selectedUser.id), selectedUserClaims)"
              >
                {{ isCopied(copyStateKey('claims', selectedUser.id)) ? t('common.copied') : t('common.copy') }}
              </button>
            </div>

            <p v-if="(selectedUser.extraValidScopes ?? []).length > 0" class="claims-scopes">
              {{ t('openidConnect.claimsScopes', { scopes: selectedUser.extraValidScopes?.join(', ') }) }}
            </p>

            <pre class="code-surface claims-json">{{ selectedUserClaims }}</pre>
          </div>
        </div>
      </section>

      <section class="oidc-panel oidc-panel-endpoints">
        <div class="panel-header">
          <div>
            <h3>{{ t('openidConnect.endpointsTitle') }}</h3>
          </div>
        </div>

        <div class="endpoint-list">
          <dl class="endpoint-definition-list">
            <template v-for="endpoint in endpointRows" :key="endpoint.key">
              <dt class="endpoint-label">{{ endpoint.label }}</dt>
              <dd class="endpoint-value">
                <a
                  class="endpoint-link"
                  :href="endpoint.value"
                  target="_blank"
                  rel="noreferrer"
                >
                  {{ endpoint.value }}
                </a>
              </dd>
            </template>
          </dl>
        </div>
      </section>
    </div>
  </section>
</template>

<style scoped>
.oidc-layout {
  display: grid;
  gap: 1rem;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1.08fr);
  grid-template-areas:
    "top top"
    "users endpoints";
}

.oidc-panel-top {
  grid-area: top;
}

.oidc-panel-users {
  grid-area: users;
}

.oidc-panel-endpoints {
  grid-area: endpoints;
}

.option-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.45rem;
}

.option-chip {
  padding: 0.26rem 0.55rem;
  border-radius: 999px;
  color: rgba(224, 234, 250, 0.42);
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.06);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.01em;
}

.option-chip-active {
  color: #f5fbff;
  background: rgba(34, 138, 216, 0.2);
  border-color: rgba(140, 212, 255, 0.3);
}

.users-content {
  display: grid;
  grid-template-columns: minmax(9rem, 11rem) minmax(0, 1fr);
  gap: 0.9rem;
  align-items: start;
}

.user-list {
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
}

.user-button {
  width: fit-content;
  min-width: 9.5rem;
  max-width: 100%;
  border: 1px solid rgba(123, 198, 255, 0.24);
  border-radius: 999px;
  background: linear-gradient(135deg, rgba(255, 255, 255, 0.08), rgba(176, 220, 255, 0.08));
  color: #e8f4ff;
  font-size: 0.9rem;
  font-weight: 700;
  text-align: left;
  padding: 0.52rem 0.95rem;
  cursor: pointer;
  transition:
    transform 140ms ease,
    box-shadow 140ms ease,
    filter 140ms ease;
}

.user-button:hover,
.user-button-active {
  transform: translateY(-1px);
  box-shadow: 0 14px 24px rgba(5, 23, 60, 0.22);
}

.user-button:hover {
  background: linear-gradient(135deg, #2a8dee, #1767bd);
  border-color: rgba(173, 226, 255, 0.42);
  color: #ffffff;
}

.user-button-active {
  background: linear-gradient(135deg, #0f7ae0, #0b57aa);
  border-color: rgba(204, 237, 255, 0.48);
  filter: brightness(1.05);
  color: #ffffff;
}

.claims-panel {
  display: flex;
  flex-direction: column;
  gap: 0.6rem;
  min-height: 0;
  min-width: 0;
}

.claims-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 0.8rem;
}

.claims-name,
.claims-id,
.claims-scopes {
  margin: 0;
}

.claims-name {
  color: #f6f9ff;
  font-weight: 700;
}

.claims-id,
.claims-scopes {
  color: rgba(224, 234, 250, 0.72);
  font-size: 0.8rem;
}

.claims-json {
  min-height: 16rem;
  max-height: 25rem;
}

.endpoint-list {
  min-width: 0;
}

.endpoint-definition-list {
  display: grid;
  grid-template-columns: 11.5rem minmax(0, 1fr);
  align-items: start;
  gap: 0.65rem 0.9rem;
  margin: 0;
}

.endpoint-label {
  margin: 0;
  color: rgba(188, 226, 255, 0.84);
  font-size: 0.76rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.endpoint-link {
  display: inline-block;
  color: #eaf6ff;
  text-decoration: underline;
  text-underline-offset: 0.16em;
  overflow-wrap: anywhere;
  font-size: 0.84rem;
}

.endpoint-value {
  margin: 0;
  min-width: 0;
}

@media (max-width: 980px) {
  .oidc-layout {
    grid-template-columns: 1fr;
    grid-template-areas:
      "top"
      "users"
      "endpoints";
  }

  .endpoint-definition-list,
  .users-content {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 640px) {
  .panel-header,
  .claims-header,
  .detail-value-group {
    flex-direction: column;
    align-items: flex-start;
  }

  .user-button {
    width: 100%;
  }
}
</style>
