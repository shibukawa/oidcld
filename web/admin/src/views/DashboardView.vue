<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const metrics = computed(() => [
  { label: t('dashboard.metrics.modulesLabel'), value: '4', copy: t('dashboard.metrics.modulesCopy') },
  { label: t('dashboard.metrics.tlsLabel'), value: '3', copy: t('dashboard.metrics.tlsCopy') },
  { label: t('dashboard.metrics.surfacesLabel'), value: '2', copy: t('dashboard.metrics.surfacesCopy') },
])
</script>

<template>
  <section class="page">
    <header class="page-header">
      <p class="page-eyebrow">{{ t('dashboard.overview') }}</p>
      <h2>{{ t('dashboard.title') }}</h2>
      <p class="page-copy">{{ t('dashboard.copy') }}</p>
    </header>

    <div class="metric-grid">
      <article v-for="metric in metrics" :key="metric.label" class="metric">
        <p class="metric-label">{{ metric.label }}</p>
        <p class="metric-value">{{ metric.value }}</p>
        <p class="metric-copy">{{ metric.copy }}</p>
      </article>
    </div>

    <section class="page-grid">
      <article class="page-panel">
        <p class="page-eyebrow">{{ t('dashboard.buildEyebrow') }}</p>
        <h3>{{ t('dashboard.buildTitle') }}</h3>
        <p class="list-copy">{{ t('dashboard.buildCopy') }}</p>
      </article>
      <article class="page-panel">
        <p class="page-eyebrow">{{ t('dashboard.wildcardEyebrow') }}</p>
        <h3>{{ t('dashboard.wildcardTitle') }}</h3>
        <p class="list-copy">{{ t('dashboard.wildcardCopy') }}</p>
      </article>
    </section>
  </section>
</template>

<style scoped>
h3 {
  margin: 0.25rem 0 0.65rem;
  font-size: 1.35rem;
}
</style>
