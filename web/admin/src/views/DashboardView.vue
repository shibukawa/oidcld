<script setup lang="ts">
const metrics = [
  { label: 'Managed modules', value: '4', copy: 'Dashboard, Certificates, Downloads, and System Status are reserved from the start.' },
  { label: 'TLS modes', value: '3', copy: 'Manual TLS, ACME, and managed self-signed TLS are now treated as explicit modes.' },
  { label: 'Runtime surfaces', value: '2', copy: 'OpenID Connect stays on the main listener while the Developer Console also carries local-only HTTP metadata support.' },
]
</script>

<template>
  <section class="page">
    <header class="page-header">
      <p class="page-eyebrow">Overview</p>
      <h2>Management starts with certificates, not ends there.</h2>
      <p class="page-copy">This console is shaped as a control surface for future modules. The current build focuses on local-development trust management and keeps room for proxy and settings workflows.</p>
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
        <p class="page-eyebrow">Current build</p>
        <h3>Developer Console foundation</h3>
        <p class="list-copy">The Vue app, config model, and init entry points are being laid out first so later backend integration does not have to redesign the UI shell.</p>
      </article>
      <article class="page-panel">
        <p class="page-eyebrow">Wildcard policy</p>
        <h3>Fixed suffix scope</h3>
        <p class="list-copy">Unknown domains are intentionally limited to the configured wildcard suffix. Arbitrary on-demand SAN issuance is not part of the first phase.</p>
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