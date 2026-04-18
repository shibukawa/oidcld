<script setup lang="ts">
const downloads = [
  { tag: 'Root CA', title: 'root-ca.pem', copy: 'Download the persisted root certificate for local trust installation.', href: '/console/api/downloads/root-ca.pem', action: 'Download PEM' },
  { tag: 'macOS / Linux', title: 'install.sh', copy: 'Install the root CA into the OS trust store with a single script.', href: '/console/api/downloads/install.sh', action: 'Download script' },
  { tag: 'Windows', title: 'install.ps1', copy: 'Install the root CA into the Windows certificate store.', href: '/console/api/downloads/install.ps1', action: 'Download script' },
  { tag: 'Cleanup', title: 'uninstall scripts', copy: 'Remove previously installed root certificates cleanly from the supported OS store.', href: '/console/api/downloads/uninstall.sh', action: 'Download shell uninstall' },
  { tag: 'Cleanup', title: 'uninstall.ps1', copy: 'Remove the root CA from the Windows certificate store.', href: '/console/api/downloads/uninstall.ps1', action: 'Download PowerShell uninstall' },
]
</script>

<template>
  <section class="page">
    <header class="page-header">
      <p class="page-eyebrow">Downloads</p>
      <h2>Trust distribution</h2>
      <p class="page-copy">The first concrete operator workflow is certificate distribution. These cards are wired to the endpoints that will expose the root CA and the install / uninstall helpers.</p>
    </header>

    <div class="downloads-grid">
      <article v-for="item in downloads" :key="item.title" class="download-card">
        <p class="download-tag">{{ item.tag }}</p>
        <p class="download-title">{{ item.title }}</p>
        <p class="download-copy">{{ item.copy }}</p>
        <a class="download-action" :href="item.href">{{ item.action }}</a>
      </article>
    </div>
  </section>
</template>