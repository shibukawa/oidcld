<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const downloads = computed(() => [
  { tag: t('downloads.rootTag'), title: t('downloads.rootTitle'), copy: t('downloads.rootCopy'), href: '/console/api/downloads/root-ca.pem', action: t('downloads.downloadPem') },
  { tag: t('downloads.macTag'), title: t('downloads.macTitle'), copy: t('downloads.macCopy'), href: '/console/api/downloads/install.sh', action: t('downloads.downloadScript') },
  { tag: t('downloads.windowsTag'), title: t('downloads.windowsTitle'), copy: t('downloads.windowsCopy'), href: '/console/api/downloads/install.ps1', action: t('downloads.downloadScript') },
  { tag: t('downloads.cleanupTag'), title: t('downloads.uninstallShTitle'), copy: t('downloads.uninstallShCopy'), href: '/console/api/downloads/uninstall.sh', action: t('downloads.downloadShellUninstall') },
  { tag: t('downloads.cleanupTag'), title: t('downloads.uninstallPsTitle'), copy: t('downloads.uninstallPsCopy'), href: '/console/api/downloads/uninstall.ps1', action: t('downloads.downloadPsUninstall') },
])
</script>

<template>
  <section class="page">
    <header class="page-header">
      <p class="page-eyebrow">{{ t('downloads.eyebrow') }}</p>
      <h2>{{ t('downloads.title') }}</h2>
      <p class="page-copy">{{ t('downloads.copy') }}</p>
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
