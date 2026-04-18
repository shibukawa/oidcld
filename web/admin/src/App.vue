<script setup lang="ts">
import { RouterLink, RouterView, useRoute } from 'vue-router'
import githubIcon from './assets/GitHub_Invertocat_White_Clearspace.svg'

const route = useRoute()

const navigation = [
  {
    label: 'Certificate Authority',
    to: '/certificate-authority',
    eyebrow: 'Trust',
  },
  {
    label: 'OpenID Connect',
    to: '/openid-connect',
    eyebrow: 'OIDC',
  },
  {
    label: 'Reverse Proxy',
    to: '/reverse-proxy',
    eyebrow: 'Proxy',
  },
  {
    label: 'Traffic Logs',
    to: '/reverse-proxy/logs',
    eyebrow: 'Logs',
  },
]
</script>

<template>
  <div class="shell">
    <aside class="sidebar">
      <div class="sidebar-topbar">
        <div class="sidebar-orb sidebar-orb-muted"></div>
        <div class="sidebar-orb sidebar-orb-warm"></div>
        <div class="sidebar-orb sidebar-orb-bright"></div>
      </div>

      <div class="brand-block panel-sheen">
        <p class="eyebrow">OIDCLD</p>
        <h1>Developer Console</h1>
        <p class="lede">Local tools for trust and identity.</p>
      </div>

      <nav class="nav">
        <RouterLink
          v-for="item in navigation"
          :key="item.to"
          :to="item.to"
          class="nav-link"
          :class="{ 'nav-link-active': route.path === item.to }"
        >
          <p class="nav-eyebrow">{{ item.eyebrow }}</p>
          <p class="nav-label">{{ item.label }}</p>
        </RouterLink>
      </nav>

      <div class="sidebar-footer">
        <a
          class="sidebar-icon-link"
          href="https://github.com/shibukawa/oidcld"
          target="_blank"
          rel="noreferrer"
          aria-label="GitHub repository"
        >
          <img class="sidebar-icon" :src="githubIcon" alt="" />
        </a>
      </div>
    </aside>

    <main class="content">
      <RouterView />
    </main>
  </div>
</template>

<style scoped>
.nav-link-active {
  background: linear-gradient(135deg, #0f7c8b, #1559a5);
  border-color: rgba(186, 227, 255, 0.34);
  box-shadow: 0 24px 44px rgba(4, 16, 43, 0.3);
}

.nav-link-active .nav-eyebrow,
.nav-link-active .nav-label {
  color: #f5fbff;
}
</style>
