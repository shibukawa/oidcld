import { createRouter, createWebHistory } from 'vue-router'
import CertificateAuthorityView from './views/CertificateAuthorityView.vue'
import OpenIDConnectView from './views/OpenIDConnectView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    { path: '/', redirect: '/certificate-authority' },
    { path: '/certificate-authority', name: 'certificate-authority', component: CertificateAuthorityView },
    { path: '/openid-connect', name: 'openid-connect', component: OpenIDConnectView },
    { path: '/dashboard', redirect: '/openid-connect' },
    { path: '/status', redirect: '/openid-connect' },
    { path: '/certificates', redirect: '/certificate-authority' },
    { path: '/downloads', redirect: '/certificate-authority' },
  ],
})

export default router