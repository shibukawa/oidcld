import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  base: '/console/',
  plugins: [vue(), tailwindcss()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/console/api': {
        target: process.env.OIDCLD_ADMIN_PROXY_TARGET ?? 'http://127.0.0.1:18889',
        changeOrigin: false,
      },
    },
  },
})