import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // loadEnv works in both dev and build and doesn't require node typings
  const env = loadEnv(mode, '.', '')
  const VITE_OIDC_AUTHORITY = env.VITE_OIDC_AUTHORITY || 'https://localhost:18888'

  return {
    plugins: [react(), tailwindcss()],
    define: {
      'import.meta.env.VITE_OIDC_AUTHORITY': JSON.stringify(VITE_OIDC_AUTHORITY),
    },
  }
})
