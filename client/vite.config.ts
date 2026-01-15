import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  // Reduce noise in dev/CI; override with VITE_LOG_LEVEL=info|warn|error|silent
  //logLevel: (process.env.VITE_LOG_LEVEL as any) || 'silent',
  server: {
    proxy: {
      // Default backend when running via docker compose.
      // (Self-signed cert in dev: secure=false.)
      '/api': {
        target: process.env.VITE_BACKEND_TARGET ?? 'https://localhost:8443',
        changeOrigin: true,
        secure: false,
      },
      '/turn': {
        target: process.env.VITE_BACKEND_TARGET ?? 'https://localhost:8443',
        changeOrigin: true,
        secure: false,
      },
      '/healthz': {
        target: process.env.VITE_BACKEND_TARGET ?? 'https://localhost:8443',
        changeOrigin: true,
        secure: false,
      },

      // The backend WebSocket server listens on the root path ('/').
      // In dev we expose it as '/ws' so Vite can proxy it cleanly.
      '/ws': {
        target: (process.env.VITE_BACKEND_TARGET ?? 'https://localhost:8443').replace(/^http/, 'ws'),
        ws: true,
        changeOrigin: true,
        secure: false,
        rewrite: (p) => p.replace(/^\/ws/, ''),
      },
    },
  },
})
