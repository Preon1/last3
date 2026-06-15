import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  resolve: {
    // Ensure we prefer the ESM export conditions over the package's default (CJS)
    // so browser builds don't pull in Node-only shims.
    conditions: ['import', 'module', 'browser', 'default'],
    alias: {
      // Node built-in shim: prevents Vite's "crypto externalized" warning.
      crypto: '/src/shims/nodeCrypto.ts',

      // @cloudflare/voprf-ts defaults to its SJCL backend via an internal
      // buildSettings module. SJCL includes a Node-only `require('crypto')`
      // branch that Vite warns about in browser builds.
      //
      // We force the default provider to noble for the client bundle.
      '@cloudflare/voprf-ts/lib/esm/src/buildSettings.js': '/src/shims/voprfBuildSettings.ts',
      // Defensive: if anything resolves to the CJS path, shim it too.
      '@cloudflare/voprf-ts/lib/cjs/src/buildSettings.js': '/src/shims/voprfBuildSettings.ts',
    },
  },
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
    },
  },
})
