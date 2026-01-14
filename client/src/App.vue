<script setup lang="ts">
import { computed } from 'vue'
import { useSignedStore } from './stores/signed'
import SignedSetupScreen from './components/SignedSetupScreen.vue'
import SignedAppShell from './components/SignedAppShell.vue'
import AboutModal from './components/AboutModal.vue'
import ManageKeysModal from './components/ManageKeysModal.vue'
import ShareLinkModal from './components/ShareLinkModal.vue'
import ScanQrModal from './components/ScanQrModal.vue'
import ToastHost from './components/ToastHost.vue'
import { useWakeLock } from './utils/wakeLock'
import { useBeforeUnloadConfirm } from './utils/beforeUnloadConfirm'
import { useToastStore } from './stores/toast'

const signed = useSignedStore()
const toast = useToastStore()

const signedIn = computed(() => signed.signedIn)
const signedReady = computed(() => Boolean(signedIn.value && signed.privateKey))
const restoring = computed(() => Boolean(signed.restoring))

const inAnyApp = computed(() => Boolean(signedReady.value))
useWakeLock(inAnyApp)
useBeforeUnloadConfirm(inAnyApp)

// Handle POSTed .json key files from Web Share Target
// Web Share Target API: handle POSTed .json key files
if (typeof window !== 'undefined' && typeof (window as any).launchQueue !== 'undefined') {
  // Types for launchQueue and LaunchParams
  interface LaunchQueueFile {
    kind: 'file';
    getFile(): Promise<File>;
    name?: string;
    type?: string;
  }
  interface LaunchParams {
    files?: LaunchQueueFile[];
  }
  ((window as any).launchQueue as { setConsumer: (cb: (params: LaunchParams) => void) => void }).setConsumer(
    async (launchParams: LaunchParams) => {
      if (!launchParams.files || !launchParams.files.length) return
      for (const fileHandle of launchParams.files) {
        try {
          if (fileHandle.kind === 'file') {
            const file = await fileHandle.getFile()
            if (file.type === 'application/json' || (file.name && file.name.endsWith('.json'))) {
              const text = await file.text()
              let parsed
              try {
                parsed = JSON.parse(text)
              } catch {
                toast.error('Invalid JSON', 'The shared file is not valid JSON.')
                continue
              }
              // Validate keys format: expect array of objects with encryptedUsername & encryptedPrivateKey
              if (Array.isArray(parsed) && parsed.every(k => k && typeof k.encryptedUsername === 'string' && typeof k.encryptedPrivateKey === 'string')) {
                // Merge with existing keys
                let existing = []
                try {
                  existing = JSON.parse(localStorage.getItem('lrcom-signed-keys') || '[]')
                } catch {}
                const merged = [...existing]
                let added = 0
                for (const k of parsed) {
                  if (!merged.some(e => e.encryptedUsername === k.encryptedUsername && e.encryptedPrivateKey === k.encryptedPrivateKey)) {
                    merged.push(k)
                    added++
                  }
                }
                localStorage.setItem('lrcom-signed-keys', JSON.stringify(merged))
                if (added > 0) {
                  toast.push({ title: 'Keys Imported', message: `${added} new key(s) added.`, variant: 'info', timeoutMs: 6000 })
                } else {
                  toast.push({ title: 'No New Keys', message: 'All keys were already present.', variant: 'info', timeoutMs: 6000 })
                }
              } else {
                toast.error('Invalid Key Format', 'JSON must be an array of key objects.')
              }
            }
          }
        } catch (err) {
          toast.error('Import Failed', err instanceof Error ? err.message : String(err))
        }
      }
    }
  )
}
</script>

<template>
  <main>
    <div v-if="restoring" class="restoring">
      <div class="restoring-card">Restoring session…</div>
    </div>
    <SignedSetupScreen v-else-if="!signedIn" />
    <SignedAppShell v-else />

    <ToastHost />

    <AboutModal />
    <ManageKeysModal />
    <ShareLinkModal />
    <ScanQrModal />
  </main>
</template>

<style scoped>
.restoring {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
}

.restoring-card {
  padding: 16px 18px;
  border-radius: 12px;
  background: rgba(0, 0, 0, 0.08);
  color: inherit;
  font-size: 14px;
}
</style>
