<script setup lang="ts">
import { computed, watchEffect } from 'vue'
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

const signed = useSignedStore()

const signedIn = computed(() => signed.signedIn)
const signedUnlocked = computed(() => Boolean(signed.privateKey))
const signedReady = computed(() => Boolean(signedIn.value && signedUnlocked.value))

// If the page refreshes, we may restore token+user from sessionStorage but the
// private key is intentionally not persisted. Without an unlock screen, clear
// the session token and return to the setup/login screen (keeping lastUsername).
watchEffect(() => {
  if (signedIn.value && !signedUnlocked.value) {
    try {
      signed.logout(false)
    } catch {
      // ignore
    }
  }
})

const inAnyApp = computed(() => Boolean(signedReady.value))
useWakeLock(inAnyApp)
useBeforeUnloadConfirm(inAnyApp)
</script>

<template>
  <main>
    <SignedSetupScreen v-if="!signedReady" />
    <SignedAppShell v-else />

    <ToastHost />

    <AboutModal />
    <ManageKeysModal />
    <ShareLinkModal />
    <ScanQrModal />
  </main>
</template>
