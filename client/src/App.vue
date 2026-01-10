<script setup lang="ts">
import { computed } from 'vue'
import { useSignedStore } from './stores/signed'
import SignedSetupScreen from './components/SignedSetupScreen.vue'
import SignedUnlockScreen from './components/SignedUnlockScreen.vue'
import SignedAppShell from './components/SignedAppShell.vue'
import AboutModal from './components/AboutModal.vue'
import ToastHost from './components/ToastHost.vue'
import { useWakeLock } from './utils/wakeLock'
import { useBeforeUnloadConfirm } from './utils/beforeUnloadConfirm'

const signed = useSignedStore()

const signedIn = computed(() => signed.signedIn)
const signedUnlocked = computed(() => Boolean(signed.privateKey))

async function onSignedLogin(v: { username: string; password: string }) {
  await signed.login(v)
}

async function onSignedRegister(v: { username: string; password: string; expirationDays: number; extraEntropy?: Uint8Array }) {
  await signed.register(v)
}

const inAnyApp = computed(() => Boolean(signedIn.value))
useWakeLock(inAnyApp)
useBeforeUnloadConfirm(inAnyApp)
</script>

<template>
  <main>
    <SignedSetupScreen v-if="!signedIn" @login="onSignedLogin" @register="onSignedRegister" />
    <SignedUnlockScreen v-else-if="signedIn && !signedUnlocked" @logout="() => signed.logout(true)" />
    <SignedAppShell v-else />

    <ToastHost />

    <AboutModal />
  </main>
</template>
