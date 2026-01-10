<script setup lang="ts">
import { computed, ref, watch, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useSessionStore } from './stores/session'
import { useSignedStore } from './stores/signed'
import { useNotificationsStore } from './stores/notifications'
import { useUiStore } from './stores/ui'
import { useCallStore } from './stores/call'
import SetupScreen from './components/SetupScreen.vue'
import SignedSetupScreen from './components/SignedSetupScreen.vue'
import SignedUnlockScreen from './components/SignedUnlockScreen.vue'
import AppShell from './components/AppShell.vue'
import SignedAppShell from './components/SignedAppShell.vue'
import AboutModal from './components/AboutModal.vue'
import ToastHost from './components/ToastHost.vue'
import NotificationsPrompt from './components/NotificationsPrompt.vue'
import { useWakeLock } from './utils/wakeLock'
import { useBeforeUnloadConfirm } from './utils/beforeUnloadConfirm'

const session = useSessionStore()
const signed = useSignedStore()
const notifications = useNotificationsStore()
const ui = useUiStore()
const call = useCallStore()
const { inApp, status } = storeToRefs(session)
const signedIn = computed(() => signed.signedIn)
const signedUnlocked = computed(() => Boolean(signed.privateKey))

// Signed-only UI: legacy unsigned mode remains in the codebase for now,
// but we no longer expose it in the login/setup screen.
const setupMode = ref<'unsigned' | 'signed'>('signed')

const didShowNotificationsPromptThisLogin = ref(false)

const { permission, supported } = storeToRefs(notifications)
const showNotificationsPrompt = computed(() => {
  if (!inApp.value) return false
  if (!session.connected) return false
  if (!supported.value) return false
  if (permission.value !== 'default') return false
  return !didShowNotificationsPromptThisLogin.value
})

function dismissNotificationsPrompt() {
  didShowNotificationsPromptThisLogin.value = true
}

function onJoin(name: string) {
  // Important for iOS/Safari: unlock audio on user gesture.
  call.primeAudio()
  session.connect(name)
}

async function onSignedLogin(v: { username: string; password: string }) {
  await signed.login(v)
}

async function onSignedRegister(v: { username: string; password: string; expirationDays: number; extraEntropy?: Uint8Array }) {
  await signed.register(v)
}

const inAnyApp = computed(() => Boolean(inApp.value || signedIn.value))
useWakeLock(inAnyApp)
useBeforeUnloadConfirm(inAnyApp)

watchEffect(() => {
  if (!inApp.value) return
  if (!session.connected) return
  notifications.autoRequestAfterLogin()
})

watch(
  inApp,
  (next, prev) => {
    if (next && !prev) ui.goHome()
    if (next && !prev) didShowNotificationsPromptThisLogin.value = false
  },
  { flush: 'post' },
)
</script>

<template>
  <main>
    <template v-if="!inApp && !signedIn">
      <SetupScreen v-if="setupMode === 'unsigned'" :status="status" @join="onJoin" />
      <SignedSetupScreen
        v-else
        @login="onSignedLogin"
        @register="onSignedRegister"
      />
    </template>

    <SignedUnlockScreen v-else-if="signedIn && !signedUnlocked" @logout="() => signed.logout(true)" />
    <SignedAppShell v-else-if="signedIn" />
    <AppShell v-else />

    <NotificationsPrompt :open="showNotificationsPrompt" @dismiss="dismissNotificationsPrompt" />

    <ToastHost />

    <AboutModal />
  </main>
</template>
