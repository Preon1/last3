<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useAuthStore } from '../stores/auth'
import AuthAppHeader from './AuthAppHeader.vue'
import AuthContactsPage from './AuthContactsPage.vue'
import AuthChatPanel from './AuthChatPanel.vue'
import AuthSettingsPage from './AuthSettingsPage.vue'
import AuthFloatingHeader from './AuthFloatingHeader.vue'
import CallBlobHost from './CallBlobHost.vue'

const authStore = useAuthStore()
const { view } = storeToRefs(authStore)
</script>

<template>
  <section class="app" :class="{ 'no-header': view !== 'contacts' }">
    <AuthAppHeader v-if="view === 'contacts'" />

    <AuthFloatingHeader />

    <CallBlobHost :mode="view === 'contacts' ? 'flow' : 'fixed'" />
    <div v-if="view === 'chat'" class="chat-top-fade" aria-hidden="true"></div>

    <div class="content">
      <AuthContactsPage v-if="view === 'contacts'" />
      <AuthChatPanel v-else-if="view === 'chat'" />
      <AuthSettingsPage v-else />
    </div>
  </section>
</template>
