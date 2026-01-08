<script setup lang="ts">
import AppHeader from './AppHeader.vue'
import ChatPanel from './ChatPanel.vue'
import { useUiStore } from '../stores/ui'
import { storeToRefs } from 'pinia'
import ContactsPage from './ContactsPage.vue'
import SettingsPage from './SettingsPage.vue'
import FloatingHeader from './FloatingHeader.vue'
import CallBlobHost from './CallBlobHost.vue'

const ui = useUiStore()
const { view } = storeToRefs(ui)
</script>

<template>
  <section class="app" :class="{ 'no-header': view !== 'contacts' }">
    <AppHeader v-if="view === 'contacts'" />

    <FloatingHeader />
    <CallBlobHost :mode="view === 'contacts' ? 'flow' : 'fixed'" />
    <div v-if="view === 'chat'" class="chat-top-fade" aria-hidden="true"></div>

    <div class="content">
      <ContactsPage v-if="view === 'contacts'" />
      <ChatPanel v-else-if="view === 'chat'" />
      <SettingsPage v-else />
    </div>
  </section>
</template>
