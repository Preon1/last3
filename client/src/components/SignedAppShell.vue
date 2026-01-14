<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useSignedStore } from '../stores/signed'
import SignedAppHeader from './signedAppHeader.vue'
import SignedContactsPage from './SignedContactsPage.vue'
import SignedChatPanel from './SignedChatPanel.vue'
import SignedSettingsPage from './SignedSettingsPage.vue'
import SignedFloatingHeader from './SignedFloatingHeader.vue'
import CallBlobHost from './CallBlobHost.vue'

const signed = useSignedStore()
const { view } = storeToRefs(signed)
</script>

<template>
  <section class="app" :class="{ 'no-header': view !== 'contacts' }">
    <SignedAppHeader v-if="view === 'contacts'" />

    <SignedFloatingHeader />

    <CallBlobHost :mode="view === 'contacts' ? 'flow' : 'fixed'" />
    <div v-if="view === 'chat'" class="chat-top-fade" aria-hidden="true"></div>

    <div class="content">
      <SignedContactsPage v-if="view === 'contacts'" />
      <SignedChatPanel v-else-if="view === 'chat'" />
      <SignedSettingsPage v-else />
    </div>
  </section>
</template>
