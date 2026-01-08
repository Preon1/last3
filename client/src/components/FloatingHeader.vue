<script setup lang="ts">
import { storeToRefs } from 'pinia'
import { useUiStore } from '../stores/ui'
import { useI18n } from 'vue-i18n'
import ChatTopBar from './ChatTopBar.vue'
import SettingsTopBar from './SettingsTopBar.vue'
import ChatCallButton from './ChatCallButton.vue'

const ui = useUiStore()
const { view, otherPrivateChatsUnread } = storeToRefs(ui)
const { t } = useI18n()
</script>

<template>
  <div class="floating-header" v-if="view !== 'contacts'">
    <button
      class="secondary icon-only"
      type="button"
      :aria-label="String(t('common.back'))"
      @click="ui.goHome"
    >
      <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#bracket-left"></use></svg>
    </button>
    
    <div
      v-if="view === 'chat' && otherPrivateChatsUnread > 0"
      class="floating-unread-badge"
      :aria-label="String(t('common.unreadMessages', { count: otherPrivateChatsUnread }))"
    >
      {{ otherPrivateChatsUnread }}
    </div>

    <ChatTopBar v-if="view === 'chat'" />
    <SettingsTopBar v-else />

    <ChatCallButton v-if="view === 'chat'" />
  </div>
</template>
