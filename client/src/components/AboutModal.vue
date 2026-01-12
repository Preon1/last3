<script setup lang="ts">
import { watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useUiStore } from '../stores/ui'
import { useI18n } from 'vue-i18n'

const ui = useUiStore()
const { aboutOpen } = storeToRefs(ui)
const { t } = useI18n()

function onBackdropClick(e: MouseEvent) {
  if (e.target && e.target === e.currentTarget) ui.closeAbout()
}

function onEscape(e: KeyboardEvent) {
  if (e.key === 'Escape') ui.closeAbout()
}

watchEffect((onCleanup) => {
  if (!aboutOpen.value) return
  document.addEventListener('keydown', onEscape)
  onCleanup(() => document.removeEventListener('keydown', onEscape))
})
</script>

<template>
  <div v-if="aboutOpen" class="modal" role="dialog" aria-modal="true" aria-labelledby="aboutTitle" @click="onBackdropClick">
    <div class="modal-card">
      <div class="modal-title" id="aboutTitle">{{ t('about.title') }}</div>
      <div class="muted" v-html="t('about.description')"></div>
      <div class="modal-actions">
        <a href="https://github.com/Preon1/last3" target="_blank" rel="noopener noreferrer">{{ t('about.repoLink') }}</a>
        <button class="secondary" type="button" @click="ui.closeAbout">{{ t('common.close') }}</button>
      </div>
    </div>
  </div>
</template>
