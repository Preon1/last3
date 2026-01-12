<script setup lang="ts">
import { computed, ref, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useUiStore } from '../stores/ui'
import { useSignedStore } from '../stores/signed'
import { useToastStore } from '../stores/toast'
import QRCode from 'qrcode'

const ui = useUiStore()
const signed = useSignedStore()
const toast = useToastStore()
const { t } = useI18n()

const { shareLinkOpen } = storeToRefs(ui)
const { username } = storeToRefs(signed)

const link = computed(() => {
  const u = String(username.value ?? '').trim()
  if (!u) return ''
  return `${window.location.origin}/?add=${encodeURIComponent(u)}`
})

const qrDataUrl = ref<string>('')

watchEffect(async () => {
  if (!shareLinkOpen.value) {
    qrDataUrl.value = ''
    return
  }

  const l = link.value
  if (!l) {
    qrDataUrl.value = ''
    return
  }

  try {
    qrDataUrl.value = await QRCode.toDataURL(l, { width: 256, margin: 1 })
  } catch {
    qrDataUrl.value = ''
  }
})

function onBackdropClick(e: MouseEvent) {
  if (e.target && e.target === e.currentTarget) ui.closeShareLink()
}

function onKeyDown(e: KeyboardEvent) {
  if (!shareLinkOpen.value) return
  if (e.key === 'Escape') ui.closeShareLink()
}

watchEffect((onCleanup) => {
  if (!shareLinkOpen.value) return
  document.addEventListener('keydown', onKeyDown)
  onCleanup(() => document.removeEventListener('keydown', onKeyDown))
})

async function copyLink() {
  const l = link.value
  if (!l) return

  try {
    await navigator.clipboard.writeText(l)
    toast.push({ title: String(t('toast.copiedTitle')), message: String(t('toast.copiedBody')), variant: 'info', timeoutMs: 2000 })
  } catch {
    toast.error(String(t('toast.copyFailedTitle')), String(t('toast.copyFailedBody')))
  }
}
</script>

<template>
  <div v-if="shareLinkOpen" class="modal" role="dialog" aria-modal="true" aria-labelledby="shareLinkTitle" @click="onBackdropClick">
    <div class="modal-card" style="max-width: 420px;">
      <div class="modal-title" id="shareLinkTitle">{{ t('common.shareLink') }}</div>

      <div class="muted" style="margin-top: 8px; white-space: pre-line;">{{ t('shareLink.hint') }}</div>

      <div v-if="qrDataUrl" style="display:flex; justify-content:center; margin-top: 14px;">
        <img :src="qrDataUrl" alt="QR" style="width: 256px; height: 256px; border-radius: 14px; background: #fff; padding: 10px;" />
      </div>

      <label class="field" style="margin-top: 14px;">
        <span class="field-label">{{ t('shareLink.linkLabel') }}</span>
        <input :value="link" readonly />
      </label>

      <div class="modal-actions" style="margin-top: 16px;">
        <button class="secondary" type="button" @click="ui.closeShareLink">{{ t('common.close') }}</button>
        <button class="secondary" type="button" :disabled="!link" @click="copyLink">{{ t('common.copy') }}</button>
      </div>
    </div>
  </div>
</template>
