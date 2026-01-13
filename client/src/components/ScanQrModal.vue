<script setup lang="ts">
import { ref, watchEffect } from 'vue'
import { storeToRefs } from 'pinia'
import { useI18n } from 'vue-i18n'
import { useUiStore } from '../stores/ui'
import { useSignedStore } from '../stores/signed'
import { useToastStore } from '../stores/toast'
import type { IScannerControls } from '@zxing/browser'

const ui = useUiStore()
const signed = useSignedStore()
const toast = useToastStore()
const { t } = useI18n()

const { scanQrOpen } = storeToRefs(ui)

const videoEl = ref<HTMLVideoElement | null>(null)
const status = ref<string>('')
const busy = ref(false)

let reader: any | null = null
let controls: IScannerControls | null = null
let scanSession = 0
let lastText = ''

function parseInviteUsernameFromQrText(raw: string): string | null {
  const text = String(raw ?? '').trim()
  if (!text) return null

  let u: URL
  try {
    u = new URL(text)
  } catch {
    return null
  }

  // Strict: must be same-origin and root-path invite: <origin>/?add=<username>
  if (u.origin !== window.location.origin) return null
  if (u.pathname !== '/') return null
  if (u.hash) return null

  const addValues = u.searchParams.getAll('add')
  if (addValues.length !== 1) return null

  for (const k of u.searchParams.keys()) {
    if (k !== 'add') return null
  }

  const username = String(addValues[0] ?? '').trim()
  if (username.length < 3 || username.length > 64) return null

  return username
}

function onBackdropClick(e: MouseEvent) {
  if (e.target && e.target === e.currentTarget) ui.closeScanQr()
}

function onKeyDown(e: KeyboardEvent) {
  if (!scanQrOpen.value) return
  if (e.key === 'Escape') ui.closeScanQr()
}

async function stopScanning(invalidate = true) {
  if (invalidate) scanSession++

  try {
    controls?.stop()
  } catch {
    // ignore
  }
  controls = null

  try {
    // Some versions expose reset(); harmless if missing.
    ;(reader as any)?.reset?.()
  } catch {
    // ignore
  }
  reader = null

  lastText = ''
}

async function startScanning() {
  const localSession = ++scanSession

  status.value = ''
  busy.value = false
  lastText = ''

  await stopScanning(false)

  const el = videoEl.value
  if (!el) return

  if (!navigator.mediaDevices?.getUserMedia) {
    status.value = String(t('scanQr.cameraUnavailable'))
    return
  }

  const { BrowserMultiFormatReader } = await import('@zxing/browser')
  reader = new BrowserMultiFormatReader()

  try {
    controls = await reader.decodeFromVideoDevice(undefined, el, async (result: any) => {
      if (localSession !== scanSession) return
      if (!scanQrOpen.value) return
      if (!result) return

      const text = String(result.getText?.() ?? '')
      if (!text) return

      // Avoid hammering if the camera keeps seeing the same QR.
      if (text === lastText) return
      lastText = text

      const inviteUsername = parseInviteUsernameFromQrText(text)
      if (!inviteUsername) {
        status.value = String(t('scanQr.invalidInvite'))
        return
      }

      if (busy.value) return
      busy.value = true

      try {
        await stopScanning()
        await signed.createPersonalChat(inviteUsername)
        ui.closeScanQr()
      } catch (e: any) {
        const msg = typeof e?.message === 'string' ? e.message : String(t('signed.genericError'))
        if (msg === 'self') {
          status.value = String(t('signed.cannotChatWithSelf'))
        } else {
          const isIntrovert = msg === 'introvert' || msg.toLowerCase().includes('introvert mode')
          if (isIntrovert) {
            toast.error(String(t('toast.introvertTitle')), msg === 'introvert' ? String(t('toast.introvertBody')) : msg)
          } else {
            toast.error(String(t('scanQr.addFailedTitle')), msg)
          }
        }

        // If still open, resume scanning.
        if (scanQrOpen.value) {
          busy.value = false
          void startScanning()
        }
      } finally {
        busy.value = false
      }
    })

    try {
      // Some browsers require an explicit play attempt.
      await el.play()
    } catch {
      // ignore
    }
  } catch (e: any) {
    const name = typeof e?.name === 'string' ? e.name : ''
    const msg = typeof e?.message === 'string' ? e.message : ''

    if (name === 'NotAllowedError' || msg.toLowerCase().includes('permission')) {
      status.value = String(t('scanQr.cameraPermissionDenied'))
    } else if (name === 'NotFoundError') {
      status.value = String(t('scanQr.cameraUnavailable'))
    } else {
      status.value = String(t('scanQr.cameraStartFailed'))
    }

    await stopScanning()
  }
}

watchEffect((onCleanup) => {
  if (!scanQrOpen.value) {
    void stopScanning()
    return
  }

  document.addEventListener('keydown', onKeyDown)
  void startScanning()

  onCleanup(() => {
    document.removeEventListener('keydown', onKeyDown)
    void stopScanning()
  })
})
</script>

<template>
  <div v-if="scanQrOpen" class="modal" role="dialog" aria-modal="true" aria-labelledby="scanQrTitle" @click="onBackdropClick">
    <div class="modal-card" style="max-width: 520px;">
      <div class="modal-title" id="scanQrTitle">{{ t('common.scanQr') }}</div>

      <div class="muted" style="margin-top: 8px; white-space: pre-line;">{{ t('scanQr.hint') }}</div>

      <div style="margin-top: 14px; border-radius: 14px; overflow: hidden; background: #000;">
        <video
          ref="videoEl"
          autoplay
          playsinline
          muted
          style="width: 100%; height: 320px; object-fit: cover; display: block;"
        ></video>
      </div>

      <div v-if="status" class="status" aria-live="polite" style="margin-top: 12px;">{{ status }}</div>

      <div class="modal-actions" style="margin-top: 16px;">
        <button class="secondary" type="button" :disabled="busy" @click="ui.closeScanQr">{{ t('common.close') }}</button>
      </div>
    </div>
  </div>
</template>
