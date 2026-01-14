import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { i18n } from '../i18n'
import { LocalEntity, localData } from '../utils/localData'

export const useUiStore = defineStore('ui', () => {
  const aboutOpen = ref(false)
  const manageKeysOpen = ref(false)
  const shareLinkOpen = ref(false)
  const scanQrOpen = ref(false)

  const themeMode = ref<'system' | 'dark' | 'light'>('system')

  const themeLabel = computed(() => {
    // Ensure this recomputes when locale changes.
    void i18n.global.locale.value
    const mode = themeMode.value
    const modeKey = mode === 'system' ? 'theme.system' : mode === 'dark' ? 'theme.dark' : 'theme.light'
    return String(i18n.global.t('theme.label', { mode: i18n.global.t(modeKey) }))
  })

  function applyTheme() {
    try {
      if (themeMode.value === 'system') {
        document.documentElement.removeAttribute('data-theme')
      } else {
        document.documentElement.setAttribute('data-theme', themeMode.value)
      }
    } catch {
      // ignore
    }
  }

  function loadTheme() {
    const raw = localData.getString(LocalEntity.UiTheme)
    if (raw === 'dark' || raw === 'light' || raw === 'system') themeMode.value = raw
    applyTheme()
  }

  function cycleTheme() {
    themeMode.value = themeMode.value === 'system' ? 'dark' : themeMode.value === 'dark' ? 'light' : 'system'
  }

  function openAbout() {
    aboutOpen.value = true
  }

  function closeAbout() {
    aboutOpen.value = false
  }

  function openManageKeys() {
    manageKeysOpen.value = true
  }

  function closeManageKeys() {
    manageKeysOpen.value = false
  }

  function openShareLink() {
    shareLinkOpen.value = true
  }

  function closeShareLink() {
    shareLinkOpen.value = false
  }

  function openScanQr() {
    scanQrOpen.value = true
  }

  function closeScanQr() {
    scanQrOpen.value = false
  }

  // Initialize + persist theme.
  loadTheme()
  watch(
    themeMode,
    (v) => {
      localData.setString(LocalEntity.UiTheme, v)
      applyTheme()
    },
    { flush: 'post' },
  )

  return {
    aboutOpen,
    manageKeysOpen,
    shareLinkOpen,
    scanQrOpen,
    themeMode,
    themeLabel,
    cycleTheme,
    openAbout,
    closeAbout,
    openManageKeys,
    closeManageKeys,
    openShareLink,
    closeShareLink,
    openScanQr,
    closeScanQr,
  }
})
