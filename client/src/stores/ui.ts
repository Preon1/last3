import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { i18n } from '../i18n'

export const useUiStore = defineStore('ui', () => {
  const aboutOpen = ref(false)

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
    try {
      const raw = sessionStorage.getItem('lrcom-theme')
      if (raw === 'dark' || raw === 'light' || raw === 'system') {
        themeMode.value = raw
      }
    } catch {
      // ignore
    }
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

  // Initialize + persist theme.
  loadTheme()
  watch(
    themeMode,
    (v) => {
      try {
        sessionStorage.setItem('lrcom-theme', v)
      } catch {
        // ignore
      }
      applyTheme()
    },
    { flush: 'post' },
  )

  return {
    aboutOpen,
    themeMode,
    themeLabel,
    cycleTheme,
    openAbout,
    closeAbout,
  }
})
