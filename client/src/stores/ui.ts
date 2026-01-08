import { defineStore } from 'pinia'
import { computed, ref, watch } from 'vue'
import { i18n } from '../i18n'

export const useUiStore = defineStore('ui', () => {
  const view = ref<'contacts' | 'chat' | 'settings'>('contacts')

  const aboutOpen = ref(false)

  const themeMode = ref<'system' | 'dark' | 'light'>('system')

  const replyToId = ref<string | null>(null)

  // Chat selection: null means "Public chat", otherwise the peer's display name.
  const activeChatName = ref<string | null>(null)
  const unreadByChat = ref<Record<string, number>>({})

  const activeChatLabel = computed(() => {
    // Ensure this recomputes when locale changes.
    void i18n.global.locale.value
    return activeChatName.value ?? String(i18n.global.t('sidebar.groupChat'))
  })

  const otherPrivateChatsUnread = computed(() => {
    let count = 0
    for (const [key, unread] of Object.entries(unreadByChat.value)) {
      // Skip public chat (group)
      if (key === 'group') continue
      // Skip current chat
      if (key === chatKey(activeChatName.value)) continue
      // Only count private chats (keys starting with 'u:')
      if (key.startsWith('u:')) {
        count += unread
      }
    }
    return count
  })

  function isViewingChat(name: string | null) {
    if (view.value !== 'chat') return false
    return (activeChatName.value ?? null) === (name ?? null)
  }

  function chatKey(name: string | null) {
    return name ? `u:${name}` : 'group'
  }

  function getUnread(name: string | null) {
    return unreadByChat.value[chatKey(name)] ?? 0
  }

  function clearUnread(name: string | null) {
    const key = chatKey(name)
    if (!unreadByChat.value[key]) return
    unreadByChat.value = { ...unreadByChat.value, [key]: 0 }
  }

  function bumpUnread(name: string | null) {
    const key = chatKey(name)
    const cur = unreadByChat.value[key] ?? 0
    unreadByChat.value = { ...unreadByChat.value, [key]: cur + 1 }
  }

  function openChat(name: string | null) {
    activeChatName.value = name
    view.value = 'chat'
    clearUnread(name)
  }

  function goHome() {
    view.value = 'contacts'
    clearReply()
  }

  function resetChats() {
    activeChatName.value = null
    unreadByChat.value = {}
    view.value = 'contacts'
  }

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

  function openSettings() {
    view.value = 'settings'
  }

  function openAbout() {
    aboutOpen.value = true
  }

  function closeAbout() {
    aboutOpen.value = false
  }

  function setReplyTo(id: string) {
    replyToId.value = id
  }

  function clearReply() {
    replyToId.value = null
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
    view,
    aboutOpen,
    themeMode,
    themeLabel,
    cycleTheme,
    replyToId,
    activeChatName,
    activeChatLabel,
    otherPrivateChatsUnread,
    isViewingChat,
    openChat,
    goHome,
    resetChats,
    getUnread,
    bumpUnread,
    clearUnread,
    openSettings,
    openAbout,
    closeAbout,
    setReplyTo,
    clearReply,
  }
})
