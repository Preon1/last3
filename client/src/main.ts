import { createApp } from 'vue'
import { createPinia } from 'pinia'
import './style.css'
import App from './App.vue'
import { i18n } from './i18n'
import { useAuthStore } from './stores/auth'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia).use(i18n).mount('#app')

// PWA resume handling: iOS can restore the app from memory without a cold reload.
// Ensure we refresh chats/presence when the app becomes visible again.
try {
	if (typeof window !== 'undefined') {
		const w = window as any
		if (!w.__lrcomResumeSyncInstalled) {
			w.__lrcomResumeSyncInstalled = true
			const authStore = useAuthStore(pinia)

			const trigger = (reason: string) => {
				try {
					authStore.bestEffortResumeSync(reason)
				} catch {
					// ignore
				}
			}

			document.addEventListener('visibilitychange', () => {
				if (document.visibilityState === 'visible') trigger('visibility')
			})

			window.addEventListener('pageshow', (e) => {
				trigger((e as any)?.persisted ? 'pageshow_bfcache' : 'pageshow')
			})

			window.addEventListener('focus', () => {
				trigger('focus')
			})

			// Also run once shortly after startup.
			window.setTimeout(() => trigger('startup'), 500)
		}
	}
} catch {
	// ignore
}
