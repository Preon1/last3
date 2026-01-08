import { i18n } from '../i18n'

export function confirmLeave(appName = 'Last') {
  try {
    return window.confirm(String(i18n.global.t('confirm.leave', { appName })))
  } catch {
    return true
  }
}
