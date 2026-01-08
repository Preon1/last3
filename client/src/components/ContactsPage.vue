<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useSessionStore } from '../stores/session'
import { useUiStore } from '../stores/ui'
import { useI18n } from 'vue-i18n'

const session = useSessionStore()
const ui = useUiStore()
const { t } = useI18n()

const { users, myId } = storeToRefs(session)
const { activeChatName } = storeToRefs(ui)

const visibleUsers = computed(() => {
  const mine = myId.value
  return (mine ? users.value.filter((u) => u.id !== mine) : users.value).filter((u) => Boolean(u.name))
})

function onOpenPublic() {
  ui.openChat(null)
}

function onOpenUser(name: string) {
  ui.openChat(name)
}

function isActive(name: string | null) {
  return (activeChatName.value ?? null) === (name ?? null)
}
</script>

<template>
  <section class="page">
    <div class="page-inner">
      <ul class="contacts">
        <li>
          <button class="contact-row" type="button" :class="{ active: isActive(null) }" @click="onOpenPublic">
            <span class="name">{{ t('sidebar.groupChat') }}</span>
            <span v-if="ui.getUnread(null)" class="unread-badge" :aria-label="String(t('common.unreadMessages'))">
              {{ ui.getUnread(null) }}
            </span>
          </button>
        </li>

        <template v-if="visibleUsers.length">
          <li v-for="u in visibleUsers" :key="u.id">
            <button
              class="contact-row"
              type="button"
              :class="{ active: isActive(u.name!) }"
              @click="onOpenUser(u.name!)"
            >
              <span class="name">{{ u.name }}</span>
              <span class="contact-row-right">
                <span class="meta">{{ u.busy ? t('common.busy') : '' }}</span>
                <span
                  v-if="ui.getUnread(u.name!)"
                  class="unread-badge"
                  :aria-label="String(t('common.unreadMessages'))"
                >
                  {{ ui.getUnread(u.name!) }}
                </span>
              </span>
            </button>
          </li>
        </template>

        <li v-else>
          <div class="muted">{{ t('sidebar.noOneOnline') }}</div>
        </li>
      </ul>
    </div>
  </section>
</template>
