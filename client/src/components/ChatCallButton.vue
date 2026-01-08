<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useSessionStore } from '../stores/session'
import { useUiStore } from '../stores/ui'
import { useCallStore } from '../stores/call'
import { useI18n } from 'vue-i18n'

const session = useSessionStore()
const ui = useUiStore()
const call = useCallStore()
const { t } = useI18n()

const { users } = storeToRefs(session)
const { activeChatName } = storeToRefs(ui)
const { inCall, outgoingPending, pendingIncomingFrom, joinPending } = storeToRefs(call)

const activePeer = computed(() => {
  const name = activeChatName.value
  if (!name) return null
  return users.value.find((u) => u.name === name) ?? null
})

const show = computed(() => Boolean(activeChatName.value))

const canCallActivePeer = computed(() => {
  const peer = activePeer.value
  if (!peer) return false
  if (!peer.id || !peer.name) return false
  if (pendingIncomingFrom.value) return false
  if (outgoingPending.value) return false
  if (inCall.value) return false
  if (joinPending.value) return false
  return true
})

function onCallActivePeer() {
  const peer = activePeer.value
  if (!peer || !peer.id || !peer.name) return
  if (peer.busy) {
    call.openJoinConfirm(peer.id, peer.name)
    return
  }
  void call.startCall(peer.id, peer.name)
}
</script>

<template>
  <button
    v-if="show"
    class="chat-callbtn secondary icon-only"
    type="button"
    :aria-label="String(t('chat.callAria'))"
    :disabled="!canCallActivePeer"
    @click="onCallActivePeer"
  >
    <svg class="icon" aria-hidden="true" focusable="false"><use xlink:href="/icons.svg#call"></use></svg>
  </button>
</template>
