<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useCallStore } from '../stores/call'
import { useI18n } from 'vue-i18n'

const call = useCallStore()
const { t } = useI18n()
const {
  status,
  timerText,
  pendingIncomingFrom,
  pendingIncomingFromName,
  outgoingPending,
  remoteStreams,
  callLabel,
  joinPending,
  joinPendingToName,
  joinRequestFromId,
  joinRequestFromName,
} = storeToRefs(call)

const remoteIds = computed(() => Object.keys(remoteStreams.value))

function onAccept() {
  void call.acceptIncoming()
}

function onAcceptJoin() {
  call.acceptJoinRequest()
}

function onRejectJoin() {
  call.rejectJoinRequest()
}
</script>

<template>
  <div class="card call-blob">
    <div class="chat-call">
      <div class="call-title">{{ callLabel }}</div>

      <div class="call-meta">
        <div class="status">
          <template v-if="pendingIncomingFrom">
            {{ t('call.incomingFromLabel') }} <strong>{{ pendingIncomingFromName || t('call.unknown') }}</strong>
          </template>
          <template v-else-if="joinPending">
            {{ joinPendingToName ? t('call.waitingToJoinNamed', { name: joinPendingToName }) : t('call.waitingToJoin') }}
          </template>
          <template v-else>
            {{ status || (outgoingPending ? t('call.calling') : '') }}
          </template>
        </div>
        <div class="muted call-timer" :class="{ hidden: timerText === '00:00' }">{{ timerText }}</div>
      </div>

      <div class="call-actions">
        <template v-if="pendingIncomingFrom">
          <button type="button" @click="onAccept">{{ t('call.accept') }}</button>
          <button class="secondary" type="button" @click="call.rejectIncoming">{{ t('call.reject') }}</button>
        </template>
        <template v-else-if="joinPending">
          <button class="secondary" type="button" @click="call.cancelJoinPending">{{ t('call.cancelRequest') }}</button>
        </template>
        <template v-else-if="joinRequestFromId">
          <button type="button" @click="onAcceptJoin">{{ t('call.addToCall') }}</button>
          <button class="secondary" type="button" @click="onRejectJoin">{{ t('call.reject') }}</button>
        </template>
        <template v-else>
          <button v-if="call.inCall || outgoingPending" class="danger" type="button" @click="call.hangup">{{ t('call.hangUp') }}</button>
        </template>
      </div>

      <div v-if="joinRequestFromId" class="muted">
        {{ joinRequestFromName ? t('call.joinRequestNamed', { name: joinRequestFromName }) : t('call.joinRequestSomeone') }}
      </div>

      <div class="remote-audios">
        <audio
          v-for="id in remoteIds"
          :key="id"
          autoplay
          playsinline
          :ref="(el) => { if (el && remoteStreams[id]) (el as HTMLAudioElement).srcObject = remoteStreams[id] }"
        />
      </div>
    </div>
  </div>
</template>
