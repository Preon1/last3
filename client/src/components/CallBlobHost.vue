<script setup lang="ts">
import { computed } from 'vue'
import { storeToRefs } from 'pinia'
import { useCallStore } from '../stores/call'
import CallPanel from './CallPanel.vue'

type Mode = 'fixed' | 'flow'

const props = withDefaults(defineProps<{ mode?: Mode }>(), {
  mode: 'fixed',
})

const call = useCallStore()
const { inCall, outgoingPending, pendingIncomingFrom, joinPending, joinRequestFromId } = storeToRefs(call)

const show = computed(() =>
  Boolean(pendingIncomingFrom.value)
  || outgoingPending.value
  || inCall.value
  || joinPending.value
  || Boolean(joinRequestFromId.value)
)
</script>

<template>
  <CallPanel
    v-if="show"
    :class="props.mode === 'fixed' ? 'call-blob--fixed' : 'call-blob--flow'"
  />
</template>
