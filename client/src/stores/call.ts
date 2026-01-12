import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { useSignedStore } from './signed'
import { notify, vibrate } from '../utils/notify'
import { i18n } from '../i18n'

type TurnConfig = {
  iceServers?: Array<{ urls: string | string[]; username?: string; credential?: string }>
}

function asString(v: unknown): string | null {
  return typeof v === 'string' ? v : null
}

function asBool(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null
}

function asObj(v: unknown): Record<string, unknown> | null {
  if (!v || typeof v !== 'object') return null
  return v as Record<string, unknown>
}

function formatDuration(ms: number) {
  const total = Math.max(0, Math.floor(ms / 1000))
  const m = Math.floor(total / 60)
  const s = total % 60
  const mm = String(m).padStart(2, '0')
  const ss = String(s).padStart(2, '0')
  return `${mm}:${ss}`
}

function micErrorToStatus(err: unknown) {
  const name = (asObj(err)?.name as string | undefined) ?? ''
  if (name === 'NotAllowedError' || name === 'SecurityError') return String(i18n.global.t('call.micPermissionDenied'))
  if (name === 'NotFoundError') return String(i18n.global.t('call.micNotFound'))
  if (name === 'NotReadableError') return String(i18n.global.t('call.micInUse'))
  return String(i18n.global.t('call.micError'))
}

export const useCallStore = defineStore('call', () => {
  const signed = useSignedStore()

  function isSignedActive() {
    return Boolean(signed.signedIn && signed.privateKey)
  }

  function myId() {
    return isSignedActive() ? signed.userId : null
  }

  async function ensureTurn() {
    if (isSignedActive()) {
      try {
        await signed.ensureTurnConfig()
      } catch {
        // ignore
      }
    }
  }

  function getTurnConfig(): TurnConfig | null {
    const cfg = isSignedActive() ? (signed.turnConfig as any) : null
    return (cfg ?? null) as TurnConfig | null
  }

  function send(obj: unknown) {
    if (isSignedActive()) signed.sendWs(obj)
  }

  const roomId = ref<string | null>(null)
  const status = ref<string>('')

  let statusClearTimer: number | null = null

  function clearStatusClearTimer() {
    if (statusClearTimer != null) {
      window.clearTimeout(statusClearTimer)
      statusClearTimer = null
    }
  }

  function scheduleStatusAutoClear() {
    clearStatusClearTimer()
    // Keep the call UI visible briefly to show the user what happened.
    statusClearTimer = window.setTimeout(() => {
      statusClearTimer = null
      const idle =
        !roomId.value
        && !pendingIncomingFrom.value
        && !outgoingPending.value
        && !joinPending.value
        && !joinRequestFromId.value
      if (idle) status.value = ''
    }, 3000)
  }

  const pendingIncomingFrom = ref<string | null>(null)
  const pendingIncomingFromName = ref<string>('')
  const pendingIncomingRoomId = ref<string | null>(null)

  const outgoingPending = ref(false)
  const outgoingPendingName = ref('')

  // Join ongoing call flow
  const joinConfirmToId = ref<string | null>(null)
  const joinConfirmToName = ref<string>('')

  const joinPending = ref(false)
  const joinPendingToName = ref('')
  const joinPendingRoomId = ref<string | null>(null)

  // Server sends one join request at a time (queue is server-side).
  const joinRequestFromId = ref<string | null>(null)
  const joinRequestFromName = ref<string>('')
  const joinRequestRoomId = ref<string | null>(null)

  const timerStartMs = ref<number | null>(null)
  const timerText = ref('00:00')

  const remoteStreams = ref<Record<string, MediaStream>>({})

  // Peer display names must be reactive because the call UI derives its label from them.
  // Use a plain object for reliable Vue reactivity.
  const peerNames = ref<Record<string, string>>({})
  const pcs = new Map<string, RTCPeerConnection>()

  let localStream: MediaStream | null = null
  let timerInterval: number | null = null
  let handlerInstalled = false

  let incomingCallAudio: HTMLAudioElement | null = null
  let callingAudio: HTMLAudioElement | null = null
  let callingInterval: number | null = null

  // Automatic reconnection state
  let intentionalHangup = false
  let reconnectAttempts = 0
  let reconnectTimer: number | null = null
  const MAX_RECONNECT_ATTEMPTS = 3
  const RECONNECT_DELAY_MS = 1000

  function primeAudio() {
    // Mobile browsers (esp. iOS Safari) require a user gesture before audio can play.
    // Call this from a click/tap handler (e.g. Join button).
    try {
      // Prime audio elements by attempting to play them at volume 0
      if (!incomingCallAudio) {
        incomingCallAudio = new Audio('/incoming_call.wav')
        incomingCallAudio.loop = true
      }
      if (!callingAudio) {
        callingAudio = new Audio('/calling.wav')
      }
      
      // Attempt to load audio (gesture priming)
      void incomingCallAudio.load()
      void callingAudio.load()
    } catch {
      // ignore
    }
  }

  const inCall = computed(() => Boolean(roomId.value))
  const peers = computed(() => Object.entries(peerNames.value).map(([id, name]) => ({ id, name })))

  const callLabel = computed(() => {
    // Ensure this recomputes when locale changes.
    void i18n.global.locale.value
    if (!roomId.value) return String(i18n.global.t('call.notInCall'))

    const names = peers.value.map((p) => p.name).filter(Boolean)
    if (names.length === 0) return String(i18n.global.t('call.connecting'))
    return String(i18n.global.t('call.inCall', { names: names.join(', ') }))
  })

  function setPeerName(peerId: string, name: string) {
    peerNames.value = { ...peerNames.value, [peerId]: name }
  }

  function deletePeerName(peerId: string) {
    if (!(peerId in peerNames.value)) return
    const next = { ...peerNames.value }
    delete next[peerId]
    peerNames.value = next
  }

  function updateTimer() {
    if (timerStartMs.value == null) return
    timerText.value = formatDuration(Date.now() - timerStartMs.value)
  }

  function startTimerIfNeeded() {
    if (timerStartMs.value != null) return
    timerStartMs.value = Date.now()
    updateTimer()
    if (timerInterval != null) window.clearInterval(timerInterval)
    timerInterval = window.setInterval(updateTimer, 1000)
  }

  function resetTimer() {
    if (timerInterval != null) window.clearInterval(timerInterval)
    timerInterval = null
    timerStartMs.value = null
    timerText.value = '00:00'
  }

  function startRingtone() {
    try {
      stopRingtone()
      if (!incomingCallAudio) {
        incomingCallAudio = new Audio('/incoming_call.wav')
        incomingCallAudio.loop = true
      }
      incomingCallAudio.currentTime = 0
      incomingCallAudio.volume = 0.5
      void incomingCallAudio.play().catch(() => {})
    } catch {
      // ignore
    }
  }

  function stopRingtone() {
    try {
      if (incomingCallAudio) {
        incomingCallAudio.pause()
        incomingCallAudio.currentTime = 0
      }
      stopCallingSound()
    } catch {
      // ignore
    }
  }

  function startCallingSound() {
    try {
      stopCallingSound()
      if (!callingAudio) {
        callingAudio = new Audio('/calling.wav')
      }
      
      const playSound = () => {
        if (callingAudio) {
          callingAudio.currentTime = 0
          callingAudio.volume = 0.5
          void callingAudio.play().catch(() => {})
        }
      }
      
      playSound()
      callingInterval = window.setInterval(playSound, 6000)
    } catch {
      // ignore
    }
  }

  function stopCallingSound() {
    try {
      if (callingInterval != null) {
        window.clearInterval(callingInterval)
        callingInterval = null
      }
      if (callingAudio) {
        callingAudio.pause()
        callingAudio.currentTime = 0
      }
    } catch {
      // ignore
    }
  }

  function playCallInterruptedSound() {
    try {
      const audio = new Audio('/call_interrupted.wav')
      audio.volume = 0.5
      void audio.play().catch(() => {})
    } catch {
      // ignore
    }
  }

  async function ensureMic() {
    if (localStream) return localStream
    
    // Build audio constraints from environment variables (defaults to browser defaults)
    const audioConstraints: MediaTrackConstraints = {
      echoCancellation: import.meta.env.VITE_AUDIO_ECHO_CANCELLATION !== undefined 
        ? import.meta.env.VITE_AUDIO_ECHO_CANCELLATION === 'true' 
        : true,
      noiseSuppression: import.meta.env.VITE_AUDIO_NOISE_SUPPRESSION !== undefined
        ? import.meta.env.VITE_AUDIO_NOISE_SUPPRESSION === 'true'
        : true,
      autoGainControl: import.meta.env.VITE_AUDIO_AUTO_GAIN !== undefined
        ? import.meta.env.VITE_AUDIO_AUTO_GAIN === 'true'
        : true,
    }
    
    if (import.meta.env.VITE_AUDIO_SAMPLE_RATE) {
      const rate = Number.parseInt(import.meta.env.VITE_AUDIO_SAMPLE_RATE, 10)
      if (!Number.isNaN(rate) && rate >= 8000 && rate <= 96000) {
        audioConstraints.sampleRate = rate
      }
    }
    
    localStream = await navigator.mediaDevices.getUserMedia({ audio: audioConstraints, video: false })
    return localStream
  }

  function closePeer(peerId: string) {
    const pc = pcs.get(peerId)
    if (pc) {
      try {
        pc.onicecandidate = null
        pc.ontrack = null
        pc.onconnectionstatechange = null
        pc.close()
      } catch {
        // ignore
      }
    }
    pcs.delete(peerId)

    const streams = { ...remoteStreams.value }
    delete streams[peerId]
    remoteStreams.value = streams

    deletePeerName(peerId)
  }

  function clearReconnectTimer() {
    if (reconnectTimer != null) {
      window.clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
  }

  function resetCallState() {
    stopRingtone()
    clearStatusClearTimer()
    clearReconnectTimer()
    for (const id of Array.from(pcs.keys())) closePeer(id)

    peerNames.value = {}
    roomId.value = null

    pendingIncomingFrom.value = null
    pendingIncomingFromName.value = ''
    pendingIncomingRoomId.value = null

    outgoingPending.value = false
    outgoingPendingName.value = ''

    joinConfirmToId.value = null
    joinConfirmToName.value = ''

    joinPending.value = false
    joinPendingToName.value = ''
    joinPendingRoomId.value = null

    joinRequestFromId.value = null
    joinRequestFromName.value = ''
    joinRequestRoomId.value = null

    resetTimer()

    // Clear reconnection state
    intentionalHangup = false
    reconnectAttempts = 0

    try {
      localStream?.getTracks().forEach((t) => t.stop())
    } catch {
      // ignore
    }
    localStream = null
  }

  function openJoinConfirm(toId: string, toName: string) {
    joinConfirmToId.value = toId
    joinConfirmToName.value = toName
  }

  function cancelJoinConfirm() {
    joinConfirmToId.value = null
    joinConfirmToName.value = ''
  }

  async function requestJoinOngoingCall(toId: string, toName: string) {
    if (joinPending.value) return
    if (pendingIncomingFrom.value || outgoingPending.value || inCall.value) return

    try {
      await ensureTurn()
      await ensureMic()
    } catch (err) {
      status.value = micErrorToStatus(err)
      scheduleStatusAutoClear()
      return
    }

    joinPending.value = true
    joinPendingToName.value = toName
    status.value = toName
      ? String(i18n.global.t('call.requestingToJoinNamed', { name: toName }))
      : String(i18n.global.t('call.requestingToJoin'))
    send({ type: 'callJoinRequest', to: toId })
  }

  async function confirmJoinAttempt() {
    const toId = joinConfirmToId.value
    const toName = joinConfirmToName.value
    if (!toId || !toName) return
    cancelJoinConfirm()
    await requestJoinOngoingCall(toId, toName)
  }

  function cancelJoinPending() {
    if (!joinPending.value) return
    send({ type: 'callJoinCancel' })
    status.value = ''
    resetCallState()
  }

  function acceptJoinRequest() {
    if (!joinRequestFromId.value) return
    send({ type: 'callJoinAccept', from: joinRequestFromId.value, roomId: joinRequestRoomId.value })
    joinRequestFromId.value = null
    joinRequestFromName.value = ''
    joinRequestRoomId.value = null
  }

  function rejectJoinRequest() {
    if (!joinRequestFromId.value) return
    send({ type: 'callJoinReject', from: joinRequestFromId.value, roomId: joinRequestRoomId.value })
    joinRequestFromId.value = null
    joinRequestFromName.value = ''
    joinRequestRoomId.value = null
  }

  async function ensurePeerConnection(peerId: string) {
    const existing = pcs.get(peerId)
    if (existing) return existing

    const ice = getTurnConfig()
    const pc = new RTCPeerConnection(ice ?? undefined)
    pcs.set(peerId, pc)

    pc.onicecandidate = (ev) => {
      if (!ev.candidate) return
      send({ type: 'signal', to: peerId, payload: { kind: 'ice', candidate: ev.candidate } })
    }

    pc.ontrack = (ev) => {
      const stream = ev.streams?.[0]
      if (!stream) return
      remoteStreams.value = { ...remoteStreams.value, [peerId]: stream }
    }

    const stream = await ensureMic()
    for (const track of stream.getTracks()) {
      pc.addTrack(track, stream)
    }

    pc.addEventListener('connectionstatechange', () => {
      if (!pcs.has(peerId)) return
      if (pc.connectionState === 'connected') {
        // Clear reconnection state on successful connection
        reconnectAttempts = 0
        clearReconnectTimer()
        stopCallingSound()
        startTimerIfNeeded()
        const connectedLabel = String(i18n.global.t('call.connected'))
        if (status.value !== connectedLabel) status.value = connectedLabel
      }
      if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
        closePeer(peerId)
        
        // If connection failed and it wasn't an intentional hangup, attempt reconnection
        if (!intentionalHangup && roomId.value && reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
          reconnectAttempts++
          status.value = `Reconnecting... (${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})`
          
          clearReconnectTimer()
          reconnectTimer = window.setTimeout(async () => {
            // Re-establish peer connection
            try {
              await ensurePeerConnection(peerId)
            } catch (err) {
              status.value = micErrorToStatus(err)
            }
          }, RECONNECT_DELAY_MS)
          
          return
        }
        
        if (Object.keys(peerNames.value).length === 0) resetCallState()
      }
    })

    return pc
  }

  async function startCall(toId: string, toName: string) {
    try {
      await ensureTurn()
      await ensureMic()
    } catch (err) {
      status.value = micErrorToStatus(err)
      scheduleStatusAutoClear()
      return
    }

    setPeerName(toId, toName)

    if (!roomId.value) {
      outgoingPending.value = true
      outgoingPendingName.value = toName
      startCallingSound()
      status.value = toName
        ? String(i18n.global.t('call.callingNamed', { name: toName }))
        : String(i18n.global.t('call.calling'))
    } else {
      status.value = String(i18n.global.t('call.inviting'))
    }

    send({ type: 'callStart', to: toId })
  }

  function hangup() {
    // Mark as intentional so reconnection doesn't trigger
    intentionalHangup = true
    send({ type: 'callHangup' })
    status.value = String(i18n.global.t('call.callEnded'))
    stopRingtone()
    playCallInterruptedSound()
    resetCallState()
    scheduleStatusAutoClear()
  }

  async function acceptIncoming() {
    if (!pendingIncomingFrom.value) return

    try {
      await ensureTurn()
      await ensureMic()
    } catch (err) {
      status.value = micErrorToStatus(err)
      scheduleStatusAutoClear()
      return
    }

    stopRingtone()
    status.value = String(i18n.global.t('call.connecting'))
    send({
      type: 'callAccept',
      from: pendingIncomingFrom.value,
      roomId: pendingIncomingRoomId.value,
    })

    pendingIncomingFrom.value = null
    pendingIncomingFromName.value = ''
    pendingIncomingRoomId.value = null
  }

  function rejectIncoming() {
    stopRingtone()
    if (pendingIncomingFrom.value) {
      send({
        type: 'callReject',
        from: pendingIncomingFrom.value,
        roomId: pendingIncomingRoomId.value,
      })
    }

    pendingIncomingFrom.value = null
    pendingIncomingFromName.value = ''
    pendingIncomingRoomId.value = null
    status.value = ''
  }

  async function handleInbound(type: string, obj: Record<string, unknown>) {
    if (type === 'incomingCall') {
      pendingIncomingFrom.value = asString(obj.from)
      pendingIncomingFromName.value = asString(obj.fromName) ?? ''
      pendingIncomingRoomId.value = asString(obj.roomId)
      status.value = pendingIncomingFromName.value
        ? String(i18n.global.t('call.incomingCallNamed', { name: pendingIncomingFromName.value }))
        : String(i18n.global.t('call.incomingCall'))

      // Best-effort alerts (no permission prompts here).
      startRingtone()

      // Suppress OS-level notifications when user is actively in the app on
      // contacts list (they can already see incoming-call UI).
      const foreground = typeof document !== 'undefined' && document.visibilityState === 'visible'
      const onContacts = signed.view === 'contacts'
      const shouldSystemNotify = !(foreground && onContacts)
      if (shouldSystemNotify) {
        notify(
          String(i18n.global.t('call.incomingCall')),
          pendingIncomingFromName.value
            ? String(i18n.global.t('call.from', { name: pendingIncomingFromName.value }))
            : String(i18n.global.t('call.incomingCall')),
          { tag: 'lrcom-call' },
        )
        vibrate([200, 100, 200, 100, 400])
      }
      return
    }

    if (type === 'callStartResult') {
      const ok = asBool(obj.ok)
      const reason = asString(obj.reason) ?? ''
      if (!ok) {
        if (outgoingPending.value && !roomId.value) {
          stopCallingSound()
          playCallInterruptedSound()
          outgoingPending.value = false
          outgoingPendingName.value = ''
          status.value =
            reason === 'introvert'
              ? String(i18n.global.t('call.introvertBlocked'))
              : String(i18n.global.t('call.callFailed', { reason }))
          scheduleStatusAutoClear()
        }
      } else {
        if (outgoingPending.value && !roomId.value) {
          status.value = outgoingPendingName.value
            ? String(i18n.global.t('call.ringingNamed', { name: outgoingPendingName.value }))
            : String(i18n.global.t('call.ringing'))
        }
      }
      return
    }

    if (type === 'callJoinPending') {
      joinPending.value = true
      joinPendingRoomId.value = asString(obj.roomId)
      joinPendingToName.value = asString(obj.toName) ?? joinPendingToName.value
      status.value = joinPendingToName.value
        ? String(i18n.global.t('call.waitingToJoinNamed', { name: joinPendingToName.value }))
        : String(i18n.global.t('call.waitingToJoin'))
      return
    }

    if (type === 'callJoinResult') {
      const ok = asBool(obj.ok)
      const reason = asString(obj.reason) ?? ''
      if (!ok) {
        status.value = reason
          ? String(i18n.global.t('call.joinFailedReason', { reason }))
          : String(i18n.global.t('call.joinFailed'))
        resetCallState()
        scheduleStatusAutoClear()
      }
      return
    }

    if (type === 'joinRequest') {
      joinRequestFromId.value = asString(obj.from)
      joinRequestFromName.value = asString(obj.fromName) ?? ''
      joinRequestRoomId.value = asString(obj.roomId)
      return
    }

    if (type === 'callRejected') {
      if (outgoingPending.value && !roomId.value) {
        stopCallingSound()
        playCallInterruptedSound()
        outgoingPending.value = false
        outgoingPendingName.value = ''
        status.value = String(i18n.global.t('call.callRejected'))
        scheduleStatusAutoClear()
      }
      if (!roomId.value) resetCallState()
      return
    }

    if (type === 'callEnded') {
      // Server ended the call, mark as intentional to prevent reconnection
      intentionalHangup = true
      status.value = String(i18n.global.t('call.callEnded'))
      playCallInterruptedSound()
      resetCallState()
      scheduleStatusAutoClear()
      return
    }

    if (type === 'roomPeers') {
      roomId.value = asString(obj.roomId) ?? roomId.value
      stopCallingSound()
      outgoingPending.value = false
      outgoingPendingName.value = ''

      // If we were waiting to join, the server has now admitted us.
      joinPending.value = false
      joinPendingToName.value = ''
      joinPendingRoomId.value = null

      const peersArr = Array.isArray(obj.peers) ? (obj.peers as unknown[]) : []
      try {
        for (const p of peersArr) {
          const po = asObj(p)
          if (!po) continue
          const id = asString(po.id)
          if (!id || id === myId()) continue
          const name = asString(po.name) ?? ''
          setPeerName(id, name)
          await ensurePeerConnection(id)
        }
      } catch (err) {
        status.value = micErrorToStatus(err)
        hangup()
        return
      }

      status.value = String(i18n.global.t('call.connecting'))
      return
    }

    if (type === 'roomPeerJoined') {
      roomId.value = asString(obj.roomId) ?? roomId.value
      const peerObj = asObj(obj.peer)
      const peerId = peerObj ? asString(peerObj.id) : null
      if (!peerId || peerId === myId()) return
      const peerName = peerObj ? (asString(peerObj.name) ?? '') : ''
      setPeerName(peerId, peerName)

      let pc: RTCPeerConnection
      try {
        pc = await ensurePeerConnection(peerId)
      } catch (err) {
        status.value = micErrorToStatus(err)
        hangup()
        return
      }

      status.value = String(i18n.global.t('call.connecting'))
      const offer = await pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: false })
      await pc.setLocalDescription(offer)
      
      // Apply bitrate limit if configured
      if (import.meta.env.VITE_AUDIO_MAX_BITRATE && pc.localDescription) {
        const bitrate = Number.parseInt(import.meta.env.VITE_AUDIO_MAX_BITRATE, 10)
        if (!Number.isNaN(bitrate) && bitrate >= 6 && bitrate <= 510) {
          const sdp = pc.localDescription.sdp.replace(
            /(m=audio.*\r\n)/g,
            `$1b=AS:${bitrate}\r\n`
          )
          await pc.setLocalDescription({ type: pc.localDescription.type, sdp })
        }
      }
      
      send({ type: 'signal', to: peerId, payload: { kind: 'offer', sdp: pc.localDescription } })
      return
    }

    if (type === 'roomPeerLeft') {
      const peerId = asString(obj.peerId)
      if (peerId) closePeer(peerId)
      if (Object.keys(peerNames.value).length === 0) resetCallState()
      return
    }

    if (type === 'signal') {
      const payloadObj = asObj(obj.payload)
      const kind = payloadObj ? asString(payloadObj.kind) : null
      const fromId = asString(obj.from)
      const fromName = asString(obj.fromName)
      if (fromId && fromName) setPeerName(fromId, fromName)
      if (!payloadObj || !kind || !fromId) return

      if (kind === 'offer') {
        const sdp = payloadObj.sdp as RTCSessionDescriptionInit
        let pc: RTCPeerConnection
        try {
          pc = await ensurePeerConnection(fromId)
        } catch (err) {
          status.value = micErrorToStatus(err)
          hangup()
          return
        }
        await pc.setRemoteDescription(sdp)
        const answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)
        
        // Apply bitrate limit if configured
        if (import.meta.env.VITE_AUDIO_MAX_BITRATE && pc.localDescription) {
          const bitrate = Number.parseInt(import.meta.env.VITE_AUDIO_MAX_BITRATE, 10)
          if (!Number.isNaN(bitrate) && bitrate >= 6 && bitrate <= 510) {
            const sdp = pc.localDescription.sdp.replace(
              /(m=audio.*\r\n)/g,
              `$1b=AS:${bitrate}\r\n`
            )
            await pc.setLocalDescription({ type: pc.localDescription.type, sdp })
          }
        }
        
        send({ type: 'signal', to: fromId, payload: { kind: 'answer', sdp: pc.localDescription } })
        return
      }

      if (kind === 'answer') {
        const pc = pcs.get(fromId)
        if (!pc) return
        const sdp = payloadObj.sdp as RTCSessionDescriptionInit
        await pc.setRemoteDescription(sdp)
        status.value = String(i18n.global.t('call.connected'))
        return
      }

      if (kind === 'ice') {
        const pc = pcs.get(fromId)
        if (!pc) return
        try {
          await pc.addIceCandidate(payloadObj.candidate as RTCIceCandidateInit)
        } catch {
          // ignore
        }
      }
    }
  }

  function installHandler() {
    if (handlerInstalled) return
    handlerInstalled = true

    signed.registerInboundHandler((type, obj) => {
      void handleInbound(type, obj)
    })

    signed.registerDisconnectHandler(() => {
      intentionalHangup = true
      resetCallState()
      status.value = ''
    })
  }

  installHandler()

  return {
    roomId,
    status,
    inCall,
    peers,
    callLabel,
    pendingIncomingFrom,
    pendingIncomingFromName,
    outgoingPending,
    outgoingPendingName,
    joinConfirmToId,
    joinConfirmToName,
    joinPending,
    joinPendingToName,
    joinRequestFromId,
    joinRequestFromName,
    timerText,
    remoteStreams,
    startCall,
    openJoinConfirm,
    cancelJoinConfirm,
    confirmJoinAttempt,
    cancelJoinPending,
    acceptJoinRequest,
    rejectJoinRequest,
    acceptIncoming,
    rejectIncoming,
    hangup,
    primeAudio,
  }
})
