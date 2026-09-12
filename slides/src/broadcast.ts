// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The Bento authors
// Live broadcast transport for bento/slides: the presenter's slide number,
// laser and black-screen state, to any number of viewers, over the collab
// relay. Design: docs/broadcast-design.md.
//
// This is presentation machinery, not document machinery, so it lives in
// slides rather than the kernel. It was written into slides/src/sync/online.ts
// when that file held the transport; #313 moved the transport to the kernel
// and left a facade behind, so the broadcast code moved here and imports the
// two primitives it needs. Nothing about the protocol changed in the move.
import type { BentoDoc } from './model'
import { signText, syncHost } from '../../kernel/src/sync/online.ts'
import { lsGet, lsSet } from '../../kernel/src/storage.ts'
import { netWebSocket } from '../../kernel/src/net.ts'

// Two helpers the transport used to share with the collab code in the same
// file. Kept local rather than exported from the kernel: they are a dozen
// lines, and the broadcast SIGNER is deliberately a different identity from
// the collab member key (kernel deviceIdentity), so it does not borrow that.
const EC = { name: 'ECDSA', namedCurve: 'P-256' } as const
const b64u = {
  enc(bytes: Uint8Array): string {
    let s = ''
    for (const b of bytes) s += String.fromCharCode(b)
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  },
  dec(s: string): Uint8Array {
    const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'))
    const out = new Uint8Array(b.length)
    for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i)
    return out
  },
}
async function mintKeypair(): Promise<{ pub: string; priv: string }> {
  const kp = (await crypto.subtle.generateKey(EC, true, ['sign', 'verify'])) as CryptoKeyPair
  return {
    pub: b64u.enc(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))),
    priv: b64u.enc(new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey))),
  }
}


// --- live slide broadcast ---------------------------------------------------

export type BroadcastCreds = {
  /** Full WebSocket URL the broadcast socket connects to, e.g. wss://host/d/<name>. */
  room: string
  /** Room name extracted from the URL (the derived 10-char name). */
  roomName: string
  /** Possession-proof token derived from the room name. */
  tok: string
  /** Relay origin used to build viewer links (respects bento-sync-url override). */
  relay: string
  /** Public key this socket authenticates with (owner-bound `?w=`). */
  signerPub: string
  /** Private key that signs nav frames (`nav.${n}`). */
  signerPriv: string
  /** True when the local copy is the owner of the broadcast room. */
  isOwner: boolean
}

export type BroadcastHandlers = {
  onNav?: (n: number) => void
  onPresence?: (n: number) => void
  onState?: (s: BroadcastSocketState) => void
  onLaser?: (p: string | null) => void
  onBlack?: (on: boolean) => void
}

export type BroadcastSocketState = 'connecting' | 'open' | 'closed'

/**
 * Lightweight read-only (optionally owner-bound) WebSocket for live slide
 * broadcast. Reuses the same backoff + heartbeat constants as OnlineTransport.
 * Handles nav/presence/laser/black control frames and deliberately ignores
 * everything else — collab ciphertext, unknown ctl frames.
 */
export class BroadcastSocket {
  private ws: WebSocket | null = null
  private closed = false
  private backoff = 800
  private pingTimer: ReturnType<typeof setInterval> | null = null
  private awaitingPong = false
  private static readonly PING_MS = 25_000

  constructor(
    private room: string,
    private tok: string,
    private handlers: BroadcastHandlers,
    /** When provided, the socket authenticates as the room owner (?w=pub) and
     *  can send signed nav frames. When omitted, it is a read-only viewer socket. */
    private pub?: string,
  ) {}

  get state(): BroadcastSocketState {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) return 'open'
    if (this.closed) return 'closed'
    return 'connecting'
  }

  connect() {
    if (this.closed) return
    this.setState('connecting')
    let ws: WebSocket
    try {
      const url = this.pub
        ? `${this.room}?tok=${this.tok}&w=${this.pub}&since=0`
        : `${this.room}?tok=${this.tok}&since=0`
      // Through the one chokepoint, never a raw WebSocket: the offline switch
      // is a privacy promise ("nothing leaves this computer") and net.ts is
      // the only place that keeps it. A viewer who flipped it stays offline
      // even with a broadcast copy open; netWebSocket throws OfflineError,
      // caught below like any other failure to connect.
      ws = netWebSocket(url)
    } catch {
      this.retry()
      return
    }
    this.ws = ws
    ws.onopen = () => {
      this.backoff = 800
      this.setState('open')
      this.startHeartbeat(ws)
    }
    ws.onmessage = (ev) => {
      const data = String(ev.data)
      if (data === 'pong') { this.awaitingPong = false; return }
      this.onMessage(data).catch(() => {})
    }
    const drop = () => {
      if (this.ws !== ws) return
      this.stopHeartbeat()
      this.ws = null
      this.setState('closed')
      this.retry()
    }
    ws.onclose = drop
    ws.onerror = drop
  }

  private setState(s: BroadcastSocketState) {
    this.handlers.onState?.(s)
  }

  private startHeartbeat(ws: WebSocket) {
    this.stopHeartbeat()
    this.awaitingPong = false
    this.pingTimer = setInterval(() => {
      if (this.ws !== ws || ws.readyState !== WebSocket.OPEN) return
      if (this.awaitingPong) {
        // no pong since the last ping → the socket is dead (half-open); force a
        // close so onclose fires and we reconnect, rather than hanging silently.
        try { ws.close() } catch { /* already gone */ }
        return
      }
      this.awaitingPong = true
      try { ws.send('ping') } catch { /* send failed → onclose will handle it */ }
    }, BroadcastSocket.PING_MS)
  }

  private stopHeartbeat() {
    if (this.pingTimer) { clearInterval(this.pingTimer); this.pingTimer = null }
    this.awaitingPong = false
  }

  private retry() {
    if (this.closed) return
    setTimeout(() => this.connect(), this.backoff)
    this.backoff = Math.min(this.backoff * 1.8, 30000)
  }

  private async onMessage(text: string) {
    let env: { ctl?: string; n?: number } & Record<string, unknown>
    try {
      env = JSON.parse(text)
    } catch {
      return
    }
    if (env.ctl === 'nav' && Number.isInteger(env.n) && env.n! > 0) {
      this.handlers.onNav?.(env.n as number)
      return
    }
    if (env.ctl === 'presence' && Number.isInteger(env.n) && env.n! >= 0) {
      this.handlers.onPresence?.(env.n as number)
      return
    }
    if (env.ctl === 'laser') {
      if (env.off === 1) { this.handlers.onLaser?.(null); return }
      if (typeof env.p === 'string') { this.handlers.onLaser?.(env.p); return }
    }
    if (env.ctl === 'black' && (env.on === 1 || env.on === 0)) {
      this.handlers.onBlack?.(env.on === 1)
      return
    }
    // Deliberately ignore everything else: collab ciphertext, unknown ctl frames.
  }

  /** Sign and send a nav frame over this socket. */
  async sendNav(priv: string, n: number): Promise<boolean> {
    return sendNav(this.ws, priv, n)
  }

  /** Sign and send a laser frame over this socket. */
  async sendLaser(priv: string, p: string | null): Promise<boolean> {
    return sendLaser(this.ws, priv, p)
  }

  /** Sign and send a black-screen frame over this socket. */
  async sendBlack(priv: string, on: boolean): Promise<boolean> {
    return sendBlack(this.ws, priv, on)
  }

  close() {
    if (this.closed) return
    this.closed = true
    this.stopHeartbeat()
    this.setState('closed')
    this.ws?.close()
    this.ws = null
  }

  destroy() {
    this.close()
    this.handlers = {}
  }
}

/** Sign and send a nav frame over any open WebSocket. */
export async function sendNav(ws: WebSocket | null, signerPriv: string, n: number): Promise<boolean> {
  if (!ws || ws.readyState !== WebSocket.OPEN) return false
  const g = await signText(signerPriv, `nav.${n}`)
  ws.send(JSON.stringify({ ctl: 'nav', n, g }))
  return true
}

/** Sign and send a laser frame over any open WebSocket. */
export async function sendLaser(ws: WebSocket | null, signerPriv: string, p: string | null): Promise<boolean> {
  if (!ws || ws.readyState !== WebSocket.OPEN) return false
  if (p === null) {
    const g = await signText(signerPriv, 'laser.off')
    ws.send(JSON.stringify({ ctl: 'laser', off: 1, g }))
  } else {
    const g = await signText(signerPriv, 'laser.' + p)
    ws.send(JSON.stringify({ ctl: 'laser', p, g }))
  }
  return true
}

/** Sign and send a black-screen frame over any open WebSocket. */
export async function sendBlack(ws: WebSocket | null, signerPriv: string, on: boolean): Promise<boolean> {
  if (!ws || ws.readyState !== WebSocket.OPEN) return false
  const g = await signText(signerPriv, 'black.' + (on ? 'on' : 'off'))
  ws.send(JSON.stringify({ ctl: 'black', on: on ? 1 : 0, g }))
  return true
}

/** 10-char broadcast room derived from the presenter's signing key — the
 *  owner key (owner deck), the invite key (a shared editor copy — per-copy
 *  unique), or a device-local broadcast key. Every copy of a deck therefore
 *  broadcasts into its own room. A name starting with 'w' would be mistaken
 *  for a signed collab room by the relay (name commitment check), so re-hash
 *  until it doesn't. */
export async function broadcastRoom(seed: string): Promise<string> {
  let name = ''
  do {
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(seed)))
    name = b64u.enc(d).slice(0, 10)
    seed = name
  } while (name[0] === 'w')
  return name
}

/** 18-char relay token derived from the room name — presenter and viewers
 *  compute the same value, so the shareable URL carries no tok. */
export async function broadcastTok(room: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(room)))
  return b64u.enc(d).slice(0, 18)
}

/** Full URL of a hosted broadcast client pointed at these credentials. The
 *  hosted copy lives at `hostClient`; the query selects the room (no tok —
 *  viewers derive it from the room name). */
export function hostedLink(hostClient: string, room: string): string {
  return `${hostClient.replace(/\/+$/, '')}?room=${room}`
}

/** Relay origin a room URL lives on (ws://host or wss://host). */
function relayFromUrl(roomUrl: string): string {
  try {
    return new URL(roomUrl.replace(/^ws/, 'http')).origin.replace(/^http/, 'ws')
  } catch {
    return syncHost()
  }
}

/**
 * Resolve broadcast credentials for a document.
 *
 * The room is derived from the presenter's signing key, so every copy of a
 * deck broadcasts into its own room:
 *
 * Case 1: the deck has a signed collab room and this copy holds the owner key
 * (v2 `ownerPriv` or legacy `writerPriv`) — sign with it.
 *
 * Case 1.5: a shared editor copy (v2 `invite`) — sign with the per-copy
 * invite key, so each invitee's room is unique to their copy.
 *
 * Case 2: everything else. Reads/caches a broadcast-only owner keypair in
 * localStorage under `bento-broadcast-<docId>`. Per-machine by design — the
 * private key never leaves the device.
 */
export async function resolveBroadcastCreds(doc: BentoDoc, docId: string): Promise<BroadcastCreds> {
  const c = doc.collab
  // The broadcast room is derived from the presenter's SIGNING key — the key
  // this copy signs control frames with. Owner deck → owner key; a shared
  // editor copy → its per-copy invite key; legacy → the shared writer key;
  // everything else → a device-local broadcast key. Each copy of a deck
  // therefore broadcasts into its own room (the relay TOFUs the same key).
  // The room lives on the same relay as the deck's collab room (they can
  // differ when a deck's room was minted on a local/override relay).
  const relay = c?.room ? relayFromUrl(c.room) : syncHost()
  let signerPub: string
  let signerPriv: string
  if (c?.room && c.key && ((c.v === 2 && c.ownerPriv) || c.writerPriv)) {
    // Case 1: owner-signing copy of a signed room — sign with the owner key.
    signerPub = (c.v === 2 && c.owner) ? c.owner : c.writerPub!
    signerPriv = (c.v === 2 && c.ownerPriv) ? c.ownerPriv : c.writerPriv!
  } else if (c?.room && c.key && c.v === 2 && c.invite) {
    // Case 1.5: a shared editor copy — sign with its per-copy invite key, so
    // every invitee broadcasts into their own room.
    signerPub = c.invite.pub
    signerPriv = c.invite.priv
  } else {
    // Case 2: mint/cache a device-local broadcast-only owner keypair.
    const k = `bento-broadcast-${docId}`
    let saved: { pub: string; priv: string } | null = null
    try {
      const raw = lsGet(k)
      if (raw) saved = JSON.parse(raw)
    } catch { /* storage unavailable → mint ephemeral */ }
    if (!saved) {
      const id = await mintKeypair()
      saved = { pub: id.pub, priv: id.priv }
      try { lsSet(k, JSON.stringify(saved)) } catch { /* storage unavailable */ }
    }
    signerPub = saved.pub
    signerPriv = saved.priv
  }
  const roomName = await broadcastRoom(signerPub)
  const tok = await broadcastTok(roomName)
  return {
    room: `${relay}/d/${roomName}`,
    roomName,
    tok,
    relay,
    signerPub,
    signerPriv,
    isOwner: true,
  }
}
