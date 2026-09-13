// SPDX-License-Identifier: MIT
// Copyright (c) 2026 The Bento authors
/**
 * The audience projection — what a live-broadcast audience is allowed to see.
 *
 * An audience member is a collaborator holding a TICKET: an owner-signed
 * `audience` invite plus a per-show SHOW KEY that is separate from the room's
 * read key. Everything the audience receives — the handout file, the join
 * snapshot the relay serves, and every op the presenter streams mid-show — is
 * built by THIS module, so the three can never disagree about what was kept
 * back. (docs/DECISIONS.md, the broadcast entry.)
 *
 * What is kept back: `Slide.notes` (speaker notes) and `Slide.comments`
 * (review threads, documented editor-only). Nothing else. Hidden slides STAY —
 * they are reachable by link and are part of the deck; a presenter who wants
 * a slide out of the handout deletes it. The rest of the deck is the deck: an
 * audience copy is a working file, not a stream.
 *
 * Three enforcement points, one boundary:
 *   1. `projectDoc`  — the handout ("Save audience copy…") AND the `audsnap`
 *                      the relay serves to late joiners. Same function, so a
 *                      handout can never carry what the snapshot strips or
 *                      the other way round.
 *   2. `projectOp`   — every op the presenter's client encrypts under the show
 *                      key mid-show. Without this, a stripped snapshot is
 *                      REPAIRED by the next notes edit arriving as a plain
 *                      property set — the projection would hold for exactly
 *                      as long as nobody typed in the notes panel.
 *   3. the rig       — scripts/test-audience-projection.ts, negative-controlled:
 *                      with AUDIENCE_HIDDEN emptied it must fail.
 *
 * The kernel session applies `projectOp` to the aud stream and calls
 * `projectDoc` for snapshots; it is handed these functions and never learns
 * the field names — the boundary is slides' and lives here only.
 */
import type { BentoDoc, Slide } from './model'
import type { Op } from '../../kernel/src/sync/crdt'

/** Slide-level fields an audience never receives. Comments are slide-level
 *  only in the format; elements carry neither field. */
export const AUDIENCE_HIDDEN: readonly (keyof Slide)[] = ['notes', 'comments']

/** The ticket half that lives in the audience file's `collab`. */
export type AudienceTicket = {
  /** owner-signed invite with role 'audience' — the relay admits on the chain */
  invite: { pub: string; priv: string; role: 'audience'; exp?: number; sig: string }
  /** the per-show symmetric key (b64url raw AES-GCM key), NOT the room key */
  key: string
}

/** Driven by AUDIENCE_HIDDEN at call time — the rig empties that list as
 *  its negative control, and BOTH surfaces (doc and op) must go red. `notes`
 *  is a required string in the format, so it is blanked; anything optional
 *  is deleted. */
function projectSlide(slide: Slide): Slide {
  const out = { ...slide } as Record<string, unknown>
  for (const k of AUDIENCE_HIDDEN) {
    if (k === 'notes') out.notes = ''
    else delete out[k]
  }
  return out as unknown as Slide
}

/**
 * The audience document. Deep-copies; the presenter's doc is untouched.
 *
 * - every slide (interactive states included) and every custom layout goes
 *   through `projectSlide`
 * - `collab` becomes the ticket: same room, `key` = the SHOW key, the
 *   audience invite, role 'reader' (the client's read-only boot path), and no
 *   private halves — `ownerPriv`, `writerPriv` and any writer invite are gone
 * - `blobs` is dropped: blob keys derive from `collab.key`, so a show-key copy
 *   could never open room-key blobs; the bytes are already inline in `assets`
 *   on the presenter (a referenced asset that is NOT in `assets` cannot be
 *   inlined and is reported so the caller can warn)
 * - `readonly` and `template` are cleared: this file boots into the show by
 *   being an audience copy, not by being a player or a template
 */
export function projectDoc(doc: BentoDoc, ticket: AudienceTicket): { doc: BentoDoc; missingAssets: string[] } {
  const src = doc.collab
  if (!src) throw new Error('projectDoc: the presenter deck has no collab block')
  const copy: BentoDoc = JSON.parse(JSON.stringify(doc))
  copy.slides = copy.slides.map(projectSlide)
  if (copy.layouts) copy.layouts = copy.layouts.map(projectSlide)
  const missingAssets: string[] = []
  if (copy.blobs) {
    for (const k of Object.keys(copy.blobs)) if (!copy.assets?.[k]) missingAssets.push(k)
    delete copy.blobs
  }
  delete copy.readonly
  delete copy.template
  copy.collab = {
    room: src.room,
    key: ticket.key,
    on: true,
    role: 'reader',
    ...(src.v !== undefined ? { v: src.v } : {}),
    ...(src.owner !== undefined ? { owner: src.owner } : {}),
    ...(src.writerPub !== undefined ? { writerPub: src.writerPub } : {}),
    // role 'audience' — the kernel's CollabInvite union widens to it with the
    // session change that streams the show; the relay already admits it.
    invite: ticket.invite as unknown as NonNullable<BentoDoc['collab']>['invite'],
  }
  return { doc: copy, missingAssets }
}

/**
 * The op the audience may see, or null.
 *
 * - a `set` of a hidden key on a slide node → null (the audience never learns
 *   the notes changed, let alone what to)
 * - an `ins` of a slide → the same op with the inserted node projected (the
 *   slide must still arrive — minus its notes and comments)
 * - everything else → unchanged. Element ops carry no hidden field; slide
 *   deletes/orders reveal nothing; doc-level sets have no hidden keys.
 */
export function projectOp(op: Op): Op | null {
  if (op.op === 'set' && op.sl !== undefined && op.el === undefined
      && (AUDIENCE_HIDDEN as readonly string[]).includes(op.k)) return null
  if (op.op === 'ins' && op.kind === 'slide') return { ...op, node: projectSlide(op.node as Slide) }
  return op
}

/** True when a document still carries anything the projection removes —
 *  the assertion the export-secrets rig makes about an audience copy. */
export function carriesHidden(doc: BentoDoc): string[] {
  const hits: string[] = []
  const all = [...doc.slides, ...(doc.layouts ?? [])]
  for (const s of all) {
    if (s.notes) hits.push(`${s.id}.notes`)
    if ((s as { comments?: unknown }).comments !== undefined) hits.push(`${s.id}.comments`)
  }
  if (doc.blobs) hits.push('blobs')
  const c = doc.collab
  if (c?.ownerPriv) hits.push('collab.ownerPriv')
  if (c?.writerPriv) hits.push('collab.writerPriv')
  if (c?.invite && (c.invite.role as string) !== 'audience') hits.push(`collab.invite(${c.invite.role})`)
  return hits
}
