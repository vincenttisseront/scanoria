// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Analyses de PR (G18, contrat 33) et commande /scanoria accept (J15, côté
// forge), communes au webhook et à l'interrogation (mode tiré).
// - Une PR ouverte ou mise à jour met en file une analyse de son commit de
//   tête, ref refs/pull/<n>/head (Forgejo, GitHub) ou
//   refs/merge-requests/<n>/head (GitLab), avec ses fichiers modifiés ;
// - un commentaire /scanoria accept devient une DEMANDE d'exception
//   (contrat 27, requested_via 'pr-comment') : l'auteur du commentaire est
//   l'identité de la forge, jamais un approbateur. Une commande malformée
//   reçoit une aide ; aucune exception n'est créée.

import type pg from 'pg'
import type { Queryable } from '../utils/db'
import { enqueueScan } from '../scans/enqueue'
import { MAX_CHANGED_FILES, type PullRequestRef } from './pr-types'
import type { ProjectForge } from './context'
import { parseScanoriaCommand, type CommandError } from './command'
import { requestPrException } from './exceptions-bridge'
import { forgeLocale } from './publish'
import { shortId } from './summary'

type Db = Queryable & Pick<pg.Pool, 'connect'>

export function pullRequestRef(kind: 'forgejo' | 'github' | 'gitlab', number: number): string {
  return kind === 'gitlab' ? `refs/merge-requests/${number}/head` : `refs/pull/${number}/head`
}

export interface ProjectRow { id: string, forge_id: string, repo_full_name: string }

/** Projet actif d'un dépôt de la forge (ni archivé ni suspendu), ou null. */
export async function projectForRepo(db: Queryable, forgeId: string, repo: string): Promise<ProjectRow | null> {
  const r = await db.query<ProjectRow>(
    `SELECT id, forge_id::text, repo_full_name FROM projects
      WHERE forge_id = $1 AND lower(repo_full_name) = lower($2) AND archived_at IS NULL AND suspended_at IS NULL`,
    [forgeId, repo])
  return r.rows[0] ?? null
}

/**
 * Met en file l'analyse d'une PR. Les fichiers modifiés viennent de la forge
 * (bornés) : au-delà de la borne, l'analyse reste complète. Une PR brouillon
 * est analysée aussi (le retour arrive avant la revue).
 */
export async function enqueuePullRequestScan(db: Db, ctx: ProjectForge, pr: PullRequestRef): Promise<{ scanId: string, merged: boolean } | null> {
  // Déjà analysée ou en file pour ce commit de tête : rien de plus.
  const seen = await db.query(
    `SELECT 1 FROM scans WHERE project_id = $1 AND commit_sha = $2 AND pull_request IS NOT NULL
        AND (pull_request ->> 'number')::bigint = $3 AND status NOT IN ('cancelled', 'error') LIMIT 1`,
    [ctx.projectId, pr.head_sha, pr.number])
  if (seen.rowCount) return null
  let changed: string[] | undefined
  try {
    const c = await ctx.publisher.changedFiles(ctx.repo, pr.number, MAX_CHANGED_FILES)
    changed = c.truncated ? undefined : c.files
  }
  catch {
    changed = undefined // forge muette : analyse complète (jamais moins)
  }
  const pullRequest = {
    number: pr.number, base_sha: pr.base_sha, base_ref: pr.base_ref, head_sha: pr.head_sha, head_ref: pr.head_ref, author: pr.author,
    ...(changed ? { changed_files: changed } : {}),
  }
  // G9 : profil des PR du projet (migration 014), sinon le profil par défaut du projet.
  const prof = await db.query<{ slug: string }>(
    'SELECT pf.slug FROM projects p JOIN profiles pf ON pf.id = p.profile_pr_id WHERE p.id = $1', [ctx.projectId])
  const res = await enqueueScan(db, {
    projectId: ctx.projectId,
    ...(prof.rows[0] ? { profileSlug: prof.rows[0].slug } : {}),
    ref: pullRequestRef(ctx.forge.kind, pr.number),
    commit: pr.head_sha,
    trigger: 'webhook',
    pullRequest,
    incremental: changed !== undefined,
  })
  return { scanId: res.scanId, merged: res.merged }
}

const HELP: Record<'fr' | 'en', Record<CommandError | 'usage', string>> = {
  fr: {
    usage: 'Utilisation : `/scanoria accept <résultat> --until AAAA-MM-JJ --reason "motif"`. Le résultat est l\'identifiant court affiché dans le commentaire de Scanoria.',
    E_CMD_SYNTAX: 'Commande mal formée.',
    E_CMD_FINDING: 'Résultat absent ou mal écrit.',
    E_CMD_UNTIL: 'Date de fin absente ou invalide (AAAA-MM-JJ).',
    E_CMD_REASON: 'Motif absent ou trop court (3 caractères au moins), entre guillemets.',
    E_CMD_UNKNOWN: 'Commande inconnue.',
    E_CMD_TOO_LONG: 'Commentaire trop long.',
  },
  en: {
    usage: 'Usage: `/scanoria accept <finding> --until YYYY-MM-DD --reason "reason"`. The finding is the short identifier shown in the Scanoria comment.',
    E_CMD_SYNTAX: 'Malformed command.',
    E_CMD_FINDING: 'Missing or malformed finding.',
    E_CMD_UNTIL: 'Missing or invalid end date (YYYY-MM-DD).',
    E_CMD_REASON: 'Missing or too short reason (at least 3 characters), in quotes.',
    E_CMD_UNKNOWN: 'Unknown command.',
    E_CMD_TOO_LONG: 'Comment too long.',
  },
}

type ReplyKey = 'requested' | 'approve' | 'note' | 'notFound' | 'ambiguous' | 'malicious' | 'locked' | 'invalid' | 'bot' | 'notAllowed' | 'limited'
const REPLY: Record<'fr' | 'en', Record<ReplyKey, string>> = {
  fr: {
    requested: 'Demande d\'exception enregistrée pour le résultat',
    approve: 'Un administrateur l\'approuve ou la refuse dans la console',
    note: 'La demande ne débloque rien tant qu\'elle n\'est pas approuvée. L\'auteur du commit et les comptes non humains ne peuvent pas approuver.',
    notFound: 'Aucun résultat de cette PR ne correspond à',
    ambiguous: 'Plusieurs résultats correspondent à',
    malicious: 'Un paquet malveillant (MAL-) ne peut jamais faire l\'objet d\'une exception.',
    locked: 'Cette exigence est verrouillée par le profil : aucune exception n\'est possible.',
    invalid: 'Demande refusée : date de fin passée ou à plus d\'un an, ou motif invalide.',
    bot: 'Les commandes des comptes de robots ne sont pas prises en compte.',
    notAllowed: 'Seuls l\'auteur de la PR et les comptes qui ont le droit d\'écriture sur le dépôt peuvent demander une exception.',
    limited: 'Trop de commandes Scanoria de votre part sur cette PR : au plus {n} par heure. Les suivantes sont ignorées jusqu\'à la fin de l\'heure.',
  },
  en: {
    requested: 'Exception request recorded for finding',
    approve: 'An administrator approves or refuses it in the console',
    note: 'The request unblocks nothing until it is approved. The commit author and non-human accounts cannot approve.',
    notFound: 'No finding of this PR matches',
    ambiguous: 'Several findings match',
    malicious: 'A malicious package (MAL-) can never be excepted.',
    locked: 'This requirement is locked by the profile: no exception is possible.',
    invalid: 'Request refused: end date in the past or more than one year ahead, or invalid reason.',
    bot: 'Commands from bot accounts are ignored.',
    notAllowed: 'Only the PR author and accounts with write access to the repository can request an exception.',
    limited: 'Too many Scanoria commands from you on this PR: at most {n} per hour. Further ones are ignored until the hour is over.',
  },
}

/** Auteur de la PR (relu dans la forge si l'analyse ne le porte pas) ou droit d'écriture sur le dépôt. */
async function mayRequest(ctx: ProjectForge, number: number, login: string, knownAuthor: string | null): Promise<boolean> {
  const author = knownAuthor ?? await ctx.publisher.pullRequest(ctx.repo, number).then(p => p.author).catch(() => null)
  if (author && author.toLowerCase() === login.toLowerCase()) return true
  const perm = await ctx.publisher.permission(ctx.repo, login).catch(() => 'none' as const)
  return perm === 'write' || perm === 'admin'
}

/** Compte de service de la forge (jamais une commande : ce sont nos propres réponses). */
async function serviceLogin(db: Queryable, ctx: ProjectForge): Promise<string | null> {
  if (!ctx.forge.credential_id) return null
  const r = await db.query<{ username: string | null }>('SELECT username FROM credentials WHERE id = $1', [ctx.forge.credential_id])
  return r.rows[0]?.username ?? null
}

/** Dernière analyse terminée de la PR (celle dont le commentaire montre les résultats). */
async function latestPrScan(db: Queryable, projectId: string, number: number): Promise<{ id: string, commit_sha: string | null, author: string | null } | null> {
  const r = await db.query<{ id: string, commit_sha: string | null, author: string | null }>(
    `SELECT id, commit_sha, pull_request ->> 'author' AS author FROM scans WHERE project_id = $1 AND pull_request IS NOT NULL
        AND (pull_request ->> 'number')::bigint = $2 AND status = 'done'
      ORDER BY finished_at DESC NULLS LAST LIMIT 1`, [projectId, number])
  return r.rows[0] ?? null
}

/** Résultat de la PR désigné par son identifiant (UUID) ou sa forme courte. */
async function resolveFinding(db: Queryable, scanId: string, ref: string): Promise<{ id: string } | 'none' | 'ambiguous'> {
  const full = /^[0-9a-f]{8}-/.test(ref)
  const r = await db.query<{ id: string }>(
    `SELECT f.id FROM scan_findings sf JOIN findings f ON f.id = sf.finding_id
      WHERE sf.scan_id = $1 AND (${full ? 'f.id = $2::uuid' : `replace(f.id::text, '-', '') LIKE $2 || '%'`}) LIMIT 2`,
    [scanId, ref])
  if (!r.rows.length) return 'none'
  return r.rows.length > 1 ? 'ambiguous' : r.rows[0]!
}

/** Marque des commentaires déjà traités (webhook_deliveries, hors calcul du mode). */
export const COMMENT_SEEN = 'comment-seen'

/** Commandes /scanoria traitées par heure, par PR et par identité de la forge ; au-delà, ignorées. */
export const MAX_COMMANDS_PER_HOUR = 10

export interface CommentInput {
  number: number
  comment: { id: string, author: string | null, author_is_bot: boolean, body: string }
}

/**
 * Traite un commentaire de PR. Rend ce qui a été fait (pour le journal du
 * webhook) ; la réponse est publiée dans la PR par le client (contrat 30).
 */
export async function handlePrComment(db: Queryable, ctx: ProjectForge, input: CommentInput): Promise<'ignored' | 'help' | 'requested' | 'refused' | 'limited'> {
  const cmd = parseScanoriaCommand(input.comment.body)
  if (!cmd) return 'ignored'
  const locale = forgeLocale()
  const t = REPLY[locale]
  const reply = async (text: string) => {
    await ctx.publisher.replyComment(ctx.repo, input.number, text).catch(() => {})
  }
  // Une réponse de Scanoria (ou d'un autre robot) n'est jamais une commande.
  if (input.comment.author_is_bot || !input.comment.author || input.comment.author.toLowerCase() === (await serviceLogin(db, ctx))?.toLowerCase()) {
    return 'ignored'
  }
  // Un commentaire n'est traité qu'une fois, qu'il arrive par webhook ou par interrogation.
  if (!/^[0-9]{1,20}$/.test(input.comment.id)) return 'ignored'
  // La marque porte la PR et l'identité : elle sert aussi à borner le nombre de commandes.
  const who = `cmd:${ctx.projectId}:${input.number}:${input.comment.author.toLowerCase()}`.slice(0, 500)
  const once = await db.query(
    `INSERT INTO webhook_deliveries (forge_id, delivery_id, event, status, detail) VALUES ($1, $2, '${COMMENT_SEEN}', 'ignored', $3)
     ON CONFLICT (forge_id, delivery_id) DO NOTHING`, [ctx.forge.id, `comment:${input.comment.id}`, who])
  if (!once.rowCount) return 'ignored'
  const recent = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM webhook_deliveries
      WHERE forge_id = $1 AND event = '${COMMENT_SEEN}' AND detail = $2 AND received_at > now() - interval '1 hour'`, [ctx.forge.id, who])
  const n = recent.rows[0]?.n ?? 0
  if (n > MAX_COMMANDS_PER_HOUR) {
    // Une seule réponse au premier dépassement : répondre à chaque fois serait aussi une inondation.
    if (n === MAX_COMMANDS_PER_HOUR + 1) await reply(t.limited.replace('{n}', String(MAX_COMMANDS_PER_HOUR)))
    return 'limited'
  }
  if (cmd.kind === 'help') {
    await reply([cmd.error ? HELP[locale][cmd.error] : '', HELP[locale].usage].filter(Boolean).join(' '))
    return 'help'
  }
  const scan = await latestPrScan(db, ctx.projectId, input.number)
  // Dépôt éventuellement public : seuls l'auteur de la PR et les comptes qui
  // peuvent écrire dans le dépôt (lu dans la forge) demandent une exception.
  if (!(await mayRequest(ctx, input.number, input.comment.author, scan?.author ?? null))) {
    await reply(t.notAllowed)
    return 'refused'
  }
  const found = scan ? await resolveFinding(db, scan.id, cmd.finding) : 'none'
  if (found === 'none' || found === 'ambiguous' || !scan) {
    await reply(`${found === 'ambiguous' ? t.ambiguous : t.notFound} \`${cmd.finding}\`. ${HELP[locale].usage}`)
    return 'help'
  }
  // J15 : les auteurs du commit analysé sont lus dans la forge, exclus de l'approbation.
  const authors = scan.commit_sha ? await ctx.publisher.commitAuthors(ctx.repo, scan.commit_sha).catch(() => [] as string[]) : []
  const outcome = await requestPrException(db, {
    projectId: ctx.projectId,
    scanId: scan.id,
    findingId: found.id,
    until: cmd.until,
    reason: cmd.reason,
    requesterLabel: `${ctx.forge.kind}:${input.comment.author}`,
    commitAuthors: authors,
  })
  if (outcome.ok) {
    const url = ctx.consoleUrl ? `${ctx.consoleUrl}/findings/exceptions?project_id=${ctx.projectId}` : null
    await reply(`${t.requested} \`${shortId(found.id)}\` (${cmd.until}). ${t.approve}${url ? ` : [${url}](${url})` : '.'}\n\n${t.note}`)
    return 'requested'
  }
  await reply(outcome.code === 'E_MALICIOUS' ? t.malicious : outcome.code === 'E_LOCKED' ? t.locked : t.invalid)
  return 'refused'
}
