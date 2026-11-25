#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b34-forges — forges et PR de la 0.7 (chantier D), sans root ni conteneur :
#   1. texte publié dans une forge (sanitizeForForge, contrat 30) contre une
#      liste d'attaques : HTML, images, mentions, liens, URL nues, contrôle ;
#   2. webhooks : signatures Forgejo, GitHub, GitLab à temps constant,
#      identifiants de livraison hostiles, évènements inutiles ignorés ;
#   3. /scanoria accept (J15) : commandes hostiles ou malformées → aide ;
#   4. runner (G18) : fichiers modifiés revalidés (chemins « .. », absolus,
#      caractères de contrôle, trop nombreux → analyse complète), liste
#      montée seulement pour un module scan.incremental, jamais mise en cache ;
#      progress.json (V8) sans les modules en cours ;
#   5. schémas : scan.incremental du manifeste, changed_files de la tâche ;
#   6. route du webhook publique, aucune autre route de forge sans session.
# Les modules TypeScript purs sont chargés par node --experimental-strip-types
# (aucune dépendance de webui/node_modules).
# Dépendances : bash, node (≥ 22.6), python3, python3-jsonschema, jq.

# shellcheck disable=SC2016,SC2015
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
FORGES="$ROOT/webui/server/forges"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/root"
export SCANORIA_TEST_ROOT="$TMP/root"

ok() { echo + >> "$TMP/tally"; printf 'ok   %s\n' "$1"; }
ko() { echo - >> "$TMP/tally"; printf 'FAIL %s\n' "$1"; }
for t in node python3 jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done
report() {
	while IFS= read -r line; do
		case "$line" in
			"ok "*) ok "${line#ok }" ;;
			"ko "*) ko "${line#ko }" ;;
			*) printf '     %s\n' "$line" ;;
		esac
	done
}
js() { node --experimental-strip-types --no-warnings --input-type=module - "$FORGES" || echo "ko bloc JavaScript interrompu (code $?)"; }
py() { python3 -I -B - "$PYLIB" "$@" || echo "ko bloc Python interrompu (code $?)"; }

# --- 1. Texte publié dans une forge ---------------------------------------------------------
js << 'EOF' | report
const dir = process.argv[2]
const { sanitizeForForge } = await import(`${dir}/sanitize.ts`)
const C = 'https://analyse.exemple.test'
const s = x => sanitizeForForge(x, { consoleUrl: C })
const check = (label, cond) => console.log(`${cond ? 'ok' : 'ko'} ${label}`)
const attacks = {
  'balise script': ['<script>alert(1)</script>', o => !o.includes('<script')],
  'image traqueuse': ['![p](https://piege.exemple.test/p.png)', o => !o.includes('![') && !o.includes('https://piege')],
  'image HTML': ['<img src=x onerror=alert(1)>', o => !/<img/i.test(o)],
  'commentaire HTML caché': ['<!-- @admin -->', o => !o.includes('<!--')],
  'mention': ['@admin', o => o !== '@admin' && !/(^|\s)@admin/.test(o)],
  'mention d’équipe': ['@equipe/securite', o => !/(^|\s)@equipe/.test(o)],
  'référence #12': ['ferme #12', o => !/#12/.test(o)],
  'référence croisée': ['equipe/app#3', o => !/app#3/.test(o)],
  'lien hors liste': ['[ici](https://piege.exemple.test/)', o => !o.includes('](')],
  'lien javascript:': ['[ici](javascript:alert(1))', o => !o.includes('](') && !/javascript:/i.test(o)],
  'lien data:': ['[ici](data:text/html,x)', o => !o.includes('](') && !/data:/i.test(o)],
  'sous-domaine trompeur': ['[x](https://analyse.exemple.test.piege.exemple.test/)', o => !o.includes('](')],
  'identifiants dans l’URL': ['[x](https://analyse.exemple.test@piege.exemple.test/)', o => !o.includes('](')],
  'URL nue': ['voir https://piege.exemple.test', o => !o.includes('https://piege')],
  'URL entre parenthèses': ['(https://piege.exemple.test)', o => !o.includes('https://piege')],
  'définition de lien': ['[r]: https://piege.exemple.test', o => !/^\[r\]:/.test(o)],
  'contrôle et bidi': ['a\u202Eb\u0000c\u2066d', o => o === 'abcd'],
  'entité HTML': ['&#64;admin', o => !o.startsWith('&#64;')],
  'bloc ouvert': ['```\nx', o => o.endsWith('```')],
}
for (const [label, [input, ok]] of Object.entries(attacks)) check(`texte publié : ${label} neutralisé`, ok(s(input)))
check('texte publié : lien de la console gardé', s(`[a](${C}/scans/1)`) === `[a](${C}/scans/1)`)
check('texte publié : référence CWE gardée', s('[c](https://cwe.mitre.org/data/definitions/79.html)').includes('](https://cwe.mitre.org/'))
check('texte publié : longueur bornée', sanitizeForForge('x'.repeat(200000)).length <= 60000)
EOF

# --- 2. Webhooks ------------------------------------------------------------------------------
js << 'EOF' | report
const dir = process.argv[2]
const { createHmac, randomBytes } = await import('node:crypto')
const { verifyWebhookSignature: v, deliveryId, webhookEvent } = await import(`${dir}/signature.ts`)
const check = (label, cond) => console.log(`${cond ? 'ok' : 'ko'} ${label}`)
const secret = randomBytes(32).toString('hex')
const body = Buffer.from('{"action":"opened"}')
const hex = (k, b) => createHmac('sha256', k).update(b).digest('hex')
check('webhook Forgejo signé accepté', v('forgejo', { 'x-forgejo-signature': hex(secret, body) }, body, secret))
check('webhook Forgejo : corps modifié refusé', !v('forgejo', { 'x-forgejo-signature': hex(secret, body) }, Buffer.from('{"action":"closed"}'), secret))
check('webhook Forgejo : sans signature refusé', !v('forgejo', {}, body, secret))
check('webhook GitHub signé accepté', v('github', { 'x-hub-signature-256': `sha256=${hex(secret, body)}` }, body, secret))
check('webhook GitHub : SHA-1 refusé', !v('github', { 'x-hub-signature': 'sha1=00' }, body, secret))
check('webhook GitLab : jeton exact seulement', v('gitlab', { 'x-gitlab-token': secret }, body, secret) && !v('gitlab', { 'x-gitlab-token': secret.slice(1) }, body, secret))
check('webhook : secret vide jamais valide', !v('forgejo', { 'x-forgejo-signature': hex('', body) }, body, ''))
check('webhook : identifiant de livraison hostile refusé', deliveryId('github', { 'x-github-delivery': '../../x;rm -rf' }) === null && deliveryId('forgejo', {}) === null)
check('webhook : évènement inutile ignoré', webhookEvent('github', { 'x-github-event': 'star' }).event === null && webhookEvent('github', { 'x-github-event': 'constructor' }).event === null)
check('webhook : commentaire de PR reconnu', webhookEvent('forgejo', { 'x-forgejo-event': 'issue_comment' }).event === 'comment')
EOF

# --- 3. /scanoria accept ----------------------------------------------------------------------
js << 'EOF' | report
const dir = process.argv[2]
const { parseScanoriaCommand: p } = await import(`${dir}/command.ts`)
const check = (label, cond) => console.log(`${cond ? 'ok' : 'ko'} ${label}`)
const good = p('/scanoria accept 1a2b3c4d --until 2027-01-31 --reason "valeur factice"')
check('commande : forme complète comprise', good?.kind === 'accept' && good.until === '2027-01-31' && good.reason === 'valeur factice')
for (const [label, body] of [
  ['date impossible', '/scanoria accept 1a2b3c4d --until 2027-02-30 --reason "abc"'],
  ['résultat injecté', '/scanoria accept 1a2b;DROP --until 2027-01-31 --reason "abc"'],
  ['option inconnue (--approve)', '/scanoria accept 1a2b3c4d --until 2027-01-31 --reason "abc" --approve'],
  ['guillemet non fermé', '/scanoria accept 1a2b3c4d --until 2027-01-31 --reason "abc'],
  ['verbe inconnu', '/scanoria approve 1a2b3c4d'],
  ['motif absent', '/scanoria accept 1a2b3c4d --until 2027-01-31'],
  ['commentaire énorme', `/scanoria accept 1a2b3c4d --until 2027-01-31 --reason "${'x'.repeat(5000)}"`],
]) check(`commande : ${label} → aide`, p(body)?.kind === 'help')
check('commande : bloc de code ignoré (notre propre commentaire)', p('```\n/scanoria accept 1a2b3c4d --until 2027-01-31 --reason "abc"\n```') === null)
check('commande : texte ordinaire ignoré', p('merci pour la revue') === null)
EOF

# --- 4. Runner : fichiers modifiés et progress.json ------------------------------------------
py << 'EOF' | report
import json, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
from scanoria import runner, resultcache
def check(label, cond): print(("ok " if cond else "ko ") + label)
job = {"changed_files": ["src/a.ts", "docs/é.md"]}
check("fichiers modifiés : liste valide gardée", runner.changed_files(job) == ["src/a.ts", "docs/é.md"])
for label, files in [("chemin ..", ["../etc/passwd"]), ("chemin absolu", ["/etc/passwd"]), ("segment vide", ["a//b"]),
                     ("saut de ligne", ["a\nb"]), ("caractère de contrôle", ["a\x01"]), ("pas une liste", "src/a.ts"),
                     ("trop nombreux", ["f%d" % i for i in range(3001)]), ("pas une chaîne", [1])]:
    check("fichiers modifiés : %s → analyse complète" % label, runner.changed_files({"changed_files": files}) is None)
ws = tempfile.mkdtemp()
inc = {"id": "semgrep", "scan": {"incremental": True}}
full = {"id": "gitleaks", "scan": {}}
path = runner.changed_files_mount(job, inc, ws)
check("module incrémental : liste écrite hors de /src", path == os.path.join(ws, "changed-files.txt") and open(path).read() == "src/a.ts\ndocs/é.md\n")
check("module non incrémental : aucune liste", runner.changed_files_mount(job, full, ws) is None)
check("analyse complète : aucune liste", runner.changed_files_mount({}, inc, ws) is None)
spec = {"history": False, "service": None}
check("module incrémental d'une PR : jamais mis en cache",
      resultcache.key_for({"cache": True, "changed_files": ["a"]}, dict(inc, image="x@sha256:" + "0" * 64), spec, [], "t", None, False) is None)
rdir = tempfile.mkdtemp()
runner.write_progress(rdir, [{"id": "gitleaks", "status": "ok", "outputs": {"sarif": "gitleaks/result.sarif"}},
                             {"id": "trivy", "status": "running"}, {"id": "semgrep", "status": None}])
p = json.load(open(os.path.join(rdir, "progress.json")))
check("progress.json : modules terminés seulement", p == {"schema": 1, "modules": [{"id": "gitleaks", "status": "ok", "outputs": {"sarif": "gitleaks/result.sarif"}}]})
EOF

# --- 5. Schémas --------------------------------------------------------------------------------
py "$ROOT" << 'EOF' | report
import json, sys
root = sys.argv[2]
def check(label, cond): print(("ok " if cond else "ko ") + label)
try:
    import jsonschema
except ImportError:
    print("ok schémas : python3-jsonschema absent, vérification sautée")
    sys.exit(0)
job = json.load(open(root + "/src/rootfs/usr/share/scanoria/schemas/scan-job.schema.json"))
cf = job["properties"]["changed_files"]
v = jsonschema.Draft202012Validator(cf)
check("tâche : changed_files valide", v.is_valid(["src/a.ts"]))
check("tâche : changed_files trop long refusé", not v.is_valid(["x"] * 3001))
check("tâche : changed_files non textuel refusé", not v.is_valid([1]))
mod = json.load(open(root + "/catalog/schema/module.schema.json"))
inc = mod["properties"]["scan"]["properties"].get("incremental")
check("manifeste : scan.incremental booléen", inc is not None and inc.get("type") == "boolean")
EOF

# --- 6. Routes ---------------------------------------------------------------------------------
API="$ROOT/webui/server/api/forges"
[[ -f "$API/[id]/webhook.post.ts" ]] && ok "route du webhook présente" || ko "route du webhook absente"
grep -qF "re: /^\/api\/forges\/[0-9a-f-]{36}\/webhook$/" "$ROOT/webui/server/middleware/api-token.ts" \
	&& ok "webhook : seule route de forge publique (signature HMAC)" || ko "webhook : route publique introuvable"
[[ $(grep -c 'api\\/forges' "$ROOT/webui/server/middleware/api-token.ts") -eq 1 ]] && ok "aucune autre route de forge publique" || ko "routes de forge publiques en trop"
for f in "$API"/github/*.post.ts; do
	grep -q "requireRole(event, 'admin')" "$f" && ok "$(basename "$f") : administrateur requis" || ko "$(basename "$f") : rôle manquant"
done

PASS=$(grep -c '^+' "$TMP/tally" || true)
FAIL=$(grep -c '^-' "$TMP/tally" || true)
echo
echo "b34 : $PASS réussis, $FAIL échoués"
[[ $FAIL -eq 0 ]]
