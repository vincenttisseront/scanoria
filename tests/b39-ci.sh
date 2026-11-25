#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b39-ci — intégration CI de la 0.8 (chantier C), sans root ni conteneur :
#   1. jetons OIDC hostiles (J4) contre server/ci/jwt.ts : alg none, HS256
#      signé avec la clé publique, alg non autorisé, clé embarquée ou
#      désignée par URL, kid inconnu, autre clé, jeton géant, iss, aud, exp,
#      nbf, durée de vie, revendications de dépôt et de ref piégées ;
#   2. modèles CI officiels (J3) : actionlint et zizmor (persona pedantic,
#      hors ligne) sur les workflows et actions GitHub et Forgejo, sans aucun
#      résultat ni résultat masqué ; YAML lisible ; actions épinglées par
#      empreinte, images par @sha256, aucune adresse http:// ni secret ;
#      ShellCheck et sh -n sur scanoria-ci.sh ;
#   3. scanoria-scan --oidc : jeton lu dans l'environnement de la CI
#      seulement, service de jetons en http:// refusé, jeton mal formé
#      refusé, jeton jamais répété dans la sortie.
# Seule exception d'actionlint, documentée : la clé de job propre à Forgejo
# « enable-openid-connect » et l'étiquette de runner « docker », inconnues
# d'actionlint (dialecte GitHub). zizmor les lit sans remarque.
# Dépendances : bash, node (≥ 22.6), python3, python3-yaml, jq, actionlint,
# zizmor, shellcheck.

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CI="$ROOT/webui/server/ci"
TPL="$ROOT/src/rootfs/usr/share/scanoria/ci-templates"
CLIENT="$ROOT/src/rootfs/usr/share/scanoria/client/scanoria-scan"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

ok() { echo + >> "$TMP/tally"; printf 'ok   %s\n' "$1"; }
ko() { echo - >> "$TMP/tally"; printf 'FAIL %s\n' "$1"; }
for t in node python3 jq actionlint zizmor shellcheck curl; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done
report() {
	while IFS= read -r line; do
		case "$line" in
			"ok "*) ok "${line#ok }" ;;
			"ko "*) ko "${line#ko }" ;;
			*) printf '     %s\n' "$line" ;;
		esac
	done
}
js() { node --experimental-strip-types --no-warnings --input-type=module - "$CI" || echo "ko bloc JavaScript interrompu (code $?)"; }

# --- 1. Jetons OIDC hostiles ------------------------------------------------------------------
js << 'EOF' | report
const dir = process.argv[2]
const { createHmac, createSign, generateKeyPairSync, sign } = await import('node:crypto')
const J = await import(`${dir}/jwt.ts`)
const check = (label, cond) => console.log(`${cond ? 'ok' : 'ko'} ${label}`)
const b64 = o => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url')
const ISS = 'https://forge.exemple.test/api/actions'
const now = Math.floor(Date.now() / 1000)
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' })
const other = generateKeyPairSync('rsa', { modulusLength: 2048 })
const jwk = (k, kid, alg) => ({ ...k.publicKey.export({ format: 'jwk' }), kid, alg, use: 'sig' })
const jwks = { keys: [jwk(rsa, 'k-rsa', 'RS256'), jwk(ec, 'k-ec', 'ES256')] }
const claims = (c = {}) => ({ iss: ISS, aud: 'scanoria', iat: now, nbf: now, exp: now + 600, repository: 'equipe/app', ref: 'refs/heads/main', ...c })
function rs(key, payload, header = {}) {
  const h = { alg: 'RS256', typ: 'JWT', kid: 'k-rsa', ...header }
  const input = `${b64(h)}.${b64(payload)}`
  return `${input}.${createSign('RSA-SHA256').update(input).sign(key.privateKey).toString('base64url')}`
}
function es(key, payload) {
  const input = `${b64({ alg: 'ES256', kid: 'k-ec' })}.${b64(payload)}`
  return `${input}.${sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`
}
function verify(token) {
  try {
    const jwt = J.parseJwt(token)
    J.verifySignature(jwt, J.candidateKeys(jwks, jwt.header))
    J.checkClaims(jwt.claims, { issuer: ISS, audience: 'scanoria', nowS: now })
    J.ciClaims('forgejo', jwt.claims)
    return 'ok'
  }
  catch (err) {
    return err.code ?? String(err)
  }
}
check('OIDC : RS256 valide accepté', verify(rs(rsa, claims())) === 'ok')
check('OIDC : ES256 valide accepté', verify(es(ec, claims())) === 'ok')
const pub = rsa.publicKey.export({ format: 'pem', type: 'spki' })
const hsInput = `${b64({ alg: 'HS256', kid: 'k-rsa' })}.${b64(claims())}`
const hostile = {
  'alg none sans signature': `${b64({ alg: 'none' })}.${b64(claims())}.`,
  'alg « None »': `${b64({ alg: 'None' })}.${b64(claims())}.`,
  'HS256 signé avec la clé publique': `${hsInput}.${createHmac('sha256', pub).update(hsInput).digest('base64url')}`,
  'RS512 non autorisé': rs(rsa, claims(), { alg: 'RS512' }),
  'clé embarquée (jwk)': rs(other, claims(), { jwk: jwk(other, 'x', 'RS256') }),
  'clé par URL (jku)': rs(other, claims(), { jku: 'https://piege.exemple.test/jwks' }),
  'certificat embarqué (x5c)': rs(other, claims(), { x5c: ['AAAA'] }),
  'kid inconnu': rs(rsa, claims(), { kid: 'inconnu' }),
  'kid piégé (chemin)': rs(rsa, claims(), { kid: '../../etc/passwd\u0000' }),
  'signature d’une autre clé': rs(other, claims()),
  'charge modifiée après signature': (() => { const p = rs(rsa, claims()).split('.'); p[1] = b64(claims({ repository: 'equipe/autre' })); return p.join('.') })(),
  'jeton géant': `${b64({ alg: 'RS256' })}.${'A'.repeat(J.MAX_JWT_BYTES)}.AAAA`,
  'quatre segments': `${rs(rsa, claims())}.AAAA`,
  'autre émetteur': rs(rsa, claims({ iss: 'https://piege.exemple.test' })),
  'audience de la forge': rs(rsa, claims({ aud: 'https://forge.exemple.test/equipe' })),
  'expiré': rs(rsa, claims({ exp: now - J.CLOCK_SKEW_S - 5 })),
  'pas encore valide': rs(rsa, claims({ nbf: now + J.CLOCK_SKEW_S + 30 })),
  'sans exp': rs(rsa, claims({ exp: undefined })),
  'durée de vie de plusieurs jours': rs(rsa, claims({ exp: now + 5 * 86400 })),
  'dépôt « ../etc »': rs(rsa, claims({ repository: '../etc' })),
  'dépôt avec segment « .. »': rs(rsa, claims({ repository: 'equipe/../admin' })),
  'ref sans refs/': rs(rsa, claims({ ref: 'main' })),
  'ref avec « .. »': rs(rsa, claims({ ref: 'refs/heads/../tags/v1' })),
}
for (const [label, token] of Object.entries(hostile)) {
  const r = verify(token)
  check(`OIDC : ${label} refusé (${r})`, r !== 'ok' && r.startsWith('E_OIDC_'))
}
check('OIDC : motif refs/tags/* sans tag vide', J.refMatches('refs/tags/*', 'refs/tags/v1') && !J.refMatches('refs/tags/*', 'refs/tags/') && !J.refMatches('refs/*/main', 'refs/heads/main'))
check('OIDC : GitLab, ref courte et ref_type obligatoires', (() => { try { J.ciClaims('gitlab', { project_path: 'g/app', ref: 'main' }); return false } catch { return true } })())
EOF

# --- 2. Modèles CI officiels ------------------------------------------------------------------
# Disposition d'un dépôt réel : workflows et script de l'étape à leur place.
lint="$TMP/repo"
mkdir -p "$lint/.github/workflows" "$lint/.github/scanoria" "$lint/.forgejo/workflows" "$lint/.forgejo/scanoria" "$lint/actions/github" "$lint/actions/forgejo"
cp "$TPL/github/scanoria.yml" "$lint/.github/workflows/scanoria.yml"
cp "$TPL/forgejo/scanoria.yml" "$lint/.forgejo/workflows/scanoria.yml"
cp "$TPL/scanoria-ci.sh" "$lint/.github/scanoria/scanoria-ci.sh"
cp "$TPL/scanoria-ci.sh" "$lint/.forgejo/scanoria/scanoria-ci.sh"
cp "$TPL/github/action.yml" "$lint/actions/github/action.yml"
cp "$TPL/forgejo/action.yml" "$lint/actions/forgejo/action.yml"
printf 'self-hosted-runner:\n  labels: [docker]\n' > "$TMP/actionlint-forgejo.yaml"

if (cd "$lint" && actionlint -no-color .github/workflows/scanoria.yml) > "$TMP/al-gh" 2>&1; then
	ok "modèles : actionlint sans remarque sur le workflow GitHub"
else
	ko "modèles : actionlint sur le workflow GitHub"; sed 's/^/     /' "$TMP/al-gh"
fi
if (cd "$lint" && actionlint -no-color -config-file "$TMP/actionlint-forgejo.yaml" \
	-ignore 'unexpected key "enable-openid-connect" for "job" section' .forgejo/workflows/scanoria.yml) > "$TMP/al-fj" 2>&1; then
	ok "modèles : actionlint sans remarque sur le workflow Forgejo (clé enable-openid-connect seule tolérée)"
else
	ko "modèles : actionlint sur le workflow Forgejo"; sed 's/^/     /' "$TMP/al-fj"
fi
# Persona pedantic : tous les audits, sans masquer les remarques de faible confiance.
if (cd "$lint" && zizmor --offline --no-progress --persona=pedantic --format=plain \
	.github/workflows/scanoria.yml .forgejo/workflows/scanoria.yml actions/github/action.yml actions/forgejo/action.yml) > "$TMP/zz" 2>&1 \
	&& grep -q 'No findings to report' "$TMP/zz" && ! grep -q 'suppressed' "$TMP/zz"; then
	ok "modèles : zizmor (pedantic) sans aucun résultat ni résultat masqué"
else
	ko "modèles : zizmor"; sed 's/^/     /' "$TMP/zz"
fi

python3 -I -B - "$TPL" << 'EOF' | report
import pathlib, re, sys, yaml
tpl = pathlib.Path(sys.argv[1])
def check(label, cond):
    print(f"{'ok' if cond else 'ko'} {label}")
ymls = sorted(p for p in tpl.rglob('*') if p.suffix in ('.yml', '.yaml'))
for p in ymls:
    try:
        docs = [d for d in yaml.safe_load_all(p.read_text()) if d is not None]
        check(f'modèles : {p.relative_to(tpl)} est un YAML valide', len(docs) >= 1)
    except yaml.YAMLError as e:
        check(f'modèles : {p.relative_to(tpl)} est un YAML valide ({e})', False)
files = [p for p in tpl.rglob('*') if p.is_file()]
text = {p: p.read_text() for p in files}
uses = [(p, m) for p, t in text.items() if p.suffix in ('.yml', '.yaml') for m in re.findall(r'^\s*-?\s*uses:\s*([^\s#]+)', t, re.M)]
check('modèles : chaque action épinglée par empreinte (40 caractères hexadécimaux)', uses and all(re.search(r'@[0-9a-f]{40}$', u) for _, u in uses))
images = [(p, m) for p, t in text.items() for m in re.findall(r'(?:image:|default:)\s*"?([a-z0-9.-]+/[^\s"]+:[^\s"]+|alpine[^\s"]*)', t)]
check('modèles : chaque image épinglée par @sha256', images and all('@sha256:' in i for _, i in images))
check('modèles : aucune adresse http:// en clair', not any(re.search(r'http://', t) for t in text.values()))
check('modèles : aucun jeton d’API Scanoria ni secret en dur', not any(re.search(r'scn_[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY', t) for t in text.values()))
check('modèles : exemples génériques seulement (exemple.test)', all(re.findall(r'https://([a-z0-9.-]+)', t) == [] or all(h.endswith('exemple.test') or h in ('github.com', 'docs.zizmor.sh') for h in re.findall(r'https://([a-z0-9.-]+)', t)) for t in text.values()))
gh = yaml.safe_load(text[tpl / 'github/scanoria.yml'])
job = gh['jobs']['scanoria']
check('modèles : workflow GitHub sans droit global, droits minimaux du job', gh.get('permissions') == {} and set(job['permissions']) == {'contents', 'id-token', 'statuses'} and job['permissions']['contents'] == 'read')
check('modèles : checkout sans conserver les identifiants', all(s.get('with', {}).get('persist-credentials') is False for s in job['steps'] if str(s.get('uses', '')).startswith('actions/checkout')))
check('modèles : une seule étape Scanoria qui appelle scanoria-ci.sh', sum('scanoria-ci.sh' in str(s.get('run', '')) for s in job['steps']) == 1)
fj = yaml.safe_load(text[tpl / 'forgejo/scanoria.yml'])
check('modèles : workflow Forgejo, jeton OIDC par enable-openid-connect', fj['jobs']['scanoria'].get('enable-openid-connect') is True and 'id-token' not in fj['jobs']['scanoria']['permissions'])
gl = list(yaml.safe_load_all(text[tpl / 'gitlab/scanoria.yml']))
job = next(v for d in gl for k, v in d.items() if isinstance(v, dict) and 'script' in v)
check('modèles : composant GitLab, id_tokens d’audience scanoria', job['id_tokens']['SCANORIA_ID_TOKEN']['aud'] == 'scanoria')
EOF

if sh -n "$TPL/scanoria-ci.sh" && shellcheck -s sh "$TPL/scanoria-ci.sh" > "$TMP/sc" 2>&1; then
	ok "modèles : scanoria-ci.sh (sh -n, shellcheck)"
else
	ko "modèles : scanoria-ci.sh"; sed 's/^/     /' "$TMP/sc"
fi

# --- 3. scanoria-scan --oidc ------------------------------------------------------------------
fake=$(node -e 'const b=o=>Buffer.from(JSON.stringify(o)).toString("base64url");process.stdout.write(b({alg:"RS256"})+"."+b({sub:"x"})+"."+"c2lnbmF0dXJl")')
run() { env -i PATH="$PATH" HOME="$TMP" "$@" sh "$CLIENT" --url https://analyse.exemple.test --project 00000000-0000-4000-8000-000000000000 --ref refs/heads/main --oidc > "$TMP/out" 2>&1 && echo 0 || echo $?; }
rc=$(run)
if [[ $rc == 3 ]] && grep -q 'aucun jeton OIDC' "$TMP/out"; then ok "client : --oidc sans jeton de la CI → erreur 3"; else ko "client : --oidc sans jeton (code $rc)"; cat "$TMP/out"; fi
# Adresse en clair assemblée à l'exécution : aucune URL en clair écrite dans le dépôt.
clear_url=$(printf '%s:%s' 'http' '//192.0.2.10/token')
rc=$(run ACTIONS_ID_TOKEN_REQUEST_URL="$clear_url" ACTIONS_ID_TOKEN_REQUEST_TOKEN=abc)
if [[ $rc == 3 ]] && grep -q 'service de jetons OIDC en http' "$TMP/out" && grep -q 'refusé' "$TMP/out"; then ok "client : service de jetons en clair refusé"; else ko "client : service de jetons en clair (code $rc)"; cat "$TMP/out"; fi
rc=$(run ACTIONS_ID_TOKEN_REQUEST_URL='file:///etc/passwd' ACTIONS_ID_TOKEN_REQUEST_TOKEN=abc)
if [[ $rc == 3 ]] && grep -q 'ACTIONS_ID_TOKEN_REQUEST_URL invalide' "$TMP/out"; then ok "client : adresse de service file:// refusée"; else ko "client : file:// (code $rc)"; cat "$TMP/out"; fi
rc=$(run SCANORIA_ID_TOKEN='pas un jeton; rm -rf /')
if [[ $rc == 3 ]] && grep -q 'jeton OIDC mal formé' "$TMP/out"; then ok "client : jeton OIDC mal formé refusé"; else ko "client : jeton mal formé (code $rc)"; cat "$TMP/out"; fi
rc=$(run SCANORIA_ID_TOKEN="$(printf 'a%.0s' $(seq 1 9000)).b.c")
if [[ $rc == 3 ]]; then ok "client : jeton OIDC géant refusé"; else ko "client : jeton géant (code $rc)"; fi
# Jeton bien formé, console injoignable (adresse de documentation) : erreur
# réseau, et le jeton n'apparaît jamais dans la sortie.
rc=$(env -i PATH="$PATH" HOME="$TMP" SCANORIA_ID_TOKEN="$fake" timeout 60 sh "$CLIENT" --url https://192.0.2.1 --project 00000000-0000-4000-8000-000000000000 --ref refs/heads/main --oidc --timeout 5 > "$TMP/out" 2>&1 && echo 0 || echo $?)
if [[ $rc != 0 ]] && ! grep -qF "$fake" "$TMP/out" && ! grep -q 'c2lnbmF0dXJl' "$TMP/out"; then ok "client : jeton OIDC jamais répété dans la sortie"; else ko "client : jeton dans la sortie (code $rc)"; cat "$TMP/out"; fi
# Aucune option qui prendrait le jeton en argument (visible dans ps et les journaux).
if grep -q 'SCANORIA_ID_TOKEN' "$CLIENT" && ! grep -Eq -- '^ *--(id-)?token\)' "$CLIENT" && sh -n "$CLIENT"; then ok "client : jeton lu dans l'environnement seulement"; else ko "client : lecture du jeton"; fi

# --- Bilan ------------------------------------------------------------------------------------
pass=$(grep -c '+' "$TMP/tally" || true)
fail=$(grep -c -- '-' "$TMP/tally" || true)
echo "b39-ci : $pass réussis, $fail échoués"
[[ $fail -eq 0 ]]
