#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b26 — vigilance de l'appliance (0.6, chantier B), sans root. Le helper tourne
# en mode test (SCANORIA_TEST_ROOT) ; podman est un bouchon qui journalise.
# Couvre :
# - demandes hostiles self-sbom, run-canaries, start-trial (schéma, injection,
#   module inconnu, version absente de l'index vérifié, image non épinglée,
#   rétrogradation, abandon d'un essai qui n'existe pas) ;
# - images retenues (G6, F13) : versions figées gardées à la mise à jour,
#   jamais retirées par remove_image, enregistrement altéré ignoré, ménage des
#   versions plus figées et des essais oubliés ;
# - pins.json écrit par la console lu sans confiance (lien, taille, JSON) ;
# - résolution du runner (alternate) : installée, retenue, absente (infra) ;
# - canaris (G14) : échec signalé (E_CANARY_FAILED) sans désactiver le module ;
# - self-sbom (F19) sans Syft ni comparateur : trous publiés, demande réussie.
# Dépendances : bash, python3, jq.

# shellcheck disable=SC2016
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

for t in python3 jq; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYLIB="$ROOT/src/rootfs/usr/lib/scanoria/py"
HELPER="$ROOT/src/rootfs/usr/sbin/scanoria-helper"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect() {
	if [[ "$2" == "$3" ]]; then ok "$1"; else ko "$1 (obtenu « $2 », attendu « $3 »)"; fi
}

T="$TMP/root"
STUBS="$TMP/stubs"
CALLS="$TMP/calls.log"
mkdir -p "$T"/var/lib/scanoria/requests/{tmp,incoming,work,done,failed} "$T/var/lib/scanoria/modules" \
	"$T/var/lib/scanoria/console" "$T/run/scanoria" "$T/etc/scanoria" "$T/opt/scanoria/current" "$STUBS"
chmod 0700 "$T/var/lib/scanoria/requests/incoming" "$T/var/lib/scanoria/requests/work"
echo 0.6.0 > "$T/opt/scanoria/current/VERSION"
: > "$CALLS"
export SCANORIA_TEST_ROOT="$T" SCANORIA_TEST_BIN="$STUBS" SCANORIA_TEST_CONSOLE_SBOM="$TMP/console.cdx.json"
export SCANORIA_RUNNER_STATE="$TMP/runner.json"
for c in podman systemctl; do
	cat > "$STUBS/$c" <<-EOF
		#!/bin/bash
		jq -cn --arg c "$c" '[\$c] + \$ARGS.positional' --args -- "\$@" >> "$CALLS"
		exit 0
	EOF
	chmod 0755 "$STUBS/$c"
done
echo '{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "a"}, {"name": "b"}]}' > "$TMP/console.cdx.json"

D1=sha256:$(printf 'a%.0s' {1..64})
D2=sha256:$(printf 'b%.0s' {1..64})
D3=sha256:$(printf 'c%.0s' {1..64})

# py SNIPPET : exécute du Python avec le paquet scanoria et des aides de test.
py() {
	python3 -I -B - "$PYLIB" "$@" <<-EOF
	import json, os, sys
	sys.path.insert(0, sys.argv[1])
	from scanoria import common, modules, vigilance
	from scanoria.common import Fail
	def manifest(ver, digest, mid="gitleaks"):
	    return {"id": mid, "name": mid, "type": "scanner", "version": ver, "categories": ["secrets"],
	            "image": "ghcr.io/exemple/%s@%s" % (mid, digest), "license": {"spdx": "MIT", "restrictions": "none"},
	            "scan": {"command": [mid, "dir", "/src"]}}
	def install(ver, digest, mid="gitleaks", status="healthy", enabled=True):
	    reg = modules.load_registry()
	    reg["modules"][mid] = {"manifest": manifest(ver, digest, mid), "status": status, "enabled": enabled,
	                           "installed_at": "2026-11-24T00:00:00Z", "options": {}, "accepted": "none"}
	    common.write_json(modules.REGISTRY, reg, 0o600, group_scanoria=False)
	    return reg
	def code(fn, *a):
	    try:
	        fn(*a)
	        return "OK"
	    except Fail as f:
	        return f.code
	$1
	EOF
}
hx() {
	R=$("$HELPER" exec --origin cli --type "$1" --params "$2" 2> "$TMP/helper.err") || true
	[[ -n "$R" ]] || { R='{"code":"NO_OUTPUT"}'; sed 's/^/     /' "$TMP/helper.err"; }
}

# --- 1. Schémas des demandes : tout ce qui n'est pas prévu est refusé ------------------------
for bad in '{"subject": "console"}' '{"ids": ["gitleaks"]}' '{"image": "x"}'; do
	hx self-sbom "$bad"
	expect "self-sbom hostile refusée : $bad" "$(jq -r .code <<< "$R")" E_SCHEMA
done
for bad in '{"ids": []}' '{"ids": ["../gitleaks"]}' '{"ids": ["Gitleaks"]}' '{"ids": "gitleaks"}' \
	'{"ids": ["gitleaks;reboot"]}' '{"all": true}' '{"ids": ["gitleaks", "gitleaks"]}'; do
	hx run-canaries "$bad"
	expect "run-canaries hostile refusée : $bad" "$(jq -r .code <<< "$R")" E_SCHEMA
done
for bad in '{}' '{"module": "gitleaks"}' '{"version": "8.30.1"}' '{"module": "../gitleaks", "version": "8.30.1"}' \
	'{"module": "gitleaks", "version": "8.30.1;rm -rf /"}' '{"module": "gitleaks", "version": "$(id)"}' \
	'{"module": "gitleaks", "version": "8.30.1", "action": "adopt"}' \
	'{"module": "gitleaks", "version": "8.30.1", "trial_id": "../../x"}' \
	"{\"module\": \"gitleaks\", \"version\": \"8.30.1\", \"image\": \"ghcr.io/x@$D3\"}" \
	"{\"module\": \"gitleaks\", \"version\": \"8.30.1\", \"image_digest\": \"$D3\"}"; do
	hx start-trial "$bad"
	expect "start-trial hostile refusée : $(cut -c1-60 <<< "$bad")" "$(jq -r .code <<< "$R")" E_SCHEMA
done
if grep -q '"pull"' "$CALLS"; then ko "demandes hostiles : aucune image récupérée"; else ok "demandes hostiles : aucune image récupérée"; fi

# --- 2. Modules inconnus ----------------------------------------------------------------------
hx run-canaries '{"ids": ["inconnu"]}'
expect "run-canaries : module non installé" "$(jq -r .code <<< "$R")" E_NOT_FOUND
hx start-trial '{"module": "inconnu", "version": "1.0.0"}'
expect "start-trial : module non installé" "$(jq -r .code <<< "$R")" E_NOT_FOUND
hx run-canaries '{}'
expect "run-canaries sans scanner installé : rien à faire, réussite" "$(jq -r '.code + " " + (.output.canaries | length | tostring)' <<< "$R")" "OK 0"

# --- 3. start-trial : la candidate vient de l'index vérifié, jamais de la demande ------------
R=$(py "
install('8.30.0', '$D1')
index = [manifest('8.30.0', '$D1'), manifest('8.30.1', '$D2'), manifest('8.29.1', '$D3')]
modules.catalog = lambda: index
class C:
    def __init__(self, p): self.params = p
    def left(self): return 600
out = {}
out['absent'] = code(vigilance.act_start_trial, C({'module': 'gitleaks', 'version': '9.0.0'}))
out['older'] = code(vigilance.act_start_trial, C({'module': 'gitleaks', 'version': '8.29.1'}))
out['same'] = code(vigilance.act_start_trial, C({'module': 'gitleaks', 'version': '8.30.0'}))
bad = manifest('8.31.0', '$D3'); bad['image'] = 'ghcr.io/exemple/gitleaks:8.31.0'
index.append(bad)
out['tag'] = code(vigilance.act_start_trial, C({'module': 'gitleaks', 'version': '8.31.0'}))
index.pop()
svc = manifest('8.32.0', '$D3'); svc['type'] = 'service'
index.append(svc)
out['service'] = code(vigilance.act_start_trial, C({'module': 'gitleaks', 'version': '8.32.0'}))
index.pop()
install('8.30.0', '$D1', status='failed')
out['unhealthy'] = code(vigilance.act_start_trial, C({'module': 'gitleaks', 'version': '8.30.1'}))
install('8.30.0', '$D1')
out['abandon-none'] = vigilance.act_start_trial(C({'module': 'gitleaks', 'version': '8.30.1', 'action': 'abandon'}))['released']
out['start'] = vigilance.act_start_trial(C({'module': 'gitleaks', 'version': '8.30.1', 'trial_id': '0b6f9c2e-1d3a-4c5b-8e7f-9a0b1c2d3e4f'}))['image_digest']
rec = vigilance.retained_for('gitleaks', '8.30.1')
out['kind'] = rec['kind']
out['mode'] = oct(os.stat(vigilance._record_path('gitleaks', '8.30.1')).st_mode & 0o777)
out['other-trial'] = vigilance.act_start_trial(C({'module': 'gitleaks', 'version': '8.30.1', 'action': 'abandon', 'trial_id': '1b6f9c2e-1d3a-4c5b-8e7f-9a0b1c2d3e4f'}))['released']
st = json.load(open(vigilance.STATE))
out['state'] = [r['module'] + '@' + r['version'] + ':' + r['kind'] for r in st['retained']]
print(json.dumps(out))
")
expect "start-trial : version absente de l'index" "$(jq -r .absent <<< "$R")" E_NOT_FOUND
expect "start-trial : version plus ancienne refusée" "$(jq -r .older <<< "$R")" E_VERSION
expect "start-trial : même version refusée" "$(jq -r .same <<< "$R")" E_VERSION
expect "start-trial : image par étiquette refusée" "$(jq -r .tag <<< "$R")" E_CHECKSUM
expect "start-trial : candidate qui n'est pas un scanner" "$(jq -r .service <<< "$R")" E_TRIAL_INVALID
expect "start-trial : module en échec refusé" "$(jq -r .unhealthy <<< "$R")" E_PRECONDITION
expect "abandon d'un essai inexistant : rien retiré" "$(jq -r '."abandon-none"' <<< "$R")" false
expect "start-trial : empreinte de l'index" "$(jq -r .start <<< "$R")" "$D2"
expect "start-trial : image retenue « trial »" "$(jq -r .kind <<< "$R")" trial
expect "image retenue : enregistrement root 0600" "$(jq -r .mode <<< "$R")" 0o600
expect "abandon d'un autre essai : image gardée" "$(jq -r '."other-trial"' <<< "$R")" false
expect "état publié : image d'essai visible" "$(jq -c .state <<< "$R")" '["gitleaks@8.30.1:trial"]'
if grep -q "\"pull\"" "$CALLS" && grep -q "@$D2" "$CALLS"; then ok "start-trial : image récupérée par empreinte"; else ko "start-trial : image récupérée par empreinte"; fi

# --- 4. Résolution du runner (contrats 24, 25) ------------------------------------------------
R=$(py "
reg = modules.load_registry(); e = reg['modules']['gitleaks']
r = {}
r['installed'] = vigilance.alternate(e, {'id': 'gitleaks', 'version': '8.30.0'})
r['installed-digest'] = vigilance.alternate(e, {'id': 'gitleaks', 'version': '8.30.0', 'image_digest': '$D1'})
r['retained'] = (vigilance.alternate(e, {'id': 'gitleaks', 'version': '8.30.1', 'image_digest': '$D2'}, True) or {}).get('image')
# Candidate d'essai demandée par une tâche normale (rejeu d'un essai) : refusée.
r['trial-not-trial-job'] = vigilance.alternate(e, {'id': 'gitleaks', 'version': '8.30.1', 'image_digest': '$D2'})
r['no-digest'] = vigilance.alternate(e, {'id': 'gitleaks', 'version': '8.30.1'}, True)
r['wrong-digest'] = vigilance.alternate(e, {'id': 'gitleaks', 'version': '8.30.1', 'image_digest': '$D3'})
r['absent'] = vigilance.alternate(e, {'id': 'gitleaks', 'version': '8.29.1', 'image_digest': '$D3'})
r['traversal'] = vigilance.alternate(e, {'id': 'gitleaks', 'version': '../../x'})
# Enregistrement altéré : empreinte du manifeste différente de celle déclarée.
p = vigilance._record_path('gitleaks', '8.30.1')
rec = json.load(open(p)); good = dict(rec)
rec['image_digest'] = '$D3'; json.dump(rec, open(p, 'w'))
r['tampered'] = vigilance.alternate(e, {'id': 'gitleaks', 'version': '8.30.1', 'image_digest': '$D2'}, True)
os.unlink(p); os.symlink('/etc/hostname', p)
r['symlink'] = vigilance.alternate(e, {'id': 'gitleaks', 'version': '8.30.1', 'image_digest': '$D2'}, True)
os.unlink(p); json.dump(good, open(p, 'w')); os.chmod(p, 0o600)
print(json.dumps(r))
")
expect "alternate : version installée → None" "$(jq -r .installed <<< "$R")/$(jq -r '."installed-digest"' <<< "$R")" null/null
expect "alternate : version retenue → son manifeste" "$(jq -r .retained <<< "$R")" "ghcr.io/exemple/gitleaks@$D2"
expect "alternate : candidate refusée hors tâche d'essai" "$(jq -r '."trial-not-trial-job"' <<< "$R")" false
expect "alternate : autre version sans empreinte refusée" "$(jq -r '."no-digest"' <<< "$R")" false
expect "alternate : empreinte différente → absente" "$(jq -r '."wrong-digest"' <<< "$R")" false
expect "alternate : version jamais retenue → absente (infra)" "$(jq -r .absent <<< "$R")" false
expect "alternate : version piégée → absente" "$(jq -r .traversal <<< "$R")" false
expect "alternate : enregistrement altéré ignoré" "$(jq -r .tampered <<< "$R")" false
expect "alternate : lien symbolique ignoré" "$(jq -r .symlink <<< "$R")" false

# --- 5. pins.json écrit par la console, lu sans confiance -------------------------------------
PINS="$T/var/lib/scanoria/console/pins.json"
pins_count() { py "p = vigilance.read_pins(); print('illisible' if p is None else len(p))"; }
echo "{\"version\": 1, \"pins\": [{\"module\": \"gitleaks\", \"version\": \"8.30.0\", \"image_digest\": \"$D1\"}, {\"module\": \"../x\", \"version\": \"1\", \"image_digest\": \"$D1\"}, {\"module\": \"gitleaks\", \"version\": \"8.30.0\", \"image_digest\": \"sha256:court\"}]}" > "$PINS"
expect "pins.json : entrées invalides écartées" "$(pins_count)" 1
cp "$PINS" "$TMP/pins.ok"
ln -sf "$TMP/pins.ok" "$PINS.lnk" && mv -f "$PINS.lnk" "$PINS"
expect "pins.json : lien symbolique ignoré" "$(pins_count)" illisible
rm -f "$PINS"
python3 -c 'import json; print(json.dumps({"version": 1, "pins": [], "pad": "x" * 1100000}))' > "$PINS"
expect "pins.json : plus de 1 Mio ignoré" "$(pins_count)" illisible
printf '{"version": 1, "pins": [], "pins": []}' > "$PINS"
expect "pins.json : clé dupliquée ignorée" "$(pins_count)" illisible
printf 'pas du json' > "$PINS"
expect "pins.json : JSON invalide ignoré" "$(pins_count)" illisible
echo '{"version": 2, "pins": []}' > "$PINS"
expect "pins.json : version inconnue ignorée" "$(pins_count)" illisible

# --- 6. Mise à jour d'un module figé : l'ancienne image est gardée ----------------------------
cp "$TMP/pins.ok" "$PINS"
: > "$CALLS"
R=$(py "
old = modules.load_registry()['modules']['gitleaks']['manifest']
r = {'keep': vigilance.keep_pinned(old)}
r['kind'] = vigilance.retained_for('gitleaks', '8.30.0')['kind']
r['protected'] = vigilance.image_retained(old['image'])
modules.remove_image({'modules': {}}, old['image'])   # comme après la mise à jour : plus installée
# Une version figée essayée reste figée.
vigilance.retain(old, 'trial', '0b6f9c2e-1d3a-4c5b-8e7f-9a0b1c2d3e4f')
r['still-pin'] = vigilance.retained_for('gitleaks', '8.30.0')['kind']
other = manifest('8.28.0', '$D3')
r['not-pinned'] = vigilance.keep_pinned(other)
print(json.dumps(r))
")
expect "mise à jour : version figée retenue" "$(jq -r .keep <<< "$R")/$(jq -r .kind <<< "$R")" true/pin
expect "image figée protégée de remove_image" "$(jq -r .protected <<< "$R")" true
if grep -q '"rmi"' "$CALLS"; then ko "remove_image : image figée jamais retirée"; else ok "remove_image : image figée jamais retirée"; fi
expect "version figée essayée : reste figée" "$(jq -r '."still-pin"' <<< "$R")" pin
expect "version non figée : non retenue" "$(jq -r '."not-pinned"' <<< "$R")" false

# --- 7. Ménage : version plus figée, essai oublié ---------------------------------------------
: > "$CALLS"
R=$(py "
import datetime
reg = install('8.30.1', '$D2')   # essai adopté : la candidate est désormais installée
r = {'kept': vigilance.gc_retained(reg)}
later = common.now() + datetime.timedelta(days=15)
# pins.json absent (restauration) : échec fermé, la version figée reste.
os.unlink('$PINS')
r['no-pins'] = [x['version'] for x in vigilance.list_retained() if x['kind'] == 'pin' and x['version'] not in vigilance.gc_retained(reg, later)]
r['no-pins-left'] = sorted(x['version'] for x in vigilance.list_retained())
# Plus aucun projet ne fige 8.30.0, et l'essai a plus de 14 jours.
json.dump({'version': 1, 'pins': []}, open('$PINS', 'w'))
r['released'] = sorted(vigilance.gc_retained(reg, later))
r['left'] = [x['version'] for x in vigilance.list_retained()]
print(json.dumps(r))
")
expect "ménage : essai récent et version figée gardés" "$(jq -c .kept <<< "$R")" '[]'
expect "ménage sans pins.json : version figée gardée (échec fermé)" "$(jq -c '."no-pins-left"' <<< "$R")" '["8.30.0"]'
expect "ménage : version libérée retirée" "$(jq -c .released <<< "$R")" '["gitleaks@8.30.0"]'
expect "ménage : plus aucune image retenue" "$(jq -c .left <<< "$R")" '[]'
if grep -q "\"rmi\",\"--ignore\",\"ghcr.io/exemple/gitleaks@$D1\"" "$CALLS"; then ok "ménage : ancienne image retirée"; else ko "ménage : ancienne image retirée"; fi
if grep -q "\"rmi\",\"--ignore\",\"ghcr.io/exemple/gitleaks@$D2\"" "$CALLS"; then ko "ménage : image installée jamais retirée"; else ok "ménage : image installée jamais retirée"; fi

# --- 8. Canaris : un échec est signalé, le module reste actif ---------------------------------
R=$(py "
from scanoria import testbed
install('8.30.1', '$D2')
install('1.0.0', '$D3', mid='osv-scanner')
def fake(m, timeout=None):
    if m['id'] == 'gitleaks':
        return {'passed': True, 'details': [{'rule': 'generic-api-key', 'min': 1, 'found': 2, 'ok': True}]}
    raise Fail('E_TESTBED', 'expected findings not found', {'testbed': {'details': [{'category': 'sca', 'min': 1, 'found': 0, 'ok': False}]}})
testbed.run = fake
class C:
    params = {}
    def left(self): return 3000
try:
    vigilance.act_run_canaries(C()); out = {'code': 'OK'}
except Fail as f:
    out = {'code': f.code, 'output': f.output}
reg = modules.load_registry()
out['enabled'] = [reg['modules'][m]['enabled'] for m in ('gitleaks', 'osv-scanner')]
out['status'] = reg['modules']['osv-scanner']['status']
print(json.dumps(out))
")
expect "canaris : échec signalé" "$(jq -r .code <<< "$R")" E_CANARY_FAILED
expect "canaris : résultats de chaque module" "$(jq -c '[.output.canaries[] | [.module, .ok]]' <<< "$R")" '[["gitleaks",true],["osv-scanner",false]]'
expect "canaris : détail de l'attendu manquant" "$(jq -c '.output.canaries[1].details | [.error.code, .expect[0].found]' <<< "$R")" '["E_TESTBED",0]'
expect "canaris : aucun module désactivé" "$(jq -c .enabled <<< "$R")/$(jq -r .status <<< "$R")" '[true,true]/healthy'
expect "canaris : détection perdue classée detection" "$(jq -r '.output.canaries[1].details.error.class' <<< "$R")" detection
R=$(py "
from scanoria import testbed
def fake(m, timeout=None):
    if m['id'] == 'gitleaks':
        return {'passed': True, 'details': []}
    raise Fail('E_TIMEOUT', 'podman timed out after 300s')
testbed.run = fake
class C:
    params = {}
    def left(self): return 3000
try:
    out = {'code': 'OK', 'output': vigilance.act_run_canaries(C())}
except Fail as f:
    out = {'code': f.code, 'output': f.output}
print(json.dumps(out))
")
expect "canaris : délai dépassé = infra, sans échec de détection (G12)" "$(jq -r '.code + "/" + .output.canaries[1].details.error.class' <<< "$R")" OK/infra
echo '{"busy": 1}' > "$TMP/runner.json"
expect "canaris : runner occupé détecté" "$(py 'print(vigilance._runner_busy())')" True
rm -f "$TMP/runner.json"

# --- 9. self-sbom sans Syft ni comparateur ----------------------------------------------------
py "
reg = modules.load_registry(); del reg['modules']['osv-scanner']
common.write_json(modules.REGISTRY, reg, 0o600, group_scanoria=False)
"
hx self-sbom '{}'
expect "self-sbom : réussit sans outil" "$(jq -r .code <<< "$R")" OK
expect "self-sbom : trous publiés" "$(jq -c '.output.gaps' <<< "$R")" '["syft-missing","matcher-missing"]'
expect "self-sbom : SBOM de la console lu" "$(jq -c '.output.subjects | map([.subject, .components])' <<< "$R")" '[["console",2]]'
SELF="$T/var/lib/scanoria/vigilance/self"
expect "self-sbom : statut publié pour la console (0640)" "$(stat -c %a "$SELF/status.json")" 640
expect "self-sbom : relevé repris dans state.json" "$(jq -r '.self_sbom.subjects[0].subject' "$T/var/lib/scanoria/vigilance/state.json")" console
echo '{"components": [' > "$TMP/console.cdx.json"
hx self-sbom '{}'
expect "self-sbom : SBOM de la console invalide signalé" "$(jq -r '.output.subjects[0].error.code' <<< "$R")" E_SELFSBOM_OUTPUT
rm -f "$TMP/console.cdx.json"
hx self-sbom '{}'
expect "self-sbom : SBOM de la console absent signalé" "$(jq -c '.output.gaps' <<< "$R")" '["syft-missing","matcher-missing","console-sbom-missing"]'

echo
echo "b26 : $PASS réussis, $FAIL échoués"
[[ "$FAIL" -eq 0 ]]
