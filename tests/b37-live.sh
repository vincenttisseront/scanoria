#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# b37-live — gate de release de la 0.8 (chantier A, CLAUDE.md § 7) contre un
# VRAI Forgejo (job CI release-live, machine de test root jetable) :
#   1. AC jetable, certificats de forge.exemple.test et analyse.exemple.test ;
#   2. Forgejo en conteneur (même image épinglée que b34-live), HTTPS, comptes
#      créés par sa ligne de commande et leurs jetons ;
#   3. la console (tests/integration/release-live.test.ts, vrai PostgreSQL et
#      vrai helper, qui crée et garde la clé Ed25519 de l'appliance) : tag et
#      release dans Forgejo → interrogation (mode tiré) → analyse de release →
#      rapport signé par le helper → statut scanoria/release-gate dans Forgejo
#      → fichiers joints à la release, téléchargés depuis Forgejo et vérifiés
#      par scanoria-verify avec la clé publique de l'appliance ; deuxième tag
#      avec la comparaison F2 ; tag déplacé signalé sans réanalyse ;
#   4. nettoyage : conteneur, entrées /etc/hosts.
# Moteur : podman (CI) ; SCANORIA_ENGINE=docker pour une machine de développement.
# Dépendances : bash, openssl, curl, jq, podman, postgresql-16, node et webui/node_modules.

# shellcheck disable=SC2016,SC2015
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "b37-live : root requis" >&2; exit 2; }
ENGINE=${SCANORIA_ENGINE:-podman}
for t in openssl curl jq node python3 "$ENGINE"; do command -v "$t" > /dev/null || { echo "outil manquant : $t" >&2; exit 2; }; done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# Forgejo 17.0.2 (licence GPL-3.0-or-later), empreinte relevée le 2026-11-25 (skopeo inspect --raw | sha256sum).
FORGEJO_IMAGE=${SCANORIA_FORGEJO_IMAGE:-"codeberg.org/forgejo/forgejo@sha256:879f4f10a98e3e167b32cde5f7ae3af0163d50bfacf567559a27a0e95a95670c"}
CLI=${SCANORIA_FORGEJO_CLI:-forgejo}
NAME=scanoria-b37-forgejo
PORT=3000
TMP=$(mktemp -d)
HOSTS_MARK="# scanoria-b37"
cleanup() {
	"$ENGINE" rm -f "$NAME" > /dev/null 2>&1 || true
	sed -i "/$HOSTS_MARK\$/d" /etc/hosts || true
	rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
ko() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }

# --- 1. AC et certificats jetables ----------------------------------------------------------
cd "$TMP"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=Scanoria b37 AC de test" -keyout ca.key -out ca.pem > /dev/null 2>&1
for h in forge analyse; do
	openssl req -newkey rsa:2048 -nodes -subj "/CN=$h.exemple.test" -keyout "$h.key" -out "$h.csr" > /dev/null 2>&1
	printf 'subjectAltName=DNS:%s.exemple.test\nextendedKeyUsage=serverAuth\n' "$h" > "$h.ext"
	openssl x509 -req -in "$h.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile "$h.ext" -out "$h.pem" > /dev/null 2>&1
done
mkdir -p certs && cp forge.pem forge.key certs/ && chmod 755 certs && chmod 644 certs/*
printf '127.0.0.1 forge.exemple.test analyse.exemple.test %s\n' "$HOSTS_MARK" >> /etc/hosts
ok "AC jetable et certificats émis"

# --- 2. Forgejo -----------------------------------------------------------------------------
env_args=()
for prefix in FORGEJO GITEA; do
	env_args+=(
		-e "${prefix}__security__INSTALL_LOCK=true"
		-e "${prefix}__server__PROTOCOL=https"
		-e "${prefix}__server__HTTP_PORT=$PORT"
		-e "${prefix}__server__DOMAIN=forge.exemple.test"
		-e "${prefix}__server__ROOT_URL=https://forge.exemple.test:$PORT/"
		-e "${prefix}__server__CERT_FILE=/certs/forge.pem"
		-e "${prefix}__server__KEY_FILE=/certs/forge.key"
		-e "${prefix}__server__DISABLE_SSH=true"
		-e "${prefix}__database__DB_TYPE=sqlite3"
		-e "${prefix}__webhook__ALLOWED_HOST_LIST=*"
		-e "${prefix}__webhook__SKIP_TLS_VERIFY=true"
		-e "${prefix}__webhook__DELIVER_TIMEOUT=10"
		-e "${prefix}__service__DISABLE_REGISTRATION=true"
		-e "${prefix}__repository__DEFAULT_BRANCH=main"
		-e "${prefix}__log__LEVEL=Warn"
	)
done
"$ENGINE" run -d --name "$NAME" --network host --add-host analyse.exemple.test:127.0.0.1 \
	-v "$TMP/certs:/certs:ro" "${env_args[@]}" "$FORGEJO_IMAGE" > /dev/null
for _ in $(seq 1 90); do
	curl -sf -m 5 --noproxy "*" --cacert "$TMP/ca.pem" "https://forge.exemple.test:$PORT/api/v1/version" > /dev/null 2>&1 && break
	sleep 1
done
if curl -sf -m 5 --noproxy "*" --cacert "$TMP/ca.pem" "https://forge.exemple.test:$PORT/api/v1/version" > "$TMP/version.json"; then
	ok "Forgejo démarré en HTTPS (version $(jq -r .version "$TMP/version.json"))"
else
	ko "Forgejo injoignable"
	"$ENGINE" logs "$NAME" 2>&1 | tail -n 40
	exit 1
fi

fj() { "$ENGINE" exec -u git "$NAME" "$CLI" admin user "$@"; }
pw() { openssl rand -hex 16; }
fj create --admin --username scanoria-admin --password "$(pw)" --email admin@exemple.test --must-change-password=false > /dev/null
for u in scanoria-bot dev-une relectrice; do
	fj create --username "$u" --password "$(pw)" --email "$u@exemple.test" --must-change-password=false > /dev/null
done
tok() { fj generate-access-token --username "$1" --token-name "b37-$1" --scopes "$2" --raw | tail -n 1; }
jq -n --arg admin "$(tok scanoria-admin all)" \
	--arg bot "$(tok scanoria-bot read:user,read:organization,write:repository,write:issue)" \
	--arg dev "$(tok dev-une read:user,write:repository,write:issue)" \
	--arg reviewer "$(tok relectrice read:user,write:repository,write:issue)" \
	'{admin: $admin, bot: $bot, dev: $dev, reviewer: $reviewer}' > "$TMP/tokens.json"
chmod 600 "$TMP/tokens.json"
[[ $(jq '[.[] | select(length >= 20)] | length' "$TMP/tokens.json") -eq 4 ]] && ok "comptes et jetons créés (compte de service à droits réduits)" || ko "jetons Forgejo"

# --- 3. Console, helper et gate de release contre le vrai Forgejo ----------------------------
if [[ -z "${DATABASE_URL:-}" ]]; then
	systemctl start postgresql.service
	# Mot de passe tiré à l'exécution : rien de littéral dans le dépôt.
	pg_pass=$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')
	runuser -u postgres -- psql -X -q -c "ALTER USER postgres PASSWORD '$pg_pass'" > /dev/null
	DATABASE_URL="postgres://postgres:$pg_pass@127.0.0.1:5432/postgres"
fi
if (cd "$ROOT/webui" && DATABASE_URL="$DATABASE_URL" \
	SCANORIA_FORGEJO_URL="https://forge.exemple.test:$PORT" SCANORIA_FORGE_CA="$TMP/ca.pem" SCANORIA_FORGEJO_TOKENS="$TMP/tokens.json" \
	NUXT_FORGE_LOCALE=fr node_modules/.bin/vitest run --project server tests/integration/release-live.test.ts); then
	ok "gate de release : tag → interrogation → analyse → rapport signé → statut → fichiers joints vérifiés par scanoria-verify ; F2 ; tag déplacé"
else
	ko "gate de release contre le vrai Forgejo"
	"$ENGINE" logs "$NAME" 2>&1 | tail -n 40
fi
grep -rqF -- "$(jq -r .bot "$TMP/tokens.json")" "$ROOT/webui" --include=*.log 2> /dev/null && ko "jeton dans un journal" || ok "jeton du compte de service absent des journaux"

echo
echo "b37-live : $PASS réussis, $FAIL échoués"
[[ $FAIL -eq 0 ]]
