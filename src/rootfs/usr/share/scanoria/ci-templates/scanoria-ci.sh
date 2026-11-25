#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# scanoria-ci.sh : étape commune des modèles CI officiels de Scanoria (J3,
# 0.8) pour GitHub Actions, Forgejo Actions, GitLab CI, Jenkins et Tekton.
# sh POSIX, avec curl, jq et sha256sum (ou shasum). Paramètres par variables
# d'environnement (jamais un secret en argument) :
#   SCANORIA_URL           https://<appliance> (obligatoire en mode poussé)
#   SCANORIA_PROJECT       identifiant du projet (page Intégration CI)
#   SCANORIA_MODE          push (défaut) : la CI appelle l'appliance et attend
#                          le verdict ; pull : la CI attend le statut de commit
#                          scanoria/release-gate posé par l'appliance (§ 7.2)
#   SCANORIA_PROFILE       profil (défaut : celui du déclencheur, G9)
#   SCANORIA_REF           ref analysée (défaut : branche ou tag de la CI)
#   SCANORIA_CACERT        AC de l'appliance (fichier PEM), si elle n'est pas
#                          dans le magasin du runner
#   SCANORIA_CLIENT_SHA256 empreinte attendue du client scanoria-scan
#                          téléchargé depuis l'appliance (posée par la PR
#                          d'intégration J2) : client refusé si elle diffère
#   SCANORIA_OIDC          auto (défaut) : OIDC si la CI le fournit, sinon
#                          SCANORIA_TOKEN ; 1 : OIDC obligatoire ; 0 : jeton
#   SCANORIA_TOKEN         jeton d'API du projet (si OIDC indisponible)
#   SCANORIA_SARIF         fichiers SARIF ou CycloneDX produits par la CI, à
#                          téléverser (J6), séparés par des espaces
#   SCANORIA_TIMEOUT       délai d'attente du verdict en secondes (3600)
#   Mode tiré : SCANORIA_FORGE_TOKEN (jeton de lecture des statuts, le jeton
#   éphémère du job), GITHUB_API_URL, GITHUB_REPOSITORY, GITHUB_SHA (ou leurs
#   équivalents FORGEJO_*).
# Codes de sortie : ceux de scanoria-scan (0 favorable, 1 défavorable,
# 2 non concluant, 3 erreur d'utilisation ou d'accès).

set -u

MODE=${SCANORIA_MODE:-push}
TIMEOUT=${SCANORIA_TIMEOUT:-3600}
case $TIMEOUT in ''|*[!0-9]*) echo "scanoria-ci: SCANORIA_TIMEOUT invalide" >&2; exit 3 ;; esac

out() {
  # out <clé> <valeur> : sortie de l'étape (GitHub et Forgejo Actions).
  if [ -n "${GITHUB_OUTPUT:-}" ] && [ -w "${GITHUB_OUTPUT}" ]; then printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"; fi
}

sha256() {
  if command -v sha256sum > /dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

TMP=$(mktemp -d 2> /dev/null) || { echo "scanoria-ci: mktemp a échoué" >&2; exit 3; }
trap 'rm -rf "$TMP"' EXIT
umask 077

if [ "$MODE" = pull ]; then
  # Mode tiré : l'appliance n'est pas jointe ; on attend son statut de commit.
  api=${FORGEJO_API_URL:-${GITHUB_API_URL:-}}
  repo=${FORGEJO_REPOSITORY:-${GITHUB_REPOSITORY:-}}
  sha=${FORGEJO_SHA:-${GITHUB_SHA:-}}
  case $api in https://*) ;; *) echo "scanoria-ci: mode tiré : GITHUB_API_URL en https:// requis" >&2; exit 3 ;; esac
  printf '%s' "$repo" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || { echo "scanoria-ci: GITHUB_REPOSITORY invalide" >&2; exit 3; }
  printf '%s' "$sha" | grep -Eq '^[0-9a-f]{40,64}$' || { echo "scanoria-ci: GITHUB_SHA invalide" >&2; exit 3; }
  [ -n "${SCANORIA_FORGE_TOKEN:-}" ] || { echo "scanoria-ci: SCANORIA_FORGE_TOKEN requis en mode tiré" >&2; exit 3; }
  printf 'Authorization: Bearer %s\n' "$SCANORIA_FORGE_TOKEN" > "$TMP/auth"
  unset SCANORIA_FORGE_TOKEN
  start=$(date +%s)
  while :; do
    code=$(curl -sS --max-time 30 -H @"$TMP/auth" -H 'Accept: application/json' -o "$TMP/st" -w '%{http_code}' \
      "$api/repos/$repo/commits/$sha/statuses" 2> /dev/null) || code=000
    if [ "$code" = 200 ]; then
      # Statut le plus récent du contexte scanoria/release-gate (GitHub et Forgejo : du plus récent au plus ancien).
      state=$(jq -r '[.[] | select(.context == "scanoria/release-gate")][0].state // empty' "$TMP/st" 2> /dev/null)
      case $state in
        success) echo "scanoria-ci: scanoria/release-gate : favorable"; out verdict passed; exit 0 ;;
        failure) echo "scanoria-ci: scanoria/release-gate : défavorable" >&2; out verdict failed; exit 1 ;;
        error) echo "scanoria-ci: scanoria/release-gate : non concluant" >&2; out verdict inconclusive; exit 2 ;;
      esac
    fi
    if [ $(($(date +%s) - start)) -ge "$TIMEOUT" ]; then
      echo "scanoria-ci: statut scanoria/release-gate non posé après $TIMEOUT s : non concluant" >&2
      out verdict inconclusive
      exit 2
    fi
    sleep 15
  done
fi

[ "$MODE" = push ] || { echo "scanoria-ci: SCANORIA_MODE attend push ou pull" >&2; exit 3; }
URL=${SCANORIA_URL:-}
URL=${URL%/}
case $URL in https://*) ;; *) echo "scanoria-ci: SCANORIA_URL en https:// requis" >&2; exit 3 ;; esac

# Ref par défaut : branche de la PR, sinon branche ou tag de la CI.
if [ -z "${SCANORIA_REF:-}" ]; then
  SCANORIA_REF=${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-${CI_COMMIT_TAG:-${CI_MERGE_REQUEST_SOURCE_BRANCH_NAME:-${CI_COMMIT_REF_NAME:-${TAG_NAME:-${BRANCH_NAME:-}}}}}}}
fi
[ -n "$SCANORIA_REF" ] || { echo "scanoria-ci: ref inconnue (SCANORIA_REF)" >&2; exit 3; }
export SCANORIA_URL="$URL" SCANORIA_REF

# Client téléchargé depuis l'appliance, vérifié par son empreinte.
set -- -fsS --max-time 60 -o "$TMP/scanoria-scan"
if [ -n "${SCANORIA_CACERT:-}" ]; then set -- "$@" --cacert "$SCANORIA_CACERT"; fi
curl "$@" "$URL/api/gates/client" || { echo "scanoria-ci: client scanoria-scan non téléchargé depuis $URL" >&2; exit 3; }
got=$(sha256 "$TMP/scanoria-scan")
if [ -n "${SCANORIA_CLIENT_SHA256:-}" ]; then
  [ "$got" = "$SCANORIA_CLIENT_SHA256" ] || { echo "scanoria-ci: empreinte du client inattendue ($got) : refusé" >&2; exit 3; }
else
  echo "scanoria-ci: avertissement : empreinte du client non épinglée (SCANORIA_CLIENT_SHA256) ; reçu $got" >&2
fi
chmod 0700 "$TMP/scanoria-scan"

# OIDC par défaut quand la CI le fournit (J4) ; sinon le jeton d'API du projet.
case ${SCANORIA_OIDC:-auto} in
  1|true|yes) export SCANORIA_OIDC=1 ;;
  0|false|no) export SCANORIA_OIDC=0 ;;
  *)
    if [ -n "${SCANORIA_ID_TOKEN:-}" ] || { [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; }; then
      export SCANORIA_OIDC=1
    else
      export SCANORIA_OIDC=0
    fi ;;
esac

for f in ${SCANORIA_SARIF:-}; do
  "$TMP/scanoria-scan" upload "$f" --project "${SCANORIA_PROJECT:-}" --ref "$SCANORIA_REF" --quiet > /dev/null \
    || echo "scanoria-ci: téléversement refusé : $f" >&2
done

set -- --project "${SCANORIA_PROJECT:-}" --wait --timeout "$TIMEOUT"
if [ -n "${SCANORIA_PROFILE:-}" ]; then set -- "$@" --profile "$SCANORIA_PROFILE"; fi
"$TMP/scanoria-scan" "$@" > "$TMP/scan.out"
rc=$?
cat "$TMP/scan.out"
case $rc in
  0) out verdict passed ;;
  1) out verdict failed ;;
  2) out verdict inconclusive ;;
  *) out verdict error ;;
esac
exit "$rc"
