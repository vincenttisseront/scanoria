#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Attend que le contrôle « ci-ok » de ci.yml réussisse sur le commit
# $GITHUB_SHA (CLAUDE.md § 16 : jamais de publication sans CI verte).
#   wait-ci-ok.sh [MINUTES]   (défaut : 170)
# Échec immédiat si ci-ok échoue, échec au délai s'il reste absent ou en cours.
# Un contrôle qui a une date de fin et une conclusion est terminé, même si
# l'API le dit encore « in_progress » (incohérence vue le 2026-11-24, qui a
# bloqué la publication du catalogue pendant le délai complet).
# Variables : GH_TOKEN (droit checks: read), GITHUB_REPOSITORY, GITHUB_SHA.
set -euo pipefail

: "${GH_TOKEN:?}" "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}"
minutes=${1:-170}
[[ "$minutes" =~ ^[0-9]{1,4}$ ]] || { echo "wait-ci-ok: délai invalide : $minutes" >&2; exit 2; }
end=$(( $(date +%s) + minutes * 60 ))
while :; do
	state=$(gh api "repos/$GITHUB_REPOSITORY/commits/$GITHUB_SHA/check-runs?check_name=ci-ok&filter=latest" \
		--jq '(.check_runs | sort_by(.started_at) | last) // {} | "\(if .completed_at != null and .conclusion != null then "completed" else (.status // "absent") end)/\(.conclusion // "none")"')
	case "$state" in
		completed/success)
			echo "ci-ok réussi sur $GITHUB_SHA"; exit 0 ;;
		completed/*)
			echo "::error::ci-ok en échec sur $GITHUB_SHA ($state) : aucune publication"; exit 1 ;;
	esac
	if [[ "$(date +%s)" -ge "$end" ]]; then
		echo "::error::ci-ok toujours absent ou en cours sur $GITHUB_SHA ($state)"; exit 1
	fi
	echo "ci-ok : $state, nouvelle lecture dans 60 s"
	sleep 60
done
