#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
#
# Affiche les conditions du quality gate SonarQube Cloud et les issues ouvertes
# de l'analyse courante (PR ou branche), et celles de main. Lecture seule.
set -euo pipefail
: "${SONAR_TOKEN:?}"
KEY=$(sed -n 's/^sonar\.projectKey=//p' sonar-project.properties)
API=https://sonarcloud.io/api
out=${GITHUB_STEP_SUMMARY:-/dev/stdout}

report() { # libellé paramètre=valeur
	local label=$1 scope=$2
	{
		echo "### Quality gate : $label"
		curl -fsS -u "$SONAR_TOKEN:" "$API/qualitygates/project_status?projectKey=$KEY&$scope" \
			| jq -r '"Statut : \(.projectStatus.status)", (.projectStatus.conditions[]
				| "- \(.status) \(.metricKey) : \(.actualValue // "—") (\(.comparator) \(.errorThreshold))")'
		echo
		echo "Issues ouvertes :"
		curl -fsS -u "$SONAR_TOKEN:" "$API/issues/search?componentKeys=$KEY&$scope&issueStatuses=OPEN,CONFIRMED&ps=100" \
			| jq -r '.issues[] | "- \(.impacts | map("\(.softwareQuality)/\(.severity)") | join(",")) \(.rule) \(.component | sub("^[^:]*:"; "")):\(.line // 0) — \(.message)"'
		echo
	} | tee -a "$out" || echo "lecture impossible ($label)"
}

if [[ -n "${PR_NUMBER:-}" ]]; then
	report "PR #$PR_NUMBER" "pullRequest=$PR_NUMBER"
else
	report "branche $BRANCH" "branch=$BRANCH"
fi
report "main" "branch=main"
