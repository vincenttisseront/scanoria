// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Vincent Tisseront
//
// Shared library Jenkins Scanoria (J3, 0.8) : une ligne dans le Jenkinsfile,
//   scanoria(url: 'https://analyse.exemple.test', project: '<id>', credentialsId: 'scanoria-token')
// Jenkins n'émet pas de jeton OIDC de CI standard : le jeton d'API du projet
// est lu depuis un identifiant Jenkins (« Secret text »), jamais en clair.
// L'étape commune scanoria-ci.sh est livrée dans resources/ de la bibliothèque.
def call(Map args = [:]) {
  def url = args.url ?: error('scanoria : url requis')
  def project = args.project ?: error('scanoria : project requis')
  def vars = [
    "SCANORIA_URL=${url}",
    "SCANORIA_PROJECT=${project}",
    "SCANORIA_PROFILE=${args.profile ?: ''}",
    "SCANORIA_REF=${args.ref ?: (env.TAG_NAME ?: env.BRANCH_NAME ?: '')}",
    "SCANORIA_CLIENT_SHA256=${args.clientSha256 ?: ''}",
    "SCANORIA_CACERT=${args.cacert ?: ''}",
    "SCANORIA_TIMEOUT=${args.timeout ?: 3600}",
    'SCANORIA_OIDC=0',
  ]
  writeFile file: '.scanoria-ci.sh', text: libraryResource('scanoria-ci.sh')
  def rc
  withCredentials([string(credentialsId: args.credentialsId ?: 'scanoria-token', variable: 'SCANORIA_TOKEN')]) {
    withEnv(vars) {
      rc = sh(script: 'sh .scanoria-ci.sh', returnStatus: true)
    }
  }
  if (rc == 1) error('Scanoria : verdict défavorable')
  if (rc != 0) error("Scanoria : verdict non concluant ou erreur (code ${rc})")
}
