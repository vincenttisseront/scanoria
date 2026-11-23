# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Vincent Tisseront
<#
.SYNOPSIS
    Lanceur Windows de build.sh : construit l'ISO, le lot de mise à jour ou
    l'arborescence du lot dans un conteneur ubuntu:24.04 neuf.

.DESCRIPTION
    Équivalent de « ./build.sh --iso|--bundle|--stage » pour Windows, avec
    Docker Desktop ou Podman (détecté). Le dépôt est monté en lecture seule ;
    toute la construction se fait dans le conteneur (build.sh --in-container).
    Sortie dans out\ (ou -OutDir).

.PARAMETER Mode
    iso (défaut), bundle ou stage.

.PARAMETER Repo
    Source des mises à jour PROPRIÉTAIRE/DÉPÔT (update-source.json). Défaut :
    $env:GITHUB_REPOSITORY, puis le dépôt GitHub du remote « origin ».

.PARAMETER Engine
    docker ou podman (défaut : détecté).

.PARAMETER OutDir
    Répertoire de sortie (défaut : out\ à la racine du dépôt).

.EXAMPLE
    .\make-iso.ps1
    .\make-iso.ps1 -Mode bundle -Repo proprietaire/scanoria
#>
[CmdletBinding()]
param(
    [ValidateSet('iso', 'bundle', 'stage')]
    [string]$Mode = 'iso',
    [string]$Repo = '',
    [ValidateSet('', 'docker', 'podman')]
    [string]$Engine = '',
    [string]$OutDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string]$Message) {
    Write-Host "[build] $Message" -ForegroundColor Cyan
}

function Stop-Build([string]$Message) {
    Write-Host "[build] ERREUR / ERROR : $Message" -ForegroundColor Red
    exit 1
}

function Get-EnvValue([string]$Path, [string]$Key) {
    $line = Get-Content -LiteralPath $Path | Where-Object { $_ -match "^$Key=" } | Select-Object -Last 1
    if (-not $line) { Stop-Build "$Key absent de $Path" }
    return $line.Substring($Key.Length + 1).Trim()
}

function Test-Command([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

$Root = $PSScriptRoot

# Les scripts doivent garder des fins de ligne LF (sinon bash échoue dans le
# conteneur et le lot contiendrait des scripts invalides).
$probe = [System.IO.File]::ReadAllText((Join-Path $Root 'build.sh'))
if ($probe.Contains("`r")) {
    Stop-Build ("build.sh contient des fins de ligne CRLF : cloner avec " +
        "« git config core.autocrlf false » (ou .gitattributes « *.sh text eol=lf »), puis recloner. / " +
        "build.sh has CRLF line endings: clone with core.autocrlf=false.")
}

# Moteur de conteneurs
if (-not $Engine) {
    if ((Test-Command 'docker')) {
        & docker info *> $null
        if ($LASTEXITCODE -eq 0) { $Engine = 'docker' }
    }
    if (-not $Engine -and (Test-Command 'podman')) { $Engine = 'podman' }
    if (-not $Engine) {
        Stop-Build 'ni Docker Desktop ni Podman disponible / neither Docker Desktop nor Podman found'
    }
}

# Dépôt source des mises à jour
if (-not $Repo) { $Repo = $env:GITHUB_REPOSITORY }
if (-not $Repo -and (Test-Command 'git')) {
    $url = (& git -C $Root remote get-url origin 2>$null)
    if ($url -and ($url -replace '\.git$', '') -match 'github\.com[:/]([A-Za-z0-9-]+/[A-Za-z0-9._-]+)$') {
        $Repo = $Matches[1]
    }
}
if ($Repo -notmatch '^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$') {
    Stop-Build 'dépôt source des mises à jour inconnu : -Repo PROPRIETAIRE/DEPOT'
}

# Commit et date de référence (reproductibilité)
$Commit = $env:SCANORIA_COMMIT
if (-not $Commit -and (Test-Command 'git')) { $Commit = (& git -C $Root rev-parse HEAD 2>$null) }
if ($Commit -notmatch '^[0-9a-f]{40}$') { Stop-Build 'commit inconnu (SCANORIA_COMMIT)' }
$Epoch = $env:SOURCE_DATE_EPOCH
if (-not $Epoch -and (Test-Command 'git')) { $Epoch = (& git -C $Root log -1 --format=%ct 2>$null) }
if ($Epoch -notmatch '^[0-9]+$') { Stop-Build 'SOURCE_DATE_EPOCH inconnu' }

if (-not $OutDir) { $OutDir = Join-Path $Root 'out' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path -LiteralPath $OutDir).Path

$Image = $env:BUILD_IMAGE
if (-not $Image) { $Image = Get-EnvValue (Join-Path $Root 'src/iso/build.env') 'BUILD_IMAGE' }

$runArgs = @(
    'run', '--rm', '--pull=always', '--security-opt', 'label=disable',
    '-v', "${Root}:/src:ro",
    '-v', "${OutDir}:/out",
    '-e', "SCANORIA_REPO=$Repo",
    '-e', "SCANORIA_COMMIT=$Commit",
    '-e', "SOURCE_DATE_EPOCH=$Epoch",
    '-e', "SCANORIA_REUSE_BUNDLE=$(if ($env:SCANORIA_REUSE_BUNDLE -eq '1') { '1' } else { '0' })",
    $Image, 'bash', '/src/build.sh', '--in-container', "--$Mode"
)

Write-Step "$Mode : $Engine, image $Image, dépôt $Repo, sortie $OutDir"
Write-Step 'construction en cours, cela peut durer plusieurs minutes… / building, this may take several minutes…'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
& $Engine @runArgs
$code = $LASTEXITCODE
$sw.Stop()
if ($code -ne 0) { Stop-Build "échec de la construction (code $code) / build failed" }
Write-Step ("terminé en {0:N0} s / done in {0:N0} s" -f $sw.Elapsed.TotalSeconds)
Get-ChildItem -LiteralPath $OutDir -File | Format-Table Name, Length -AutoSize
