<#
.SYNOPSIS
  pgsafe dev tasks for Windows - same targets as the Makefile.
.EXAMPLE
  .\make.ps1 dev-up
  .\make.ps1 test
#>
param([Parameter(Position = 0)][string]$Target = 'help')

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$Compose = @('compose', '-f', 'deploy/compose.dev.yml')
# server/ and web/ are absent in the open-source mirror (github.com/desnarong/pgsafe).
$HasServer = Test-Path 'server/go.mod'
$ServerPkgs = @(if ($HasServer) { './server/...' })
$Pkgs = @('./agent/...') + $ServerPkgs + @('./shared/apitypes/...')

# A stale GOROOT (pointing at an older Go than the one on PATH) breaks every build
# with "compile: version ... does not match go tool version". Ignore it for this run.
if ($env:GOROOT -and (Test-Path (Join-Path $env:GOROOT 'VERSION'))) {
    $rootVer = (Get-Content (Join-Path $env:GOROOT 'VERSION') -TotalCount 1)
    $pathVer = ((go version) -split ' ')[2]
    if ($rootVer -ne $pathVer) {
        Write-Warning "GOROOT points at $rootVer but go on PATH is $pathVer - ignoring GOROOT for this run. Remove the GOROOT user variable to fix permanently."
        $env:GOROOT = $null
    }
}

function Invoke-Native {
    param([string]$Exe, [string[]]$ArgList)
    # Windows PowerShell 5.1 turns native stderr (docker progress output) into
    # terminating errors under 'Stop'; rely on the exit code instead.
    $ErrorActionPreference = 'Continue'
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($ArgList -join ' ') failed with exit code $LASTEXITCODE" }
}

function Get-GitValue([string[]]$ArgList, [string]$Default) {
    $ErrorActionPreference = 'Continue'
    $v = & git @ArgList 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $v) { return $Default }
    return $v
}

# Release tooling runs from pinned images (keep in sync with the Makefile and release.yml).
$GoreleaserImage = 'goreleaser/goreleaser:v2.19.0'
$ShellcheckImage = 'koalaman/shellcheck:v0.10.0'
$ShScripts = @('deploy/install/install.sh', 'deploy/install/install_test.sh', 'deploy/nfpm/postinstall.sh', 'deploy/minio/init.sh')

function Get-GoreleaserArgs {
    $a = @('run', '--rm', '-v', "${PSScriptRoot}:/src", '-w', '/src',
        '-v', '/var/run/docker.sock:/var/run/docker.sock', '-v', 'pgsafe-gomod:/go/pkg/mod',
        '-e', 'GIT_CONFIG_COUNT=1', '-e', 'GIT_CONFIG_KEY_0=safe.directory', '-e', 'GIT_CONFIG_VALUE_0=*')
    # In a git worktree .git is a pointer file with a Windows path: mount the common git dir.
    $gitDir = Get-GitValue @('rev-parse', '--absolute-git-dir') ''
    $common = Get-GitValue @('rev-parse', '--path-format=absolute', '--git-common-dir') ''
    if ($gitDir -and $common -and ($gitDir -ne $common)) {
        $a += @('-v', "${common}:/gitcommon", '-e', "GIT_DIR=/gitcommon/worktrees/$(Split-Path $gitDir -Leaf)", '-e', 'GIT_WORK_TREE=/src')
    }
    return $a + @($GoreleaserImage)
}

# Control plane (server/) and dashboard (web/) targets live in private.ps1, which is
# not part of the open-source mirror. It defines $PrivateTargets (name -> scriptblock).
$PrivateTargets = @{}
if (Test-Path (Join-Path $PSScriptRoot 'private.ps1')) { . (Join-Path $PSScriptRoot 'private.ps1') }
if ($PrivateTargets.ContainsKey($Target)) { & $PrivateTargets[$Target]; return }

switch ($Target) {
    'dev-up'    { Invoke-Native docker ($Compose + @('up', '-d', '--wait')) }
    'dev-down'  { Invoke-Native docker ($Compose + @('down')) }
    'dev-reset' {
        Invoke-Native docker ($Compose + @('down', '-v'))
        Invoke-Native docker ($Compose + @('up', '-d', '--wait'))
    }
    'dev-logs'  { Invoke-Native docker ($Compose + @('logs', '-f', '--tail=100')) }
    'build' {
        Invoke-Native go (@('build') + $Pkgs + @('./e2e/...'))
        $ver = Get-GitValue @('describe', '--tags', '--always', '--dirty') '0.0.0-dev'
        $sha = Get-GitValue @('rev-parse', '--short', 'HEAD') 'none'
        $env:CGO_ENABLED = '0'
        Invoke-Native go @('build', '-trimpath', '-ldflags', "-s -w -X main.version=$ver -X main.commit=$sha", '-o', 'bin/pgsafe.exe', './agent/cmd/pgsafe')
        if ($HasServer) { Invoke-Native go @('build', '-trimpath', '-ldflags', "-s -w -X main.version=$ver", '-o', 'bin/pgsafe-server.exe', './server/cmd/server') }
    }
    'test' {
        Invoke-Native go (@('vet') + $Pkgs)
        Invoke-Native go (@('test') + $Pkgs)
    }
    'e2e'  { Invoke-Native go (@('test', '-tags', 'e2e', '-count=1', '-timeout', '30m', '-v', './agent/...') + $ServerPkgs + @('./e2e/...')) }
    'e2e-perf' {
        $env:PGSAFE_E2E_PERF = '1'
        Invoke-Native go @('test', '-tags', 'e2e', '-count=1', '-timeout', '60m', '-v', '-run', 'TestMaskPerformance', './e2e/...')
    }
    'release-check' {
        # Validates .goreleaser.yaml and builds a local snapshot in dist/. Publishes nothing.
        $g = Get-GoreleaserArgs
        Invoke-Native docker ($g + @('check'))
        Invoke-Native docker ($g + @('release', '--snapshot', '--clean', '--skip=publish,sign,sbom'))
    }
    'install-test' {
        if (-not (Test-Path 'dist/metadata.json')) { throw 'run .\make.ps1 release-check first' }
        foreach ($img in @('alpine:3.20', 'debian:bookworm-slim')) {
            Invoke-Native docker @('run', '--rm', '-v', "${PSScriptRoot}:/src:ro", '-v', "${PSScriptRoot}\dist:/dist:ro", $img, 'sh', '/src/deploy/install/install_test.sh')
        }
    }
    'shellcheck' {
        Invoke-Native docker (@('run', '--rm', '-v', "${PSScriptRoot}:/mnt", '-w', '/mnt', $ShellcheckImage, '--shell=sh') + $ShScripts)
    }
    'fmt'  { Invoke-Native gofmt (@('-s', '-w', 'agent') + @(if ($HasServer) { 'server' }) + @('shared', 'e2e')) }
    default { Write-Host ('targets: dev-up dev-down dev-reset dev-logs build test e2e e2e-perf fmt release-check install-test shellcheck ' + (($PrivateTargets.Keys | Sort-Object) -join ' ')) }
}
