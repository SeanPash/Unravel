<#
.SYNOPSIS
  Windows build for the Unravel engine (replaces the Unix Makefile, which needs
  `make` + a POSIX shell that Windows does not ship).

.DESCRIPTION
  Builds the React UI, copies the production bundle into the go:embed directory,
  then compiles the engine binary with the UI baked in. Optionally installs it
  onto your PATH.

  Prereqs: `go` and `npm` on PATH (you have both). No `make` required.

  With -Install it copies the binary to ~/.local/bin and, if that directory is
  not already on your PATH, adds it to your persistent user PATH so you can type
  `unravel` from a new terminal.

.EXAMPLE
  ./build.ps1                # build UI + binary -> engine/unravel.exe
  ./build.ps1 -Install       # also install to ~/.local/bin and put it on PATH
  ./build.ps1 -SkipUI        # rebuild only the Go binary (reuse embedded UI)
#>
param(
  [switch]$Install,
  [switch]$SkipUI
)

$ErrorActionPreference = 'Stop'
$engine = $PSScriptRoot
$static = Join-Path $engine 'internal/api/static'

# Fail loudly if the toolchain is missing, with a next step the user can act on.
function Require-Tool($name, $hint) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: '$name' was not found on your PATH." -ForegroundColor Red
    Write-Host "  $hint" -ForegroundColor Yellow
    Write-Host "  Then open a new terminal and run ./build.ps1 again." -ForegroundColor Yellow
    exit 1
  }
}
Require-Tool 'go'  'Install Go 1.25+ from https://go.dev/dl/ (or: winget install GoLang.Go).'
Require-Tool 'npm' 'Install Node 20+ from https://nodejs.org/ (or: winget install OpenJS.NodeJS.LTS).'

# True if $dir is already on the given PATH-style string, comparing on the
# fully-resolved path so '.local/bin' and '.local\bin' count as the same entry.
function Test-OnPath($dir, $pathString) {
  if (-not $pathString) { return $false }
  $target = [System.IO.Path]::GetFullPath($dir).TrimEnd('\')
  foreach ($entry in ($pathString -split ';')) {
    if (-not $entry) { continue }
    try { $resolved = [System.IO.Path]::GetFullPath($entry).TrimEnd('\') } catch { continue }
    if ($resolved -ieq $target) { return $true }
  }
  return $false
}

# Optional build-time Gemini key from a gitignored engine/gemini.key (newline
# stripped; a stray newline 401s against Gemini). Absent -> empty -> stub narrator.
$ldflags = ''
$keyFile = Join-Path $engine 'gemini.key'
if (Test-Path $keyFile) {
  $key = (Get-Content -Raw $keyFile).Trim()
  if ($key) { $ldflags = "-X 'main.embeddedGeminiKey=$key'" }
}

if (-not $SkipUI) {
  Write-Host '==> Building UI' -ForegroundColor Cyan
  npm --prefix (Join-Path $engine '../ui') install
  npm --prefix (Join-Path $engine '../ui') run build

  Write-Host '==> Copying UI bundle into embed dir' -ForegroundColor Cyan
  # Clear static/ except the two tracked placeholders, then copy the fresh bundle.
  Get-ChildItem $static -Force |
    Where-Object { $_.Name -notin '.gitkeep', '.gitignore' } |
    Remove-Item -Recurse -Force
  Copy-Item (Join-Path $engine '../ui/dist/*') $static -Recurse -Force
}

Write-Host '==> Compiling engine binary' -ForegroundColor Cyan
$out = Join-Path $engine 'unravel.exe'
if ($ldflags) {
  go build -ldflags $ldflags -o $out ./cmd/engine
} else {
  go build -o $out ./cmd/engine
}
if ($LASTEXITCODE -ne 0) {
  throw "go build failed (exit $LASTEXITCODE). If the file is locked, stop any running unravel.exe first: Get-Process unravel | Stop-Process -Force"
}

$size = [math]::Round((Get-Item $out).Length / 1MB, 1)
Write-Host "==> Built $out ($size MB)" -ForegroundColor Green

if ($Install) {
  $bin = Join-Path $HOME '.local/bin'
  New-Item -ItemType Directory -Force $bin | Out-Null
  Copy-Item $out (Join-Path $bin 'unravel.exe') -Force
  Write-Host "==> Installed to $bin\unravel.exe" -ForegroundColor Green

  # Make `unravel` resolvable by name. A fresh Windows profile rarely has
  # ~/.local/bin on PATH, so add it to the persistent *user* PATH if it is
  # missing. Skip if it is already there (in either the persisted user PATH or
  # the current process PATH, e.g. from a system-wide entry).
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if ((Test-OnPath $bin $userPath) -or (Test-OnPath $bin $env:Path)) {
    Write-Host "==> $bin is already on your PATH. Run: unravel" -ForegroundColor Green
  } else {
    $newUserPath = if ($userPath) { "$userPath;$bin" } else { $bin }
    [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
    Write-Host "==> Added $bin to your user PATH." -ForegroundColor Green
    Write-Host "    Open a NEW terminal, then run: unravel" -ForegroundColor Yellow
    Write-Host "    (This terminal won't see the change; PATH is read at startup.)" -ForegroundColor Yellow
  }
}
