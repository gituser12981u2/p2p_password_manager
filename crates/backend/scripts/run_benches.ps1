$ErrorActionPreference = "Stop"

# Workspace root (script is at crates/backend/scripts)
$WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
Set-Location $WorkspaceRoot

# Target dir (honor CARGO_TARGET_DIR)
$TargetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $WorkspaceRoot "target" }
$CriterionDir = Join-Path $TargetDir "criterion"

# Config
$BenchTarget = if ($env:BENCH_TARGET) { $env:BENCH_TARGET } else { "bench_backend" }
$ResultsDir  = if ($env:RESULTS_DIR)  { $env:RESULTS_DIR }  else { Join-Path $WorkspaceRoot "bench_results" }

# Detect host
$OS = "windows"
# architecture mapping
$archCode = (Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture
switch ($archCode) {
  9  { $ArchStr = "x64" }
  5  { $ArchStr = "arm" }
  12 { $ArchStr = "arm64" }
  default { $ArchStr = "unknown" }
}

$Rustv  = ((rustc --version) -split ' ')[1]
$Stamp  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH-mm-ssZ")
$Baseline = "$OS-$ArchStr-rust$Rustv"

$Out = Join-Path $ResultsDir "$Stamp-$OS-$ArchStr-rust$Rustv"
New-Item -ItemType Directory -Force -Path (Join-Path $Out "criterion") | Out-Null

# Metadata
Get-CimInstance Win32_Processor |
  Format-List Name,NumberOfCores,NumberOfLogicalProcessors |
  Out-File (Join-Path $Out "cpu.txt")
systeminfo | Out-File (Join-Path $Out "os.txt")

# Build + bench (package-scoped)
cargo build --release -p backend

# pass extra Criterion args after "--"
$extra = $args
cargo bench -p backend --bench $BenchTarget -- --save-baseline $Baseline @extra

# Archive Criterion outputs from WORKSPACE target dir
if (-not (Test-Path $CriterionDir)) {
  Write-Error "No criterion output at $CriterionDir"
  exit 2
}

# Copy only json/csv artifacts, keep structure
robocopy $CriterionDir (Join-Path $Out "criterion") *.json *.csv /S > $null

Write-Output "Saved to: $Out"
Write-Output "Baseline: $Baseline"
Write-Output "From: $CriterionDir"