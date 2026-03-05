<#
.SYNOPSIS
    run_pipeline.ps1 — Varaksha SLSA secure pipeline (PowerShell wrapper)

.DESCRIPTION
    Runs the 5-step SLSA pipeline simulation on Windows.
    Wraps security/slsa/examples/pipeline_simulation.py.

    Steps executed:
      1. GATE-M diff review (AST inspection)
      2. Simulated build (produces varaksha_patch.bin)
      3. SLSA provenance generation (in-toto v0.1 / SLSA v0.2)
      4. Ed25519 artifact signing
      5. 4-point SLSA verification

.PARAMETER TaskId
    Optional GATE-M task UUID to embed in provenance.
    If omitted, a new UUID is generated automatically.

.PARAMETER OutputDir
    Optional output directory for pipeline artefacts.
    Defaults to security/slsa/pipeline_output/

.EXAMPLE
    # Run with auto-generated task id:
    .\security\slsa\examples\run_pipeline.ps1

.EXAMPLE
    # Run with a specific GATE-M task id:
    .\security\slsa\examples\run_pipeline.ps1 -TaskId "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

.EXAMPLE
    # Run and write artefacts to a custom directory:
    .\security\slsa\examples\run_pipeline.ps1 -OutputDir "C:\temp\pipeline_out"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TaskId = "",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve repo root (3 levels up from this script) ─────────────────────────
$ScriptDir = Split-Path -Parent $PSCommandPath         # …/security/slsa/examples/
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir "..\..\..")).Path

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   VARAKSHA SLSA PIPELINE  (PowerShell runner)       ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  Repo root : $RepoRoot" -ForegroundColor Gray
Write-Host ""

# ── Locate Python ─────────────────────────────────────────────────────────────
$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$Python = if (Test-Path $VenvPython) { $VenvPython } else { "python" }
Write-Host "  Python    : $Python" -ForegroundColor Gray

# ── Build argument list ───────────────────────────────────────────────────────
$PipelineScript = Join-Path $ScriptDir "pipeline_simulation.py"
$PythonArgs = @($PipelineScript)

if ($TaskId -ne "") {
    $PythonArgs += "--gate-m-task-id"
    $PythonArgs += $TaskId
}

if ($OutputDir -ne "") {
    $PythonArgs += "--output-dir"
    $PythonArgs += $OutputDir
}

# ── Run ───────────────────────────────────────────────────────────────────────
Write-Host ""
$StartTime = Get-Date

try {
    & $Python @PythonArgs
    $ExitCode = $LASTEXITCODE
} catch {
    Write-Host "  [ERROR] Failed to launch Python pipeline: $_" -ForegroundColor Red
    exit 1
}

$Elapsed = [math]::Round(((Get-Date) - $StartTime).TotalMilliseconds)

Write-Host ""
if ($ExitCode -eq 0) {
    Write-Host "  Pipeline completed successfully  ($Elapsed ms)" -ForegroundColor Green
} else {
    Write-Host "  Pipeline FAILED with exit code $ExitCode  ($Elapsed ms)" -ForegroundColor Red
}
Write-Host ""
exit $ExitCode
